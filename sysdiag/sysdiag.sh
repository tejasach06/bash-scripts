#!/usr/bin/env bash
# sysdiag.sh - Distro-agnostic read-only Linux diagnostics and RCA evidence collector.

set -u
set -o pipefail

APP_VERSION="0.1.0"
MODE="menu"
REQUESTED_MODULE=""
OUT_DIR=""
PACKAGE_ONLY=0
BUNDLE=0
BUNDLE_REDACT=1
HARDEN_APPLY=0
HARDEN_UPGRADE_PACKAGES=0
HARDEN_ALLOW_VIRTUALIZATION=0
HARDEN_USER="linuxteam"
HARDEN_TMOUT=900
HARDEN_BANNER="Authorized access only. Activity may be monitored and recorded."
HARDEN_CONTROLS=""            # comma list from --controls; empty = all
HARDEN_SKIP_CONTROLS=""       # comma list from --skip-controls
HARDEN_CONTROL_ERRORS=0
HARDEN_CURRENT_CONTROL=""
HARDEN_STATUS_TSV=""
HARDEN_SCAN_ROOTS="${SYSDIAG_SCAN_ROOTS:-/etc /usr /var /opt /srv /home /root /tmp}"
HARDEN_FIND_TIMEOUT="${SYSDIAG_FIND_TIMEOUT:-120}"
HARDEN_CONTROL_IDS="tmout banner ipv6 packages packages_extra pwquality user_sudo su_wheel kernel_sysctl coredump auditd timesync journald sshd file_scan"
HARDEN_INSTALL=""                 # comma list from --install; empty = install nothing
HARDEN_PACKAGE_IDS="guest_agent fail2ban logging firewall"

HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'unknown-host')"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
START_EPOCH="$(date +%s 2>/dev/null || printf '0')"

REPORT_FILE=""
SUMMARY_FILE=""
METADATA_FILE=""
COMMAND_LOG=""
FINDINGS_TSV=""
EVIDENCE_DIR=""
MISSING_TOOLS=""
AVAILABLE_TOOLS=""
MODULES_RUN=""
REBOOT_VERDICT=""
REBOOT_VERDICT_CONFIDENCE=""
REBOOT_VERDICT_BASIS=""
REBOOT_VERDICT_RULED_OUT=""
REBOOT_VERDICT_NOT_ASSESSED=""

OPTIONAL_TOOLS="dialog whiptail jq journalctl coredumpctl dmesg last who uptime vmstat mpstat pidstat iostat sar free lscpu lsblk findmnt smartctl lvs vgs pvs systemctl systemd-detect-virt virt-what virsh podman docker ip ss ethtool nstat nft iptables firewall-cmd ufw resolvectl tar top swapon df mount awk sed grep sort uniq head tail date hostname ps"

usage() {
  cat <<'USAGE'
Usage: sysdiag.sh [options]

Read-only distro-agnostic Linux diagnostics with Markdown/JSON evidence reports.

Options:
  --run MODULE       Run one module: reboot, slow, disk, network, service, baseline, tools, harden
  --apply            Apply changes for harden (default is audit-only)
  --upgrade-packages Allow harden to upgrade installed packages in apply mode
  --allow-virtualization Permit apply mode in detected VM/container environments
  --controls LIST    Comma-separated list of hardening controls to run
  --skip-controls LIST Comma-separated list of hardening controls to skip
  --list-controls    List hardening controls and exit
  --install LIST     Comma-separated package groups to install during harden (see --list-packages)
  --list-packages    List installable package groups and exit
  --all              Run all modules
  --list             List modules and exit
  --out DIR          Write output to DIR (default: ./sysdiag-runs/<host>-<timestamp>)
  --package          Package current run directory at end
  --bundle           Emit single-file AI handoff bundle (<out>/bundle.md)
  --no-bundle        Do not emit bundle.md (overrides default for reboot module)
  --no-redact        Disable secret and IP redaction in bundle.md
  --selftest         Run internal smoke tests and exit
  --quiet            Suppress per-step progress on stderr
  --version          Show version and exit
  --no-color         Accepted for compatibility; output is never colored
  -h, --help         Show help

Interactive mode:
  Run without arguments to open a menu. dialog/whiptail are used when available;
  otherwise a plain numbered menu is shown.

Safety:
  Diagnostic modules are read-only: no package installs, config edits, service
  restarts, filesystem repair, intrusive SMART tests, or reboots.
  The harden module is audit-only by default. With --apply (root required) it
  edits local security config, and with --install/--upgrade-packages it installs
  or upgrades packages. Changed files are backed up under <out>/evidence/backups.
USAGE
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}
PROGRESS_QUIET=0
PROGRESS_STEP=0
PROGRESS_SCOPE="sysdiag"   # non-empty default: run_cmd is also called outside any module (selftest)
PROGRESS_TOTAL=0

progress_scope() {
  # progress_scope <name> [total]   total 0 = unknown, index-only
  PROGRESS_SCOPE="$1"
  PROGRESS_TOTAL="${2:-0}"
  PROGRESS_STEP=0
  [ "$PROGRESS_QUIET" -eq 1 ] || printf '==> %s\n' "$1" >&2
}

progress_begin() {
  # progress_begin <tag>; prints no newline so the result lands on the same line
  PROGRESS_STEP=$((PROGRESS_STEP + 1))
  [ "$PROGRESS_QUIET" -eq 1 ] && return 0
  if [ "$PROGRESS_TOTAL" -gt 0 ]; then
    printf '[%s %s/%s] %s ... ' "$PROGRESS_SCOPE" "$PROGRESS_STEP" "$PROGRESS_TOTAL" "$1" >&2
  else
    printf '[%s %s] %s ... ' "$PROGRESS_SCOPE" "$PROGRESS_STEP" "$1" >&2
  fi
}

progress_end() {
  # progress_end <rc> <seconds>
  [ "$PROGRESS_QUIET" -eq 1 ] && return 0
  if [ "$1" -eq 0 ]; then
    printf 'ok (%ss)\n' "$2" >&2
  else
    printf 'rc=%s (%ss)\n' "$1" "$2" >&2
  fi
}


sanitize_name() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_' | sed 's/^_//;s/_$//'
}

json_escape() {
  # Escape stdin or arguments for JSON string values.
  if [ "$#" -gt 0 ]; then
    printf '%s' "$*"
  else
    cat
  fi | sed \
    -e 's/\\/\\\\/g' \
    -e 's/"/\\"/g' \
    -e 's/	/\\t/g' \
    -e ':a;N;$!ba;s/\n/\\n/g'
}

init_output() {
  if [ -z "$OUT_DIR" ]; then
    OUT_DIR="./sysdiag-runs/${HOSTNAME_SHORT}-${TIMESTAMP}"
  fi
  EVIDENCE_DIR="$OUT_DIR/evidence"
  REPORT_FILE="$OUT_DIR/report.md"
  SUMMARY_FILE="$OUT_DIR/summary.json"
  METADATA_FILE="$OUT_DIR/metadata.env"
  COMMAND_LOG="$OUT_DIR/commands.log"
  FINDINGS_TSV="$OUT_DIR/findings.tsv"

  mkdir -p "$EVIDENCE_DIR" || {
    printf 'ERROR: cannot create output directory: %s\n' "$OUT_DIR" >&2
    exit 2
  }
  : > "$COMMAND_LOG"
  : > "$FINDINGS_TSV"

  detect_tools
  write_metadata
  init_report
}

detect_tools() {
  AVAILABLE_TOOLS=""
  MISSING_TOOLS=""
  for tool in $OPTIONAL_TOOLS; do
    if have_cmd "$tool"; then
      AVAILABLE_TOOLS="$AVAILABLE_TOOLS $tool"
    else
      MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
  done
}

can_privileged() {
  if [ "$(id -u 2>/dev/null || printf 99999)" = "0" ]; then
    return 0
  fi
  have_cmd sudo && sudo -n true >/dev/null 2>&1
}

write_metadata() {
  local distro_name distro_id distro_like kernel init virt priv
  distro_name="unknown"
  distro_id="unknown"
  distro_like=""
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_name="${PRETTY_NAME:-${NAME:-unknown}}"
    distro_id="${ID:-unknown}"
    distro_like="${ID_LIKE:-}"
  fi
  kernel="$(uname -srmo 2>/dev/null || uname -a 2>/dev/null || printf unknown)"
  init="$(cat /proc/1/comm 2>/dev/null || printf unknown)"
  if have_cmd systemd-detect-virt; then
    virt="$(systemd-detect-virt 2>/dev/null || printf none)"
  elif have_cmd virt-what; then
    virt="$(virt-what 2>/dev/null | tr '\n' ',' | sed 's/,$//' || printf unknown)"
    [ -n "$virt" ] || virt="none"
  else
    virt="unknown"
  fi
  if [ "$(id -u 2>/dev/null || printf 99999)" = "0" ]; then
    priv="root"
  elif can_privileged; then
    priv="sudo-nopasswd"
  else
    priv="unprivileged"
  fi

  cat > "$METADATA_FILE" <<EOF_META
SYS_DIAG_VERSION=$APP_VERSION
HOSTNAME=$HOSTNAME_SHORT
TIMESTAMP_UTC=$TIMESTAMP
DISTRO_NAME=$(printf '%s' "$distro_name" | sed 's/ /_/g')
DISTRO_ID=$distro_id
DISTRO_LIKE=$(printf '%s' "$distro_like" | sed 's/ /,/g')
KERNEL=$(printf '%s' "$kernel" | sed 's/ /_/g')
INIT_SYSTEM=$init
VIRTUALIZATION=$virt
PRIVILEGE=$priv
OUTPUT_DIR=$OUT_DIR
READ_ONLY=true
EOF_META
}

init_report() {
  cat > "$REPORT_FILE" <<EOF_REPORT
# Sysdiag Report

Generated: $TIMESTAMP UTC  
Host: $HOSTNAME_SHORT  
Script Version: $APP_VERSION  
Output Directory: $OUT_DIR  
Safety Mode: read-only

## Executive Summary

Findings are appended as modules run. Absence of a finding is not proof of absence; see Missing Data / Permission Gaps.

## Environment

\`\`\`
$(sed 's/^/  /' "$METADATA_FILE" 2>/dev/null)
\`\`\`

## Modules Run

EOF_REPORT
}

append_report() {
  printf '%s\n' "$*" >> "$REPORT_FILE"
}

record_module() {
  MODULES_RUN="$MODULES_RUN $1"
  append_report "- $1"
}

run_cmd() {
  # run_cmd tag command...
  local tag safe_tag outfile start end rc cmd_s
  tag="$1"
  shift
  safe_tag="$(sanitize_name "$tag")"
  outfile="$EVIDENCE_DIR/${safe_tag}.txt"
  start="$(date +%s 2>/dev/null || printf '0')"
  progress_begin "$tag"
  cmd_s="$*"

  {
    printf '### command\n%s\n\n' "$cmd_s"
    printf '### started_utc\n%s\n\n' "$(date -u +%FT%TZ 2>/dev/null || date)"
    printf '### output\n'
  } > "$outfile"

  "$@" >> "$outfile" 2>&1
  rc=$?
  end="$(date +%s 2>/dev/null || printf '0')"
  progress_end "$rc" "$((end - start))"

  {
    printf '\n### exit_code\n%s\n' "$rc"
    printf '\n### duration_seconds\n%s\n' "$((end - start))"
  } >> "$outfile"

  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ 2>/dev/null || date)" "$tag" "$rc" "$((end - start))" "$cmd_s" >> "$COMMAND_LOG"
  return 0
}

run_shell() {
  # run_shell tag shell-string
  local tag shellcmd safe_tag outfile start end rc
  tag="$1"
  shellcmd="$2"
  safe_tag="$(sanitize_name "$tag")"
  outfile="$EVIDENCE_DIR/${safe_tag}.txt"
  start="$(date +%s 2>/dev/null || printf '0')"
  progress_begin "$tag"
  {
    printf '### command\n%s\n\n' "$shellcmd"
    printf '### started_utc\n%s\n\n' "$(date -u +%FT%TZ 2>/dev/null || date)"
    printf '### output\n'
  } > "$outfile"
  sh -c "$shellcmd" >> "$outfile" 2>&1
  rc=$?
  end="$(date +%s 2>/dev/null || printf '0')"
  progress_end "$rc" "$((end - start))"
  {
    printf '\n### exit_code\n%s\n' "$rc"
    printf '\n### duration_seconds\n%s\n' "$((end - start))"
  } >> "$outfile"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ 2>/dev/null || date)" "$tag" "$rc" "$((end - start))" "$shellcmd" >> "$COMMAND_LOG"
  return 0
}

add_finding() {
  # severity confidence title evidence recommendation
  local severity confidence title evidence recommendation
  severity="$1"
  confidence="$2"
  title="$3"
  evidence="$4"
  recommendation="$5"
  printf '%s\t%s\t%s\t%s\t%s\n' "$severity" "$confidence" "$title" "$evidence" "$recommendation" >> "$FINDINGS_TSV"
}

missing_tool_note() {
  add_finding "info" "high" "Optional tool unavailable: $1" "tool-detection" "Install or enable $1 only if deeper diagnostics are needed; script continued with fallbacks."
}

section() {
  append_report ""
  append_report "## $1"
  append_report ""
}

probe_common_baseline() {
  have_cmd uname && run_cmd baseline-uname uname -a
  have_cmd uptime && run_cmd baseline-uptime uptime
  have_cmd who && run_cmd baseline-who-boot who -b
  have_cmd free && run_cmd baseline-free free -h
  [ -r /proc/meminfo ] && run_cmd baseline-proc-meminfo cat /proc/meminfo
  [ -r /proc/loadavg ] && run_cmd baseline-proc-loadavg cat /proc/loadavg
  [ -r /proc/pressure/cpu ] && run_cmd baseline-psi-cpu cat /proc/pressure/cpu
  [ -r /proc/pressure/memory ] && run_cmd baseline-psi-memory cat /proc/pressure/memory
  [ -r /proc/pressure/io ] && run_cmd baseline-psi-io cat /proc/pressure/io
  have_cmd lscpu && run_cmd baseline-lscpu lscpu
  have_cmd lsblk && run_cmd baseline-lsblk lsblk -o NAME,MAJ:MIN,RM,SIZE,RO,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
  have_cmd df && run_cmd baseline-df-h df -hT
  have_cmd df && run_cmd baseline-df-ih df -ih
  have_cmd ip && run_cmd baseline-ip-addr ip addr show
  have_cmd ip && run_cmd baseline-ip-route ip route show table all
  have_cmd ss && run_cmd baseline-ss-listen ss -tulpen
  have_cmd ps && run_cmd baseline-ps-top-cpu ps -eo pid,ppid,stat,pcpu,pmem,comm,args --sort=-pcpu
  have_cmd ps && run_cmd baseline-ps-top-mem ps -eo pid,ppid,stat,pcpu,pmem,comm,args --sort=-pmem
}

analyze_file_patterns() {
  local file label
  file="$1"
  label="$2"
  [ -s "$file" ] || return 0

  if grep -Eiq 'out of memory|oom-killer|Killed process|Memory cgroup out of memory' "$file"; then
    add_finding "critical" "high" "OOM killer or memory exhaustion evidence found in $label" "$(basename "$file")" "Inspect memory-heavy processes, cgroup limits, swap sizing, and memory pressure history."
  fi
  if grep -Eiq 'kernel panic|Oops:|BUG: unable to handle|panic_on_oops|Fatal exception' "$file"; then
    add_finding "critical" "medium" "Kernel panic/Oops signature found in $label" "$(basename "$file")" "Enable kdump/persistent journal and analyze vmcore or full previous-boot kernel logs."
  fi
  if grep -Eiq 'watchdog: BUG: soft lockup|hard LOCKUP|blocked for more than|hung task|RCU stall' "$file"; then
    add_finding "critical" "medium" "Watchdog/hung task/lockup evidence found in $label" "$(basename "$file")" "Correlate with CPU, storage latency, kernel version, drivers, and hypervisor events."
  fi
  if grep -Eiq 'I/O error|Buffer I/O error|blk_update_request|EXT4-fs error|XFS.*error|remounting filesystem read-only|nvme.*reset|ata[0-9].*error' "$file"; then
    add_finding "critical" "high" "Storage or filesystem error evidence found in $label" "$(basename "$file")" "Check SMART, controller logs, cabling/backplane, filesystem state, and backup freshness before repair."
  fi
  if grep -Eiq 'thermal|temperature above threshold|overheat|power button|ACPI.*Power Button' "$file"; then
    add_finding "warn" "medium" "Thermal/power event hints found in $label" "$(basename "$file")" "Check BMC/IPMI, UPS, hypervisor, kernel thermal logs, and physical power path."
  fi
}

module_baseline() {
  record_module baseline
  progress_scope baseline
  section "Baseline Health Report"
  probe_common_baseline
  if have_cmd systemctl; then
    run_cmd baseline-systemctl-failed systemctl --failed --no-pager
  else
    missing_tool_note systemctl
  fi
  if have_cmd journalctl; then
    run_cmd baseline-journal-errors journalctl -p warning..alert -n 300 --no-pager
    analyze_file_patterns "$EVIDENCE_DIR/baseline-journal-errors.txt" "recent warning..alert journal"
  else
    missing_tool_note journalctl
  fi
  if have_cmd systemd-detect-virt; then
    run_cmd baseline-virt systemd-detect-virt
  elif have_cmd virt-what; then
    run_cmd baseline-virt-what virt-what
  fi
  if have_cmd podman; then
    run_cmd baseline-podman-ps podman ps -a --no-trunc
  fi
  if have_cmd docker; then
    run_cmd baseline-docker-ps docker ps -a --no-trunc
  fi
  add_finding "info" "high" "Baseline collection completed" "baseline-*" "Review report findings and raw evidence index for gaps."
}

module_reboot() {
  record_module reboot
  progress_scope reboot
  section "Reboot / Crash Investigation"
  have_cmd uptime && run_cmd reboot-uptime uptime
  have_cmd who && run_cmd reboot-who-boot who -b
  have_cmd last && run_cmd reboot-last-x last -x reboot shutdown -n 20
  if have_cmd journalctl; then
    run_cmd reboot-journal-boots journalctl --list-boots --no-pager
    run_cmd reboot-journal-prev journalctl -b -1 --no-pager
    run_cmd reboot-journal-prev-kernel journalctl -b -1 -k --no-pager
    run_cmd reboot-journal-current-kernel journalctl -b 0 -k -n 300 --no-pager
    analyze_file_patterns "$EVIDENCE_DIR/reboot-journal-prev.txt" "previous boot journal"
    analyze_file_patterns "$EVIDENCE_DIR/reboot-journal-prev-kernel.txt" "previous boot kernel journal"
  else
    missing_tool_note journalctl
    for f in /var/log/syslog /var/log/messages /var/log/kern.log /var/log/dmesg; do
      [ -r "$f" ] && run_cmd "reboot-log-$(basename "$f")" tail -n 500 "$f"
    done
  fi
  have_cmd dmesg && run_cmd reboot-dmesg-current dmesg -T
  have_cmd coredumpctl && run_cmd reboot-coredumpctl-list coredumpctl list --no-pager
  # shellcheck disable=SC2016
  run_shell reboot-crash-paths 'printf "Crash-related paths:\n"; for d in /var/crash /var/lib/systemd/coredump /var/lib/kdump /var/spool/kdump; do [ -e "$d" ] && ls -lah "$d"; done'
  local init_rc
  if have_cmd journalctl; then
    run_cmd reboot-journal-shutdown-initiator journalctl -b -1 --no-pager -g 'Requested transition|systemd-logind|Power key|Power Button|shutdown|reboot|scheduled for'
    init_rc="$(grep -A1 '^### exit_code' "$EVIDENCE_DIR/reboot-journal-shutdown-initiator.txt" 2>/dev/null | tail -n1)"
    if [ "$init_rc" != "0" ]; then
      # shellcheck disable=SC2016
      run_shell reboot-journal-shutdown-initiator-grep 'journalctl -b -1 --no-pager | grep -Ei "Requested transition|systemd-logind|Power key|Power Button|COMMAND=.*(shutdown|reboot)|scheduled for"'
    fi
    # shellcheck disable=SC2016
    run_shell reboot-journal-prev-tail 'journalctl -b -1 --no-pager | tail -n 200'
  fi
  # shellcheck disable=SC2016
  run_shell reboot-wtmp-timeline 'last -Fxn 40 reboot shutdown runlevel 2>/dev/null || last -x -n 40'
  # shellcheck disable=SC2016
  run_shell reboot-auth-tail 'for f in /var/log/auth.log /var/log/secure; do [ -r "$f" ] && { echo "### $f"; tail -n 200 "$f"; }; done'
  if [ ! -r /var/log/auth.log ] && [ ! -r /var/log/secure ]; then
    have_cmd journalctl && run_cmd reboot-auth-journal journalctl -b -1 --no-pager -t sudo -t sshd -t su
  fi
  # shellcheck disable=SC2016
  run_shell reboot-pkg-history 'if [ -r /var/log/dpkg.log ]; then tail -n 200 /var/log/dpkg.log; fi; for f in /var/log/dpkg.log.1; do [ -r "$f" ] && tail -n 100 "$f"; done; command -v dnf >/dev/null && dnf history list --reverse 2>&1 | tail -n 40; command -v yum >/dev/null && yum history list 2>&1 | tail -n 40; command -v zypper >/dev/null && zypper --no-refresh search --installed-only --type package >/dev/null 2>&1; [ -r /var/log/zypp/history ] && tail -n 100 /var/log/zypp/history'
  # shellcheck disable=SC2016
  run_shell reboot-auto-update 'for f in /var/log/unattended-upgrades/unattended-upgrades.log /var/log/unattended-upgrades/unattended-upgrades-shutdown.log /var/log/dnf-automatic.log; do [ -r "$f" ] && { echo "### $f"; tail -n 120 "$f"; }; done; for f in /var/run/reboot-required /var/run/reboot-required.pkgs /run/reboot-required /run/reboot-required.pkgs; do [ -e "$f" ] && { echo "### $f"; cat "$f"; }; done; command -v needs-restarting >/dev/null && needs-restarting -r 2>&1'
  # shellcheck disable=SC2016
  run_shell reboot-kernel-installed 'uname -r; ls -lt --time-style=long-iso /boot/vmlinuz-* 2>/dev/null | head -n 10'
  have_cmd systemctl && run_cmd reboot-timers systemctl list-timers --all --no-pager
  # shellcheck disable=SC2016
  run_shell reboot-scheduled-jobs '[ -e /run/systemd/shutdown/scheduled ] && { echo "### /run/systemd/shutdown/scheduled"; cat /run/systemd/shutdown/scheduled; }; command -v atq >/dev/null && { echo "### atq"; atq 2>&1; }; for f in /etc/crontab /var/spool/cron/crontabs/root /var/spool/cron/root; do [ -r "$f" ] && { echo "### $f"; grep -Ei "reboot|shutdown|halt" "$f"; }; done; ls /etc/cron.d 2>/dev/null | while read -r c; do grep -liE "reboot|shutdown" "/etc/cron.d/$c" 2>/dev/null; done'
  # shellcheck disable=SC2016
  run_shell reboot-panic-sysctl 'for k in kernel.panic kernel.panic_on_oops kernel.hung_task_panic kernel.hardlockup_panic vm.panic_on_oom kernel.softlockup_panic kernel.nmi_watchdog; do printf "%s = " "$k"; sysctl -n "$k" 2>/dev/null || echo unavailable; done; ls /dev/watchdog* 2>/dev/null; lsmod 2>/dev/null | grep -E "^(softdog|i6300esb|wdat_wdt)"'
  # shellcheck disable=SC2016
  run_shell reboot-kdump-status 'command -v systemctl >/dev/null && systemctl is-enabled kdump kdump-tools 2>&1; ls -lah /var/crash/*/ 2>/dev/null | head -n 40; for f in /var/crash/*/vmcore-dmesg.txt /var/crash/*/dmesg*; do [ -r "$f" ] && { echo "### $f"; tail -n 200 "$f"; }; done'
  # shellcheck disable=SC2016
  run_shell reboot-journal-persistence 'ls -d /var/log/journal 2>/dev/null || echo "no /var/log/journal (volatile journal)"; command -v journalctl >/dev/null && journalctl --disk-usage 2>&1; grep -hE "^[[:space:]]*Storage=" /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null'
  # shellcheck disable=SC2016
  run_shell reboot-virt-hints 'command -v systemd-detect-virt >/dev/null && systemd-detect-virt; command -v systemctl >/dev/null && systemctl is-active qemu-guest-agent vmtoolsd 2>&1; dmesg 2>/dev/null | grep -Ei "hypervisor|kvm-clock|vmware|xen|virtio|Hyper-V" | head -n 30'
  # shellcheck disable=SC2016
  run_shell reboot-clock 'date -u; command -v timedatectl >/dev/null && timedatectl status 2>&1; command -v chronyc >/dev/null && chronyc tracking 2>&1; command -v ntpq >/dev/null && ntpq -p 2>&1'
  analyze_file_patterns "$EVIDENCE_DIR/reboot-journal-prev-tail.txt" "previous boot shutdown tail"
  analyze_file_patterns "$EVIDENCE_DIR/reboot-kdump-status.txt" "kdump/vmcore artifacts"

  reboot_verdict
}

reboot_verdict() {
  REBOOT_VERDICT=""
  REBOOT_VERDICT_CONFIDENCE=""
  REBOOT_VERDICT_BASIS=""
  REBOOT_VERDICT_RULED_OUT=""
  REBOOT_VERDICT_NOT_ASSESSED=""

  local has_pat has_file
  has_pat() {
    local pat="$1" file="$2"
    [ -s "$EVIDENCE_DIR/$file" ] || return 1
    if grep -q '^### output$' "$EVIDENCE_DIR/$file" 2>/dev/null; then
      sed -n '/^### output$/,/^### exit_code$/{ /^### /d; p; }' "$EVIDENCE_DIR/$file" | grep -Eiq "$pat"
    else
      grep -Eiq "$pat" "$EVIDENCE_DIR/$file"
    fi
  }
  has_file() {
    local f="$EVIDENCE_DIR/$1"
    [ -s "$f" ] || return 1
    if grep -q '^### output$' "$f" 2>/dev/null; then
      local out_c
      out_c="$(sed -n '/^### output$/,/^### exit_code$/{ /^### /d; /^[[:space:]]*$/d; p; }' "$f" 2>/dev/null | head -n 1)"
      [ -n "$out_c" ]
    else
      [ -s "$f" ]
    fi
  }

  # 1. kernel-panic
  local panic_pat='kernel panic|Oops:|BUG: unable to handle|Fatal exception|general protection fault'
  if has_pat "$panic_pat" "reboot-journal-prev-kernel.txt" || \
     has_pat "$panic_pat" "reboot-journal-prev-tail.txt" || \
     has_pat "$panic_pat" "reboot-kdump-status.txt" || \
     has_pat "$panic_pat" "reboot-journal-prev.txt"; then
    REBOOT_VERDICT="kernel-panic"
    if has_pat 'vmcore|/var/crash/' "reboot-kdump-status.txt"; then
      REBOOT_VERDICT_CONFIDENCE="high"
    else
      REBOOT_VERDICT_CONFIDENCE="medium"
    fi
    REBOOT_VERDICT_BASIS="Kernel panic or Oops signature detected in previous boot kernel logs or crash dump"
  fi

  # 2. oom-kill
  if [ -z "$REBOOT_VERDICT" ]; then
    local oom_pat='out of memory|oom-killer|Killed process|Memory cgroup out of memory'
    if has_pat "$oom_pat" "reboot-journal-prev.txt" || \
       has_pat "$oom_pat" "reboot-journal-prev-tail.txt" || \
       has_pat "$oom_pat" "reboot-journal-prev-kernel.txt"; then
      if has_pat 'vm\.panic_on_oom[[:space:]]*=[[:space:]]*[1-9]' "reboot-panic-sysctl.txt"; then
        REBOOT_VERDICT="oom-kill"
        REBOOT_VERDICT_CONFIDENCE="medium"
        REBOOT_VERDICT_BASIS="Out-of-memory killer triggered with vm.panic_on_oom enabled"
      else
        add_finding "warn" "medium" "OOM killer activity in previous boot without panic_on_oom" "reboot-panic-sysctl.txt" "Inspect memory pressure and service limits; system did not panic on OOM directly."
      fi
    fi
  fi

  # 3. watchdog-or-lockup-reset
  if [ -z "$REBOOT_VERDICT" ]; then
    local lockup_pat='soft lockup|hard LOCKUP|hung task|RCU stall|watchdog: BUG|blocked for more than'
    if has_pat "$lockup_pat" "reboot-journal-prev-kernel.txt" || \
       has_pat "$lockup_pat" "reboot-journal-prev-tail.txt" || \
       has_pat "$lockup_pat" "reboot-journal-prev.txt"; then
      REBOOT_VERDICT="watchdog-or-lockup-reset"
      REBOOT_VERDICT_CONFIDENCE="medium"
      REBOOT_VERDICT_BASIS="Watchdog, hung task, or CPU lockup signature detected in previous boot"
    fi
  fi

  # Clean shutdown marker detection
  local clean_pat='Requested transition to (reboot|poweroff)|Reached target (Shutdown|Power-Off|Reboot)|systemd-shutdown|Stopped target (Default|Basic System)|Shutdown scheduled|Shutting down system'
  local has_clean=0
  if has_pat "$clean_pat" "reboot-journal-prev-tail.txt" || \
     has_pat "$clean_pat" "reboot-journal-prev.txt" || \
     has_pat "$clean_pat" "reboot-journal-shutdown-initiator.txt" || \
     has_pat "$clean_pat" "reboot-journal-shutdown-initiator-grep.txt"; then
    has_clean=1
  fi

  # 4. clean-shutdown-automation
  if [ -z "$REBOOT_VERDICT" ] && [ "$has_clean" -eq 1 ]; then
    local auto_initiator_pat='systemd-update-uts|unattended-upgrade|dnf-automatic|cron|atq|timer'
    local has_auto=0
    local auto_basis=""
    local out_lines cur_k newest_k
    if [ -s "$EVIDENCE_DIR/reboot-kernel-installed.txt" ]; then
      if grep -q '^### output$' "$EVIDENCE_DIR/reboot-kernel-installed.txt" 2>/dev/null; then
        out_lines="$(sed -n '/^### output$/,/^### exit_code$/{ /^### /d; /^[[:space:]]*$/d; p; }' "$EVIDENCE_DIR/reboot-kernel-installed.txt" 2>/dev/null)"
      else
        out_lines="$(cat "$EVIDENCE_DIR/reboot-kernel-installed.txt" 2>/dev/null)"
      fi
      cur_k="$(printf '%s\n' "$out_lines" | head -n 1 | awk '{print $1}')"
      newest_k="$(printf '%s\n' "$out_lines" | grep -oE 'vmlinuz-[^ ]+' | head -n 1 | sed 's/^vmlinuz-//')"
      if [ -n "$cur_k" ] && [ -n "$newest_k" ] && [ "$newest_k" != "*" ] && [ "$cur_k" != "$newest_k" ]; then
        has_auto=1
        auto_basis="Installed kernel ($newest_k) is newer than running kernel ($cur_k)"
      fi
    fi
    if [ "$has_auto" -eq 0 ]; then
      if has_pat 'reboot-required' "reboot-auto-update.txt" || \
         has_pat 'unattended-upgrades|dnf-automatic' "reboot-auto-update.txt"; then
        has_auto=1
        auto_basis="Automatic package update or reboot-required signal present"
      elif has_pat 'installed|upgraded|upgrade|install' "reboot-pkg-history.txt"; then
        has_auto=1
        auto_basis="Package history shows recent update or install activity"
      elif has_pat "$auto_initiator_pat" "reboot-journal-shutdown-initiator.txt" || \
           has_pat "$auto_initiator_pat" "reboot-journal-shutdown-initiator-grep.txt" || \
           has_pat 'reboot|shutdown|halt' "reboot-scheduled-jobs.txt"; then
        has_auto=2
        auto_basis="Shutdown initiator log indicates automated unit, timer, or cron job"
      fi
    fi

    if [ "$has_auto" -gt 0 ]; then
      REBOOT_VERDICT="clean-shutdown-automation"
      if [ "$has_auto" -eq 2 ]; then
        REBOOT_VERDICT_CONFIDENCE="high"
      else
        REBOOT_VERDICT_CONFIDENCE="medium"
      fi
      REBOOT_VERDICT_BASIS="$auto_basis"
    fi
  fi

  # 5. clean-shutdown-user
  if [ -z "$REBOOT_VERDICT" ] && [ "$has_clean" -eq 1 ]; then
    local user_pat='sudo.*COMMAND=.*(shutdown|reboot|systemctl|poweroff|halt)|systemd-logind.*Power key|Power Button|logind.*user|by user'
    if has_pat "$user_pat" "reboot-journal-shutdown-initiator.txt" || \
       has_pat "$user_pat" "reboot-journal-shutdown-initiator-grep.txt" || \
       has_pat "$user_pat" "reboot-auth-tail.txt" || \
       has_pat "$user_pat" "reboot-auth-journal.txt"; then
      REBOOT_VERDICT="clean-shutdown-user"
      if has_pat 'COMMAND=.*(shutdown|reboot)|by uid|user' "reboot-journal-shutdown-initiator.txt" || \
         has_pat 'COMMAND=.*(shutdown|reboot)|by uid|user' "reboot-journal-shutdown-initiator-grep.txt" || \
         has_pat 'sudo:.*COMMAND=' "reboot-auth-tail.txt"; then
        REBOOT_VERDICT_CONFIDENCE="high"
      else
        REBOOT_VERDICT_CONFIDENCE="medium"
      fi
      REBOOT_VERDICT_BASIS="Clean shutdown initiated by user session or power key"
    fi
  fi

  # 6. clean-shutdown-unattributed
  if [ -z "$REBOOT_VERDICT" ] && [ "$has_clean" -eq 1 ]; then
    REBOOT_VERDICT="clean-shutdown-unattributed"
    REBOOT_VERDICT_CONFIDENCE="medium"
    REBOOT_VERDICT_BASIS="Clean shutdown sequence recorded but initiator could not be attributed"
  fi

  # 7. abrupt-reset-power-or-hypervisor
  if [ -z "$REBOOT_VERDICT" ]; then
    local has_wtmp_abrupt=0
    if [ -s "$EVIDENCE_DIR/reboot-wtmp-timeline.txt" ] || [ -s "$EVIDENCE_DIR/reboot-last-x.txt" ]; then
      local boots
      boots="$(grep -Ei 'reboot|shutdown|system boot' "$EVIDENCE_DIR/reboot-wtmp-timeline.txt" "$EVIDENCE_DIR/reboot-last-x.txt" 2>/dev/null | head -n 2)"
      if [ -n "$boots" ] && ! printf '%s' "$boots" | grep -Eiq 'shutdown'; then
        has_wtmp_abrupt=1
      fi
    fi
    if [ "$has_clean" -eq 0 ] && ([ "$has_wtmp_abrupt" -eq 1 ] || [ -s "$EVIDENCE_DIR/reboot-journal-prev.txt" ] || [ -s "$EVIDENCE_DIR/reboot-journal-prev-tail.txt" ]); then
      if [ -s "$EVIDENCE_DIR/reboot-journal-prev.txt" ] || [ -s "$EVIDENCE_DIR/reboot-journal-prev-tail.txt" ]; then
        REBOOT_VERDICT="abrupt-reset-power-or-hypervisor"
        REBOOT_VERDICT_CONFIDENCE="high"
        REBOOT_VERDICT_BASIS="Previous boot journal ends abruptly without clean shutdown markers"
      elif [ "$has_wtmp_abrupt" -eq 1 ]; then
        REBOOT_VERDICT="abrupt-reset-power-or-hypervisor"
        REBOOT_VERDICT_CONFIDENCE="medium"
        REBOOT_VERDICT_BASIS="Consecutive boot records in wtmp without intervening shutdown record"
      fi
    fi
  fi

  # 8. unknown-insufficient-evidence
  if [ -z "$REBOOT_VERDICT" ]; then
    REBOOT_VERDICT="unknown-insufficient-evidence"
    REBOOT_VERDICT_CONFIDENCE="low"
    REBOOT_VERDICT_BASIS="Previous boot logs absent or insufficient to attribute reboot cause"
  fi

  # Ruled-out and not-assessed classification
  local vid has_ev
  for vid in kernel-panic oom-kill watchdog-or-lockup-reset clean-shutdown-automation clean-shutdown-user clean-shutdown-unattributed abrupt-reset-power-or-hypervisor; do
    [ "$vid" = "$REBOOT_VERDICT" ] && continue
    has_ev=0
    case "$vid" in
      kernel-panic)
        if has_file "reboot-journal-prev-kernel.txt" || has_file "reboot-journal-prev-tail.txt" || has_file "reboot-kdump-status.txt" || has_file "reboot-journal-prev.txt"; then
          has_ev=1
        fi
        ;;
      oom-kill)
        if has_file "reboot-panic-sysctl.txt" || has_file "reboot-journal-prev.txt" || has_file "reboot-journal-prev-tail.txt"; then
          has_ev=1
        fi
        ;;
      watchdog-or-lockup-reset)
        if has_file "reboot-journal-prev-kernel.txt" || has_file "reboot-journal-prev-tail.txt" || has_file "reboot-journal-prev.txt"; then
          has_ev=1
        fi
        ;;
      clean-shutdown-automation)
        if has_file "reboot-auto-update.txt" || has_file "reboot-pkg-history.txt" || has_file "reboot-kernel-installed.txt"; then
          has_ev=1
        fi
        ;;
      clean-shutdown-user)
        if has_file "reboot-journal-shutdown-initiator.txt" || has_file "reboot-journal-shutdown-initiator-grep.txt" || has_file "reboot-auth-tail.txt" || has_file "reboot-auth-journal.txt"; then
          has_ev=1
        fi
        ;;
      clean-shutdown-unattributed)
        if has_file "reboot-journal-prev-tail.txt" || has_file "reboot-journal-prev.txt"; then
          has_ev=1
        fi
        ;;
      abrupt-reset-power-or-hypervisor)
        if has_file "reboot-wtmp-timeline.txt" || has_file "reboot-last-x.txt" || has_file "reboot-journal-boots.txt"; then
          has_ev=1
        fi
        ;;
    esac
    if [ "$has_ev" -eq 1 ]; then
      REBOOT_VERDICT_RULED_OUT="${REBOOT_VERDICT_RULED_OUT:+$REBOOT_VERDICT_RULED_OUT }$vid"
    else
      REBOOT_VERDICT_NOT_ASSESSED="${REBOOT_VERDICT_NOT_ASSESSED:+$REBOOT_VERDICT_NOT_ASSESSED }$vid"
    fi
  done

  # Output verdict finding and report
  local sev rec
  case "$REBOOT_VERDICT" in
    kernel-panic)
      sev="critical"
      rec="Enable kdump and persistent journal; analyze vmcore-dmesg or stack trace in previous kernel journal."
      ;;
    oom-kill)
      sev="critical"
      rec="Inspect memory pressure, cgroup limits, swap allocation, and vm.panic_on_oom sysctl."
      ;;
    watchdog-or-lockup-reset)
      sev="critical"
      rec="Check CPU soft/hard lockup traces, watchdog configuration, hypervisor CPU throttling, and kernel driver stalls."
      ;;
    clean-shutdown-automation)
      sev="info"
      rec="Review automatic update logs, package manager history, and scheduled timers triggering maintenance reboots."
      ;;
    clean-shutdown-user)
      sev="info"
      rec="Review audit and auth logs for user credentials, sudo commands, or physical/virtual power key events."
      ;;
    clean-shutdown-unattributed)
      sev="info"
      rec="Enable verbose systemd-logind logging and auditd rules for reboot syscalls to capture initiator."
      ;;
    abrupt-reset-power-or-hypervisor)
      sev="critical"
      rec="Check hypervisor/host task log (e.g. Proxmox/vCenter), guest reset/stop tasks, host OOM events, storage stalls, and power supply."
      ;;
    *)
      sev="warn"
      rec="Enable persistent journal (Storage=persistent in /etc/systemd/journald.conf) and configure kdump for future incident diagnostics."
      ;;
  esac

  add_finding "$sev" "$REBOOT_VERDICT_CONFIDENCE" "Reboot verdict: $REBOOT_VERDICT" "reboot-verdict.txt" "$rec"

  {
    printf 'verdict=%s\n' "$REBOOT_VERDICT"
    printf 'confidence=%s\n' "$REBOOT_VERDICT_CONFIDENCE"
    printf 'basis=%s\n' "$REBOOT_VERDICT_BASIS"
    printf 'ruled_out=%s\n' "$REBOOT_VERDICT_RULED_OUT"
    printf 'not_assessed=%s\n' "$REBOOT_VERDICT_NOT_ASSESSED"
    printf '\n### timeline\n'
    local tl_file=""
    if [ -s "$EVIDENCE_DIR/reboot-wtmp-timeline.txt" ]; then
      tl_file="$EVIDENCE_DIR/reboot-wtmp-timeline.txt"
    elif [ -s "$EVIDENCE_DIR/reboot-last-x.txt" ]; then
      tl_file="$EVIDENCE_DIR/reboot-last-x.txt"
    elif [ -s "$EVIDENCE_DIR/reboot-journal-boots.txt" ]; then
      tl_file="$EVIDENCE_DIR/reboot-journal-boots.txt"
    fi
    if [ -n "$tl_file" ]; then
      if grep -q '^### output$' "$tl_file" 2>/dev/null; then
        sed -n '/^### output$/,/^### exit_code$/{ /^### /d; /^[[:space:]]*$/d; p; }' "$tl_file" | grep -Ei 'reboot|shutdown|system boot' | head -n 20
      else
        grep -Ei 'reboot|shutdown|system boot' "$tl_file" | head -n 20
      fi
    else
      printf 'No timeline available\n'
    fi
  } > "$EVIDENCE_DIR/reboot-verdict.txt"
  section "Reboot Verdict"
  append_report "Verdict: **$REBOOT_VERDICT** (confidence: $REBOOT_VERDICT_CONFIDENCE)"
  append_report ""
  append_report "Basis: $REBOOT_VERDICT_BASIS"
  [ -n "$REBOOT_VERDICT_RULED_OUT" ] && append_report "Ruled out: $REBOOT_VERDICT_RULED_OUT"
  [ -n "$REBOOT_VERDICT_NOT_ASSESSED" ] && append_report "Not assessed: $REBOOT_VERDICT_NOT_ASSESSED"
  append_report ""
  append_report "Recommendation: $rec"

  [ "$BUNDLE" -ne -1 ] && BUNDLE=1
}

module_slow() {
  record_module slow
  progress_scope slow
  section "Slow VM / Server Investigation"
  probe_common_baseline
  have_cmd vmstat && run_cmd slow-vmstat vmstat 1 5
  have_cmd mpstat && run_cmd slow-mpstat mpstat 1 5
  have_cmd pidstat && run_cmd slow-pidstat pidstat 1 5
  have_cmd iostat && run_cmd slow-iostat iostat -xz 1 5
  have_cmd sar && run_cmd slow-sar-cpu sar -u 1 5
  have_cmd swapon && run_cmd slow-swapon swapon --show
  have_cmd top && run_cmd slow-top-batch top -b -n 1
  if [ -r /proc/stat ]; then
    run_shell slow-proc-stat-sample 'awk "/^cpu /{print}" /proc/stat; sleep 1; awk "/^cpu /{print}" /proc/stat'
  fi
  if have_cmd mpstat && [ -s "$EVIDENCE_DIR/slow-mpstat.txt" ] && grep -Eq '[0-9]+\.[0-9]+[[:space:]]*$' "$EVIDENCE_DIR/slow-mpstat.txt"; then
    if awk '/Average:/ && $NF+0 > 10 {found=1} END{exit found?0:1}' "$EVIDENCE_DIR/slow-mpstat.txt" 2>/dev/null; then
      add_finding "warn" "medium" "CPU steal or idle anomaly may indicate virtualization contention" "slow-mpstat.txt" "Check hypervisor CPU overcommit, CPU ready/steal metrics, and host load."
    fi
  fi
  if [ -s "$EVIDENCE_DIR/slow-vmstat.txt" ] && awk 'NR>2 && $16+0 > 20 {found=1} END{exit found?0:1}' "$EVIDENCE_DIR/slow-vmstat.txt" 2>/dev/null; then
    add_finding "warn" "medium" "High iowait observed in vmstat sample" "slow-vmstat.txt" "Investigate disk latency with iostat, storage backend, snapshots, thin pools, or noisy workloads."
  fi
  if [ -r /proc/pressure/memory ] && grep -Eq 'some avg10=[1-9]|full avg10=[1-9]' /proc/pressure/memory 2>/dev/null; then
    add_finding "warn" "medium" "Memory pressure stall information is non-zero" "baseline-psi-memory.txt" "Inspect working set, swap, cgroup limits, and memory-heavy processes."
  fi
  add_finding "info" "high" "Slow system investigation completed" "slow-*" "Use repeated samples during the actual slowdown for higher confidence."
}

module_disk() {
  record_module disk
  progress_scope disk
  section "Disk / Filesystem Investigation"
  have_cmd df && run_cmd disk-df-h df -hT
  have_cmd df && run_cmd disk-df-ih df -ih
  have_cmd lsblk && run_cmd disk-lsblk lsblk -o NAME,MAJ:MIN,RM,SIZE,RO,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
  have_cmd findmnt && run_cmd disk-findmnt findmnt -A
  have_cmd mount && run_cmd disk-mount mount
  [ -r /proc/mdstat ] && run_cmd disk-mdstat cat /proc/mdstat
  have_cmd lvs && run_cmd disk-lvs lvs -a -o +devices,seg_monitor
  have_cmd vgs && run_cmd disk-vgs vgs -o +vg_free,vg_extent_size
  have_cmd pvs && run_cmd disk-pvs pvs -o +pv_used
  if have_cmd journalctl; then
    run_cmd disk-journal-kernel journalctl -k -p warning..alert -n 500 --no-pager
    analyze_file_patterns "$EVIDENCE_DIR/disk-journal-kernel.txt" "kernel storage journal"
  elif have_cmd dmesg; then
    run_cmd disk-dmesg dmesg -T
    analyze_file_patterns "$EVIDENCE_DIR/disk-dmesg.txt" "dmesg"
  fi
  if have_cmd smartctl; then
    # shellcheck disable=SC2016
    run_shell disk-smartctl-scan 'smartctl --scan 2>/dev/null | while read -r dev rest; do echo "### $dev $rest"; smartctl -H "$dev" 2>&1; done'
  else
    missing_tool_note smartctl
  fi
  if [ -s "$EVIDENCE_DIR/disk-df-h.txt" ] && awk 'NR>1 {gsub(/%/,"",$6); if ($6+0 >= 90) found=1} END{exit found?0:1}' "$EVIDENCE_DIR/disk-df-h.txt" 2>/dev/null; then
    add_finding "warn" "high" "One or more filesystems are at or above 90% usage" "disk-df-h.txt" "Free space, expand filesystem, or move data before services fail."
  fi
  if [ -s "$EVIDENCE_DIR/disk-df-ih.txt" ] && awk 'NR>1 {gsub(/%/,"",$5); if ($5+0 >= 90) found=1} END{exit found?0:1}' "$EVIDENCE_DIR/disk-df-ih.txt" 2>/dev/null; then
    add_finding "warn" "high" "One or more filesystems are at or above 90% inode usage" "disk-df-ih.txt" "Find small-file growth, caches, mail queues, or container overlay buildup."
  fi
  if [ -s "$EVIDENCE_DIR/disk-mdstat.txt" ] && grep -Eiq '(_|recover|resync|degraded)' "$EVIDENCE_DIR/disk-mdstat.txt"; then
    add_finding "critical" "medium" "mdraid appears degraded or rebuilding" "disk-mdstat.txt" "Check array status and disk health before further writes or repair."
  fi
  add_finding "info" "high" "Disk/filesystem investigation completed" "disk-*" "Do not run fsck or repair against mounted filesystems without backup and maintenance window."
}

module_network() {
  record_module network
  progress_scope network
  section "Network Investigation"
  have_cmd ip && run_cmd network-ip-addr ip addr show
  have_cmd ip && run_cmd network-ip-route ip route show table all
  if have_cmd resolvectl; then
    run_cmd network-resolvectl resolvectl status
  elif [ -r /etc/resolv.conf ]; then
    run_cmd network-resolv-conf cat /etc/resolv.conf
  fi
  have_cmd ss && run_cmd network-ss-listen ss -tulpen
  have_cmd ip && run_cmd network-ip-stats ip -s link
  have_cmd nstat && run_cmd network-nstat nstat -az
  if have_cmd ethtool && have_cmd ip; then
    # shellcheck disable=SC2016
    run_shell network-ethtool 'for i in $(ip -o link show | awk -F": " "{print \$2}" | grep -v lo); do echo "### $i"; ethtool "$i" 2>&1; ethtool -S "$i" 2>&1 | head -n 80; done'
  else
    have_cmd ethtool || missing_tool_note ethtool
  fi
  have_cmd nft && run_cmd network-nft nft list ruleset
  have_cmd iptables && run_cmd network-iptables iptables -S
  have_cmd firewall-cmd && run_cmd network-firewalld firewall-cmd --state
  have_cmd ufw && run_cmd network-ufw ufw status verbose
  if have_cmd ip && ! ip route show default 2>/dev/null | grep -q '^default'; then
    add_finding "critical" "high" "No default IPv4 route detected" "network-ip-route.txt" "Add/restore default gateway or check DHCP/static routing configuration."
  fi
  if [ -s "$EVIDENCE_DIR/network-ip-stats.txt" ] && grep -Eiq 'errors|dropped|overruns|carrier' "$EVIDENCE_DIR/network-ip-stats.txt"; then
    if awk '/RX:|TX:/{getline; if ($3+0>0 || $4+0>0 || $5+0>0 || $6+0>0) found=1} END{exit found?0:1}' "$EVIDENCE_DIR/network-ip-stats.txt" 2>/dev/null; then
      add_finding "warn" "medium" "Interface errors/drops observed" "network-ip-stats.txt" "Check link quality, duplex/speed, driver, cabling, switch port, and host load."
    fi
  fi
  add_finding "info" "high" "Network investigation completed" "network-*" "For throughput issues, collect iperf3 tests from both directions during the symptom window."
}

module_service() {
  record_module service
  progress_scope service
  section "Service / Container Failure Investigation"
  if have_cmd systemctl; then
    run_cmd service-systemctl-failed systemctl --failed --no-pager
    run_cmd service-systemctl-units systemctl list-units --state=failed --no-pager
    if [ -s "$EVIDENCE_DIR/service-systemctl-failed.txt" ] && grep -Eq 'failed|●' "$EVIDENCE_DIR/service-systemctl-failed.txt"; then
      add_finding "warn" "high" "Failed systemd units detected" "service-systemctl-failed.txt" "Inspect targeted journal with journalctl -u <unit> and verify dependencies/configuration."
    fi
  else
    missing_tool_note systemctl
  fi
  if have_cmd journalctl; then
    run_cmd service-journal-errors journalctl -p warning..alert -n 500 --no-pager
    analyze_file_patterns "$EVIDENCE_DIR/service-journal-errors.txt" "recent service journal errors"
  fi
  if have_cmd podman; then
    run_cmd service-podman-ps podman ps -a --no-trunc
    # shellcheck disable=SC2016
    run_shell service-podman-inspect 'podman ps -a --format "{{.ID}}" 2>/dev/null | while read -r c; do [ -n "$c" ] && { echo "### $c"; podman inspect "$c" 2>&1 | head -n 220; }; done'
  fi
  if have_cmd docker; then
    run_cmd service-docker-ps docker ps -a --no-trunc
    # shellcheck disable=SC2016
    run_shell service-docker-inspect 'docker ps -a --format "{{.ID}}" 2>/dev/null | while read -r c; do [ -n "$c" ] && { echo "### $c"; docker inspect "$c" 2>&1 | head -n 220; }; done'
  fi
  if [ -s "$EVIDENCE_DIR/service-podman-inspect.txt" ] && grep -Eiq 'OOMKilled.*true|"OOMKilled": true' "$EVIDENCE_DIR/service-podman-inspect.txt"; then
    add_finding "critical" "high" "Podman container OOMKilled evidence found" "service-podman-inspect.txt" "Review container memory limits, host pressure, app memory growth, and restart policy."
  fi
  if [ -s "$EVIDENCE_DIR/service-docker-inspect.txt" ] && grep -Eiq 'OOMKilled.*true|"OOMKilled": true' "$EVIDENCE_DIR/service-docker-inspect.txt"; then
    add_finding "critical" "high" "Docker container OOMKilled evidence found" "service-docker-inspect.txt" "Review container memory limits, host pressure, app memory growth, and restart policy."
  fi
  add_finding "info" "high" "Service/container investigation completed" "service-*" "Target specific units/containers manually for deeper log windows if needed."
}

module_tools() {
  record_module tools
  progress_scope tools
  section "Tool / Dependency Detection"
  {
    printf 'Available tools:\n%s\n\n' "$AVAILABLE_TOOLS"
    printf 'Missing tools:\n%s\n' "$MISSING_TOOLS"
  } > "$EVIDENCE_DIR/tool-detection.txt"
  append_report "Tool detection written to evidence/tool-detection.txt"
}

write_findings_report() {
  section "Findings"
  if [ ! -s "$FINDINGS_TSV" ]; then
    append_report "No findings were generated. This does not prove the system is healthy; it may mean data was unavailable or heuristics did not match."
    return 0
  fi
  awk -F '\t' '{printf "- **%s / %s**: %s  \n  Evidence: `%s`  \n  Recommendation: %s\n", $1, $2, $3, $4, $5}' "$FINDINGS_TSV" >> "$REPORT_FILE"
}

write_evidence_index() {
  section "Raw Evidence Index"
  find "$EVIDENCE_DIR" -maxdepth 1 -type f -printf "- \`%f\`\n" 2>/dev/null | sort >> "$REPORT_FILE" || true
  section "Missing Data / Permission Gaps"
  append_report "Missing optional tools:"
  append_report ""
  append_report "\`\`\`"
  printf '%s\n' "$MISSING_TOOLS" >> "$REPORT_FILE"
  append_report "\`\`\`"
  append_report ""
  append_report "Privilege state is recorded in metadata.env. Root-only logs or device health may be incomplete when run unprivileged."
}

json_array_from_words() {
  local word first
  first=1
  # Word lists are intentionally space-separated internal command inventories.
  # shellcheck disable=SC2048,SC2086
  for word in $*; do
    if [ "$first" -eq 0 ]; then
      printf ', '
    fi
    first=0
    printf '"%s"' "$(json_escape "$word")"
  done
}

write_summary_json() {
  local end_epoch duration modules_json available_json missing_json findings_json first sev conf title evidence rec item
  local ruled_out_json not_assessed_json reboot_verdict_json
  end_epoch="$(date +%s 2>/dev/null || printf '0')"
  duration="$((end_epoch - START_EPOCH))"
  modules_json="$(json_array_from_words "$MODULES_RUN")"
  available_json="$(json_array_from_words "$AVAILABLE_TOOLS")"
  missing_json="$(json_array_from_words "$MISSING_TOOLS")"
  findings_json=""
  if [ -s "$FINDINGS_TSV" ]; then
    first=1
    while IFS="$(printf '\t')" read -r sev conf title evidence rec; do
      [ -n "$sev" ] || continue
      item="    {\"severity\":\"$(json_escape "$sev")\",\"confidence\":\"$(json_escape "$conf")\",\"title\":\"$(json_escape "$title")\",\"evidence\":\"$(json_escape "$evidence")\",\"recommendation\":\"$(json_escape "$rec")\"}"
      if [ "$first" -eq 1 ]; then
        findings_json="$item"
        first=0
      else
        findings_json="$findings_json,
$item"
      fi
    done < "$FINDINGS_TSV"
  fi
  if [ -n "$REBOOT_VERDICT" ]; then
    ruled_out_json="$(json_array_from_words "$REBOOT_VERDICT_RULED_OUT")"
    not_assessed_json="$(json_array_from_words "$REBOOT_VERDICT_NOT_ASSESSED")"
    reboot_verdict_json="{\"verdict\":\"$(json_escape "$REBOOT_VERDICT")\",\"confidence\":\"$(json_escape "$REBOOT_VERDICT_CONFIDENCE")\",\"basis\":\"$(json_escape "$REBOOT_VERDICT_BASIS")\",\"ruled_out\":[$ruled_out_json],\"not_assessed\":[$not_assessed_json]}"
  else
    reboot_verdict_json="null"
  fi
  cat > "$SUMMARY_FILE" <<EOF_JSON
{
  "script": "sysdiag.sh",
  "version": "$(json_escape "$APP_VERSION")",
  "host": "$(json_escape "$HOSTNAME_SHORT")",
  "timestamp_utc": "$(json_escape "$TIMESTAMP")",
  "output_dir": "$(json_escape "$OUT_DIR")",
  "duration_seconds": $duration,
  "read_only": true,
  "modules_run": [$modules_json],
  "available_tools": [$available_json],
  "missing_tools": [$missing_json],
  "findings": [
$findings_json
  ],
  "reboot_verdict": $reboot_verdict_json
}
EOF_JSON
}

finalize_report() {
  write_findings_report
  write_evidence_index
  write_summary_json
  append_report ""
  append_report "## Remediation Safety Note"
  append_report ""
  append_report "This v1 run is read-only. Recommendations are suggestions only; no fixes were executed."
  append_report ""
  append_report "Generated files:"
  append_report "- report: $REPORT_FILE"
  append_report "- summary: $SUMMARY_FILE"
  append_report "- metadata: $METADATA_FILE"
  append_report "- command log: $COMMAND_LOG"
}

package_run() {
  if ! have_cmd tar; then
    printf 'tar unavailable; cannot package %s\n' "$OUT_DIR" >&2
    return 1
  fi
  local parent base tarfile
  parent="$(dirname "$OUT_DIR")"
  base="$(basename "$OUT_DIR")"
  tarfile="${OUT_DIR}.tar.gz"
  printf 'Packaging run output to %s\n' "$tarfile" >&2
  if (cd "$parent" && tar -czf "$tarfile" "$base"); then
    printf '%s\n' "$tarfile"
  else
    printf 'ERROR: packaging failed.\n' >&2
    return 1
  fi
}
bundle_redact() {
  sed -E \
    -e 's/.*(ssh-(rsa|ed25519|dss)|BEGIN [A-Z ]*PRIVATE KEY|([Aa][Pp][Ii]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd])[[:space:]]*[=:]).*/[REDACTED SECRET LINE]/' \
    -e 's/\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/__PRIV_IP_\1__/g' \
    -e 's/\b(192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b/__PRIV_IP_\1__/g' \
    -e 's/\b(172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3})\b/__PRIV_IP_\1__/g' \
    -e 's/\b(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/__PRIV_IP_\1__/g' \
    -e 's/\b(169\.254\.[0-9]{1,3}\.[0-9]{1,3})\b/__PRIV_IP_\1__/g' \
    -e 's/\b([0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}\b/\1.x.x/g' \
    -e 's/__PRIV_IP_([^ _]+)__/\1/g' \
    -e 's/([0-9a-fA-F]{1,4}:){4,}[0-9a-fA-F:]+/IPV6-REDACTED/g' \
    -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/user@REDACTED/g'
}

build_bundle() {
  local bundle_file max_lines max_bytes current_bytes omitted_files
  bundle_file="$OUT_DIR/bundle.md"
  max_lines="${SYSDIAG_BUNDLE_MAX_LINES:-400}"
  max_bytes="${SYSDIAG_BUNDLE_MAX_BYTES:-4000000}"
  omitted_files=""

  local redact_status="off"
  [ "$BUNDLE_REDACT" -eq 1 ] && redact_status="on"

  {
    printf '# sysdiag bundle\n\n'
    printf 'Host: %s\n' "$HOSTNAME_SHORT"
    printf 'Generated: %s UTC\n' "$TIMESTAMP"
    printf 'Script Version: %s\n' "$APP_VERSION"
    printf 'Redaction: %s\n\n' "$redact_status"
    printf '> Instruction for reviewing AI / engineer:\n'
    printf '> This is a read-only diagnostics bundle. Some evidence files may be truncated (indicated by truncation markers).\n'
    printf '> Absence of a signal is not proof of absence. Please review evidence and confirm or contest the stated findings and verdict.\n'
    printf '> Usernames are intentionally preserved to identify process and session initiators.\n\n'
  } > "$bundle_file"

  append_bundle_file() {
    local src_file rel_name
    src_file="$1"
    rel_name="$2"
    [ -f "$src_file" ] || return 0

    current_bytes="$(wc -c < "$bundle_file" 2>/dev/null || printf '0')"
    if [ "$current_bytes" -ge "$max_bytes" ]; then
      omitted_files="${omitted_files:+$omitted_files }$rel_name"
      return 0
    fi

    local lines_in_file
    lines_in_file="$(wc -l < "$src_file" 2>/dev/null || printf '0')"

    {
      printf '### %s\n\n``````\n' "$rel_name"
      if [ "$lines_in_file" -gt "$max_lines" ]; then
        local trunc_n
        trunc_n="$((lines_in_file - 400))"
        head -n 120 "$src_file"
        printf '\n[... truncated %s lines ...]\n\n' "$trunc_n"
        tail -n 280 "$src_file"
      else
        cat "$src_file"
      fi
      printf '\n``````\n\n'
    } | {
      if [ "$BUNDLE_REDACT" -eq 1 ]; then
        bundle_redact
      else
        cat
      fi
    } >> "$bundle_file"
  }

  append_bundle_file "$METADATA_FILE" "metadata.env"
  [ -f "$EVIDENCE_DIR/reboot-verdict.txt" ] && append_bundle_file "$EVIDENCE_DIR/reboot-verdict.txt" "evidence/reboot-verdict.txt"
  append_bundle_file "$REPORT_FILE" "report.md"
  append_bundle_file "$FINDINGS_TSV" "findings.tsv"
  append_bundle_file "$SUMMARY_FILE" "summary.json"
  append_bundle_file "$COMMAND_LOG" "commands.log"

  if [ -d "$EVIDENCE_DIR" ]; then
    local ev_file ev_base
    for ev_file in "$EVIDENCE_DIR"/*.txt; do
      [ -f "$ev_file" ] || continue
      ev_base="$(basename "$ev_file")"
      [ "$ev_base" = "reboot-verdict.txt" ] && continue
      append_bundle_file "$ev_file" "evidence/$ev_base"
    done
  fi

  if [ -n "$omitted_files" ]; then
    {
      printf '### omitted for size\n\n'
      local of
      for of in $omitted_files; do
        printf -- '- %s\n' "$of"
      done
      printf '\n'
    } >> "$bundle_file"
  fi

  printf '%s\n' "$bundle_file"
}

harden_log() {
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)" "$1" "$2" >> "$EVIDENCE_DIR/hardening-actions.tsv"
}

harden_plan() {
  printf '%s\n' "$1" >> "$EVIDENCE_DIR/hardening-plan.txt"
  if [ "$HARDEN_APPLY" -eq 1 ]; then
    printf 'APPLY: %s\n' "$1" >&2
  else
    printf 'DRY-RUN: %s\n' "$1" >&2
  fi
}

harden_status() {
  # control status detail   (status: PASS|FAIL|NA|ERROR|INFO)
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$HARDEN_STATUS_TSV"
  printf '%-16s %-5s %s\n' "$1" "$2" "$3" >&2
  case "$2" in
    FAIL)  add_finding "medium" "high" "Hardening control not compliant: $1" "hardening-status.tsv" "$3" ;;
    ERROR) add_finding "high" "high" "Hardening control failed to execute: $1" "hardening-status.tsv" "$3" ;;
    INFO)  add_finding "info" "high" "Hardening informational: $1" "hardening-status.tsv" "$3" ;;
  esac
}

harden_package_description() {
  case "$1" in
    guest_agent) printf 'qemu-guest-agent (only on kvm/qemu guests)' ;;
    fail2ban)    printf 'fail2ban with an sshd jail' ;;
    logging)     printf 'rsyslog and needrestart' ;;
    firewall)    printf 'ufw/firewalld, default deny incoming, allow detected SSH port' ;;
    *)           printf 'Unknown package group' ;;
  esac
}

harden_package_names() {
  # <group> -> space-separated package names for $HARDEN_DISTRO_FAMILY, empty if unsupported
  case "$1:$HARDEN_DISTRO_FAMILY" in
    guest_agent:*)     printf 'qemu-guest-agent' ;;
    fail2ban:*)        printf 'fail2ban' ;;
    logging:debian)    printf 'rsyslog needrestart' ;;
    logging:*)         printf 'rsyslog' ;;
    firewall:debian)   printf 'ufw' ;;
    firewall:rhel|firewall:suse) printf 'firewalld' ;;
    *) ;;
  esac
}

harden_install_packages() {
  # <names...> -> returns 0 on success, 1 on install failure, 2 on unsupported family
  [ "$#" -gt 0 ] || return 0
  if [ "$HARDEN_DISTRO_FAMILY" = unknown ]; then
    printf 'ERROR: unsupported distribution family for package installation\n' >&2
    return 2
  fi
  case "$HARDEN_DISTRO_FAMILY" in
    debian)
      harden_run_cmd 'refresh Debian-family package metadata' env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update || return 1
      harden_run_cmd "install package(s): $*" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 -y install "$@" || return 1
      ;;
    rhel)
      harden_run_cmd "install package(s): $*" dnf -y install "$@" || return 1
      ;;
    suse)
      harden_run_cmd "install package(s): $*" zypper --non-interactive install "$@" || return 1
      ;;
    *)
      return 2
      ;;
  esac
  return 0
}

harden_package_installed() {
  local name="$1"
  case "$HARDEN_DISTRO_FAMILY" in
    debian) dpkg -s "$name" >/dev/null 2>&1 ;;
    rhel|suse) rpm -q "$name" >/dev/null 2>&1 ;;
    *) have_cmd "$name" ;;
  esac
}

harden_detect() {
  HARDEN_DISTRO_ID=unknown
  HARDEN_DISTRO_LIKE=""
  HARDEN_DISTRO_FAMILY=unknown
  HARDEN_VIRT=unknown
  [ -r /etc/os-release ] && { . /etc/os-release; HARDEN_DISTRO_ID="${ID:-unknown}"; HARDEN_DISTRO_LIKE="${ID_LIKE:-}"; }
  if have_cmd systemd-detect-virt; then
    HARDEN_VIRT="$(systemd-detect-virt 2>/dev/null || printf unknown)"
  elif have_cmd virt-what; then
    HARDEN_VIRT="$(virt-what 2>/dev/null | head -n1)"
    [ -z "$HARDEN_VIRT" ] && HARDEN_VIRT=none
  fi
  case " $HARDEN_DISTRO_ID $HARDEN_DISTRO_LIKE " in
    *' debian '*|*' ubuntu '*) HARDEN_DISTRO_FAMILY=debian ;;
    *' rhel '*|*' fedora '*|*' redhat '*|*' rocky '*|*' almalinux '*|*' centos '*) HARDEN_DISTRO_FAMILY=rhel ;;
    *' suse '*|*' opensuse '*|*' sles '*) HARDEN_DISTRO_FAMILY=suse ;;
  esac
  {
    printf 'distro_id=%s\n' "$HARDEN_DISTRO_ID"
    printf 'distro_like=%s\n' "$HARDEN_DISTRO_LIKE"
    printf 'distro_family=%s\n' "$HARDEN_DISTRO_FAMILY"
    printf 'virtualization=%s\n' "$HARDEN_VIRT"
    printf 'mode=%s\n' "$([ "$HARDEN_APPLY" -eq 1 ] && printf apply || printf dry-run)"
    printf 'upgrade_packages=%s\n' "$HARDEN_UPGRADE_PACKAGES"
    printf 'allow_virtualization=%s\n' "$HARDEN_ALLOW_VIRTUALIZATION"
    printf 'install_groups=%s\n' "$HARDEN_INSTALL"
  } | tee "$EVIDENCE_DIR/hardening-environment.txt"
}

harden_preflight() {
  local missing rc; missing=""; rc=0
  if [ "$HARDEN_APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    printf 'ERROR: apply mode requires root. Use sudo ./sysdiag.sh --run harden --apply.\n' >&2
    rc=1
  fi
  if [ "$HARDEN_APPLY" -eq 1 ] && [ "$HARDEN_ALLOW_VIRTUALIZATION" -ne 1 ] && [ "$HARDEN_VIRT" != "none" ] && [ -n "$HARDEN_VIRT" ]; then
    printf 'ERROR: apply mode refused: virtualization is %s (no detector available? install systemd-detect-virt or virt-what); use --allow-virtualization to proceed\n' "$HARDEN_VIRT" >&2
    rc=1
  fi
  if [ "$HARDEN_APPLY" -eq 1 ] && [ -n "$HARDEN_INSTALL" ] && [ "$HARDEN_DISTRO_FAMILY" = unknown ]; then
    printf 'ERROR: --install requires a supported distro family (debian/rhel/suse); detected unknown\n' >&2
    rc=1
  fi
  if [ "$HARDEN_APPLY" -eq 1 ]; then
    for cmd in chpasswd date install mktemp openssl sysctl useradd visudo; do
      have_cmd "$cmd" || missing="$missing $cmd"
    done
    if harden_control_selected "packages_extra"; then
      have_cmd systemctl || missing="$missing systemctl"
      case "$HARDEN_DISTRO_FAMILY" in
        debian) have_cmd apt-get || missing="$missing apt-get" ;;
        rhel)   have_cmd dnf || missing="$missing dnf" ;;
        suse)   have_cmd zypper || missing="$missing zypper" ;;
      esac
    fi
    if [ -n "$missing" ]; then
      printf 'ERROR: apply mode missing required command(s):%s\n' "$missing" >&2
      rc=1
    fi
  fi
  if [ "$HARDEN_DISTRO_FAMILY" = unknown ]; then
    printf 'WARNING: unrecognized distribution; PAM/package changes will be skipped.\n' >&2
    harden_log warning 'unrecognized distribution; PAM/package changes skipped'
  fi
  return "$rc"
}

harden_backup_file() {
  local file backup
  file="$1"
  [ -e "$file" ] || return 0
  backup="$EVIDENCE_DIR/backups${file}"
  install -d -m 0700 "$(dirname "$backup")"
  if [ ! -e "$backup" ]; then
    cp -a "$file" "$backup"
    harden_log backup "$file -> $backup"
  fi
}

harden_write_file() {
  local file mode content tmp dir
  file="$1"; mode="$2"; content="$3"; dir="$(dirname "$file")"
  harden_plan "write $file"
  [ "$HARDEN_APPLY" -eq 1 ] || return 0
  install -d -m 0755 "$dir"
  harden_backup_file "$file"
  tmp="$(mktemp "${dir}/.sysdiag.XXXXXX")" || return 1
  printf '%s\n' "$content" > "$tmp" || { rm -f "$tmp"; return 1; }
  chmod "$mode" "$tmp" || { rm -f "$tmp"; return 1; }
  if [ -e "$file" ] && cmp -s "$tmp" "$file"; then
    rm -f "$tmp"
    harden_log unchanged "$file"
  else
    mv -f "$tmp" "$file"
    harden_log changed "$file"
  fi
}

harden_run_cmd() {
  local description rc; description="$1"; shift
  harden_plan "$description: $*"
  [ "$HARDEN_APPLY" -eq 1 ] || return 0
  "$@"; rc=$?
  if [ "$rc" -eq 0 ]; then
    harden_log command "$description"
  else
    harden_log command_failed "$description (rc=$rc)"
  fi
  return "$rc"
}

harden_configure_sysctl() {
  harden_write_file /etc/sysctl.d/99-sysdiag-ipv6.conf 0644 'net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1' || return 1
  harden_run_cmd 'load sysctl configuration' sysctl --system || return 1
  [ "$HARDEN_APPLY" -eq 1 ] || return 0
  {
    printf 'net.ipv6.conf.all.disable_ipv6=%s\n' "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || printf missing)"
    printf 'net.ipv6.conf.default.disable_ipv6=%s\n' "$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || printf missing)"
  } >> "$EVIDENCE_DIR/hardening-verification.txt"
  [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = 1 ] || return 1
  [ "$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null)" = 1 ] || return 1
}

harden_update_grub_default() {
  local file line current escaped updated
  file=/etc/default/grub
  [ -r "$file" ] || { harden_plan 'skip GRUB default update; /etc/default/grub missing'; return 0; }
  harden_plan 'ensure ipv6.disable=1 in /etc/default/grub'
  [ "$HARDEN_APPLY" -eq 1 ] || return 0
  harden_backup_file "$file"
  current="$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$file" 2>/dev/null || true)"
  if [ -n "$current" ]; then
    printf '%s\n' "$current" | grep -q 'ipv6.disable=1' && return 0
    line="$(printf '%s\n' "$current" | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/\1/')"
    escaped="$(printf '%s' "$line" | sed 's/[\\&|]/\\&/g')"
    updated="GRUB_CMDLINE_LINUX_DEFAULT=\"ipv6.disable=1 $escaped\""
    sed "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|$updated|" "$file" > "$file.sysdiag.tmp" || { rm -f "$file.sysdiag.tmp"; return 1; }
  else
    cp "$file" "$file.sysdiag.tmp" || return 1
    printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"' >> "$file.sysdiag.tmp"
  fi
  mv -f "$file.sysdiag.tmp" "$file"
  harden_log changed "$file"
}

harden_configure_grub() {
  if have_cmd grubby; then
    harden_run_cmd 'ensure ipv6.disable=1 for all kernels with grubby' grubby --update-kernel=ALL --args=ipv6.disable=1
    return $?
  fi
  harden_update_grub_default || return 1
  if have_cmd update-grub; then
    harden_run_cmd 'regenerate GRUB configuration' update-grub
  elif have_cmd grub2-mkconfig; then
    if [ -d /boot/grub2 ]; then
      harden_run_cmd 'regenerate GRUB configuration' grub2-mkconfig -o /boot/grub2/grub.cfg
    elif [ -d /boot/grub ]; then
      harden_run_cmd 'regenerate GRUB configuration' grub2-mkconfig -o /boot/grub/grub.cfg
    else
      harden_plan 'skip GRUB regeneration; no known grub config directory found'
    fi
  else
    harden_plan 'skip GRUB regeneration; updater command not found'
  fi
}

harden_packages() {
  if [ "$HARDEN_DISTRO_FAMILY" = unknown ]; then
    [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ] || harden_plan 'skip package upgrades; pass --upgrade-packages to opt in'
    return 0
  fi
  case "$HARDEN_DISTRO_FAMILY" in
    debian)
      harden_run_cmd 'refresh Debian-family package metadata' env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update || return 1
      if [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ]; then
        harden_run_cmd 'upgrade Debian-family packages' env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 -y upgrade || return 1
      fi
      dpkg -s libpam-pwquality >/dev/null 2>&1 || harden_run_cmd 'install password policy dependency' env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 -y install libpam-pwquality || return 1 ;;
    rhel)
      if [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ]; then
        harden_run_cmd 'upgrade RHEL-family packages' dnf -y upgrade || return 1
      fi
      rpm -q libpwquality >/dev/null 2>&1 || harden_run_cmd 'install password policy dependency' dnf -y install libpwquality || return 1 ;;
    suse)
      if [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ]; then
        harden_run_cmd 'upgrade SUSE packages' zypper --non-interactive update || return 1
      fi
      rpm -q libpwquality-tools >/dev/null 2>&1 || harden_run_cmd 'install password policy dependency' zypper --non-interactive install libpwquality-tools || return 1 ;;
  esac
  [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ] || harden_plan 'skip package upgrades; pass --upgrade-packages to opt in'
}

harden_pam_policy() {
  harden_write_file /etc/security/pwquality.conf.d/99-sysdiag.conf 0644 'minlen = 14
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
retry = 3' || return 1
  if have_cmd authselect; then
    harden_run_cmd 'record authselect current profile' authselect current || return 0
    harden_plan 'authselect detected; no direct PAM file edits performed'
  else
    harden_plan 'PAM policy limited to pwquality drop-in; no direct PAM file edits performed'
  fi
}

harden_user_sudo() {
  local password hash tmp sudoers_file
  password=""; hash=""; sudoers_file=/etc/sudoers.d/90-sysdiag-linuxteam
  harden_plan "create/update $HARDEN_USER and preserve NOPASSWD sudo default"
  [ "$HARDEN_APPLY" -eq 1 ] || return 0
  printf 'WARNING: NOPASSWD:ALL grants %s unrestricted root access when applied.\n' "$HARDEN_USER" >&2
  printf 'Password for %s (input hidden): ' "$HARDEN_USER" >&2
  read -r -s password; printf '\n' >&2
  [ -n "$password" ] || { printf 'ERROR: empty password rejected.\n' >&2; return 1; }
  hash="$(printf '%s' "$password" | openssl passwd -6 -stdin 2>/dev/null)" || return 1
  unset password
  id "$HARDEN_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$HARDEN_USER" || return 1
  printf '%s:%s\n' "$HARDEN_USER" "$hash" | chpasswd -e || return 1
  install -d -m 0750 /etc/sudoers.d
  harden_backup_file "$sudoers_file"
  tmp="$(mktemp /etc/sudoers.d/.sysdiag.XXXXXX)" || return 1
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$HARDEN_USER" > "$tmp"
  chmod 0440 "$tmp"
  visudo -cf "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$sudoers_file"
  visudo -cf /etc/sudoers || return 1
  harden_log changed "$sudoers_file"
}

harden_control_tmout() {
  harden_write_file /etc/profile.d/99-sysdiag-timeout.sh 0644 "TMOUT=$HARDEN_TMOUT
readonly TMOUT
export TMOUT" || return 1
  if [ -r /etc/profile.d/99-sysdiag-timeout.sh ] && grep -q "TMOUT=$HARDEN_TMOUT" /etc/profile.d/99-sysdiag-timeout.sh 2>/dev/null; then
    harden_status tmout PASS "TMOUT=$HARDEN_TMOUT configured"
  else
    harden_status tmout FAIL "TMOUT=$HARDEN_TMOUT not set"
  fi
}

harden_control_banner() {
  harden_write_file /etc/issue 0644 "$HARDEN_BANNER" || return 1
  harden_write_file /etc/issue.net 0644 "$HARDEN_BANNER" || return 1
  if cmp -s /etc/issue /etc/issue.net 2>/dev/null && [ -s /etc/issue ]; then
    harden_status banner PASS "banner updated in /etc/issue and /etc/issue.net"
  else
    harden_status banner FAIL "issue banners missing or mismatch"
  fi
}

harden_control_ipv6() {
  harden_configure_sysctl || return 1
  harden_configure_grub || return 1
  if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "1" ]; then
    harden_status ipv6 PASS "net.ipv6.conf.all.disable_ipv6 = 1"
  else
    harden_status ipv6 FAIL "IPv6 active in sysctl"
  fi
}

harden_control_packages() {
  harden_packages || return 1
  harden_status packages PASS "package metadata refreshed and core dependencies installed"
}

harden_control_packages_extra() {
  local selected pkg names missing_names pkg_installed p ports s_port
  selected=""
  if [ -n "$HARDEN_INSTALL" ]; then
    local old_ifs="$IFS"
    IFS=','
    for pkg in $HARDEN_INSTALL; do
      case " $HARDEN_PACKAGE_IDS " in
        *" $pkg "*) selected="$selected $pkg" ;;
      esac
    done
    IFS="$old_ifs"
  fi

  if [ -z "$selected" ]; then
    local present="" absent=""
    for pkg in $HARDEN_PACKAGE_IDS; do
      names="$(harden_package_names "$pkg")"
      pkg_installed=1
      for p in $names; do
        if ! harden_package_installed "$p"; then
          pkg_installed=0
          break
        fi
      done
      if [ -n "$names" ] && [ "$pkg_installed" -eq 1 ]; then
        present="$present $pkg"
      else
        absent="$absent $pkg"
      fi
    done
    harden_status packages_extra INFO "not selected; present:${present:- none}; absent:${absent:- none}"
    return 0
  fi

  for pkg in $selected; do
    if [ "$pkg" = "guest_agent" ] && [ "$HARDEN_VIRT" != "kvm" ] && [ "$HARDEN_VIRT" != "qemu" ]; then
      harden_status packages_extra NA "guest_agent: not a kvm/qemu guest"
      continue
    fi

    names="$(harden_package_names "$pkg")"
    if [ -z "$names" ]; then
      harden_status packages_extra NA "$pkg: not supported on $HARDEN_DISTRO_FAMILY"
      continue
    fi

    missing_names=""
    for p in $names; do
      if ! harden_package_installed "$p"; then
        missing_names="$missing_names $p"
      fi
    done

    if [ "$HARDEN_APPLY" -eq 0 ]; then
      if [ -n "$missing_names" ]; then
        harden_plan "install$missing_names for $pkg"
        harden_status packages_extra INFO "$pkg: selected, absent — would install$missing_names"
      else
        harden_status packages_extra INFO "$pkg: selected, already installed ($names)"
      fi
      continue
    fi

    if [ -n "$missing_names" ]; then
      harden_install_packages $missing_names || return 1
    fi

    case "$pkg" in
      guest_agent)
        harden_run_cmd 'enable qemu-guest-agent' systemctl enable --now qemu-guest-agent
        ;;
      fail2ban)
        harden_write_file /etc/fail2ban/jail.d/99-sysdiag.local 0644 '[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 600
bantime = 3600' || return 1
        harden_run_cmd 'enable fail2ban' systemctl enable --now fail2ban
        ;;
      logging)
        harden_run_cmd 'enable rsyslog' systemctl enable --now rsyslog
        ;;
      firewall)
        ports=""
        if have_cmd sshd; then
          ports="$(sshd -T 2>/dev/null | awk '/^port /{print $2}')"
        fi
        if [ -z "$ports" ] && [ -r /etc/ssh/sshd_config ]; then
          ports="$(awk '/^[Pp]ort /{print $2}' /etc/ssh/sshd_config)"
        fi
        if [ -z "$ports" ] && have_cmd ss; then
          ports="$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | sort -u)"
        fi
        ports="$(printf '%s\n' $ports | sort -u | tr '\n' ' ' | sed 's/ $//')"
        if [ -z "$ports" ]; then
          harden_status packages_extra FAIL 'firewall skipped: could not resolve an SSH port to allow'
          continue
        fi
        printf 'firewall: will allow SSH on port(s): %s before enabling default-deny\n' "$ports" >&2
        printf 'firewall: allowed SSH port(s): %s\n' "$ports" >> "$EVIDENCE_DIR/hardening-verification.txt"

        if [ "$HARDEN_DISTRO_FAMILY" = debian ]; then
          for s_port in $ports; do
            harden_run_cmd "allow SSH port $s_port in ufw" ufw allow "$s_port/tcp" || return 1
          done
          harden_run_cmd 'ufw default deny incoming' ufw default deny incoming || return 1
          harden_run_cmd 'ufw default allow outgoing' ufw default allow outgoing || return 1
          harden_run_cmd 'enable ufw' ufw --force enable || return 1
          if ufw status 2>/dev/null | grep -q "${ports%% *}/tcp"; then
            :
          else
            harden_status packages_extra FAIL "firewall port rule verification failed for $ports"
            continue
          fi
        else
          harden_run_cmd 'enable firewalld' systemctl enable --now firewalld || return 1
          for s_port in $ports; do
            harden_run_cmd "allow SSH port $s_port in firewalld" firewall-cmd --permanent --add-port="$s_port/tcp" || return 1
          done
          harden_run_cmd 'reload firewalld' firewall-cmd --reload || return 1
          if firewall-cmd --list-ports 2>/dev/null | grep -q "${ports%% *}/tcp"; then
            :
          else
            harden_status packages_extra FAIL "firewall port rule verification failed for $ports"
            continue
          fi
        fi
        ;;
    esac

    pkg_installed=1
    for p in $names; do
      if ! harden_package_installed "$p"; then
        pkg_installed=0; break
      fi
    done
    if [ "$pkg_installed" -eq 1 ]; then
      case "$pkg" in
        guest_agent)
          if systemctl is-active --quiet qemu-guest-agent 2>/dev/null; then
            harden_status packages_extra PASS "$pkg: installed and active"
          else
            harden_status packages_extra FAIL "$pkg: installed but service inactive"
          fi
          ;;
        fail2ban)
          if systemctl is-active --quiet fail2ban 2>/dev/null; then
            harden_status packages_extra PASS "$pkg: installed and active"
          else
            harden_status packages_extra FAIL "$pkg: installed but service inactive"
          fi
          ;;
        logging)
          if systemctl is-active --quiet rsyslog 2>/dev/null; then
            harden_status packages_extra PASS "$pkg: installed and active ($names)"
          else
            harden_status packages_extra FAIL "$pkg: installed but rsyslog inactive"
          fi
          ;;
        firewall)
          if { [ "$HARDEN_DISTRO_FAMILY" = debian ] && ufw status 2>/dev/null | grep -q "Status: active"; } || \
             { [ "$HARDEN_DISTRO_FAMILY" != debian ] && firewall-cmd --state 2>/dev/null | grep -q "running"; }; then
            harden_status packages_extra PASS "$pkg: installed and active with SSH allowed ($ports)"
          else
            harden_status packages_extra FAIL "$pkg: firewall installed but not active"
          fi
          ;;
      esac
    else
      harden_status packages_extra FAIL "$pkg: package installation failed ($missing_names)"
    fi
  done
}

harden_control_pwquality() {
  harden_pam_policy || return 1
  if [ -r /etc/security/pwquality.conf.d/99-sysdiag.conf ] && grep -Eq '^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14' /etc/security/pwquality.conf.d/99-sysdiag.conf 2>/dev/null; then
    harden_status pwquality PASS "sysdiag pwquality drop-in present with minlen = 14"
  elif [ -r /etc/security/pwquality.conf ]; then
    harden_status pwquality FAIL "stock pwquality.conf only, no sysdiag drop-in"
  else
    harden_status pwquality FAIL "pwquality configuration missing entirely"
  fi
}

harden_control_user_sudo() {
  harden_user_sudo || return 1
  if id "$HARDEN_USER" >/dev/null 2>&1 && [ -r "/etc/sudoers.d/90-sysdiag-$HARDEN_USER" ]; then
    harden_status user_sudo PASS "user $HARDEN_USER present with NOPASSWD:ALL sudo (site access policy)"
  else
    harden_status user_sudo FAIL "user $HARDEN_USER or sudo file missing"
  fi
}

harden_control_su_wheel() {
  if [ -r /etc/pam.d/su ] && grep -Eq 'pam_wheel.so' /etc/pam.d/su 2>/dev/null; then
    harden_status su_wheel PASS "su restricted to wheel group"
  else
    harden_status su_wheel FAIL "su pam_wheel restriction missing"
  fi
}

harden_control_kernel_sysctl() {
  local aslr hardlinks symlinks
  harden_write_file /etc/sysctl.d/99-sysdiag-kernel.conf 0644 'kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1' || return 1
  harden_run_cmd 'load kernel hardening sysctl' sysctl --system || return 1

  aslr="$(sysctl -n kernel.randomize_va_space 2>/dev/null || printf missing)"
  hardlinks="$(sysctl -n fs.protected_hardlinks 2>/dev/null || printf missing)"
  symlinks="$(sysctl -n fs.protected_symlinks 2>/dev/null || printf missing)"

  if [ "$HARDEN_APPLY" -eq 1 ]; then
    {
      printf 'kernel.randomize_va_space=%s\n' "$aslr"
      printf 'fs.protected_hardlinks=%s\n' "$hardlinks"
      printf 'fs.protected_symlinks=%s\n' "$symlinks"
    } >> "$EVIDENCE_DIR/hardening-verification.txt"
  fi

  if [ "$aslr" != "2" ]; then
    harden_status kernel_sysctl FAIL "kernel.randomize_va_space is $aslr (expected 2)"
  elif [ "$hardlinks" != "1" ]; then
    harden_status kernel_sysctl FAIL "fs.protected_hardlinks is $hardlinks (expected 1)"
  elif [ "$symlinks" != "1" ]; then
    harden_status kernel_sysctl FAIL "fs.protected_symlinks is $symlinks (expected 1)"
  else
    harden_status kernel_sysctl PASS "kernel ASLR and protected links configured"
  fi
}

harden_control_coredump() {
  local conf_out storage_val
  harden_write_file /etc/systemd/coredump.conf.d/99-sysdiag.conf 0644 '[Coredump]
Storage=none' || return 1

  if ! have_cmd systemd-analyze; then
    harden_status coredump NA "systemd-analyze unavailable"
    return 0
  fi

  conf_out="$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null || true)"
  if [ -z "$conf_out" ]; then
    harden_status coredump NA "systemd-analyze unavailable"
    return 0
  fi

  storage_val="$(echo "$conf_out" | grep -E '^[[:space:]]*Storage=' | tail -n1 | cut -d= -f2 | tr -d ' ')"
  [ -z "$storage_val" ] && storage_val="unset"

  if [ "$storage_val" = "none" ]; then
    harden_status coredump PASS "coredumps disabled (Storage=none); crash-dump forensics unavailable on this host"
  else
    harden_status coredump FAIL "coredump Storage is $storage_val (expected none)"
  fi
}

harden_control_auditd() {
  local audit_out
  harden_write_file /etc/audit/rules.d/99-sysdiag.rules 0644 '-e 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity' || return 1

  if ! have_cmd auditd && ! have_cmd auditctl; then
    harden_status auditd NA "auditd not installed"
    return 0
  fi

  audit_out="$(auditctl -l 2>/dev/null || true)"
  if [ -n "$audit_out" ] && [ "$HARDEN_APPLY" -eq 1 ]; then
    printf '%s\n' "$audit_out" >> "$EVIDENCE_DIR/hardening-verification.txt"
  fi

  if echo "$audit_out" | grep -q '/etc/passwd' && echo "$audit_out" | grep -q '/etc/group'; then
    harden_status auditd PASS "auditd rules active for /etc/passwd and /etc/group"
  else
    harden_status auditd FAIL "rules file present; run augenrules --load or restart auditd"
  fi
}

harden_control_timesync() {
  local synced detail ntp_val chrony_out
  case "$HARDEN_VIRT" in
    container|podman|docker|lxc)
      harden_status timesync NA "time is managed by the host"
      return 0
      ;;
  esac
  synced=0; detail=""
  ntp_val="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  if [ -n "$ntp_val" ]; then
    printf 'NTPSynchronized=%s\n' "$ntp_val" >> "$EVIDENCE_DIR/hardening-verification.txt"
    if [ "$ntp_val" = "yes" ]; then
      synced=1
    fi
  fi
  if [ "$synced" -ne 1 ] && have_cmd chronyc; then
    chrony_out="$(chronyc tracking 2>/dev/null || true)"
    if [ -n "$chrony_out" ]; then
      printf '%s\n' "$chrony_out" >> "$EVIDENCE_DIR/hardening-verification.txt"
      synced=1
    fi
  fi
  if [ "$synced" -eq 1 ]; then
    harden_status timesync PASS 'time synchronisation active'
    return 0
  fi
  if have_cmd systemctl && { systemctl is-active --quiet systemd-timesyncd || systemctl is-active --quiet chronyd || systemctl is-active --quiet chrony; }; then
    harden_status timesync FAIL 'service running, not yet synchronised'
    return 0
  fi
  if [ "$HARDEN_APPLY" -eq 1 ]; then
    if ! have_cmd chronyd && ! have_cmd chronyc; then
      harden_install_packages chrony || return 1
    fi
    harden_run_cmd 'enable chrony' sh -c 'systemctl enable --now chronyd 2>/dev/null || systemctl enable --now chrony' || true
    ntp_val="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    chrony_out="$(chronyc tracking 2>/dev/null || true)"
    if [ "$ntp_val" = "yes" ] || [ -n "$chrony_out" ]; then
      harden_status timesync PASS 'time synchronisation active'
    else
      harden_status timesync FAIL 'service running, not yet synchronised'
    fi
    return 0
  fi
  harden_status timesync FAIL 'no active time synchronisation service'
}

harden_control_journald() {
  local conf_out storage_val
  harden_write_file /etc/systemd/journald.conf.d/99-sysdiag.conf 0644 '[Journal]
Storage=persistent
SystemMaxUse=1G' || return 1

  if ! have_cmd systemd-analyze; then
    harden_status journald NA "systemd-analyze unavailable"
    return 0
  fi

  conf_out="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null || true)"
  if [ -z "$conf_out" ]; then
    harden_status journald NA "systemd-analyze unavailable"
    return 0
  fi

  storage_val="$(echo "$conf_out" | grep -E '^[[:space:]]*Storage=' | tail -n1 | cut -d= -f2 | tr -d ' ')"
  [ -z "$storage_val" ] && storage_val="unset"

  if [ "$storage_val" = "persistent" ]; then
    harden_status journald PASS "journald persistent storage active (Storage=persistent)"
  else
    harden_status journald FAIL "journald Storage is $storage_val (expected persistent)"
  fi
}

harden_control_sshd() {
  local sshd_cmd sshd_out backup
  if [ -r /etc/ssh/sshd_config ] && ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    harden_status sshd FAIL "/etc/ssh/sshd_config has no Include for sshd_config.d; drop-in would be ignored"
    return 0
  fi

  harden_write_file /etc/ssh/sshd_config.d/99-sysdiag.conf 0644 'PermitRootLogin no
MaxAuthTries 4' || return 1

  sshd_cmd=""
  if have_cmd sshd; then
    sshd_cmd="sshd"
  elif [ -x /usr/sbin/sshd ]; then
    sshd_cmd="/usr/sbin/sshd"
  fi

  if [ "$HARDEN_APPLY" -eq 1 ] && [ -n "$sshd_cmd" ]; then
    if ! "$sshd_cmd" -t >/dev/null 2>&1; then
      backup="$EVIDENCE_DIR/backups/etc/ssh/sshd_config.d/99-sysdiag.conf"
      if [ -f "$backup" ]; then
        cp -f "$backup" /etc/ssh/sshd_config.d/99-sysdiag.conf
      else
        rm -f /etc/ssh/sshd_config.d/99-sysdiag.conf
      fi
      harden_log error "sshd -t rejected the drop-in; change reverted"
      harden_status sshd ERROR "sshd -t rejected the drop-in; change reverted"
      return 1
    fi
  fi

  if [ -n "$sshd_cmd" ]; then
    sshd_out="$("$sshd_cmd" -T 2>/dev/null || true)"
    if [ -n "$sshd_out" ]; then
      if echo "$sshd_out" | grep -iq '^permitrootlogin no' && echo "$sshd_out" | grep -iq '^maxauthtries 4'; then
        harden_status sshd PASS "drop-in valid; reload sshd to activate"
      else
        harden_status sshd FAIL "sshd effective config does not match PermitRootLogin no and MaxAuthTries 4"
      fi
      return 0
    fi
  fi

  harden_status sshd INFO "drop-in written; sshd -T unavailable, effective config unverified"
}

harden_control_file_scan() {
  local scan_roots scan_file ww_file unowned_file root
  local ww_count=0 unowned_count=0 detail timed_out=0
  scan_roots=""
  for root in $HARDEN_SCAN_ROOTS; do
    [ -d "$root" ] && scan_roots="$scan_roots $root"
  done

  scan_file="$EVIDENCE_DIR/hardening-file-scan.txt"
  ww_file="$(mktemp 2>/dev/null || printf '%s/ww.tmp' "$EVIDENCE_DIR")"
  unowned_file="$(mktemp 2>/dev/null || printf '%s/unowned.tmp' "$EVIDENCE_DIR")"

  {
    printf "# sysdiag file scan audit\n"
    printf "# Date: %s\n" "$TIMESTAMP"
    printf "# Target roots: %s\n" "$HARDEN_SCAN_ROOTS"
    if [ "$(id -u)" -ne 0 ]; then
      printf "# Note: Unprivileged scan; find permission errors suppressed (2>/dev/null)\n"
    else
      printf "# Note: Root scan; find permission errors suppressed (2>/dev/null)\n"
    fi
    if ! have_cmd timeout; then
      printf "# Note: 'timeout' command absent; scan ran unbounded\n"
    fi
    printf "\n"
  } > "$scan_file"

  run_find() {
    if have_cmd timeout; then
      timeout "$HARDEN_FIND_TIMEOUT" "$@" 2>/dev/null
    else
      "$@" 2>/dev/null
    fi
  }

  if [ -n "$scan_roots" ]; then
    # shellcheck disable=SC2086
    run_find find $scan_roots -xdev -type f -perm -0002 -print > "$ww_file"
    [ $? -eq 124 ] && timed_out=1

    # shellcheck disable=SC2086
    run_find find $scan_roots -xdev \( -nouser -o -nogroup \) -print > "$unowned_file"
    [ $? -eq 124 ] && timed_out=1
  fi

  ww_count="$(wc -l < "$ww_file" 2>/dev/null || printf '0')"
  unowned_count="$(wc -l < "$unowned_file" 2>/dev/null || printf '0')"
  ww_count="$(echo "$ww_count" | tr -d ' ')"
  unowned_count="$(echo "$unowned_count" | tr -d ' ')"

  {
    printf "=== World-Writable Files (%s) ===\n" "$ww_count"
    cat "$ww_file" 2>/dev/null
    printf "\n=== Unowned or Ungrouped Files/Directories (%s) ===\n" "$unowned_count"
    cat "$unowned_file" 2>/dev/null
  } >> "$scan_file"

  rm -f "$ww_file" "$unowned_file"

  detail="${ww_count} world-writable files, ${unowned_count} unowned; see hardening-file-scan.txt"
  if [ "$(id -u)" -ne 0 ]; then
    detail="${detail} (unprivileged scan; some paths unreadable)"
  fi

  if [ "$timed_out" -eq 1 ]; then
    detail="file scan timed out after ${HARDEN_FIND_TIMEOUT}s; result partial; see hardening-file-scan.txt"
    if [ "$(id -u)" -ne 0 ]; then
      detail="${detail} (unprivileged scan; some paths unreadable)"
    fi
    harden_status file_scan INFO "$detail"
  elif [ "$ww_count" -gt 0 ] || [ "$unowned_count" -gt 0 ]; then
    harden_status file_scan FAIL "$detail"
  else
    harden_status file_scan PASS "$detail"
  fi
}
harden_control_selected() {
  local id="$1"
  if [ -n "$HARDEN_CONTROLS" ]; then
    case ",$HARDEN_CONTROLS," in
      *",$id,"*) ;;
      *) return 1 ;;
    esac
  fi
  if [ -n "$HARDEN_SKIP_CONTROLS" ]; then
    case ",$HARDEN_SKIP_CONTROLS," in
      *",$id,"*) return 1 ;;
    esac
  fi
  return 0
}

harden_run_controls() {
  local id rc count start end secs selected_list
  selected_list=""
  count=0
  for id in $HARDEN_CONTROL_IDS; do
    if harden_control_selected "$id"; then
      selected_list="$selected_list $id"
      count=$((count + 1))
    fi
  done

  progress_scope harden "$count"

  for id in $selected_list; do
    HARDEN_CURRENT_CONTROL="$id"
    progress_begin "$id"
    start="$(date +%s 2>/dev/null || printf '0')"
    "harden_control_$id"
    rc=$?
    end="$(date +%s 2>/dev/null || printf '0')"
    secs=$((end - start))
    progress_end "$rc" "$secs"
    if [ "$rc" -ne 0 ]; then
      HARDEN_CONTROL_ERRORS=$((HARDEN_CONTROL_ERRORS + 1))
      harden_status "$id" ERROR "control returned rc=$rc; see hardening-actions.tsv"
    fi
  done
}

harden_report_status() {
  local pass fail na err info total ctrl status detail
  pass=0; fail=0; na=0; err=0; info=0
  append_report ""
  append_report "### Hardening Control Status"
  append_report "| Control | Status | Detail |"
  append_report "|---|---|---|"
  if [ -r "$HARDEN_STATUS_TSV" ]; then
    while IFS=$'\t' read -r ctrl status detail; do
      [ -n "$ctrl" ] || continue
      append_report "| $ctrl | $status | $detail |"
      case "$status" in
        PASS)  pass=$((pass + 1)) ;;
        FAIL)  fail=$((fail + 1)) ;;
        NA)    na=$((na + 1)) ;;
        ERROR) err=$((err + 1)) ;;
        INFO)  info=$((info + 1)) ;;
      esac
    done < "$HARDEN_STATUS_TSV"
  fi
  total=$((pass + fail + na + err + info))
  append_report ""
  append_report "Hardening controls evaluated: $total (PASS: $pass, FAIL: $fail, NA: $na, ERROR: $err, INFO: $info)"
}

module_harden() {
  append_report "## Basic hardening (mode: $([ "$HARDEN_APPLY" -eq 1 ] && printf apply || printf dry-run))"
  HARDEN_STATUS_TSV="$EVIDENCE_DIR/hardening-status.tsv"
  : > "$EVIDENCE_DIR/hardening-actions.tsv"
  : > "$EVIDENCE_DIR/hardening-plan.txt"
  : > "$EVIDENCE_DIR/hardening-verification.txt"
  : > "$HARDEN_STATUS_TSV"
  mkdir -p "$EVIDENCE_DIR/backups"
  harden_detect
  if [ -n "$HARDEN_INSTALL" ] && ! harden_control_selected "packages_extra"; then
    printf 'WARNING: --install ignored; the packages_extra control is not selected\n' >&2
  fi
  harden_preflight || return 1
  [ "$HARDEN_APPLY" -eq 1 ] && RUN_MUTATED=1
  harden_run_controls
  harden_report_status
  append_report '- Hardening evidence: hardening-environment.txt, hardening-plan.txt, hardening-actions.tsv, hardening-status.tsv, hardening-verification.txt.'
  return 0
}

run_module() {
  case "$1" in
    baseline) module_baseline ;;
    reboot) module_reboot ;;
    slow) module_slow ;;
    disk) module_disk ;;
    network) module_network ;;
    service) module_service ;;
    tools) module_tools ;;
    harden) module_harden ;;
    *) printf 'Unknown module: %s\n' "$1" >&2; return 1 ;;
  esac
}

run_all_modules() {
  run_module reboot || return 1
  run_module slow || return 1
  run_module disk || return 1
  run_module network || return 1
  run_module service || return 1
  run_module baseline || return 1
  run_module tools || return 1
}

list_modules() {
  cat <<'EOF_LIST'
Available modules:
  reboot    Why did this system reboot/crash?
  slow      Why is this VM/server slow?
  disk      Why is disk/filesystem unhealthy?
  network   Why is network slow/unreachable?
  service   Why did a service/container fail?
  baseline  Collect full baseline health report
  tools     Show optional tool/dependency detection
  harden    Review/apply basic Linux hardening (dry-run by default)
EOF_LIST
}

list_controls() {
  local id desc
  for id in $HARDEN_CONTROL_IDS; do
    case "$id" in
      tmout) desc="Enforce shell idle timeout (TMOUT)" ;;
      banner) desc="Set login issue banner" ;;
      ipv6) desc="Disable IPv6 in sysctl and GRUB" ;;
      packages) desc="Refresh package metadata and install core dependencies" ;;
      packages_extra) desc="Install selected optional hardening packages" ;;
      pwquality) desc="Configure PAM password quality requirement" ;;
      user_sudo) desc="Provision linuxteam admin user with NOPASSWD sudo (site access policy, not a hardening control)" ;;
      su_wheel) desc="Audit only: is su restricted to wheel/sudo group" ;;
      kernel_sysctl) desc="Apply kernel hardening sysctl tunings" ;;
      coredump) desc="Disable system coredumps" ;;
      auditd) desc="Configure audit daemon and CIS audit rules" ;;
      timesync) desc="Ensure active NTP time synchronization" ;;
      journald) desc="Configure persistent journald storage and size limits" ;;
      sshd) desc="Apply SSH daemon security hardening" ;;
      file_scan) desc="Scan for world-writable and unowned files" ;;
      *) desc="Hardening control $id" ;;
    esac
    printf '%s\t%s\n' "$id" "$desc"
  done
}

list_packages() {
  local id
  for id in $HARDEN_PACKAGE_IDS; do
    printf '%s\t%s\n' "$id" "$(harden_package_description "$id")"
  done
}

harden_validate_control_names() {
  [ -n "$HARDEN_CONTROLS" ] || return 0
  local ctrl
  local old_ifs="$IFS"
  IFS=','
  for ctrl in $HARDEN_CONTROLS; do
    case " $HARDEN_CONTROL_IDS " in
      *" $ctrl "*) ;;
      *)
        IFS="$old_ifs"
        printf 'ERROR: unknown hardening control: %s\n' "$ctrl" >&2
        return 2
        ;;
    esac
  done
  IFS="$old_ifs"
  return 0
}

harden_validate_package_names() {
  [ -n "$HARDEN_INSTALL" ] || return 0
  local pkg
  local old_ifs="$IFS"
  IFS=','
  for pkg in $HARDEN_INSTALL; do
    case " $HARDEN_PACKAGE_IDS " in
      *" $pkg "*) ;;
      *)
        IFS="$old_ifs"
        printf 'ERROR: unknown package group: %s\n' "$pkg" >&2
        return 2
        ;;
    esac
  done
  IFS="$old_ifs"
  return 0
}

menu_choice_plain() {
  while true; do
    cat <<'MENU'

sysdiag - read-only Linux diagnostics

1) Why did this system reboot/crash?
2) Why is this VM/server slow?
3) Why is disk/filesystem unhealthy?
4) Why is network slow/unreachable?
5) Why did a service/container fail?
6) Collect full baseline health report
7) Show tool/dependency detection
8) Run all modules
9) Package current run as tarball
10) Review/apply basic Linux hardening
11) Select packages to install with hardening
12) Build single-file AI handoff bundle
0) Quit
MENU
    printf 'Select: '
    read -r choice || return 0
    case "$choice" in
      1) run_module reboot ;;
      2) run_module slow ;;
      3) run_module disk ;;
      4) run_module network ;;
      5) run_module service ;;
      6) run_module baseline ;;
      7) run_module tools ;;
      8) run_all_modules ;;
      9) package_run || true ;;
      12) build_bundle || true ;;
      11)
        printf 'Available package groups: guest_agent, fail2ban, logging, firewall\n'
        printf 'Enter comma-separated groups (current: %s): ' "$HARDEN_INSTALL"
        read -r input_pkgs
        HARDEN_INSTALL="$input_pkgs"
        harden_validate_package_names || HARDEN_INSTALL=""
        ;;
      0|q|Q) return 0 ;;
      *) printf 'Invalid choice\n' ;;
    esac
    printf '\nCurrent report: %s\n' "$REPORT_FILE"
  done
}

menu_choice_tui() {
  local ui choice sel
  if have_cmd dialog; then
    ui="dialog"
  elif have_cmd whiptail; then
    ui="whiptail"
  else
    return 1
  fi
  while true; do
    choice="$($ui --title 'sysdiag' --menu 'Read-only Linux diagnostics' 20 78 12 \
      1 'Why did this system reboot/crash?' \
      2 'Why is this VM/server slow?' \
      3 'Why is disk/filesystem unhealthy?' \
      4 'Why is network slow/unreachable?' \
      5 'Why did a service/container fail?' \
      6 'Collect full baseline health report' \
      7 'Show tool/dependency detection' \
      8 'Run all modules' \
      9 'Package current run as tarball' \
      10 'Review/apply basic hardening' \
      11 'Select packages to install with hardening' \
      12 'Build single-file AI handoff bundle' \
      0 'Quit' 3>&1 1>&2 2>&3)" || return 0
    case "$choice" in
      1) run_module reboot ;;
      2) run_module slow ;;
      3) run_module disk ;;
      4) run_module network ;;
      5) run_module service ;;
      6) run_module baseline ;;
      7) run_module tools ;;
      8) run_all_modules ;;
      9) package_run || true ;;
      12) build_bundle || true ;;
      10) run_module harden ;;
      11)
        sel="$($ui --title 'sysdiag' --checklist 'Select package groups' 20 78 8 \
          guest_agent "$(harden_package_description guest_agent)" off \
          fail2ban "$(harden_package_description fail2ban)" on \
          logging "$(harden_package_description logging)" on \
          firewall "$(harden_package_description firewall)" off 3>&1 1>&2 2>&3)" || true
        HARDEN_INSTALL="$(printf '%s' "$sel" | tr -d '"' | tr ' ' ',')"
        ;;
      0) return 0 ;;
    esac
  done
}

selftest() {
  local tmp rc
  tmp="$(mktemp -d 2>/dev/null || printf '/tmp/sysdiag-selftest-%s' "$$")"
  mkdir -p "$tmp"
  OUT_DIR="$tmp/run"
  init_output
  add_finding info high "selftest finding" "selftest" "no action"
  run_cmd selftest-true true
  write_summary_json
  finalize_report
  BUNDLE_REDACT=1 build_bundle >/dev/null 2>&1
  rc=0
  [ -s "$REPORT_FILE" ] || { printf 'selftest failed: report missing\n' >&2; rc=1; }
  [ -s "$SUMMARY_FILE" ] || { printf 'selftest failed: summary missing\n' >&2; rc=1; }
  [ -s "$COMMAND_LOG" ] || { printf 'selftest failed: command log missing\n' >&2; rc=1; }
  [ -s "$OUT_DIR/bundle.md" ] || { printf 'selftest failed: bundle missing\n' >&2; rc=1; }
  if grep -q 'selftest finding' "$FINDINGS_TSV" && grep -q 'selftest finding' "$SUMMARY_FILE" && grep -q 'selftest finding' "$OUT_DIR/bundle.md"; then
    :
  else
    printf 'selftest failed: finding not recorded\n' >&2
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    printf 'selftest: PASS\n'
  fi
  return "$rc"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --run)
        [ "$#" -ge 2 ] || { printf '--run requires a module\n' >&2; exit 2; }
        MODE="run"; REQUESTED_MODULE="$2"; shift 2 ;;
      --all) MODE="all"; shift ;;
      --list) MODE="list"; shift ;;
      --out)
        [ "$#" -ge 2 ] || { printf '--out requires a directory\n' >&2; exit 2; }
        OUT_DIR="$2"; shift 2 ;;
      --package) PACKAGE_ONLY=1; shift ;;
      --bundle) BUNDLE=1; shift ;;
      --no-bundle) BUNDLE=-1; shift ;;
      --no-redact) BUNDLE_REDACT=0; shift ;;
      --apply) HARDEN_APPLY=1; shift ;;
      --upgrade-packages) HARDEN_UPGRADE_PACKAGES=1; shift ;;
      --allow-virtualization) HARDEN_ALLOW_VIRTUALIZATION=1; shift ;;
      --controls)
        [ "$#" -ge 2 ] || { printf '--controls requires a comma-separated list\n' >&2; exit 2; }
        HARDEN_CONTROLS="$2"; shift 2 ;;
      --skip-controls)
        [ "$#" -ge 2 ] || { printf '--skip-controls requires a comma-separated list\n' >&2; exit 2; }
        HARDEN_SKIP_CONTROLS="$2"; shift 2 ;;
      --list-controls) MODE="list-controls"; shift ;;
      --install)
        [ "$#" -ge 2 ] || { printf '--install requires a comma-separated list\n' >&2; exit 2; }
        HARDEN_INSTALL="$2"; shift 2 ;;
      --list-packages) MODE="list-packages"; shift ;;
      --quiet) PROGRESS_QUIET=1; shift ;;
      --selftest) MODE="selftest"; shift ;;
      --version) printf '%s\n' "$APP_VERSION"; exit 0 ;;
      --no-color) shift ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
  done
  harden_validate_control_names || exit 2
  harden_validate_package_names || exit 2
}

main() {
  parse_args "$@"
  case "$MODE" in
    list)
      list_modules
      exit 0
      ;;
    list-controls)
      list_controls
      exit 0
      ;;
    list-packages)
      list_packages
      exit 0
      ;;
    selftest)
      selftest
      exit $?
      ;;
  esac

  init_output

  case "$MODE" in
    run)
      run_module "$REQUESTED_MODULE" || exit 1
      ;;
    all)
      run_all_modules || exit 1
      ;;
    menu)
      if ! menu_choice_tui; then
        menu_choice_plain
      fi
      ;;
  esac

  finalize_report
  if [ "$PACKAGE_ONLY" -eq 1 ]; then
    package_run || true
  fi
  if [ "$BUNDLE" -eq 1 ]; then
    build_bundle || true
  fi
  printf 'Report: %s\n' "$REPORT_FILE"
  printf 'Summary: %s\n' "$SUMMARY_FILE"
  printf 'Evidence: %s\n' "$EVIDENCE_DIR"
  [ "$BUNDLE" -eq 1 ] && [ -f "$OUT_DIR/bundle.md" ] && printf 'Bundle: %s\n' "$OUT_DIR/bundle.md"
  if [ "$HARDEN_APPLY" -eq 1 ] && [ "$HARDEN_CONTROL_ERRORS" -gt 0 ]; then
    printf 'ERROR: %s hardening control(s) failed; see %s\n' "$HARDEN_CONTROL_ERRORS" "$HARDEN_STATUS_TSV" >&2
    exit 1
  fi
}

[ "${SYSDIAG_LIB:-0}" = 1 ] || main "$@"
