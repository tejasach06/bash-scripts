#!/usr/bin/env bash
# sysdiag.sh - Distro-agnostic read-only Linux diagnostics and RCA evidence collector.

set -u
set -o pipefail

APP_VERSION="0.1.0"
MODE="menu"
REQUESTED_MODULE=""
OUT_DIR=""
PACKAGE_ONLY=0
HARDEN_APPLY=0
HARDEN_UPGRADE_PACKAGES=0
HARDEN_ALLOW_VIRTUALIZATION=0
HARDEN_USER="linuxteam"
HARDEN_TMOUT=900
HARDEN_BANNER="Authorized access only. Activity may be monitored and recorded."

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

OPTIONAL_TOOLS="dialog whiptail jq journalctl coredumpctl dmesg last who uptime vmstat mpstat pidstat iostat sar free lscpu lsblk findmnt smartctl lvs vgs pvs systemctl systemd-detect-virt virt-what virsh podman docker ip ss ethtool nstat nft iptables firewall-cmd ufw resolvectl tar top swapon df mount awk sed grep sort uniq head tail date hostname ps"

usage() {
  cat <<'USAGE'
Usage: sysdiag.sh [options]

Read-only distro-agnostic Linux diagnostics with Markdown/JSON evidence reports.

Options:
  --run MODULE       Run one module: reboot, slow, disk, network, service, baseline, tools, harden
  --apply            Apply changes for harden (default is dry-run)
  --upgrade-packages Allow harden to upgrade installed packages in apply mode
  --allow-virtualization Permit apply mode in detected VM/container environments
  --all              Run all modules
  --list             List modules and exit
  --out DIR          Write output to DIR (default: ./sysdiag-runs/<host>-<timestamp>)
  --package          Package current run directory at end
  --selftest         Run internal smoke tests and exit
  --version          Show version and exit
  --no-color         Disable color output
  -h, --help         Show help

Interactive mode:
  Run without arguments to open a menu. dialog/whiptail are used when available;
  otherwise a plain numbered menu is shown.

Safety:
  v1 is read-only. It does not install packages, edit configs, restart services,
  repair filesystems, run intrusive SMART tests, or reboot.
USAGE
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
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
  cmd_s="$*"

  {
    printf '### command\n%s\n\n' "$cmd_s"
    printf '### started_utc\n%s\n\n' "$(date -u +%FT%TZ 2>/dev/null || date)"
    printf '### output\n'
  } > "$outfile"

  "$@" >> "$outfile" 2>&1
  rc=$?
  end="$(date +%s 2>/dev/null || printf '0')"

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
  {
    printf '### command\n%s\n\n' "$shellcmd"
    printf '### started_utc\n%s\n\n' "$(date -u +%FT%TZ 2>/dev/null || date)"
    printf '### output\n'
  } > "$outfile"
  sh -c "$shellcmd" >> "$outfile" 2>&1
  rc=$?
  end="$(date +%s 2>/dev/null || printf '0')"
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

  if [ -s "$EVIDENCE_DIR/reboot-journal-prev.txt" ]; then
    if tail -n 80 "$EVIDENCE_DIR/reboot-journal-prev.txt" | grep -Eiq 'Reached target (Shutdown|Power-Off|Reboot)|systemd-shutdown|Stopped target'; then
      add_finding "info" "medium" "Previous boot contains clean shutdown/reboot markers" "reboot-journal-prev.txt" "Correlate with user activity, package updates, scheduled jobs, and hypervisor events."
    else
      add_finding "warn" "medium" "Previous boot log does not show obvious clean shutdown markers near end" "reboot-journal-prev.txt" "Treat as possible abrupt reset; check power, hypervisor, BMC/IPMI, kernel panic, OOM, and storage logs."
    fi
  fi
  add_finding "info" "high" "Reboot investigation completed" "reboot-*" "If evidence is incomplete, enable persistent journal and kdump for future incidents."
}

module_slow() {
  record_module slow
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
  ]
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
  (cd "$parent" && tar -czf "$tarfile" "$base")
  printf '%s\n' "$tarfile"
}

harden_log() {
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)" "$1" "$2" >> "$EVIDENCE_DIR/hardening-actions.tsv"
}

harden_plan() {
  printf '%s\n' "$1" >> "$EVIDENCE_DIR/hardening-plan.txt"
  if [ "$HARDEN_APPLY" -eq 1 ]; then
    printf 'APPLY: %s\n' "$1"
  else
    printf 'DRY-RUN: %s\n' "$1"
  fi
}

harden_detect() {
  HARDEN_DISTRO_ID=unknown
  HARDEN_DISTRO_LIKE=""
  HARDEN_DISTRO_FAMILY=unknown
  HARDEN_VIRT=none
  [ -r /etc/os-release ] && { . /etc/os-release; HARDEN_DISTRO_ID="${ID:-unknown}"; HARDEN_DISTRO_LIKE="${ID_LIKE:-}"; }
  have_cmd systemd-detect-virt && HARDEN_VIRT="$(systemd-detect-virt 2>/dev/null || printf unknown)"
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
  } | tee "$EVIDENCE_DIR/hardening-environment.txt"
}

harden_preflight() {
  local missing rc; missing=""; rc=0
  if [ "$HARDEN_APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    printf 'ERROR: apply mode requires root. Use sudo ./sysdiag.sh --run harden --apply.\n' >&2
    rc=1
  fi
  if [ "$HARDEN_APPLY" -eq 1 ] && [ "$HARDEN_ALLOW_VIRTUALIZATION" -ne 1 ] && [ "$HARDEN_VIRT" != "none" ] && [ -n "$HARDEN_VIRT" ]; then
    printf 'ERROR: apply mode refused in virtualization environment (%s); use --allow-virtualization explicitly.\n' "$HARDEN_VIRT" >&2
    rc=1
  fi
  if [ "$HARDEN_APPLY" -eq 1 ]; then
    for cmd in chpasswd date install mktemp openssl sysctl useradd visudo; do
      have_cmd "$cmd" || missing="$missing $cmd"
    done
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
  local description; description="$1"; shift
  harden_plan "$description: $*"
  [ "$HARDEN_APPLY" -eq 1 ] || return 0
  "$@"
  harden_log command "$description"
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
  [ "$HARDEN_DISTRO_FAMILY" != unknown ] || return 0
  case "$HARDEN_DISTRO_FAMILY" in
    debian)
      harden_run_cmd 'refresh Debian-family package metadata' apt-get update || return 1
      [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ] && harden_run_cmd 'upgrade Debian-family packages' apt-get -y upgrade
      harden_run_cmd 'install password policy dependency' apt-get -y install libpam-pwquality ;;
    rhel)
      [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ] && harden_run_cmd 'upgrade RHEL-family packages' dnf -y upgrade
      harden_run_cmd 'install password policy dependency' dnf -y install libpwquality ;;
    suse)
      [ "$HARDEN_UPGRADE_PACKAGES" -eq 1 ] && harden_run_cmd 'upgrade SUSE packages' zypper --non-interactive update
      harden_run_cmd 'install password policy dependency' zypper --non-interactive install libpwquality-tools ;;
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
  id "$HARDEN_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$HARDEN_USER"
  printf '%s:%s\n' "$HARDEN_USER" "$hash" | chpasswd -e
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

module_harden() {
  append_report "## Basic hardening (mode: $([ "$HARDEN_APPLY" -eq 1 ] && printf apply || printf dry-run))"
  : > "$EVIDENCE_DIR/hardening-actions.tsv"
  : > "$EVIDENCE_DIR/hardening-plan.txt"
  : > "$EVIDENCE_DIR/hardening-verification.txt"
  harden_detect
  harden_preflight || return 1
  harden_write_file /etc/profile.d/99-sysdiag-timeout.sh 0644 "TMOUT=$HARDEN_TMOUT
readonly TMOUT
export TMOUT" || return 1
  harden_write_file /etc/issue 0644 "$HARDEN_BANNER" || return 1
  harden_write_file /etc/issue.net 0644 "$HARDEN_BANNER" || return 1
  harden_configure_sysctl || return 1
  harden_configure_grub || return 1
  harden_packages || return 1
  harden_pam_policy || return 1
  harden_user_sudo || return 1
  append_report '- Hardening evidence: hardening-environment.txt, hardening-plan.txt, hardening-actions.tsv, hardening-verification.txt.'
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
      10) run_module harden ;;
      0|q|Q) return 0 ;;
      *) printf 'Invalid choice\n' ;;
    esac
    printf '\nCurrent report: %s\n' "$REPORT_FILE"
  done
}

menu_choice_tui() {
  local ui choice
  if have_cmd dialog; then
    ui="dialog"
  elif have_cmd whiptail; then
    ui="whiptail"
  else
    return 1
  fi
  while true; do
    choice="$($ui --title 'sysdiag' --menu 'Read-only Linux diagnostics' 20 78 10 \
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
      10) run_module harden ;;
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
  rc=0
  [ -s "$REPORT_FILE" ] || { printf 'selftest failed: report missing\n' >&2; rc=1; }
  [ -s "$SUMMARY_FILE" ] || { printf 'selftest failed: summary missing\n' >&2; rc=1; }
  [ -s "$COMMAND_LOG" ] || { printf 'selftest failed: command log missing\n' >&2; rc=1; }
  if grep -q 'selftest finding' "$FINDINGS_TSV" && grep -q 'selftest finding' "$SUMMARY_FILE"; then
    :
  else
    printf 'selftest failed: finding not recorded\n' >&2
    rc=1
  fi
  rm -rf "$tmp"
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
      --apply) HARDEN_APPLY=1; shift ;;
      --upgrade-packages) HARDEN_UPGRADE_PACKAGES=1; shift ;;
      --allow-virtualization) HARDEN_ALLOW_VIRTUALIZATION=1; shift ;;
      --selftest) MODE="selftest"; shift ;;
      --version) printf '%s\n' "$APP_VERSION"; exit 0 ;;
      --no-color) shift ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
  done
}

main() {
  parse_args "$@"
  case "$MODE" in
    list)
      list_modules
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
  printf 'Report: %s\n' "$REPORT_FILE"
  printf 'Summary: %s\n' "$SUMMARY_FILE"
  printf 'Evidence: %s\n' "$EVIDENCE_DIR"
}

main "$@"
