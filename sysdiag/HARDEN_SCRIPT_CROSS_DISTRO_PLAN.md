# Linux Hardening Script (`harden.sh`)

## Context

Build one self-contained POSIX-ish bash script, `harden.sh`, in `/home/tejas/Projects/bash-scripts/sysdiag/`, that applies a basic security baseline across Ubuntu/Debian, CentOS/RHEL/Rocky/Alma, openSUSE Leap/Tumbleweed, and openSUSE MicroOS. It runs read-only by default (prints a per-control PASS/CHANGE report) and only mutates the system with `--apply`. Controls: shell idle timeout, login/SSH banners, sshd hardening, IPv6 disable (default on, `--keep-ipv6` to skip), password/login policy, network sysctls, filesystem/module hardening, auditd + core dump restrictions. Every applied change is backed up and a revert script is generated.

The repo currently contains only `.gitignore`; there is no existing code or convention to follow.

## Key design decisions (do not re-decide)

- **Single file.** `harden.sh`, one bash script, one function per control named `ctl_<name>`. No `lib/` directory, no sourcing.
- **Drop-in config over in-place edits, wherever a drop-in dir exists.** Writing a new file is idempotent, trivially revertible, and avoids regex surgery on vendor files. Concretely: `/etc/profile.d/99-hardening.sh`, `/etc/sysctl.d/99-hardening.conf`, `/etc/ssh/sshd_config.d/99-hardening.conf`, `/etc/modprobe.d/99-hardening.conf`, `/etc/security/limits.d/99-hardening.conf`. In-place edits only where no drop-in mechanism exists: `/etc/login.defs`, `/etc/security/pwquality.conf`, `/etc/security/faillock.conf`, `/etc/issue*`, and `sshd_config` on distros without `Include`.
- **IPv6 via sysctl only; no GRUB/bootloader edits.** `net.ipv6.conf.{all,default,lo}.disable_ipv6=1` is reversible without a reboot and works identically on all four distro families, including MicroOS where `/usr` is read-only and bootloader regeneration requires `transactional-update`. Ceiling: kernel module stays loaded and sockets can still be opened by privileged code paths; the upgrade path (`ipv6.disable=1` on the kernel cmdline) is documented in a `ponytail:` comment, not implemented.
- **Never edit PAM stacks.** `/etc/pam.d/*` differs per distro (authselect on RHEL9, pam-config on SUSE, pam-auth-update on Debian) and a bad edit locks every account out. The script writes `/etc/security/faillock.conf` settings and, if `pam_faillock`/`pam_tally2` is not already referenced in the stack, emits a WARN telling the operator the exact distro-native command to enable it. Same policy for pwquality: write the conf, warn if not wired.
- **No package installation by default.** If `auditd` is absent, report WARN with the install command for the detected package manager; install only when `--install-missing` is passed. On MicroOS that flag maps to `transactional-update pkg install` and prints a reboot-required notice.
- **MicroOS guard.** Detected via `ID=opensuse-microos` or a read-only `/usr` mount. Controls that only touch `/etc` proceed normally; anything needing `/usr` writes or package install is skipped with a clear SKIP reason.
- **Container runtimes are first-class: hardening MUST NOT break Docker, Podman, or Kubernetes on the host.** A `detect_container_host()` probe (step 2b) sets `CONTAINER_HOST=1`, and every control consults it. Exceptions are applied automatically, never left to the operator. `--no-container-exceptions` disables the automatic relaxations for a host known to run no containers; `--container-host` forces `CONTAINER_HOST=1` for a machine that will run containers later but does not yet. Any exception taken is reported with `log_skip`/`log_warn` naming the control and the reason, so the report never silently understates the baseline.

## Approach

Steps are ordered so the script is runnable and testable (`bash -n`, `--dry-run` on this Arch box) after each one.

### 1. Skeleton, CLI, and reporting

Create `harden.sh` with `#!/usr/bin/env bash`, `set -euo pipefail`, `IFS=$'\n\t'`.

CLI flags, parsed with a `while case` loop over `$@`:

- `--apply` — perform changes (default is dry-run)
- `--dry-run` — explicit no-op default
- `--keep-ipv6` — skip the IPv6 control
- `--banner-file PATH` — override the built-in banner text
- `--only LIST` / `--skip LIST` — comma-separated control names
- `--install-missing` — allow package installs
- `--backup-dir PATH` — default `/root/hardening-backup-$(date +%Y%m%d-%H%M%S)`
- `--no-restart` — apply config but do not restart sshd/auditd
- `--container-host` — force container-runtime exceptions on
- `--no-container-exceptions` — apply strict values even when a container runtime is detected
- `--force-ipv6-off` — disable IPv6 even when IPv6-enabled container networks exist
- `--tmout N` — idle timeout seconds, default 900
- `--block-usb` — include `usb-storage` in the module blacklist
- `--force-root-login-no` — set `PermitRootLogin no` even when the lockout guard trips
- `-h|--help`, `--version`

Reporting helpers, all writing to stderr except the final summary:

```
log_pass "<control>" "<detail>"     # already compliant
log_change "<control>" "<detail>"   # would change / did change
log_skip "<control>" "<reason>"
log_warn "<control>" "<detail>"     # needs operator action
log_fail "<control>" "<detail>"     # error; increments EXIT_FAIL
die "<msg>"
```

Each increments a counter; the script ends with `Summary: N pass, N changed, N skipped, N warn, N fail` and exits `0` when no fails, `1` when any fail, `2` on usage error.

Mutation is funneled through exactly three primitives so dry-run and backup logic exist in one place:

- `write_file <path> <mode> <<'EOF' ... EOF` — compares against existing content; PASS if identical, else backup + write (or print a unified `diff` in dry-run).
- `set_kv <path> <key> <value> <separator>` — idempotent key/value edit for `login.defs`-style files: replaces the first uncommented `^\s*key\s*sep` line, else appends `key sep value`.
- `run_cmd <cmd...>` — echoes in dry-run, executes under `--apply`.

`write_file` and `set_kv` copy the original to `$BACKUP_DIR/<path with / replaced by _>` before the first modification and append a restore line to `$BACKUP_DIR/revert.sh`.

Require root for `--apply` (`[[ $EUID -eq 0 ]]`), allow non-root dry-run so the report can be generated unprivileged.

### 2. Distro detection

`detect_distro()` sources `/etc/os-release` in a subshell and sets globals:

- `DISTRO_ID` — raw `$ID`
- `DISTRO_FAMILY` — `debian` | `rhel` | `suse`, derived from `$ID` then `$ID_LIKE`; unknown IDs `die` with "unsupported distro, use --only to run individual controls".
- `PKG_MGR` — `apt-get` | `dnf` | `yum` | `zypper` | `transactional-update`
- `IS_TRANSACTIONAL` — 1 when `DISTRO_ID` is `opensuse-microos` / contains `microos`, or when `findmnt -no OPTIONS /usr` reports `ro`
- `SSHD_SERVICE` — `sshd` everywhere except Debian/Ubuntu where it is `ssh`
- `SSHD_DROPIN` — `/etc/ssh/sshd_config.d/99-hardening.conf` when `grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config`, else empty (CentOS 7 / older Leap: edit `/etc/ssh/sshd_config` in place via `set_kv`).

### 2b. Container runtime detection

`detect_container_host()` sets `CONTAINER_HOST=1` if **any** of the following holds, and records the matching evidence string in `CONTAINER_EVIDENCE` for log messages:

- `command -v docker || command -v podman || command -v containerd || command -v crio || command -v kubelet || command -v nerdctl` succeeds
- any of `docker.service`, `containerd.service`, `podman.socket`, `crio.service`, `kubelet.service` is enabled or active (`systemctl is-enabled`/`is-active`, both non-fatal)
- a runtime state directory exists: `/var/lib/docker`, `/var/lib/containers`, `/var/lib/containerd`, `/etc/cni/net.d`, `/var/lib/kubelet`
- an interface named `docker0`, `cni0`, `flannel.*`, `cali*`, `podman*`, or `br-*` exists (`ip -o link show`)
- `/etc/subuid` contains a non-root entry **and** `podman` is present (rootless podman)

Also set `IN_CONTAINER=1` when the script is itself running inside a container (`/.dockerenv` exists, or `/proc/1/cgroup` mentions `docker`/`libpod`, or `systemd-detect-virt -c` succeeds). `IN_CONTAINER=1` makes every sysctl and module control `log_skip` with "running inside a container; kernel settings belong to the host" instead of attempting writes that cannot succeed — except that `--dry-run` still prints what it would do, which is what the container verification matrix relies on.

### 3. `ctl_tmout` — shell idle timeout

`write_file /etc/profile.d/99-hardening.sh 0644` containing a `readonly TMOUT=900; export TMOUT` guarded so it does not break non-interactive shells (`[[ $- == *i* ]]` check) and does not error if TMOUT is already readonly. Also `set_kv /etc/profile.d/99-hardening.sh`-independent: add `readonly HISTSIZE`/`HISTFILESIZE`? No — out of scope, timeout only.

Timeout value is a script constant `TMOUT_SECONDS=900`, overridable with `--tmout N`.

### 4. `ctl_banner` — login and SSH banners

Built-in default text (heredoc constant `DEFAULT_BANNER`):

```
********************************************************************
*                        AUTHORIZED ACCESS ONLY                    *
* This system is restricted to authorized users. All activity is   *
* monitored and logged. Unauthorized access is prohibited and may  *
* result in disciplinary action and/or civil and criminal          *
* penalties. Disconnect immediately if you are not an authorized   *
* user.                                                            *
********************************************************************
```

`--banner-file PATH` replaces it; `die` if the path is unreadable. Write the text to `/etc/issue`, `/etc/issue.net`, and `/etc/motd` (mode 0644). Set `Banner /etc/issue.net` via the sshd drop-in (step 5) — the banner control only owns the files.

Note: many distros regenerate `/etc/motd` dynamically (Ubuntu's `update-motd.d`). Leave `update-motd.d` alone; static `/etc/motd` is additive there.

### 5. `ctl_sshd` — SSH daemon hardening

Directive set (exact values):

```
Banner /etc/issue.net
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0
X11Forwarding no
IgnoreRhosts yes
HostbasedAuthentication no
AllowTcpForwarding no
LogLevel VERBOSE
```

`PasswordAuthentication` is deliberately **not** set — disabling it on a host with no authorized keys is a lockout. Instead: if `PasswordAuthentication` is effectively `yes`, emit `log_warn` recommending key-based auth.

**Lockout guard, mandatory before writing:** if the current session is over SSH (`[[ -n ${SSH_CONNECTION:-} ]]`) and the effective user is root and no non-root account has an entry in `~/.ssh/authorized_keys`, `PermitRootLogin no` will lock the operator out. In that case skip the `PermitRootLogin` directive, `log_warn` with the reason, and continue with the rest. `--force-root-login-no` overrides.

Write via `write_file "$SSHD_DROPIN" 0600` when `SSHD_DROPIN` is set, else `set_kv /etc/ssh/sshd_config <key> <value> ' '` per directive.

Validate before restarting: `run_cmd sshd -t` (or `/usr/sbin/sshd -t`). If validation fails under `--apply`, restore from backup, `log_fail`, and do not restart. On success and unless `--no-restart`: `run_cmd systemctl reload "$SSHD_SERVICE"` (reload, not restart — keeps existing sessions alive).

### 6. `ctl_ipv6` — disable IPv6

Skipped entirely when `--keep-ipv6`. Adds to the sysctl drop-in (step 7's file, written once at the end of both controls — see note below):

```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

`log_warn` if `ss -lntH` shows services bound only to `::` (they will lose their listener), listing them.

**File-ownership note:** `ctl_ipv6` and `ctl_sysctl` both target `/etc/sysctl.d/99-hardening.conf`. Implement both as functions that append lines to a shell array `SYSCTL_LINES`, and have a single `flush_sysctl()` — called after all controls run — do one `write_file` plus `run_cmd sysctl --system`. This keeps the file idempotent when `--only` selects just one of them (the unselected control's lines are simply absent, which is correct).

**Container exception:** if `CONTAINER_HOST=1`, check for IPv6-enabled container networking before writing — `docker network ls --format '{{.Name}}' | xargs -r -n1 docker network inspect -f '{{.EnableIPv6}}'` reporting any `true`, or `"ipv6": true` in `/etc/docker/daemon.json`, or a `podman network inspect` reporting an IPv6 subnet. If any is found, skip the whole control with `log_warn "ipv6" "container networks use IPv6; skipped. Re-run with --force-ipv6-off after migrating them."`. Otherwise proceed and `log_warn` that Docker will log "IPv6 forwarding is disabled" until `ip6tables`/IPv6 is disabled in the daemon config too. `--force-ipv6-off` overrides the skip.

### 7. `ctl_sysctl` — kernel network hardening

Appends to `SYSCTL_LINES`:

```
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
```

**Container exceptions in this control** (all skipped lines are reported, each with `log_skip "sysctl" "<key> skipped: container runtime detected (<evidence>)"`):

- `net.ipv4.ip_forward = 0` — omitted entirely when `CONTAINER_HOST=1`. Docker and Podman set `ip_forward=1` at daemon start; a `sysctl.d` file forcing `0` wins on the next boot and silently kills all container egress and inter-container routing.
- `net.ipv4.conf.all.rp_filter` / `.default.rp_filter` — written as `2` (loose reverse-path) instead of `1` (strict) when `CONTAINER_HOST=1`. Strict mode drops asymmetrically routed packets on multi-homed CNI setups (Calico, Flannel) and on rootless Podman's `pasta`/`slirp4netns` paths. Loose mode keeps the anti-spoofing benefit without the breakage.
- `net.ipv4.conf.all.send_redirects` / `.default.send_redirects` — kept at `0`; harmless for bridged container networking, no exception needed.
- Never written at all, on any host: `net.bridge.bridge-nf-call-iptables`, `net.bridge.bridge-nf-call-ip6tables`, `kernel.unprivileged_userns_clone`, `user.max_user_namespaces`, `kernel.unprivileged_bpf_disabled`. These appear in CIS-style baselines but disabling them breaks Kubernetes iptables/nftables service routing and rootless Podman respectively. Nothing in this script touches them; do not add them.

When `--no-container-exceptions` is passed, the strict values (`ip_forward = 0`, `rp_filter = 1`) are written unconditionally.

### 8. `ctl_password` — login and password policy

`set_kv /etc/login.defs` with space separator:

```
PASS_MAX_DAYS 365
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
UMASK 027
```

`set_kv /etc/security/pwquality.conf` with `= ` separator (file exists on all four families via libpwquality; if absent, `log_skip`):

```
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
```

`set_kv /etc/security/faillock.conf` when the file exists:

```
deny = 5
unlock_time = 900
fail_interval = 900
```

Then the wiring check described in Key design decisions: `grep -rq pam_faillock /etc/pam.d/` (or `pam_tally2` on older systems) — if absent, `log_warn` with the distro-native command (`authselect enable-feature with-faillock` on RHEL, `pam-config -a --faillock` on SUSE, "add `auth required pam_faillock.so preauth` to /etc/pam.d/common-auth" on Debian/Ubuntu). Never edit the stack.

Also set `/etc/default/useradd`'s `INACTIVE=30` via `set_kv` with `=` separator.

### 9. `ctl_fs` — filesystem and module hardening

`write_file /etc/modprobe.d/99-hardening.conf 0644` with `install <mod> /bin/true` + `blacklist <mod>` for: `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`, `udf`, `usb-storage`, `dccp`, `sctp`, `rds`, `tipc`.

`squashfs` is required by snap (Ubuntu) and by MicroOS/immutable images. Guard: skip `squashfs` when `snap` is installed or `IS_TRANSACTIONAL=1`, with `log_skip`. Skip `usb-storage` unless `--block-usb` is given — silently killing USB storage on a laptop is hostile.

**Container exceptions in this control:**

- When `CONTAINER_HOST=1`, also skip `squashfs` — container image tooling (`podman build`, snap-packaged runtimes, some CRI image stores) mounts squashfs layers.
- The blacklist MUST NOT ever contain `overlay`, `overlay2`, `bridge`, `br_netfilter`, `veth`, `nf_nat`, `xt_conntrack`, `ip_tables`, `iptable_nat`, `nf_tables`, or `vxlan`. These are load-bearing for Docker/Podman/Kubernetes networking and storage. The written list is exactly the enumerated one above; treat any addition of these names as a bug.
- `/var/lib/docker`, `/var/lib/containers`, and `/var/lib/kubelet` are never chmod'ed or chown'ed by the permissions block — the runtimes manage their own modes and tightening them corrupts image stores. The permissions block operates only on the explicit paths listed below.

Permissions, applied via `run_cmd chmod`/`chown`, each preceded by a stat comparison so an already-correct file logs PASS:

- `/etc/crontab`, `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/cron.monthly`, `/etc/cron.d` → `root:root`, `0600`/`0700`
- `/etc/passwd` `0644`, `/etc/group` `0644`, `/etc/shadow` `0000` (Debian/SUSE use `0640 root:shadow`; detect existing group ownership and preserve it rather than forcing `0000`), `/etc/gshadow` likewise
- `/boot/grub*/grub.cfg` `0600` when present and not transactional

`/tmp` mount options: only act if `/tmp` is already a separate mount or a `tmp.mount` unit exists. Enabling `systemd`'s `tmp.mount` on a system where `/tmp` lives on `/` is a behavioral change that can lose data at reboot — `log_warn` with the recommendation instead of doing it.

### 10. `ctl_audit` — auditd and core dumps

Core dumps: append `* hard core 0` to `/etc/security/limits.d/99-hardening.conf` (via `write_file`), add `fs.suid_dumpable = 0` (already in step 7), and `write_file /etc/systemd/coredump.conf.d/99-hardening.conf 0644` with `[Coredump]\nStorage=none\nProcessSizeMax=0` when `/etc/systemd` exists.

auditd: if `systemctl list-unit-files` has no `auditd.service`, `log_warn` (or install when `--install-missing`, using `PKG_MGR`; on MicroOS use `transactional-update pkg install audit` and print the reboot notice). If present and disabled: `run_cmd systemctl enable --now auditd`.

Do not write audit rules — a full ruleset is a separate baseline and noisy on desktops. State this in a `ponytail:` comment.

### 11. Main dispatch

`CONTROLS=(tmout banner sshd ipv6 sysctl password fs audit)`. Filter through `--only`/`--skip` (validate names, `die` on unknown). For each, call `ctl_$name`, wrapping in a subshell-free `if ! ctl_$name; then log_fail ...; fi` so one failing control does not abort the run despite `set -e` (use `|| log_fail`). Then `flush_sysctl`, then finalize `revert.sh` (mode 0700, with a `#!/bin/bash` header and `set -e`), then print the summary.

Print the backup dir path and revert command in the summary whenever anything changed.

## Critical files & anchors

- `harden.sh` — the entire deliverable; nothing else is created in the repo.
- `/etc/os-release` — sole distro detection input; `ID`, `ID_LIKE`, `VERSION_ID`.
- `/etc/ssh/sshd_config` — grepped for the `Include` directive to choose drop-in vs in-place; never rewritten wholesale.

## Verification

All commands run from `/home/tejas/Projects/bash-scripts/sysdiag`.

1. **Syntax and lint:** `bash -n harden.sh` and, if available, `shellcheck harden.sh` (expect zero errors; `SC2016`-class informational warnings acceptable).
2. **Dry-run on this host, unprivileged:** `./harden.sh --dry-run`
   Expected observable output: a line per control, distro detected as `arch` → the script `die`s with the unsupported-distro message and exit code `1`. This proves detection and the failure path. Then `./harden.sh --dry-run --only tmout,banner,sysctl` must produce diffs for `/etc/profile.d/99-hardening.sh`, `/etc/issue`, and `/etc/sysctl.d/99-hardening.conf` and exit `0` without touching the filesystem — confirm with `test ! -f /etc/profile.d/99-hardening.sh`.
   *(If `arch` should be supported, add `arch` to the family table — but the request named four families only; unsupported-distro `die` is the specified behavior.)*
3. **Container matrix (primary proof):** for each of `ubuntu:22.04`, `rockylinux:9`, `opensuse/leap:15.6`:
   ```
   podman run --rm -v "$PWD:/mnt:ro" <image> bash -c \
     '/mnt/harden.sh --dry-run && /mnt/harden.sh --apply --no-restart --keep-ipv6 && /mnt/harden.sh --dry-run'
   ```
   Expected: first dry-run reports CHANGE for most controls; apply exits 0; the **second dry-run reports PASS for every control it previously changed** — this is the idempotency proof and the primary acceptance criterion.
   Also assert inside the container after apply: `grep -q 'TMOUT=900' /etc/profile.d/99-hardening.sh`, `grep -q 'AUTHORIZED ACCESS' /etc/issue.net`, `sshd -t` exits 0, and `PASS_MAX_DAYS 365` is present exactly once in `/etc/login.defs`.
   (`docker` substitutes for `podman` if that is what is installed. CentOS 7 and MicroOS have no convenient container image with systemd/sshd — verify those paths by asserting the branch logic with a stubbed `/etc/os-release`: `podman run --rm -v "$PWD:/mnt:ro" ubuntu:22.04 bash -c 'printf "ID=opensuse-microos\n" > /etc/os-release; /mnt/harden.sh --dry-run'` must show SKIP reasons mentioning transactional/read-only, not a crash.)
4. **Revert proof:** in the Ubuntu container, after `--apply`, run `bash /root/hardening-backup-*/revert.sh` then `diff <(cat /etc/login.defs)` against a copy taken before apply — must be identical, and `/etc/profile.d/99-hardening.sh` must be gone.
5. **IPv6 control:** `podman run --rm --privileged -v "$PWD:/mnt:ro" ubuntu:22.04 bash -c '/mnt/harden.sh --apply --only ipv6 --no-restart && sysctl net.ipv6.conf.all.disable_ipv6'` → prints `= 1`. Then the same with `--keep-ipv6` must report SKIP and leave the sysctl file without any `disable_ipv6` line.
6. **Container-host exception proof (required):** on a machine with Docker or Podman installed — this workstation has Podman if step 3 ran — execute `./harden.sh --dry-run --only sysctl,fs 2>&1 | grep -i container`.
   Expected observable output: at least one line stating `ip_forward` was skipped due to a detected container runtime, and the printed `/etc/sysctl.d/99-hardening.conf` diff MUST contain `net.ipv4.conf.all.rp_filter = 2` and MUST NOT contain any `net.ipv4.ip_forward` line. Assert mechanically:
   ```
   ./harden.sh --dry-run --only sysctl --container-host | tee /tmp/h.out
   grep -q 'rp_filter = 2' /tmp/h.out && ! grep -q 'ip_forward' /tmp/h.out
   ```
   Then the inverse: `./harden.sh --dry-run --only sysctl --no-container-exceptions | grep -q 'net.ipv4.ip_forward = 0'` must succeed and `rp_filter = 1` must be present.
7. **Container still works after apply (end-to-end):** on a host with Podman, run `podman run --rm alpine ping -c1 -W3 1.1.1.1` before and after `sudo ./harden.sh --apply --keep-ipv6 --no-restart`. Both must exit `0`. If the post-apply run fails, the exception logic is wrong — do not ship. Revert with `sudo bash /root/hardening-backup-*/revert.sh` and re-check.

## Assumptions & contingencies

- **Bash 4+ is available on all targets.** Associative arrays are used for the distro table. CentOS 7 ships bash 4.2 — fine. If a target with bash 3.x appears (macOS, ancient AIX), replace the associative array with a `case` statement; do not add a dependency.
- **`podman`/`docker` is available for the verification matrix.** If neither is installed, the acceptance criterion falls back to: run the three-image matrix in whatever VM/host access exists, or at minimum complete steps 1, 2, and the stubbed-`os-release` branch checks, and report explicitly that per-distro runtime verification was not performed.
- **Sysctl values are applied with `sysctl --system`.** In an unprivileged container some keys will fail to set; treat a write-failure of a sysctl *key* as `log_warn`, not `log_fail`, so container verification stays clean while a real host still surfaces genuine problems.
