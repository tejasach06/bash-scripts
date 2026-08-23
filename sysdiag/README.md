# sysdiag

Distro-agnostic, read-only Linux diagnostics and RCA evidence collector.

`sysdiag.sh` provides an interactive menu and non-interactive module runner for common system investigation questions:

- Why did this system reboot/crash?
- Why is this VM/server slow?
- Why is disk/filesystem unhealthy?
- Why is network slow/unreachable?
- Why did a service/container fail?
- Collect a full baseline health report.

The script is designed for mixed Linux estates: Debian/Ubuntu, RHEL/Rocky/Fedora, openSUSE/SLES, Arch, Proxmox, containers, and minimal cloud images. It detects optional tools at runtime and degrades cleanly when they are missing.

## Safety model

Diagnostics remain read-only. The `harden` module is dry-run by default; use `--apply` explicitly to make changes. Apply mode requires root and edits local security configuration only; package upgrades require the separate `--upgrade-packages` opt-in. The `harden` module is excluded from `--all`; running `--all` never mutates system state. The default sudo rule provisions access (`linuxteam ALL=(ALL) NOPASSWD:ALL`); this control provisions access, it does not harden, and it is listed under `--list-controls` for that reason.

Diagnostic modules do not:

- install packages
- edit configs
- restart/stop services
- repair filesystems
- run intrusive SMART tests
- reboot or power off the system

Diagnostic modules write evidence only to the selected output directory. The `harden` module is dry-run by default and mutates system state only when `--apply` is explicitly passed. When `--apply` runs, individual control errors increment the exit code count (`HARDEN_CONTROL_ERRORS`), causing `--apply` to exit with status 1 on command failure, but one control failure does not abort subsequent controls. Dry-run (audit) mode always exits 0; findings are recorded in `hardening-status.tsv` and `summary.json`.
## Requirements

Hard requirements:

- Bash
- common coreutils
- readable `/proc`, `/sys`, and standard log locations where available

Optional tools used when present:

- UI: `dialog`, `whiptail`
- logs: `journalctl`, `coredumpctl`, `dmesg`
- performance: `vmstat`, `mpstat`, `pidstat`, `iostat`, `sar`, `top`
- storage: `smartctl`, `lsblk`, `findmnt`, `lvs`, `vgs`, `pvs`
- virtualization: `systemd-detect-virt`, `virt-what`, `virsh`
- containers: `podman`, `docker`
- network: `ip`, `ss`, `ethtool`, `nstat`, `nft`, `iptables`, `firewall-cmd`, `ufw`, `resolvectl`

Missing optional tools are recorded in the report; they do not fail the run.

## Usage

Interactive menu:

```bash
./sysdiag.sh
```

List modules:

```bash
./sysdiag.sh --list
```

Run one module:

```bash
./sysdiag.sh --run reboot
./sysdiag.sh --run slow
./sysdiag.sh --run disk
./sysdiag.sh --run network
./sysdiag.sh --run service
./sysdiag.sh --run baseline
./sysdiag.sh --run tools

# Review hardening without changing the system
./sysdiag.sh --run harden --out /tmp/sysdiag-hardening-review

# Apply hardening as root (prompts for linuxteam password)
sudo ./sysdiag.sh --run harden --apply

# Also permit package upgrades during apply mode
sudo ./sysdiag.sh --run harden --apply --upgrade-packages
```

Run all diagnostic modules (reboot, slow, disk, network, service, baseline, tools):

```bash
./sysdiag.sh --all
```

Write to a specific output directory:

```bash
./sysdiag.sh --all --out /tmp/sysdiag-case-001
```

Create a tarball bundle at the end:

```bash
./sysdiag.sh --all --package --out /tmp/sysdiag-case-001
```

Show version:

```bash
./sysdiag.sh --version
```

Run self-test:

```bash
./sysdiag.sh --selftest
```

## Output layout

Default output path:

```text
./sysdiag-runs/<hostname>-<timestamp>/
```

Each run contains:

report.md        Human-readable RCA-style report
summary.json     Machine-readable summary and findings
metadata.env     Host, distro, kernel, privilege, virtualization, output metadata
commands.log     Commands executed, exit codes, and durations
findings.tsv     Structured TSV findings file
evidence/*.txt   Raw command output files

With `--package`, the script creates:

```text
<output-dir>.tar.gz
```

## Investigation modules

### `reboot`

Collects current and previous boot evidence:

- `who -b`
- `last -x reboot shutdown`
- `journalctl --list-boots`
- `journalctl -b -1`
- `journalctl -b -1 -k`
- `dmesg -T`
- crash dump paths such as `/var/crash` and `/var/lib/systemd/coredump`

Heuristics detect OOM killer, kernel panic/Oops, watchdog/hung tasks, abrupt previous-boot journal endings, storage errors, and thermal/power hints.

### `slow`

Collects CPU, memory, I/O, and pressure evidence:

- load averages and process snapshots
- `/proc/pressure/*`
- `vmstat`, `mpstat`, `pidstat`, `iostat`, `sar` when present
- memory and swap state
- virtualization detection

Heuristics flag high iowait, memory pressure, swap pressure, and possible hypervisor contention.

### `disk`

Collects filesystem and block-device evidence:

- `df -hT`, `df -ih`
- `lsblk`, `findmnt`, `mount`
- `/proc/mdstat`
- LVM state when tools exist
- kernel storage errors
- non-intrusive `smartctl -H` checks when available

Heuristics flag full filesystems, inode exhaustion, mdraid degradation, I/O errors, and read-only remount patterns.

### `network`

Collects network state:

- addresses and routes
- DNS config
- listening sockets
- link counters
- optional `ethtool` and firewall visibility

Heuristics flag missing default route and interface errors/drops.

### `service`

Collects systemd and container failure evidence:

- failed units
- recent warning/error journal entries
- `podman ps -a` / `podman inspect`
- `docker ps -a` / `docker inspect`

Heuristics flag failed systemd units and OOMKilled containers.

### `baseline`

Collects a broad read-only host baseline: OS, kernel, boot time, CPU, memory, disk, network, services, containers, and recent high-priority logs.

### `tools`

Writes available/missing optional tool inventory to the report evidence directory.

### `harden`

Reviews or applies basic Linux security configuration across 15 control IDs (dry-run by default; excluded from `--all`):

- `tmout`: Shell idle timeout enforcement (`TMOUT=900`)
- `banner`: Login issue banner configuration
- `ipv6`: Disable IPv6 via sysctl and GRUB (opinionated default; edits GRUB configuration)
- `packages`: Refresh package metadata and install core dependencies
- `packages_extra`: Install selected optional hardening packages (guest_agent, fail2ban, logging, firewall)
- `pwquality`: PAM password quality requirements (`minlen=14`)
- `user_sudo`: Dedicated admin account and NOPASSWD sudo access (access provisioning policy, not a hardening control)
- `su_wheel`: Audit PAM restriction for `su` to wheel/sudo group (audit-only check; does not edit PAM)
- `kernel_sysctl`: ASLR and protected hardlink/symlink sysctl settings
- `coredump`: Disable system coredumps via systemd (opinionated default; disables crash dumps read by `reboot` module)
- `auditd`: Audit daemon configuration and CIS rules
- `timesync`: NTP time synchronization checks and chrony service activation
- `journald`: Persistent journald storage configuration and size limits
- `sshd`: SSH daemon security drop-in (`PermitRootLogin no`, `MaxAuthTries 4`)
- `file_scan`: Bounded search for world-writable and unowned files (audit-only check)
## Example report workflow

```bash
./sysdiag.sh --all --package --out /tmp/sysdiag-$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ)
```

Then inspect:

```bash
less /tmp/sysdiag-*/report.md
python3 -m json.tool /tmp/sysdiag-*/summary.json
```

## Verification

Quality gates for this script:

bash -n sysdiag.sh
shellcheck sysdiag.sh
./sysdiag.sh --selftest
python3 -m unittest -v test_sysdiag_harden.py
./container-audit.sh
./sysdiag.sh --list
./sysdiag.sh --version
./sysdiag.sh --run baseline --out /tmp/sysdiag-test-baseline
python3 -m json.tool /tmp/sysdiag-test-baseline/summary.json >/dev/null
