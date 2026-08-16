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

Version 1 is read-only.

It does not:

- install packages
- edit configs
- restart/stop services
- repair filesystems
- run intrusive SMART tests
- reboot or power off the system

It writes evidence only to the selected output directory. Remediation is suggested in text only.

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
```

Run all modules:

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

```text
report.md        Human-readable RCA-style report
summary.json     Machine-readable summary and findings
metadata.env     Host, distro, kernel, privilege, virtualization, output metadata
commands.log     Commands executed, exit codes, and durations
evidence/*.txt   Raw command output files
```

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

```bash
bash -n sysdiag.sh
shellcheck sysdiag.sh
./sysdiag.sh --selftest
./sysdiag.sh --list
./sysdiag.sh --version
./sysdiag.sh --run baseline --out /tmp/sysdiag-test-baseline
python3 -m json.tool /tmp/sysdiag-test-baseline/summary.json >/dev/null
```
