# Filesystem Corruption RCA Log Collector

Collects comprehensive logs for filesystem corruption root cause analysis on Ubuntu 22.04 running on Proxmox. Outputs structured JSON + human-readable reports for easy LLM analysis.

## Quick Start

```bash
# Basic collection (run as root for full access)
sudo ./fs-corruption-rca-collector.py

# Custom output directory
sudo ./fs-corruption-rca-collector.py --output-dir /var/log/rca-collection

# Quiet mode (less console output)
sudo ./fs-corruption-rca-collector.py --quiet
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--output-dir DIR` | Output directory | `/tmp/fs-corruption-rca-<hostname>-<timestamp>` |
| `--quiet`, `-q` | Suppress non-error console output | `false` |
| `--version` | Show version and exit | — |
| `--help` | Show help and exit | — |

## Output Structure

```
fs-corruption-rca-<hostname>-<timestamp>/
├── rca-data.json       # Machine-readable structured data
├── rca-report.txt      # Human-readable summary report
└── fs-corruption-rca-<hostname>-<timestamp>.tar.gz  # Archive of all collected logs
```

## What It Collects

### System Information
- Kernel version, uptime, hardware (via `dmidecode`, `lscpu`, `lsmem`)
- Filesystem layout (`lsblk`, `df -h`, `mount`, `/etc/fstab`)
- Proxmox-specific: `pveversion`, `qm list`, `pvesh get /nodes`

### Kernel & Boot Logs
- `dmesg -T` (full ring buffer with timestamps)
- `journalctl -k -b -1` (previous boot kernel logs)
- `journalctl -k -b 0` (current boot kernel logs)

### Filesystem Logs
- `journalctl -u systemd-fsck*`
- `journalctl -u *-mount*`
- `smartctl -a` for all block devices
- `fsck` logs from `/var/log/fsck/`
- `ext4` / `xfs` / `btrfs` specific diagnostics

### Storage & Proxmox
- `pvesm status`, `pvesm list <storage>`
- `lvs`, `vgs`, `pvs` (LVM)
- `zpool status`, `zfs list` (if ZFS)
- `qm config <vmid>` for all VMs
- Ceph status (if applicable: `ceph -s`, `ceph health detail`)

### Application & System Logs
- Last 5000 lines of `/var/log/syslog`, `/var/log/messages`
- `journalctl -p err..crit --since "7 days ago"`
- `apt` history, `dpkg` logs
- Crash reports from `/var/crash/`

### Network & Security
- `ip addr`, `ip route`, `ss -tulpn`
- `ufw status`, `iptables -L`
- Failed SSH attempts (`journalctl -u ssh --grep="Failed"`)

## Output Formats

### JSON (rca-data.json)
Structured for programmatic analysis:
```json
{
  "metadata": { "hostname": "...", "timestamp": "...", "script_version": "1.0.0" },
  "system": { "kernel": "...", "uptime": "...", "hardware": {...} },
  "filesystems": [ { "device": "/dev/mapper/...", "fstype": "ext4", "mount": "/", "smart": {...} } ],
  "logs": { "dmesg": "...", "journalctl_kernel": "...", "syslog_tail": "..." },
  "proxmox": { "version": "...", "vms": [...], "storages": [...] },
  "analysis_hints": [ "EXT4-fs error on /dev/mapper/pve-root", "I/O error on sda" ]
}
```

### Text Report (rca-report.txt)
Human-readable summary with:
- Executive summary (vulnerability indicators)
- Key findings (filesystem errors, I/O errors, SMART warnings)
- Recommended next steps
- Full log excerpts for top issues

## Use Cases

### Post-crash analysis
```bash
# After unexpected reboot or filesystem corruption
sudo ./fs-corruption-rca-collector.py
# Send archive to colleague or LLM for analysis
scp /tmp/fs-corruption-rca-*.tar.gz analyst@jumpbox:/incoming/
```

### Proactive health check
```bash
# Weekly cron job
0 2 * * 0 root /opt/scripts/fs-corruption-rca-collector.py --output-dir /var/log/rca/weekly-$(date +\%U) --quiet
```

### Proxmox host maintenance
```bash
# Before major upgrades
sudo ./fs-corruption-rca-collector.py --output-dir /root/pre-upgrade-rca-$(date +%F)
```

## Requirements

- **Root access** (for `dmidecode`, `smartctl`, `journalctl`, Proxmox commands)
- Ubuntu 22.04 (tested), likely works on 20.04/24.04, Debian 11/12
- Proxmox VE 7.x/8.x
- Python 3.10+
- Standard tools: `smartmontools`, `dmidecode`, `lvm2`, `pve-*` commands

## Installation

```bash
# Install dependencies
apt update && apt install -y smartmontools dmidecode lvm2 python3

# Copy script
cp fs-corruption-rca-collector.py /usr/local/bin/
chmod +x /usr/local/bin/fs-corruption-rca-collector.py
```

## Analyzing Output with LLMs

The JSON output is designed for LLM consumption:

```bash
# Feed to LLM for analysis
cat rca-data.json | llm "Analyze this filesystem corruption RCA data and identify root cause"
```

Or use the text report directly:
```bash
cat rca-report.txt | llm "Summarize findings and recommend remediation"
```

## Key Analysis Hints (auto-generated)

The script flags common corruption indicators:
- `EXT4-fs error` / `XFS: Corruption` / `BTRFS: error`
- `I/O error` on block devices
- `SMART` attributes: `Reallocated_Sector_Ct`, `Current_Pending_Sector`, `Offline_Uncorrectable`
- `journalctl` filesystem emergency mode entries
- Proxmox VM disk I/O errors (`qm` logs)

## Limitations

- Requires root for full data collection (some commands fail silently without it)
- Proxmox-specific; limited value on bare metal without PVE
- Collects ~50-200MB of logs; archive may be large
- Does not *fix* corruption — only collects evidence for analysis

## License

MIT License — see [LICENSE](../LICENSE) in repo root.