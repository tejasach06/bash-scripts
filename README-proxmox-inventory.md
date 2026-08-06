# proxmox-inventory-extract.py

Extract VM inventory from a Proxmox cluster via REST API and write a CSV
compatible with **InventoryMGR's bulk import schema**.

## Quick Start

```bash
# On a Proxmox host (needs network access to API on port 8006)
export PVE_PASSWORD="your-root-password"
./proxmox-inventory-extract.py --insecure -o /tmp/inventory.csv
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output PATH` | Output CSV path | `/tmp/proxmox-inventory-<ISO-timestamp>.csv` |
| `-H, --host HOST:PORT` | Proxmox API endpoint | `127.0.0.1:8006` |
| `-u, --user USER@REALM` | Proxmox username | `root@pam` |
| `-p, --password PASS` | Password (or use `PVE_PASSWORD` env) | prompts interactively |
| `--insecure` | Disable TLS cert verification | required for self-signed certs |

## Password Precedence

1. `-p` CLI argument
2. `PVE_PASSWORD` environment variable
3. Interactive `getpass` prompt

## Output CSV Schema

Matches InventoryMGR's `ALL_HEADERS` exactly (34 columns). Key columns:

| Column | Source |
|--------|--------|
| `name` | VM config `name` |
| `platform` | always `proxmox` |
| `external_id` | Proxmox VMID (per InventoryMGR schema — `external_id = vmid`) |
| `cluster` | `/cluster/status` name or `standalone` |
| `node` | Proxmox node name |
| `disks` | `scsi0:50#scsi1:100` (disk_name:size_GB, `#`-joined) |
| `status` | `running` / `powered_off` / `suspended` (from Proxmox status) |
| `private_ip` | guest agent IPs starting with `172.` (or others not matching rules) |
| `public_ip` | guest agent IPs starting with `202.` |
| `backup_ip` | guest agent IPs starting with `10.` |
| `tags` | Proxmox tags, `#`-joined |
| `fqdn` | VM `name` |
| `os_family` | `linux` / `windows` / empty (from guest agent or `ostype`) |
| `os_distribution` | guest agent `pretty-name` (e.g. "Ubuntu 22.04 LTS") |
| `os_version` | guest agent `version-id` (e.g. "22.04") |
| `cpu_cores` | VM config `cores` |
| `memory_mb` | VM config `memory` |

## IP Mapping Rules

| IP Prefix | InventoryMGR Column |
|-----------|---------------------|
| `10.*` | `backup_ip` |
| `172.*` | `private_ip` |
| `202.*` | `public_ip` |
| *other* | `private_ip` (safe default) |

Multiple IPs per role are `#`-joined in a single cell.

## Data Sources (Priority)

| Data | Primary | Fallback |
|------|---------|----------|
| Disks | VM config (`scsi*`, `virtio*`, `ide*`, `sata*`, `efidisk*`) | — |
| IPs | Guest agent `/agent/network-get-interfaces` | Scan `tags` for IPv4 regex |
| OS | Guest agent `/agent/get-osinfo` | `ostype` map (l26→linux, win10→windows, etc.) |

## Cron Example

```bash
# /etc/cron.d/proxmox-inventory
0 2 * * * root PVE_PASSWORD="***" /path/to/proxmox-inventory-extract.py --insecure -o /backups/inventory-$(date +\%F).csv
```

## Requirements

- Python 3.8+ (stdlib only: `urllib`, `csv`, `json`, `argparse`, `ssl`, `re`, `datetime`)
- Runs **on a Proxmox host** (or machine with API access to port 8006)
- Guest agent must be enabled in VM config (`agent: enabled=1`) for live IPs/OS info