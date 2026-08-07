# Proxmox Inventory Extract

Extract VM inventory from a Proxmox cluster via REST API and write a CSV compatible with **InventoryMGR's bulk import schema**.

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
| `--version` | Show version and exit | — |
| `--help` | Show help and exit | — |

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
| `disks` | `scsi0:50;scsi1:100` (disk_name:size_GB, `;`-joined) |
| `status` | `running` / `powered_off` / `suspended` (from Proxmox status) |
| `private_ip` | guest agent IPs starting with `172.` (or others not matching rules) |
| `public_ip` | guest agent IPs starting with `202.` |
| `backup_ip` | guest agent IPs starting with `10.` |
| `tags` | Proxmox tags, `;`-joined |
| `fqdn` | VM `name` |
| `os_family` | `linux` / `windows` / empty (from guest agent or `ostype`) |
| `os_distribution` | guest agent `osinfo.id` or `ostype` |
| `os_version` | guest agent `osinfo.version` or empty |
| `cpu_cores` | VM config `cores` |
| `memory_mb` | VM config `memory` |

All 34 InventoryMGR columns are emitted; unused columns are empty strings.

## Disk Format

Disks are emitted as `;`-separated `disk_name:size_GB` pairs with **plugin-prefixed** names for block storage:

```
lvm:vm-100-disk-0:50;lvm:vm-100-disk-1:100;zfs:vm-100-disk-0:20
```

Format: `storage_plugin:disk_name:size_GB`

## IP Classification

Guest agent IPs are classified by prefix (longest match wins):

| Prefix | Column |
|--------|--------|
| `10.` | `backup_ip` |
| `172.` | `private_ip` |
| `202.` | `public_ip` |
| other | `private_ip` |

## Requirements

- **Runs on a Proxmox host** (or machine with API access to port 8006)
- Proxmox VE 7.x / 8.x
- Python 3.10+ (standard library only)
- `root@pam` credentials (or user with `VM.Audit` + `Datastore.Audit`)

## Examples

### Basic inventory
```bash
export PVE_PASSWORD="secret"
./proxmox-inventory-extract.py --insecure -o /tmp/inventory.csv
```

### Remote API host
```bash
./proxmox-inventory-extract.py -H pve-cluster.example.com:8006 -u admin@pam -p "pass" --insecure -o inventory.csv
```

### Cron job for daily inventory
```bash
# /etc/cron.daily/proxmox-inventory
#!/bin/bash
export PVE_PASSWORD="$(cat /etc/pve-inv-pass)"
/opt/scripts/proxmox-inventory-extract.py --insecure -o /var/log/inventory/proxmox-$(date +%F).csv
```

### Import into InventoryMGR
```bash
# After generating CSV
inventorymgr import /tmp/inventory.csv
```

## How It Works

1. **Authenticate** — POST `/api2/json/access/ticket` with username/password
2. **Get cluster status** — `/api2/json/cluster/status` for cluster name
3. **Enumerate nodes** — `/api2/json/nodes`
4. **Enumerate VMs per node** — `/api2/json/nodes/<node>/qemu`
5. **Get VM config** — `/api2/json/nodes/<node>/qemu/<vmid>/config`
6. **Get VM status** — `/api2/json/nodes/<node>/qemu/<vmid>/status/current`
7. **Get guest agent info** — `/api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces`
8. **Build CSV row** — map all fields to InventoryMGR schema
9. **Write CSV** — emit all 34 columns in correct order

## Special Handling

### Block Storage Disk Names
For LVM/ZFS/Ceph block storage, disk names are prefixed with the storage plugin:
- `lvm:vm-100-disk-0` (not just `vm-100-disk-0`)
- `zfs:vm-100-disk-1`
- `rbd:vm-100-disk-0`

This matches InventoryMGR's import parser which expects `plugin:disk_name`.

### External ID
`external_id` = Proxmox VMID (integer). This is the unique identifier per InventoryMGR's schema uniqueness constraint: `(platform, external_id)` when non-null.

### OS Detection
Priority: Guest Agent `osinfo` > VM config `ostype` mapping > empty.

### Tags
Proxmox tags (from VM config `tags` field) are `;`-joined.

## Troubleshooting

**SSL certificate verification failed**
- Use `--insecure` for self-signed certs (typical on Proxmox)
- Or add CA to system trust store

**Authentication failed**
- Verify username/realm: `root@pam`, `admin@pve`, `user@pam`
- Check user has `VM.Audit` and `Datastore.Audit` permissions

**No guest agent IPs**
- Ensure QEMU Guest Agent is installed and running in VM
- Check `agent: 1` in VM config
- IPs only appear when guest agent is active

**Empty cluster name**
- Single node shows `standalone`
- Cluster name from `/cluster/status` `cluster_name` field

## License

MIT License — see [LICENSE](../LICENSE) in repo root.