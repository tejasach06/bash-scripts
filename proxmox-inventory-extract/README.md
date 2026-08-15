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
| `-o, --output PATH` | Output CSV path | `/tmp/proxmox-inventory-<ts>.csv` |
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

Matches InventoryMGR's `TEMPLATE_COLUMNS` exactly (35 columns in fixed order):

| Column | Source |
|--------|--------|
| `name` | VM config `name` |
| `external_id` | Proxmox VMID (string) |
| `fqdn` | Guest agent hostname (only if dotted FQDN; else blank) |
| `sr_id` | *(empty — not available from Proxmox)* |
| `platform` | always `proxmox` |
| `datacenter` | *(empty — not available from Proxmox)* |
| `cluster` | `/cluster/status` name or `standalone` |
| `node` | Proxmox node name |
| `status` | `running` / `powered_off` / `unknown` (from Proxmox status) |
| `environment` | *(empty — not available from Proxmox)* |
| `criticality` | *(empty — not available from Proxmox)* |
| `vm_type` | *(empty — not available from Proxmox)* |
| `cpu_cores` | VM config `cores` |
| `memory_mb` | VM config `memory` |
| `disks` | `;`-separated `disk_name:size_GiB:storage_name:storage_type` |
| `storage_name` | *(empty — per-disk storage in `disks` column)* |
| `storage_type` | *(empty — per-disk storage in `disks` column)* |
| `os_family` | Guest agent OS family > `ostype` mapping > `linux` |
| `os_distribution` | Guest agent distribution name |
| `os_version` | Guest agent version |
| `private_ip` | Guest agent IPs starting with `172.` (or unmatched) |
| `public_ip` | Guest agent IPs starting with `202.` |
| `backup_ip` | Guest agent IPs starting with `10.` |
| `owner` | *(empty — not available from Proxmox)* |
| `business_owner` | *(empty — not available from Proxmox)* |
| `technical_owner` | *(empty — not available from Proxmox)* |
| `applications` | *(empty — not available from Proxmox)* |
| `monitoring_enabled` | *(empty — not available from Proxmox)* |
| `pmp_enabled` | *(empty — not available from Proxmox)* |
| `ha_enabled` | *(empty — not available from Proxmox)* |
| `backup_enabled` | *(empty — not available from Proxmox)* |
| `backup_location` | *(empty — not available from Proxmox)* |
| `tags` | Proxmox tags, `;`-joined |
| `last_patch_date` | *(empty — not available from Proxmox)* |
| `last_vuln_scan_date` | *(empty — not available from Proxmox)* |
| `last_verified_at` | *(empty — not available from Proxmox)* |
| `decommission_date` | *(empty — not available from Proxmox)* |
| `security_remarks` | *(empty — not available from Proxmox)* |
| `description` | Proxmox VM config `description` field verbatim |

All 35 InventoryMGR columns are emitted; unused columns are empty strings.

## Disk Format (Updated)

Disks are emitted as `;`-separated entries with **four fields per disk**:

```
disk_name:size_GiB:storage_name:storage_type
```

| Field | Description |
|-------|-------------|
| `disk_name` | `{lv_name}-{config_key}` e.g. `vm-100-disk-0-scsi0` |
| `size_GiB` | Integer size in GiB (from `size=` in Proxmox config) |
| `storage_name` | Storage `vgname` if available; otherwise Proxmox storage ID |
| `storage_type` | Proxmox storage plugin type (e.g., `lvm`, `lvm-thin`, `iscsi`, `rbd`, `dir`) |

**Example:**

```
vm-100-disk-0-scsi0:50:vg01:lvm;vm-100-disk-1-scsi1:100:vg01:lvm;vm-100-disk-2-virtio0:32:vg02:lvm-thin
```

**Key changes from previous version:**
- Per-disk `storage_name` and `storage_type` fields (no longer plugin-prefixed in disk name)
- `vgname` preferred; falls back to Proxmox storage ID
- EFI and TPM disks included (size may be 0 GiB if < 1 GiB)
- CDROM (`media=cdrom`) and `none` entries skipped

## IP Classification

Guest agent IPs are classified by prefix (longest match wins):

| Prefix | Column |
|--------|--------|
| `10.` | `backup_ip` |
| `172.` | `private_ip` |
| `202.` | `public_ip` |
| other | `private_ip` |

Fallback: if guest agent not available, IPs extracted from Proxmox `tags` field via regex.

## FQDN Behavior (Updated)

`fqdn` is populated **only** when the QEMU Guest Agent returns a dotted hostname (contains `.` and not `localhost`). Short hostnames are rejected. If guest agent is unavailable or returns no hostname, `fqdn` is blank.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — all VMs extracted |
| `1` | Fatal error — authentication, node enumeration, or CSV write failed |
| `2` | Partial failure — one or more nodes/VMs skipped (see stderr warnings) |

## Requirements

- **Runs on a Proxmox host** (or machine with API access to port 8006)
- Proxmox VE 7.x / 8.x
- Python 3.11+ (standard library only)
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

## Contract Testing (New)

Validate generated CSV against InventoryMGR's actual parser (requires InventoryMGR origin/main):

```bash
# Generate test CSV
./proxmox-inventory-extract.py --insecure -o /tmp/test-inventory.csv

# Run contract test (requires InventoryMGR backend at origin/main ea6f8b6)
python3 contract_test.py /tmp/test-inventory.csv
```

The contract test:
- Feeds CSV into `parse_csv_bytes` → `normalize_csv_row`
- Fails if any columns are ignored or validation errors occur
- Reports `[PASS]` with row count on success
- See `contract_test.py` for details

**InventoryMGR compatibility:** Tested against `origin/main` commit `ea6f8b6` (2026-08-15). The `csv_import_parsing` module exists only in that branch.

## How It Works

1. **Authenticate** — POST `/api2/json/access/ticket` with username/password
2. **Get cluster status** — `/api2/json/cluster/status` for cluster name
3. **Enumerate nodes** — `/api2/json/nodes` (online only)
4. **Enumerate VMs per node** — `/api2/json/nodes/<node>/qemu`
5. **Get VM config** — `/api2/json/nodes/<node>/qemu/<vmid>/config`
6. **Get storage config** — `/api2/json/nodes/<node>/storage` (for `vgname`/`type`)
7. **Get guest agent info** (if agent enabled):
   - `/api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces`
   - `/api2/json/nodes/<node>/qemu/<vmid>/agent/get-osinfo`
   - `/api2/json/nodes/<node>/qemu/<vmid>/agent/get-hostname`
8. **Parse disks** — extract LV name, size, storage from config keys (`scsi*`, `virtio*`, `sata*`, `ide*`, `efidisk*`, `tpmstate*`)
9. **Build CSV row** — map all fields to InventoryMGR `TEMPLATE_COLUMNS` order
10. **Write CSV** — emit all 35 columns in correct order

## Special Handling

### Disk Parsing

Supported Proxmox config keys: `scsi*`, `virtio*`, `sata*`, `ide*`, `efidisk*`, `tpmstate*`.

Skipped: `none`, `media=cdrom`, entries without parseable `size=`.

LV/volume name extracted from config value (e.g., `vg01:vm-100-disk-0` → `vm-100-disk-0`).

### External ID

`external_id` = Proxmox VMID (string). Matches InventoryMGR's uniqueness constraint: `(platform, external_id)` when non-null.

### OS Detection

Priority: Guest Agent `osinfo` > VM config `ostype` mapping > `linux`.

### Description

Proxmox VM config `description` field copied verbatim to InventoryMGR `description` column.

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
- Single-node (no cluster) returns `standalone`
- Cluster must be configured in Proxmox GUI

**Partial extraction (exit 2)**
- Check stderr for `[warn]` lines indicating skipped nodes/VMs
- Common: offline nodes, VMs without readable config

## File Layout

```
proxmox-inventory-extract/
├── proxmox-inventory-extract.py      # Main extractor
├── test_proxmox_inventory_extract.py # Unit tests (17 tests)
├── contract_test.py                  # Cross-repo contract test
├── conftest.py                       # pytest loader for hyphen-named script
└── README.md                         # This file
```

Run unit tests:
```bash
python3 -m pytest test_proxmox_inventory_extract.py -v
```