# Proxmox Inventory Extract

Extract VM inventory from a Proxmox cluster via REST API and write a CSV compatible with **InventoryMGR's bulk import schema**.

Implemented in high-performance **Rust** with concurrent extraction workers, with a reference **Python 3** implementation included.

## Build (Rust)

Build the optimized release binary using Cargo:

```bash
cargo build --release
```

The compiled binary is written to `target/release/proxmox-inventory-extract`.

Run the test suite and linter:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Quick Start

### Rust Binary

```bash
# Ticket authentication with environment variable
export PVE_PASSWORD="your-root-password"
./target/release/proxmox-inventory-extract -o /tmp/inventory.csv

# Ticket authentication with CLI flag
./target/release/proxmox-inventory-extract -p "your-root-password" -o /tmp/inventory.csv

# API Token authentication with CLI flag
./target/release/proxmox-inventory-extract \
  --api-token "root@pam!inventory=12345678-1234-1234-1234-123456789abc" \
  -o /tmp/inventory.csv

# API Token authentication with environment variable
export PVE_API_TOKEN="root@pam!inventory=12345678-1234-1234-1234-123456789abc"
./target/release/proxmox-inventory-extract -o /tmp/inventory.csv
```

### Python Script

```bash
# On a Proxmox host (needs network access to API on port 8006)
export PVE_PASSWORD="your-root-password"
./proxmox-inventory-extract.py -o /tmp/inventory.csv
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output PATH` | Output CSV path | `/tmp/proxmox-inventory-<ts>.csv` |
| `-H, --host HOST:PORT` | Proxmox API endpoint | `127.0.0.1:8006` |
| `-u, --user USER@REALM` | Proxmox username | `root@pam` |
| `-p, --password PASS` | Password for ticket auth (or use `PVE_PASSWORD` env) | prompts interactively if TTY |
| `--api-token TOKEN` | Proxmox API Token (or use `PVE_API_TOKEN` env) | — |
| `--verify-ssl` | Verify the Proxmox TLS certificate | skipped (Proxmox ships a self-signed cert) |
| `--timeout SECONDS` | Per-request HTTP timeout in seconds | `30` |
| `--no-probe` | Disable reverse DNS and local ARP/DHCP lease lookups | probing enabled |
| `--probe-timeout SECONDS` | Reverse DNS timeout in seconds | `2.0` |
| `--workers N` | Concurrent VM extraction workers | `8` |
| `--quiet` | Suppress the progress line | progress shown on a TTY |
| `-V, --version` | Show version and exit | — |
| `-h, --help` | Show help and exit | — |

## Authentication Precedence

Credentials are automatically resolved according to strict precedence:

1. `--api-token` CLI argument
2. `PVE_API_TOKEN` environment variable
3. `-p, --password` CLI argument
4. `PVE_PASSWORD` environment variable
5. Interactive password prompt (if stdin is a TTY)

## Output CSV Schema

Matches InventoryMGR's `TEMPLATE_COLUMNS` exactly (39 columns in fixed order):
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
| `cpu_cores` | VM config cores x sockets (each defaults to 1) |
| `memory_mb` | VM config `memory` |
| `disks` | `;`-separated `disk_name:size_GiB:storage_name:storage_type` |
| `storage_name` | Sum of all disk sizes (GiB) across `disks` column |
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
| `ha_enabled` | `true` if VM is configured in Proxmox HA (`/cluster/ha/resources`), else `false` |
| `backup_enabled` | `true` if VM is covered by a cluster backup job (`/cluster/backup`), else `false` |
| `backup_location` | Proxmox backup storage target ID if backed up, else empty |
| `tags` | Proxmox tags, `;`-joined |
| `last_patch_date` | *(empty — not available from Proxmox)* |
| `last_vuln_scan_date` | *(empty — not available from Proxmox)* |
| `last_verified_at` | *(empty — not available from Proxmox)* |
| `decommission_date` | *(empty — not available from Proxmox)* |
| `security_remarks` | *(empty — not available from Proxmox)* |
| `description` | Proxmox VM config `description` field verbatim |

All 39 InventoryMGR columns are emitted; unused columns are empty strings.

## Disk Format

Disks are emitted as `;`-separated entries with **four fields per disk**:

```
disk_name:size_GiB:storage_name:storage_type
```

| Field | Description |
|-------|-------------|
| `disk_name` | `{lv_name}-{config_key}` e.g. `vm-100-disk-0-scsi0` |
| `size_GiB` | Integer size in GiB (from `size=` in Proxmox config, sub-GiB non-zero sizes round up to 1 GiB) |
| `storage_name` | Storage `vgname` if available; otherwise Proxmox storage ID |
| `storage_type` | Proxmox storage plugin type (e.g., `lvm`, `lvm-thin`, `zfspool`, `iscsi`, `rbd`, `dir`) |

**Example:**

```
vm-100-disk-0-scsi0:50:vg01:lvm;vm-100-disk-1-scsi1:100:vg01:lvm;vm-100-disk-2-virtio0:32:vg02:lvm-thin
```

- Per-disk `storage_name` and `storage_type` fields
- `vgname` preferred; falls back to Proxmox storage ID
- EFI (`efidisk*`) and TPM (`tpmstate*`) disks included
- CDROM (`media=cdrom`) and `none` entries skipped

## IP Classification

Guest agent IPs are classified by prefix (longest match wins):

| Prefix | Column |
|--------|--------|
| `10.` | `backup_ip` |
| `172.` | `private_ip` |
| `202.` | `public_ip` |
| other | `private_ip` |

Fallback: if guest agent is not available, IPs are extracted from Proxmox `tags` field via regex, or probed via local ARP table and DHCP leases if running on the local Proxmox node.

## FQDN Behavior

`fqdn` is populated **only** when the QEMU Guest Agent returns a dotted hostname (contains `.` and not `localhost`). Short hostnames are rejected. If guest agent is unavailable or returns no dotted hostname, reverse DNS and local DHCP lease hostnames are consulted before falling back to `<name>.<searchdomain>`.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — all VMs extracted |
| `1` | Fatal error — authentication, node enumeration, or CSV write failed |
| `2` | Partial failure — one or more nodes/VMs skipped (see stderr warnings) |

## Requirements

- **Runs on a Proxmox host** (or machine with API access to port 8006)
- Proxmox VE 7.x / 8.x / 9.x
- Rust 1.80+ (for building the Rust binary)
- Python 3.11+ (if running the reference Python script)
- `root@pam` credentials (or user/token with `VM.Audit` + `Datastore.Audit`)

## Examples

### Basic inventory with Rust binary

```bash
export PVE_PASSWORD="secret"
./target/release/proxmox-inventory-extract -o /tmp/inventory.csv
```

### Remote API host with API token

```bash
./target/release/proxmox-inventory-extract \
  -H pve-cluster.example.com:8006 \
  -u admin@pam \
  --api-token "admin@pam!token=a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -o inventory.csv
```

### Daily cron job

```bash
# /etc/cron.daily/proxmox-inventory
#!/bin/bash
export PVE_API_TOKEN="$(cat /etc/pve-inv-token)"
/opt/bin/proxmox-inventory-extract -o /var/log/inventory/proxmox-$(date +%F).csv
```

### Import into InventoryMGR

```bash
# After generating CSV
inventorymgr import /tmp/inventory.csv
```

## Contract Testing

Validate generated CSV against InventoryMGR's actual parser (requires InventoryMGR origin/main):

```bash
# Generate test CSV
./target/release/proxmox-inventory-extract -o /tmp/test-inventory.csv

# Run contract test (requires InventoryMGR backend at origin/main ea6f8b6)
python3 contract_test.py /tmp/test-inventory.csv
```

The contract test:
- Feeds CSV into `parse_csv_bytes` → `normalize_csv_row`
- Fails if any columns are ignored or validation errors occur
- Reports `[PASS]` with row count on success
- See `contract_test.py` for details

## How It Works

1. **Authenticate** — Ticket auth (`POST /api2/json/access/ticket`) or API Token auth (`Authorization: PVEAPIToken=...`)
2. **Get cluster status** — `/api2/json/cluster/status` for cluster name
3. **Enumerate nodes** — `/api2/json/nodes` (online only)
4. **Enumerate backup & HA jobs** — `/api2/json/cluster/backup` and `/api2/json/cluster/ha/resources`
5. **Enumerate QEMU VMs** — `/api2/json/cluster/resources?type=vm` (with fallback to `/api2/json/nodes/<node>/qemu`)
6. **Fetch storage config & volume sizes** — `/api2/json/nodes/<node>/storage` and `/storage/<id>/content?content=images`
7. **Extract VM details in parallel workers**:
   - VM config: `/api2/json/nodes/<node>/qemu/<vmid>/config`
   - Guest agent info: `/agent/info`
   - Guest network interfaces: `/agent/network-get-interfaces`
   - Guest OS info: `/agent/get-osinfo`
   - Guest hostname: `/agent/get-host-name`
8. **Parse disks & calculate storage**: extract LV name, size, storage from config keys (`scsi*`, `virtio*`, `sata*`, `ide*`, `efidisk*`, `tpmstate*`)
9. **Build & sanitize CSV row**: validate data types and blank invalid enum values
10. **Write CSV**: emit all 39 columns in exact RFC 4180 format

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
- Pass `--verify-ssl` only once your Proxmox host has a trusted certificate; by default verification is skipped since Proxmox ships a self-signed cert

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
├── Cargo.toml                        # Rust package manifest
├── src/
│   ├── main.rs                       # Entrypoint
│   ├── lib.rs                        # Library root
│   ├── cli.rs                        # CLI argument parsing & credential resolution
│   ├── client.rs                     # Proxmox REST API client (Ticket & API Token)
│   ├── extractor.rs                  # Concurrent extraction engine & orchestrator
│   ├── model.rs                      # Data models, disk parser & IP classifier
│   ├── probe.rs                      # Local ARP/DHCP lease parser & reverse DNS
│   └── csv.rs                        # Row sanitization & RFC 4180 CSV serializer
├── tests/
│   ├── cli_test.rs                   # CLI & credential resolution tests
│   ├── client_test.rs                # HTTP client & auth tests
│   ├── csv_test.rs                   # CSV serialization & sanitization tests
│   ├── extractor_test.rs             # VM extraction engine tests
│   ├── model_test.rs                 # Parsing & classification tests
│   ├── probe_test.rs                 # Local probe tests
│   └── parity_test.rs                # Live PVE 9.2.10 mock parity test
├── proxmox-inventory-extract.py      # Reference Python extractor
├── test_proxmox_inventory_extract.py # Python unit tests
├── contract_test.py                  # Cross-repo contract test
├── conftest.py                       # pytest loader for hyphen-named script
└── README.md                         # Documentation
```

### Running Tests

```bash
# Rust test suite
cargo test

# Python test suite
python3 -m pytest test_proxmox_inventory_extract.py -v
```