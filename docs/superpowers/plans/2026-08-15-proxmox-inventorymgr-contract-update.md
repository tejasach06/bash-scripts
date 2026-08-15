# Implementation Plan: Proxmox Inventory Extractor — InventoryMGR Contract Update

**Date:** 2026-08-15  
**Spec:** `docs/superpowers/specs/2026-08-15-proxmox-inventorymgr-contract-update-design.md`  
**Target:** `proxmox-inventory-extract/proxmox-inventory-extract.py`  
**Test:** `proxmox-inventory-extract/test_proxmox_inventory_extract.py`

## File Structure

```
bash-scripts/
├── proxmox-inventory-extract/
│   ├── proxmox-inventory-extract.py      # Main extractor (rewrite)
│   ├── test_proxmox_inventory_extract.py # Unit tests (rewrite)
│   ├── conftest.py                       # Test import helper (keep)
│   ├── README.md                         # Documentation (update)
│   └── contract_test.py                  # Cross-repo contract test (new)
├── docs/superpowers/specs/
│   └── 2026-08-15-proxmox-inventorymgr-contract-update-design.md
└── docs/superpowers/plans/
    └── 2026-08-15-proxmox-inventorymgr-contract-update.md (this file)
```

## InventoryMGR Contract (from origin/main ea6f8b6)

**TEMPLATE_COLUMNS (35 columns in order):**
```
name, external_id, fqdn, sr_id, platform, datacenter, cluster, node,
status, environment, criticality, vm_type, cpu_cores, memory_mb, disks,
storage_name, storage_type, os_family, os_distribution, os_version,
private_ip, public_ip, backup_ip, owner, business_owner, technical_owner,
applications, monitoring_enabled, pmp_enabled, ha_enabled, backup_enabled,
backup_location, tags, last_patch_date, last_vuln_scan_date, last_verified_at,
decommission_date, security_remarks, description
```

**Disk format:** `name:size[:storage_name[:storage_type]]` separated by `;`

**IP columns:** `private_ip`, `public_ip`, `backup_ip` — semicolon-separated IPs

**Status enum:** `running`, `powered_off`, `unknown`, `decommissioned`, `archived`, `suspended`, `provisioning`, `migrating`

**Platform aliases:** `proxmox`, `pve` → `proxmox`; `vmware`, `vsphere` → `vmware`

## Tasks

### Task 1: Create contract test helper

**File:** `proxmox-inventory-extract/contract_test.py` (new)

**Purpose:** Validate generated CSV against InventoryMGR's actual parser. Runs inside InventoryMGR dev environment.

```python
#!/usr/bin/env python3
"""
Contract test: feed extractor output into InventoryMGR's normalize_csv_row.

Usage: python3 contract_test.py /path/to/inventory.csv

Requires: InventoryMGR backend available on PYTHONPATH
"""
import sys
import csv
from pathlib import Path

def run_contract_test(csv_path: str) -> int:
    # Add InventoryMGR backend to path
    inv_mgr = Path(__file__).parent.parent.parent / "InventoryMGR" / "backend"
    sys.path.insert(0, str(inv_mgr))
    
    try:
        from app.services.csv_import_parsing import normalize_csv_row, parse_csv_bytes
    except ImportError as e:
        print(f"[SKIP] InventoryMGR not available: {e}", file=sys.stderr)
        return 0
    
    content = Path(csv_path).read_bytes()
    rows, ignored = parse_csv_bytes(content)
    
    if ignored:
        print(f"[FAIL] Ignored columns: {ignored}")
        return 1
    
    all_errors = []
    for i, row in enumerate(rows):
        normalized, errors = normalize_csv_row(row)
        if errors:
            all_errors.extend([f"Row {i+1}: {e['field']}: {e['message']}" for e in errors])
        if normalized is None:
            all_errors.append(f"Row {i+1}: normalization returned None")
    
    if all_errors:
        print("[FAIL] Contract violations:")
        for err in all_errors:
            print(f"  {err}")
        return 1
    
    print(f"[PASS] {len(rows)} row(s) validated against InventoryMGR parser")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 contract_test.py <csv_file>")
        sys.exit(2)
    sys.exit(run_contract_test(sys.argv[1]))
```

### Task 2: Rewrite extractor core — Proxmox API client

**File:** `proxmox-inventory-extract/proxmox-inventory-extract.py`

**Functions to implement/rewrite:**

- `parse_args()` — CLI: `-o`, `-H`, `-u`, `-p`, `--insecure`, `--version`, `--help`
- `get_ticket()` — POST `/api2/json/access/ticket`
- `api_get()` — Generic GET with auth headers and SSL handling
- `get_cluster_name()` — GET `/api2/json/cluster/status`
- `get_nodes()` — GET `/api2/json/nodes`
- `get_vms_for_node()` — GET `/api2/json/nodes/{node}/qemu`
- `get_storage_config()` — GET `/api2/json/nodes/{node}/storage` (NEW: builds storage metadata map)

### Task 3: Rewrite extractor core — Structured disk parser

**Functions:**

- `parse_disk_config(config: dict, storage_meta: dict) -> list[DiskRecord]`

`DiskRecord` (namedtuple or dataclass):
- `lv_name`: volume/LV name from Proxmox config value
- `config_key`: e.g., `scsi0`, `virtio1`, `efidisk0`
- `size_gib`: integer
- `storage_id`: Proxmox storage ID from config
- `storage_name`: effective InventoryMGR storage_name (vgname or storage_id fallback)
- `storage_type`: Proxmox plugin type

**Parsing rules:**
- Supported keys: `scsi*`, `virtio*`, `sata*`, `ide*`, `efidisk*`, `tpmstate*`
- Skip: `none`, cdrom (`media=cdrom`), entries without parseable size
- Extract LV/volume name: for LVM/thin, the part before comma (e.g., `vg01:vm-100-disk-0` → `vm-100-disk-0`)
- Disk name for CSV: `{lv_name}-{config_key}` (e.g., `vm-100-disk-0-scsi0`)
- CSV format: `{disk_name}:{size_gib}:{storage_name}:{storage_type}`

### Task 4: Rewrite extractor core — Guest data collector

**Functions:**

- `get_guest_ips(host, node, vmid, ticket, csrf, verify_ssl) -> list[str]`
  - GET `/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`
  - Extract non-loopback, non-link-local IPv4 addresses
  
- `get_guest_os(host, node, vmid, ticket, csrf, verify_ssl) -> dict`
  - GET `/api2/json/nodes/{node}/qemu/{vmid}/agent/get-osinfo`
  - Return: `os_family`, `os_distribution`, `os_version`

- `get_guest_fqdn(host, node, vmid, ticket, csrf, verify_ssl) -> str | None`
  - GET `/api2/json/nodes/{node}/qemu/{vmid}/agent/get-hostname`
  - Return hostname only if dotted; else None

- All guest calls wrapped in try/except; failures are non-fatal warnings

### Task 5: Rewrite extractor core — VM normalizer and serializer

**Functions:**

- `normalize_vm(config, status, node, cluster_name, disks, ips, os_info, fqdn, description, tags) -> dict`
  - Returns internal VM record with all fields

- `serialize_vm(vm_record: dict) -> dict`
  - Maps internal record to InventoryMGR CSV columns in TEMPLATE_COLUMNS order
  - Fields not available from Proxmox → empty string
  - IP classification: existing prefix rules (10.→backup, 172.→private, 202.→public, other→private)
  - Status mapping: running→running, stopped→powered_off, else→unknown
  - Tags: Proxmox tags only, semicolon-joined
  - Description: Proxmox config `description` verbatim
  - Row-level `storage_name`, `storage_type` → empty (per-disk fields carry storage)

### Task 6: Rewrite CSV writer and main pipeline

**Functions:**

- `write_csv(rows: list[dict], output_path: str) -> None`
  - `csv.DictWriter` with TEMPLATE_COLUMNS fieldnames
  - UTF-8, deterministic order

- `extract_vm(vmid, node, client, storage_meta) -> dict | None`
  - Orchestrates per-VM extraction
  - Returns serialized row or None on skip

- `main() -> int`
  - Auth → cluster → nodes → storage_meta → VMs per node
  - Tracks partial failures (node/VM skip → exit 2)
  - Fatal failures → exit 1
  - Success → exit 0

### Task 7: Rewrite unit tests

**File:** `proxmox-inventory-extract/test_proxmox_inventory_extract.py`

**Test cases (all using pytest):**

- CLI parsing (defaults, full args, password precedence)
- Disk parsing: LVM, LVM-thin, iSCSI, file-backed, EFI, TPM, malformed, multiple
- Disk naming: LV+config_key format, semicolon joining, per-disk storage fields
- Storage metadata: vgname preference, storage_id fallback
- IP classification: all prefixes, multiple IPs per role
- FQDN: dotted hostname accepted, short hostname rejected, missing agent blank
- Status mapping: all Proxmox states
- Proxmox notes → description mapping
- Guest-agent fallbacks (IP from tags, OS from ostype)
- Partial extraction exit codes (0, 1, 2)
- Template header order matches TEMPLATE_COLUMNS exactly

### Task 8: Run contract test

**Command:**
```bash
cd /home/hermes/git/bash-scripts/proxmox-inventory-extract
python3 proxmox-inventory-extract.py --insecure -o /tmp/test-inventory.csv
python3 contract_test.py /tmp/test-inventory.csv
```

**Expected:** Exit 0, no ignored columns, no validation errors

### Task 9: Update README.md

**Sections to update:**
- Output CSV Schema table (all 35 columns)
- Disk format examples
- New FQDN behavior
- Proxmox notes → description
- Exit codes
- Contract test instructions
- Record InventoryMGR commit used (ea6f8b6)

## Dependencies

- Python 3.11+ stdlib only (urllib, csv, json, argparse, ssl, dataclasses, typing)
- No third-party packages
- InventoryMGR backend only needed for contract test (optional)

## Acceptance Criteria

1. All unit tests pass
2. Contract test passes against InventoryMGR origin/main (ea6f8b6)
3. Generated CSV has exact TEMPLATE_COLUMNS header order
4. Disk format matches `name:size:storage_name:storage_type` grammar
5. Proxmox notes appear in `description` column
6. FQDN populated only for dotted guest-agent hostname
7. Exit codes: 0 (success), 1 (fatal), 2 (partial)
8. README.md documents all changes
9. Existing worktree changes in other scripts preserved; only extractor files modified

## Commit Strategy

1. `feat: rewrite extractor for InventoryMGR contract`
2. `test: add contract test helper`
3. `test: update unit tests for new contract`
4. `docs: update README for new disk format, FQDN, exit codes`
5. `chore: record InventoryMGR commit ea6f8b6 for compatibility`