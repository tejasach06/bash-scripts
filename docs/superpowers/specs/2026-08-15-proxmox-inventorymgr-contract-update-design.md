# Proxmox Inventory Extractor — InventoryMGR Contract Update

**Date:** 2026-08-15  
**Status:** design approved  
**Repositories:** `tejasach06/bash-scripts`, `tejasach06/InventoryMGR`

## Purpose

Update `proxmox-inventory-extract.py` so its CSV output is accepted by the current InventoryMGR importer on `origin/main`. InventoryMGR is consulted during development and verification; the deployed extractor remains a standalone, Python-standard-library script with no runtime GitHub or InventoryMGR dependency.

The extractor covers Proxmox QEMU VMs. LXC containers and automatic InventoryMGR upload, preview, or commit are out of scope.

## Compatibility Authority

Before implementation, fetch InventoryMGR `origin/main` and use its current:

- `backend/app/services/csv_import_parsing.py`
- `backend/app/services/csv_import.py`
- `backend/app/api/routes/imports.py`
- VM schema definitions

The implementation must record the exact InventoryMGR commit used for the acceptance test. The design investigation inspected `origin/main` at `ea6f8b6`; implementation must fetch again rather than assume that commit is still current.

The extractor hard-codes the verified contract. It does not fetch schema information at runtime.

## Architecture

The runtime pipeline is:

1. Authenticate with the Proxmox API.
2. Read cluster, node, VM, and storage configuration.
3. For each VM, collect configuration, status, supported guest-agent data, and Proxmox notes.
4. Normalize Proxmox data into an internal VM record.
5. Serialize the record using the verified InventoryMGR CSV contract.
6. Write a UTF-8 CSV with deterministic headers.

Collection and serialization remain separate. Proxmox API functions return structured values and do not decide CSV column order or cell grammar. InventoryMGR serialization performs no API calls.

## Components

### Proxmox API client

Retain ticket authentication and the generic GET helper. The client owns URL construction, authentication headers, TLS verification, and request timeouts. It contains no InventoryMGR mapping rules.

### Storage metadata collector

Query Proxmox cluster storage configuration once and build a map keyed by Proxmox storage ID. Each entry records:

- Proxmox storage ID
- plugin type
- `vgname`, when the backend exposes one

The effective InventoryMGR `storage_name` is `vgname` when available. Otherwise it is the Proxmox storage ID. If storage metadata cannot be fetched, disk config still supplies the storage ID; unavailable plugin type remains blank.

### Structured disk parser

Inspect supported Proxmox disk keys:

- `scsi*`
- `virtio*`
- `sata*`
- `ide*`
- `efidisk*`
- `tpmstate*`

Skip CD-ROM, `none`, and entries without a usable size. For each real disk, return a structured record containing:

- LV or volume name
- Proxmox config key
- size in GiB
- effective storage name
- storage plugin type

The InventoryMGR disk name is:

```text
<LV-or-volume-name>-<Proxmox-config-key>
```

The serialized disk entry uses InventoryMGR's current grammar:

```text
<disk-name>:<size-gib>[:<storage-name>[:<storage-type>]]
```

Example input:

```text
config key: scsi0
value:      vg01:vm-100-disk-0,size=50G
plugin:     lvm
```

Example output:

```text
vm-100-disk-0-scsi0:50:vg01:lvm
```

EFI and TPM disks use their actual config keys, such as `efidisk0` and `tpmstate0`. Multiple disks are joined with semicolons.

Row-level `storage_name` and `storage_type` columns remain blank because each disk carries its own storage details.

### Guest-data collector

Run guest-agent requests only when the VM config enables the agent.

- Fetch network interfaces once and extract non-loopback, non-link-local IPv4 addresses.
- Fetch guest OS information from `get-osinfo`.
- Fetch hostname from the guest-agent hostname endpoint.
- Populate `fqdn` only when the returned hostname is dotted.
- Leave `fqdn` blank for a short hostname or unavailable agent; do not substitute the Proxmox VM name.

Do not infer VLAN, gateway, or hostname from network-interface fields that do not reliably provide those values.

### VM normalizer

Combine config, current status, storage metadata, disk records, guest data, cluster identity, and node identity into one internal VM record. Copy Proxmox VM config `description` verbatim as the normalized description.

### InventoryMGR serializer

Emit columns in the current InventoryMGR template order. Populate only values reliably available from Proxmox. Unsupported fields remain blank, allowing InventoryMGR creation defaults to apply.

The verified header order is:

```text
name,external_id,fqdn,sr_id,platform,datacenter,cluster,node,status,
environment,criticality,vm_type,cpu_cores,memory_mb,disks,storage_name,
storage_type,os_family,os_distribution,os_version,private_ip,public_ip,
backup_ip,owner,business_owner,technical_owner,applications,
monitoring_enabled,pmp_enabled,ha_enabled,backup_enabled,backup_location,
tags,last_patch_date,last_vuln_scan_date,last_verified_at,decommission_date,
security_remarks,description
```

The physical CSV header is one line; wrapping above is for readability only. Implementation must re-check this order against the freshly fetched InventoryMGR revision and update it if `TEMPLATE_COLUMNS` changed.

### CSV writer

Use `csv.DictWriter` with UTF-8 output and deterministic field order. Standard CSV quoting preserves commas, quotes, and newlines in Proxmox notes.

## Field Mapping

| InventoryMGR column | Proxmox source or rule |
|---|---|
| `name` | VM config `name`; fallback `vm-<vmid>` |
| `external_id` | VMID converted to string |
| `platform` | Constant `proxmox` |
| `cluster` | Cluster name; `standalone` when not clustered |
| `node` | Proxmox node name |
| `status` | Current VM status mapping |
| `cpu_cores` | VM config `cores` |
| `memory_mb` | VM config `memory` |
| `disks` | Per-disk format defined above |
| `private_ip` | Existing prefix classification rules |
| `public_ip` | Existing prefix classification rules |
| `backup_ip` | Existing prefix classification rules |
| `fqdn` | Dotted guest-agent hostname only |
| `os_family` | Guest OS data, with Proxmox `ostype` fallback |
| `os_distribution` | Guest-agent OS data when available |
| `os_version` | Guest-agent OS data when available |
| `tags` | Proxmox VM tags only |
| `description` | Proxmox VM config `description`/notes |

Status mapping must use values accepted by current InventoryMGR:

| Proxmox status | InventoryMGR status |
|---|---|
| `running` | `running` |
| `stopped` | `powered_off` |
| Any unsupported state, including `paused` | `unknown` |

Retain the existing IP-prefix classification contract:

| Prefix | Destination column |
|---|---|
| `10.` | `backup_ip` |
| `172.` | `private_ip` |
| `202.` | `public_ip` |
| Other IPv4 | `private_ip` |

The remaining InventoryMGR import columns stay blank, including `vm_type`, `applications`, ownership, environment, criticality, boolean controls, compliance dates, `sr_id`, and row-level storage defaults.

## Proxmox Notes

Proxmox VM notes are exposed as config `description`. Map this value directly to InventoryMGR CSV `description`.

Disk provenance must not overwrite or be appended to this field. Notes are preserved as provided; CSV quoting handles multiline text and delimiters.

## Error Handling

Exit statuses are explicit:

- `0`: complete extraction, including a valid header-only result when the cluster has no VMs
- `1`: fatal failure prevented a usable output
- `2`: partial output was written after skipping a node, VM, or malformed disk

### Fatal failures

Authentication, cluster/node enumeration, and output-write failures terminate with a clear stderr message and non-zero exit status.

### Partial extraction

Failure to enumerate VMs on one node identifies and skips that node while other nodes continue. An individual VM config or status failure identifies the node and VMID, skips that VM, and continues processing. Both cases write the partial CSV and exit with status `2`.

### Optional guest data

Guest-agent failures are non-fatal. Fall back to tag-derived IP addresses. Leave OS details or FQDN blank when they cannot be determined reliably.

### Storage metadata

When storage metadata lookup fails, retain the storage ID parsed from VM disk config, leave unavailable plugin type blank, and warn once per affected storage or node.

### Malformed disks

A malformed disk entry does not suppress the VM row. Skip that disk, emit a warning containing VMID and config key, and exit with status `2` after writing the partial CSV.

### Empty inventory

When no VMs are found, write a header-only CSV and emit a warning.

## Cleanup of Existing Worktree Changes

Rework useful existing changes rather than preserving or discarding them wholesale:

- Consolidate duplicate disk parsing paths into one structured parser.
- Remove disk provenance from `description`.
- Stop adding synthetic `storage:<plugin>:<storage>` tags.
- Remove inaccurate VLAN and gateway extraction.
- Replace network-interface hostname inference with the guest-agent hostname endpoint.
- Fetch guest network interfaces once per VM.
- Remove dead values and comments for fields absent from the current InventoryMGR contract.
- Remove obsolete `lifecycle` assumptions.
- Preserve unrelated user worktree changes and commit only files belonging to this feature.

## Verification

### Unit tests

Tests must cover:

- exact InventoryMGR `origin/main` template header order
- volume/LV plus Proxmox config-key disk naming
- `vgname` preference and storage-ID fallback
- LVM, LVM-thin, iSCSI-backed, file-backed, EFI, and TPM disk cases
- optional per-disk storage fields
- semicolon-separated multiple disks
- multiline and quoted Proxmox notes mapped to `description`
- accepted and unsupported status mappings
- dotted FQDN acceptance and short-hostname rejection
- guest-agent and storage-metadata fallbacks
- malformed disk handling
- partial extraction exit behavior
- existing supported extractor behavior

### Cross-repository contract test

Generate representative CSV using the extractor's real serializer, then process it with InventoryMGR `origin/main`'s actual `normalize_csv_row()` and disk parser inside the InventoryMGR development environment.

Assert that:

- no columns are ignored
- rows produce no validation errors
- required identity fields survive normalization
- disk name, size, VG/storage name, and plugin type parse exactly
- Proxmox notes survive as `description`

The contract test may skip when InventoryMGR is absent, but implementation acceptance requires a successful run against the available `/home/hermes/git/InventoryMGR` checkout after fetching `origin/main`.

## Documentation

Update `proxmox-inventory-extract/README.md` to document:

- the current InventoryMGR header contract
- the new disk grammar and VG fallback
- Proxmox notes mapping
- FQDN behavior
- partial-success exit behavior
- actual CSV import workflow
- the InventoryMGR commit used for compatibility verification

## Implementation Constraint

Use the requested `omniroute-worker` for implementation after the implementation plan is approved.

## Out of Scope

- Runtime GitHub schema discovery
- Runtime InventoryMGR template discovery
- Automatic InventoryMGR API upload, preview, or commit
- InventoryMGR schema changes
- LXC inventory
- Inventing defaults for fields Proxmox cannot determine reliably
- VLAN or gateway inference
