# Proxmox Inventory Extract: Rust Migration Design Specification

- **Date**: 2026-09-23
- **Status**: Reviewed & Hardened (Zero-Shortcuts Audit)
- **Target Repository**: `proxmox-inventory-extract` (in `tejasach06/bash-scripts`)

## 1. Overview & Goals

Migrate `proxmox-inventory-extract.py` (~1,000 lines of Python) to an idiomatic, high-performance, standalone Rust binary. The Rust implementation will reside in the root of `proxmox-inventory-extract` as a Cargo crate (`Cargo.toml` in root, source in `src/`), keeping the existing Python script as a reference and testing oracle.

### Key Goals
1. **1:1 Behavioral & Contract Parity**:
   - Exact CLI argument interface, defaults, and exit codes (0 = all success, 1 = fatal error, 2 = partial failure/warning).
   - Strict adherence to `TEMPLATE_COLUMNS` (39 columns) and InventoryMGR schema.
   - Exact warning messages printed to `stderr`.
   - Exact calculation and fallback rules (vCPU, memory, disks, IP classification, FQDN resolution, OS mapping, HA, backups).
2. **Added Feature**:
   - Proxmox API Token authentication (`--api-token` / `PVE_API_TOKEN`) alongside existing password/ticket authentication.
3. **Standalone Single Binary**:
   - Zero external runtime dependencies (no Python, no OpenSSL C-dev library required; pure Rust TLS via `rustls`).
4. **Performance & Concurrency**:
   - Async I/O fan-out using Tokio and Reqwest with bounded worker semaphore (`--workers`, default 8).
   - Sequential pre-warmed node storage caches before fan-out.
   - Low-latency streaming progress display on stderr (gated on terminal interactive mode).
5. **Deterministic Row Ordering**:
   - Output CSV row order strictly matches target VM discovery order.

---

## 2. Dependencies (`Cargo.toml`)

```toml
[package]
name = "proxmox-inventory-extract"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.5", features = ["derive", "env"] }
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "cookies"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
csv = "1.3"
regex = "1.10"
chrono = "0.4"
rpassword = "7.3"
glob = "0.3"
dns-lookup = "2.0"
gethostname = "0.5"

[dev-dependencies]
tempfile = "3.10"
```

---

## 3. CLI Interface & Configuration (`src/cli.rs`)

| Flag | Short | Default | Description |
|---|---|---|---|
| `--output` | `-o` | `/tmp/proxmox-inventory-<YYYYMMDDTHHMMSSZ>.csv` | Destination CSV file path |
| `--host` | `-H` | `127.0.0.1:8006` | Proxmox API endpoint host and port |
| `--user` | `-u` | `root@pam` | Proxmox user name |
| `--password` | `-p` | None | Proxmox password (or `PVE_PASSWORD` env, or interactive prompt) |
| `--api-token` | | None | Proxmox API Token (or `PVE_API_TOKEN` env, format: `USER@REALM!TOKENID=UUID`) |
| `--verify-ssl` | | false | Verify Proxmox TLS certificate (default false, accepting self-signed certs) |
| `--timeout` | | `30` | Per-request HTTP timeout in seconds |
| `--no-probe` | | false | Disable reverse DNS and ARP/DHCP lease table lookups |
| `--probe-timeout`| | `2.0` | Reverse DNS query timeout in seconds |
| `--workers` | | `8` | Max concurrent worker tasks for VM extraction |
| `--quiet` | | false | Suppress live stderr progress line |

### Credential Resolution Precedence
1. If `--api-token` is passed, or `PVE_API_TOKEN` is present in the environment, use API token authentication.
2. Otherwise, if `--password` is passed, or `PVE_PASSWORD` is present in the environment (non-empty), use ticket authentication with that password.
3. Otherwise, if stdin/stderr is an interactive terminal, prompt securely with `rpassword::prompt_password("Proxmox password: ")`.
4. If no credentials can be obtained (e.g. non-interactive with no password/token provided), exit with code 1.

---

## 4. Proxmox API Client (`src/client.rs`)

- Configured with `danger_accept_invalid_certs(!verify_ssl)` and timeout `Duration::from_secs(timeout)`.
- Scheme normalized: if `--host` does not start with `http://` or `https://`, prepend `https://`.
- **Authentication**:
  - `Ticket`: Sends `POST /api2/json/access/ticket` with form data `username` and `password`. Saves `ticket` and `CSRFPreventionToken`. Injects `Cookie: PVEAuthCookie=<ticket>` and `CSRFPreventionToken: <csrf>` on all requests.
  - `ApiToken`: Injects `Authorization: PVEAPIToken=<token>` header on all requests.
- **Unwrapping Payload**:
  - Proxmox API wraps responses in `{"data": ...}`.
  - QEMU guest agent endpoints (`/agent/{cmd}`) wrap results in `{"data": {"result": ...}}` or sometimes bare payloads. The client must unwrap `data` and then unwrap `result` if present.
- **Endpoints**:
  - `GET /api2/json/cluster/status`: If any entry has `"type": "cluster"`, return `name`, else `"standalone"`.
  - `GET /api2/json/nodes`: Filter `status == "online"`.
  - `GET /api2/json/cluster/resources?type=vm`: Filter `id.starts_with("qemu/")`.
  - `GET /api2/json/nodes/{node}/qemu`: Per-node fallback if cluster resources fails or returns 0 VMs.
  - `GET /api2/json/nodes/{node}/qemu/{vmid}/config`: VM config dictionary.
  - `GET /api2/json/nodes/{node}/storage`: Storage list.
  - `GET /api2/json/nodes/{node}/storage/{storage}/content?content=images`: Image content and provisioned sizes.
  - `GET /api2/json/cluster/backup`: Cluster backup jobs list.
  - `GET /api2/json/cluster/ha/resources`: Parse `sid` starting with `"vm:"` into numeric VMIDs set.
  - `GET /api2/json/nodes/{node}/qemu/{vmid}/agent/info`: Agent version check.
  - `GET /api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`: Guest network interfaces.
  - `GET /api2/json/nodes/{node}/qemu/{vmid}/agent/get-osinfo`: Guest OS details (`id`, `pretty-name`, `name`, `version-id`, `version`, `kernel-release`).
  - `GET /api2/json/nodes/{node}/qemu/{vmid}/agent/get-host-name`: Guest hostname (`host-name` or `hostname`).

---

## 5. Domain Rules & Data Processing (`src/model.rs`)

### 5.1 Storage & Disk Parsing
- `StorageMeta`: Map `storage_id -> { storage_id, type, vgname }`.
- `VolumeSizes`: Map `volid -> size_gib` (`size // 1024^3`).
- Supported disk keys: regex `^(?:scsi|virtio|ide|sata|unused|efidisk|tpmstate)\d+$` (skips `scsihw`).
- Keys processed in sorted order.
- Skips empty values, `"none"`, and strings containing `"media=cdrom"`.
- Splits comma-separated values:
  - First part: `storage_id:volume`.
  - Additional parameters: search for `size=...`.
  - Size conversion (`parse_size_to_gib`): Supports units `B`, `K`, `M`, `G`, `T`, `P`. Non-zero values < 1 GiB (e.g. `4M`, `512K`) round up to 1.
  - If no `size=` parameter is present in config, fallback to `volume_sizes.get(volid, 0)`.
  - If `lv_name` is empty or no colon in main part, prints `[warn] Skipping malformed disk {key}={value}` to stderr and skips.
- Storage name in `DiskRecord`: `vgname` if non-empty, else fallback to `storage_id`.
- Disk name: `{lv_name}-{config_key}`. E.g. `vm-100-disk-0-scsi0`.
- Format in CSV `disks` column: `{disk_name}:{size_gib}:{storage_name}:{storage_type}` joined by `;`.
- Format in CSV `storage_name` column: `sum(size_gib for all disks)` if disks exist, else `""`.

### 5.2 IP Address Filtering & Classification
- `valid_ipv4(str)`:
  - Strips `/CIDR` suffix.
  - Rejects loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast (`224.0.0.0/4`), unspecified (`0.0.0.0`), and IPv6.
- Sources precedence:
  1. Guest agent `network-get-interfaces` (only probed if VM `status == "running"` and `agent/info` succeeds).
  2. Cloud-init `ipconfig\d+` keys (sorted by numeric index; parse `ip=`, skip `"dhcp"`).
  3. Proxmox `tags` (regex match IPv4 strings `(?:\d{1,3}\.){3}\d{1,3}`).
  4. Local host probe: If `probe_enabled` and `node == local_node`, match MACs from `net\d+` against `/proc/net/arp` and DHCP leases.
- `classify_ips`:
  - `10.0.0.0/8` -> `backup_ip`
  - Other valid IPv4 -> `private_ip`
  - Deduplicated preserving encounter order. Joined by `;`.
  - `public_ip` remains empty (human-curated).

### 5.3 FQDN Resolution Fallbacks
1. Guest agent `get-host-name`: valid if non-empty, contains `.`, and does not start with `"localhost"`.
2. DHCP leases: If `probe_enabled`, `node == local_node`, check MACs against `lease_hosts` for dotted, non-localhost name.
3. Reverse DNS: If `probe_enabled`, attempt PTR query for `private_ip` then `backup_ip` with timeout `probe_timeout`. Valid if dotted and not starting with `"localhost"`.
4. Searchdomain fallback: If `config.searchdomain` and VM name exist: `{vm_name}.{searchdomain}`.

### 5.4 OS Mapping
- `ostype` from VM config:
  - Starts with `"l"` -> `"linux"`
  - Starts with `"w"` -> `"windows"`
  - Non-empty but doesn't start with `"l"` or `"w"` (e.g. `solaris`, `freebsd`, `other`) -> `""` (unmappable).
- If `ostype` is empty, fallback to guest agent OS ID:
  - In `AGENT_LINUX_IDS` -> `"linux"`
  - Contains `"windows"` or `"mswin"` -> `"windows"`
  - Else `""`.
- `os_distribution`: Guest agent `pretty-name` or `name` or `""`.
- `os_version`: Combined `"{version} ({kernel})"` if both present, else version or kernel.

### 5.5 Backup & HA Coverage
- Backup: Checks `job.enabled != 0`. VM covered if `vmid` in `job.vmid`, or `job.all == 1` and `vmid` not in `job.exclude`, or `job.pool == vm_pool`. If covered: `backup_enabled = "true"`, `backup_location = job.storage`.
- HA: `ha_enabled = "true"` if `resource.hastate` is present or `vmid` in `ha_vmids`, else `"false"`.

### 5.6 Description, Tags & Human-Curated Columns
- `description`: Copied directly from `config.description` without modification.
- `tags`: Semicolon-separated tags from `config.tags`. If `resource.template == "1"`, append `"template"` tag if not already present.
- Human-curated columns stay strictly empty (`""`):
  `sr_id`, `datacenter`, `environment`, `criticality`, `vm_type`, `public_ip`, `owner`, `business_owner`, `technical_owner`, `applications`, `monitoring_enabled`, `pmp_enabled`, `last_patch_date`, `last_vuln_scan_date`, `last_verified_at`, `decommission_date`, `security_remarks`.

---

## 6. Validation & CSV Output (`src/csv.rs`)

### 6.1 `sanitize_row`
Checks each row before writing, blanks invalid values, and emits warnings to `stderr` formatted as:
`[warn] VM {external_id}: {warning}`

Warnings and checks:
1. `ENUM_COLUMNS`:
   - `status`: `{"running", "powered_off", "decommissioned", "unknown"}`
   - `environment`: `{"production", "development", "testing", "uat", "dr", "staging", "sandbox"}`
   - `criticality`: `{"low", "medium", "high", "critical"}`
   - `os_family`: `{"linux", "windows"}`
   - `vm_type`: `{"permanent", "temporary"}`
   - If non-empty and not in set: `{col} '{val}' not importable, blanked`
2. `BOOL_COLUMNS` (`monitoring_enabled`, `pmp_enabled`, `ha_enabled`, `backup_enabled`):
   - Valid: `{"true", "false", "yes", "no", "1", "0"}` (case-insensitive).
   - If invalid: `{col} '{val}' not a valid boolean, blanked`
3. `INT_COLUMNS` (`cpu_cores`, `memory_mb`):
   - Valid: integer `>= 0`.
   - If invalid: `{col} '{val}' not a valid integer >= 0, blanked`
4. `DATE_COLUMNS` (`last_patch_date`, `last_vuln_scan_date`, `last_verified_at`, `decommission_date`):
   - Valid: regex `^\d{4}-\d{2}-\d{2}$`.
   - If invalid: `{col} '{val}' not a valid ISO date YYYY-MM-DD, blanked`
5. `REQUIRED_COLUMNS` (`name`, `platform`, `cluster`):
   - If blank: `{col} is blank; InventoryMGR will reject this row`

### 6.2 CSV Generation
- Exact 39 columns matching `TEMPLATE_COLUMNS`:
  `name,external_id,fqdn,sr_id,platform,datacenter,cluster,node,status,environment,criticality,vm_type,cpu_cores,memory_mb,disks,storage_name,storage_type,os_family,os_distribution,os_version,private_ip,public_ip,backup_ip,owner,business_owner,technical_owner,applications,monitoring_enabled,pmp_enabled,ha_enabled,backup_enabled,backup_location,tags,last_patch_date,last_vuln_scan_date,last_verified_at,decommission_date,security_remarks,description`
- Escapes fields via `csv::WriterBuilder`.

---

## 7. Execution Orchestration (`src/main.rs`)

1. Parse CLI arguments.
2. Resolve credentials.
3. Authenticate against Proxmox host.
4. Fetch cluster name (warn and fallback to `"standalone"` if unavailable, flag `partial_failure = true`).
5. Fetch online nodes.
6. Fetch backup jobs and HA VMIDs (warn on failure, continue).
7. If local host probing enabled:
   - Identify `local_node = gethostname().split('.')[0]`.
   - Parse `/proc/net/arp` and dnsmasq lease files.
8. Discover VMs:
   - Try `get_cluster_vms()`.
   - If fails or returns empty: warn and fallback to per-node `get_vms_for_node(node)`, flag `partial_failure = true`.
9. Sequentially warm storage metadata and image volume sizes for every unique node across target VMs into `Arc<HashMap<String, NodeStorageCaches>>`.
10. Fan-out extraction across worker tasks bounded by `tokio::sync::Semaphore` with limit `--workers`.
11. Update live progress on `stderr` if `!quiet && stderr.is_terminal()`:
    `\r[{n}/{total}] vm {vmid} ({elapsed:.1f}s)          `
12. Collect results into original order. If any VM failed to extract, mark `partial_failure = true`.
13. Write CSV to `--output`.
14. Print `[ok] Wrote {n} VM(s) to {output_path}` on stdout.
15. Exit with 0 (or 2 if `partial_failure`, or 1 if fatal error).

---

## 8. Verification & Test Plan

1. **Unit Test Coverage** (`tests/unit_test.rs` or inline modules):
   - Argument parsing, default values, env var fallback, API token handling.
   - Password resolution & interactive prompt fallback.
   - Disk parsing, size calculations, unit conversions, passthrough disk handling, sorting.
   - IP classification (private RFC 1918, 10/8 backup, deduplication, invalid address rejection).
   - OS mapping (Linux IDs, Windows prefix/keyword detection, ostype fallback).
   - Row sanitization, enum validation, blanking, warning formats.
   - ARP table `/proc/net/arp` and DHCP lease file parsing.
2. **End-to-End Live Mock Fixture Test**:
   - Exact port of `test_live_pve_host_payload_end_to_end` using the real Proxmox VE 9.2.10 payload from 192.168.0.5.
   - Verifies all 39 columns and sanitization match expected outputs.
3. **Parity Comparison Test**:
   - Run both Python script and Rust binary on sample/mock payload and compare output CSV diff.
