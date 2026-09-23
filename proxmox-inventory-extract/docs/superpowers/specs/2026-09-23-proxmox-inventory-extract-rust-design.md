# Proxmox Inventory Extract: Rust Migration Design Specification

- **Date**: 2026-09-23
- **Status**: Approved
- **Target Repository**: `proxmox-inventory-extract` (in `tejasach06/bash-scripts`)

## 1. Overview & Goals

Migrate `proxmox-inventory-extract.py` (~1,000 lines of Python) to an idiomatic, high-performance, standalone Rust binary. The Rust implementation will reside in the root of `proxmox-inventory-extract` as a Cargo crate (`Cargo.toml` in root, source in `src/`), keeping the existing Python script as a reference and testing oracle.

### Key Goals
1. **1:1 Functional Parity**: Match CLI argument interface, output CSV format (`TEMPLATE_COLUMNS`, 39 columns), parsing rules, exit codes, and operational semantics.
2. **Added Feature**: Support Proxmox API Token authentication (`--api-token` / `PVE_API_TOKEN`) alongside existing password/ticket authentication.
3. **Standalone Single Binary**: Zero external runtime dependencies (no Python interpreter, no OpenSSL C-dev library required; pure Rust TLS via `rustls`).
4. **Performance & Concurrency**: Async I/O fan-out using Tokio and Reqwest with bounded worker semaphore (`--workers`, default 8), pre-warmed node storage caches, and low-latency streaming progress display on stderr.
5. **Robust Error Handling**: Exit codes (0 = all success, 1 = fatal error, 2 = partial failure/warning).

---

## 2. CLI Interface & Configuration (`src/cli.rs`)

Using `clap` with `derive`:

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

### Password & Token Precedence
1. If `--api-token` or `PVE_API_TOKEN` is provided, use API token authentication.
2. Otherwise, if `--password` or `PVE_PASSWORD` is provided, use ticket authentication with that password.
3. Otherwise, if running in an interactive terminal, securely prompt for password with `rpassword`.
4. If no credentials can be obtained, exit with code 1.

---

## 3. Architecture & Components

```
proxmox-inventory-extract/
├── Cargo.toml
├── src/
│   ├── main.rs       # Entrypoint, argument parsing, orchestration, progress display, exit codes
│   ├── cli.rs        # Clap struct definition and credential resolution
│   ├── client.rs     # ProxmoxClient: Reqwest HTTP client, auth (ticket + token), Proxmox API endpoints
│   ├── model.rs      # Data structs, constants, disk record representation, parsing helpers
│   ├── extractor.rs  # Concurrent VM extraction, storage cache pre-warming, ARP/DHCP/DNS probing
│   └── csv.rs        # Row validation, sanitization against schema constraints, CSV generation
├── tests/
│   └── parity_test.rs # Integration and schema conformance tests
└── proxmox-inventory-extract.py # Retained as reference/oracle
```

### 3.1 Proxmox Client (`src/client.rs`)
- Uses `reqwest::Client` with `rustls-tls` and `danger_accept_invalid_certs(!verify_ssl)`.
- **Authentication**:
  - `Ticket`: Sends `POST /api2/json/access/ticket` with username and password. Stores `ticket` and `CSRFPreventionToken`. Injects `Cookie: PVEAuthCookie=<ticket>` and `CSRFPreventionToken: <token>` into all subsequent requests.
  - `ApiToken`: Injects `Authorization: PVEAPIToken=<api_token>` into all requests.
- **API Endpoints**:
  - `/api2/json/cluster/status`: Cluster name or fallback `"standalone"`.
  - `/api2/json/nodes`: Online node list.
  - `/api2/json/cluster/resources?type=vm`: Discovers all QEMU VMs cluster-wide.
  - `/api2/json/nodes/{node}/qemu`: Per-node fallback when cluster resources endpoint is inaccessible.
  - `/api2/json/nodes/{node}/qemu/{vmid}/config`: VM hardware and cloud-init configuration.
  - `/api2/json/nodes/{node}/storage`: Node storage configuration and types.
  - `/api2/json/nodes/{node}/storage/{storage}/content?content=images`: Image volume sizes.
  - `/api2/json/cluster/backup`: Cluster backup schedules and covered pools/VMs.
  - `/api2/json/cluster/ha/resources`: High-availability resources.
  - `/api2/json/nodes/{node}/qemu/{vmid}/agent/{command}`:
    - `network-get-interfaces`: Guest IPs.
    - `get-osinfo`: Guest OS details.
    - `get-host-name`: Guest FQDN.
  - Errors on individual guest-agent calls return warnings and empty results, allowing extraction to continue.

### 3.2 Data Models & Parsing Rules (`src/model.rs`)
- **`DiskRecord`**:
  - Encapsulates `lv_name`, `config_key`, `size_gib`, `storage_name`, `storage_type`.
  - CSV format: `format!("{}-{}:{}:{}:{}", lv_name, config_key, size_gib, storage_name, storage_type)`.
- **Disk Configuration Parser**:
  - Scans keys matching regex `^(?:scsi|virtio|ide|sata|unused|efidisk|tpmstate)\d+$`.
  - Skips empty or CD-ROM drives (`none`, `media=cdrom`).
  - Converts disk sizes with suffix multipliers (K, M, G, T, P) to GiB.
  - Resolves storage type from node storage metadata map.
  - Detects physical disk passthrough (`/dev/...`) and issues a warning without failing.
- **IP Classification**:
  - Rejects non-IPv4, loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and multicast (`224.0.0.0/4`).
  - Classifies into:
    - `private_ip`: RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
    - `backup_ip`: Configured backup network if applicable.
    - `public_ip`: Non-private routable addresses.
- **OS Normalization**:
  - Checks QEMU agent `id` against known Linux distributions (`alpine`, `debian`, `ubuntu`, `centos`, `rhel`, `rocky`, `arch`, `fedora`, `suse`, etc.).
  - Detects Windows keywords.
  - Falls back to QEMU config `ostype` (`l26` -> linux, `win10` -> windows, etc.).
- **Description Parsing**:
  - Extracts key-value pairs formatted as `key: value` on separate lines (e.g. `owner: ...`, `criticality: ...`, `environment: ...`).
  - Cleans remaining lines into the `description` column.

### 3.3 Extraction Workflow & Concurrency (`src/extractor.rs`)
1. **Cache Warming**: Sequentially queries storage configurations and image volume sizes for every unique node discovered in the VM target list. Stores in an immutable `Arc<HashMap<String, NodeStorageCaches>>`.
2. **Local Probes**: If `--no-probe` is not set:
   - Reads `/proc/net/arp` into MAC -> IP address mapping.
   - Reads DHCP lease files (`/var/lib/misc/dnsmasq.leases`, etc.) for IP and hostname mapping.
3. **Parallel VM Extraction**:
   - Spawns tasks up to `--workers` using `tokio::sync::Semaphore`.
   - Each task queries VM config, guest-agent interfaces, OS info, FQDN (with fallback to reverse DNS and search domain), backup coverage, and HA membership.
   - Returns row with original index to preserve deterministic target ordering.
4. **Progress Reporting**:
   - If stderr is a TTY and not `--quiet`, prints `\r[{n}/{total}] vm {vmid} ({elapsed:.1f}s)`.

### 3.4 CSV Formatting & Validation (`src/csv.rs`)
- Exact 39 columns in order:
  `name`, `external_id`, `fqdn`, `sr_id`, `platform`, `datacenter`, `cluster`, `node`, `status`, `environment`, `criticality`, `vm_type`, `cpu_cores`, `memory_mb`, `disks`, `storage_name`, `storage_type`, `os_family`, `os_distribution`, `os_version`, `private_ip`, `public_ip`, `backup_ip`, `owner`, `business_owner`, `technical_owner`, `applications`, `monitoring_enabled`, `pmp_enabled`, `ha_enabled`, `backup_enabled`, `backup_location`, `tags`, `last_patch_date`, `last_vuln_scan_date`, `last_verified_at`, `decommission_date`, `security_remarks`, `description`.
- `sanitize_row`:
  - Enforces enum values for `status`, `environment`, `criticality`, `os_family`, `vm_type`. Blanks invalid values with warning.
  - Validates boolean columns (`monitoring_enabled`, `pmp_enabled`, `ha_enabled`, `backup_enabled`).
  - Validates positive integers for `cpu_cores` and `memory_mb`.
  - Validates ISO dates (`YYYY-MM-DD`).
  - Warns if required columns (`name`, `platform`, `cluster`) are missing.
- Writes CSV with RFC 4180 escaping via `csv::WriterBuilder`.

---

## 4. Verification & Testing

- **Unit Tests**:
  - CLI argument parsing, defaults, env var fallback, API token handling.
  - Disk config parser, size calculations, unit conversions, passthrough disk handling.
  - IP classification logic (private, public, backup).
  - OS normalization (Linux IDs, Windows detection, ostype fallback).
  - Description metadata parsing and remainder cleanup.
  - Row sanitization, enum blanking, and CSV schema conformance.
- **Integration & Build Verification**:
  - `cargo check`, `cargo clippy -- -D warnings`, `cargo test`.
  - Comparison against Python script fixtures and output schema.
