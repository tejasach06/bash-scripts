# Proxmox Inventory Extract Rust Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `proxmox-inventory-extract.py` to an idiomatic, single-binary Rust application with 1:1 behavioral parity, strict CSV schema compliance, and added Proxmox API Token authentication support.

**Architecture:** A modular Rust application using Tokio and Reqwest for async Proxmox API communication, Clap for CLI arguments, and CSV for RFC 4180 output. Storage caches are pre-warmed sequentially across nodes before concurrent per-VM extraction is fanned out using a worker semaphore, preserving deterministic output row ordering.

**Tech Stack:** Rust 2021, Tokio 1.x, Reqwest 0.12 (rustls-tls), Clap 4.5, Serde/Serde_json 1.0, Csv 1.3, Regex 1.10, Chrono 0.4, Rpassword 7.3, Glob 0.3, Dns-lookup 2.0, Gethostname 0.5.

**Spec:** [`docs/superpowers/specs/2026-09-23-proxmox-inventory-extract-rust-design.md`](file:///home/tejas/Projects/bash-scripts/proxmox-inventory-extract/docs/superpowers/specs/2026-09-23-proxmox-inventory-extract-rust-design.md)

## Global Constraints

- Standalone single binary with zero dynamic library dependencies outside libc (pure Rust TLS via rustls; no libssl-dev required).
- Userland only: executable must run as unprivileged user `tejas`.
- Exact 39 columns matching `TEMPLATE_COLUMNS` in strict order.
- Output row order must strictly match target VM discovery order.
- Human-curated columns (`sr_id`, `datacenter`, `environment`, `criticality`, `vm_type`, `public_ip`, `owner`, `business_owner`, `technical_owner`, `applications`, `monitoring_enabled`, `pmp_enabled`, `last_patch_date`, `last_vuln_scan_date`, `last_verified_at`, `decommission_date`, `security_remarks`) must remain empty (`""`).
- `storage_name` column in CSV must store the sum of disk sizes in GiB if disks exist, else `""`.
- Exit codes: 0 = all success, 1 = fatal error (auth / output write failure), 2 = partial failure (warnings / fallback triggered).

## Review Focus

1. **Self-signed TLS Certificates**: Proxmox ships with self-signed certs by default. Requests must accept invalid certificates unless `--verify-ssl` is explicitly passed.
2. **Missing `size=` Parameter in Disk Config**: When VM config line lacks `size=`, the extractor must fall back to the pre-cached volume size from `/nodes/{node}/storage/{storage}/content`, or default to 0 GiB, without crashing.
3. **Physical Disk Passthrough**: Configs with raw disk passthrough (e.g. `/dev/disk/by-id/...`) lack standard `storage:volume` syntax; must emit `[warn] Skipping malformed disk ...` and continue rather than crashing.
4. **Guest Agent Unresponsive/Stopped VMs**: Stopped VMs or VMs with uninstalled/unresponsive guest agents must gracefully fall back to cloud-init IPs, Proxmox tags, local ARP/DHCP lookups, and reverse DNS without failing.
5. **Partial Failures & Cluster Resources Fallback**: If `/api2/json/cluster/resources?type=vm` fails or returns 0 VMs, the extractor must fall back to enumerating `/api2/json/nodes/{node}/qemu` across all online nodes, write the partial inventory, and exit with code 2.

---

### Task 1: Crate Setup, CLI Interface & Credential Resolution

**Files:**
- Create: `Cargo.toml`
- Create: `src/cli.rs`
- Create: `src/lib.rs`
- Test: `tests/cli_test.rs`

**Interfaces:**
- Consumes: Standard CLI args and environment variables (`PVE_PASSWORD`, `PVE_API_TOKEN`).
- Produces: `pub struct Args` with parsed CLI parameters, `pub enum AuthMethod { Ticket { password: String }, ApiToken { token: String } }`, and `pub fn resolve_credentials(args: &Args) -> Result<AuthMethod, String>`.

- [ ] **Step 1: Write the failing test for CLI parsing and credential resolution**

Create `tests/cli_test.rs`:
```rust
use proxmox_inventory_extract::cli::{Args, AuthMethod, resolve_credentials};
use clap::Parser;

#[test]
fn test_cli_defaults() {
    let args = Args::parse_from(["proxmox-inventory-extract", "-p", "secret"]);
    assert_eq!(args.host, "127.0.0.1:8006");
    assert_eq!(args.user, "root@pam");
    assert_eq!(args.password.as_deref(), Some("secret"));
    assert!(!args.verify_ssl);
    assert_eq!(args.timeout, 30);
    assert_eq!(args.workers, 8);
    assert!(!args.no_probe);
    assert_eq!(args.probe_timeout, 2.0);
    assert!(!args.quiet);
    assert!(args.output.is_none());
}

#[test]
fn test_resolve_credentials_precedence() {
    let args_token = Args::parse_from([
        "proxmox-inventory-extract",
        "-p", "mypass",
        "--api-token", "root@pam!token=uuid"
    ]);
    let auth = resolve_credentials(&args_token).unwrap();
    match auth {
        AuthMethod::ApiToken { token } => assert_eq!(token, "root@pam!token=uuid"),
        _ => panic!("Expected ApiToken"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli_test`
Expected: FAIL (crate / module doesn't exist)

- [ ] **Step 3: Create `Cargo.toml`, `src/lib.rs`, and `src/cli.rs`**

Write `Cargo.toml`:
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

Write `src/lib.rs`:
```rust
pub mod cli;
```

Write `src/cli.rs`:
```rust
use clap::Parser;
use std::env;
use std::io::IsTerminal;

pub const API_TIMEOUT: u64 = 30;

#[derive(Parser, Debug, Clone)]
#[command(name = "proxmox-inventory-extract", version = "2026-08-15")]
#[command(about = "Extract Proxmox VM inventory as InventoryMGR-compatible CSV")]
pub struct Args {
    #[arg(short = 'o', long = "output", help = "Output CSV path (default: /tmp/proxmox-inventory-<ts>.csv)")]
    pub output: Option<String>,

    #[arg(short = 'H', long = "host", default_value = "127.0.0.1:8006", help = "Proxmox API endpoint")]
    pub host: String,

    #[arg(short = 'u', long = "user", default_value = "root@pam", help = "Proxmox username")]
    pub user: String,

    #[arg(short = 'p', long = "password", help = "Password (or use PVE_PASSWORD env)")]
    pub password: Option<String>,

    #[arg(long = "api-token", help = "Proxmox API Token (or use PVE_API_TOKEN env)")]
    pub api_token: Option<String>,

    #[arg(long = "verify-ssl", help = "Verify the Proxmox TLS certificate (default: false)")]
    pub verify_ssl: bool,

    #[arg(long = "timeout", default_value_t = API_TIMEOUT, help = "Per-request HTTP timeout in seconds")]
    pub timeout: u64,

    #[arg(long = "no-probe", help = "Disable reverse DNS and local ARP/DHCP lease lookups")]
    pub no_probe: bool,

    #[arg(long = "probe-timeout", default_value_t = 2.0, help = "Reverse DNS timeout in seconds")]
    pub probe_timeout: f64,

    #[arg(long = "workers", default_value_t = 8, help = "Concurrent VM extraction workers")]
    pub workers: usize,

    #[arg(long = "quiet", help = "Suppress the progress line")]
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Ticket { password: String },
    ApiToken { token: String },
}

pub fn resolve_credentials(args: &Args) -> Result<AuthMethod, String> {
    if let Some(token) = &args.api_token {
        if !token.trim().is_empty() {
            return Ok(AuthMethod::ApiToken { token: token.clone() });
        }
    }
    if let Ok(token) = env::var("PVE_API_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(AuthMethod::ApiToken { token });
        }
    }

    if let Some(pass) = &args.password {
        if !pass.is_empty() {
            return Ok(AuthMethod::Ticket { password: pass.clone() });
        }
    }
    if let Ok(pass) = env::var("PVE_PASSWORD") {
        if !pass.is_empty() {
            return Ok(AuthMethod::Ticket { password: pass });
        }
    }

    if std::io::stdin().is_terminal() {
        match rpassword::prompt_password("Proxmox password: ") {
            Ok(pass) if !pass.is_empty() => Ok(AuthMethod::Ticket { password: pass }),
            _ => Err("Password entry was aborted or empty".to_string()),
        }
    } else {
        Err("No password or API token provided and stdin is not interactive".to_string())
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test cli_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs src/cli.rs tests/cli_test.rs
git commit -m "feat(rust): add Cargo.toml and CLI parsing with credential resolution"
```

---

### Task 2: Data Models, Parsing Helpers & Calculation Logic

**Files:**
- Create: `src/model.rs`
- Modify: `src/lib.rs`
- Test: `tests/model_test.rs`

**Interfaces:**
- Consumes: Types from `serde` and `regex`.
- Produces:
  - `pub const TEMPLATE_COLUMNS: [&str; 39]`
  - `pub struct DiskRecord` and `to_csv_field(&self) -> String`
  - `pub fn parse_size_to_gib(size_str: &str) -> u64`
  - `pub fn parse_disk_value(value: &str) -> (String, u64, String, String)`
  - `pub fn parse_disks(config: &serde_json::Map<String, serde_json::Value>, storage_meta: &HashMap<String, StorageMeta>, volume_sizes: &HashMap<String, u64>) -> Vec<DiskRecord>`
  - `pub fn valid_ipv4(value: &str) -> String`
  - `pub fn classify_ips(ips: &[String]) -> HashMap<&'static str, Vec<String>>`
  - `pub fn total_vcpus(config: &serde_json::Map<String, serde_json::Value>) -> String`
  - `pub fn resource_num(resource: &serde_json::Map<String, serde_json::Value>, key: &str, divisor: u64) -> String`
  - `pub fn map_os_family(ostype: &str, guest_os_family: Option<&str>) -> &'static str`
  - `pub fn parse_tags(config: &serde_json::Map<String, serde_json::Value>) -> String`
  - `pub fn backup_coverage(jobs: &[serde_json::Value], vmid: u64, pool: &str) -> (String, String)`

- [ ] **Step 1: Write failing unit tests for model and parsing functions**

Create `tests/model_test.rs` covering:
- `test_parse_size_to_gib`: `50G` -> 50, `100.5G` -> 100, `2.5T` -> 2560, `512M` -> 1, `4M` -> 1, `0` -> 0, invalid -> 0.
- `test_parse_disk_value`: LVM thin, iSCSI, raw paths.
- `test_parse_disks`: key sorting (`efidisk0` before `scsi0`), `scsihw` skipping, passthrough skipping.
- `test_valid_ipv4`: strips CIDR, rejects loopback `127.0.0.1`, link-local, multicast, IPv6.
- `test_classify_ips`: `10.*` -> backup_ip, others -> private_ip, deduplication.
- `test_total_vcpus`: cores * sockets, defaulting missing field to 1 if one present.
- `test_map_os_family`: `l26` -> linux, `win11` -> windows, `solaris` -> `""`.
- `test_backup_coverage`: direct vmid, all with exclude, pool match.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test model_test`
Expected: FAIL (module `model` not found)

- [ ] **Step 3: Implement `src/model.rs`**

Write `src/model.rs` with exact logic matching Python:
- `TEMPLATE_COLUMNS` (39 items).
- `DiskRecord` struct: `lv_name`, `config_key`, `size_gib`, `storage_name`, `storage_type`. `disk_name` = `{lv_name}-{config_key}`. `to_csv_field` = `{disk_name}:{size_gib}:{storage_name}:{storage_type}`.
- `DISK_KEY_RE`: `^(?:scsi|virtio|ide|sata|unused|efidisk|tpmstate)\d+$`.
- `parse_size_to_gib`: handles regex `^(\d+(?:\.\d+)?)([KMGT]?)B?$`.
- `parse_disk_value`: splits by `,`, parses storage:volume, extracts `size=`.
- `parse_disks`: sorts keys, ignores empty/`media=cdrom`/`none`, handles fallback to `volume_sizes`, emits warning on malformed.
- `valid_ipv4`: uses `std::net::Ipv4Addr` to check loopback, link_local, multicast, unspecified.
- `classify_ips`: checks `ip.starts_with("10.")`, deduplicates preserving order.
- `total_vcpus`: parses `cores` and `sockets`. If both None -> `""`. If one present, other defaults to 1.
- `resource_num`: parses numeric value, divides by divisor.
- `map_os_family`: checks `ostype.starts_with('l')` -> `"linux"`, `'w'` -> `"windows"`, other non-empty -> `""`. Guest agent Linux IDs check.
- `parse_tags`: splits by `;`, trims, joins non-empty by `;`.
- `backup_coverage`: checks `enabled != "0"`, matches vmid, all (respecting exclude), or pool.

Register in `src/lib.rs`:
```rust
pub mod cli;
pub mod model;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test model_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/model.rs src/lib.rs tests/model_test.rs
git commit -m "feat(rust): add data models, disk parsing, IP classification, and calculation rules"
```

---

### Task 3: CSV Validation, Row Sanitization & Output Generation

**Files:**
- Create: `src/csv.rs`
- Modify: `src/lib.rs`
- Test: `tests/csv_test.rs`

**Interfaces:**
- Consumes: `HashMap<String, String>` representation of VM row, `model::TEMPLATE_COLUMNS`.
- Produces:
  - `pub fn sanitize_row(row: &mut HashMap<String, String>) -> Vec<String>`
  - `pub fn write_csv(rows: &[HashMap<String, String>], output_path: &str) -> Result<(), std::io::Error>`

- [ ] **Step 1: Write failing unit test for row sanitization and CSV writing**

Create `tests/csv_test.rs`:
```rust
use proxmox_inventory_extract::csv::{sanitize_row, write_csv};
use proxmox_inventory_extract::model::TEMPLATE_COLUMNS;
use std::collections::HashMap;

#[test]
fn test_sanitize_row_invalid_enums_and_types() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS.iter().map(|&c| (c.to_string(), String::new())).collect();
    row.insert("name".to_string(), "vm1".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "c1".to_string());
    row.insert("os_family".to_string(), "bsd".to_string());
    row.insert("last_verified_at".to_string(), "2026-08-27T13:00:00Z".to_string());
    row.insert("cpu_cores".to_string(), "4.0".to_string());

    let warnings = sanitize_row(&mut row);
    assert_eq!(warnings.len(), 3);
    assert_eq!(row["os_family"], "");
    assert_eq!(row["last_verified_at"], "");
    assert_eq!(row["cpu_cores"], "");
    assert_eq!(row["name"], "vm1");
}

#[test]
fn test_write_csv_headers_and_row() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS.iter().map(|&c| (c.to_string(), String::new())).collect();
    row.insert("name".to_string(), "vm100".to_string());
    row.insert("external_id".to_string(), "100".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "c1".to_string());

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();
    write_csv(&[row], path).unwrap();

    let content = std::fs::read_to_string(path).unwrap();
    let mut lines = content.lines();
    assert_eq!(lines.next().unwrap(), TEMPLATE_COLUMNS.join(","));
    assert!(lines.next().unwrap().contains("vm100,100"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test csv_test`
Expected: FAIL (module `csv` not found)

- [ ] **Step 3: Implement `src/csv.rs`**

Write `src/csv.rs`:
- Implements `ENUM_COLUMNS`, `BOOL_COLUMNS`, `INT_COLUMNS`, `DATE_COLUMNS`, `REQUIRED_COLUMNS`.
- `sanitize_row`: checks each column, blanks invalid ones, returns warnings list matching Python strings:
  `"{col} '{val}' not importable, blanked"`
  `"{col} '{val}' not a valid boolean, blanked"`
  `"{col} '{val}' not a valid integer >= 0, blanked"`
  `"{col} '{val}' not a valid ISO date YYYY-MM-DD, blanked"`
  `"{col} is blank; InventoryMGR will reject this row"`
- `write_csv`: runs `sanitize_row`, prints `[warn] VM {id}: {warning}` to `stderr`, writes rows in `TEMPLATE_COLUMNS` order using `csv::WriterBuilder`.

Register in `src/lib.rs`:
```rust
pub mod cli;
pub mod model;
pub mod csv;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test csv_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/csv.rs src/lib.rs tests/csv_test.rs
git commit -m "feat(rust): add row sanitization and RFC 4180 CSV serialization"
```

---

### Task 4: Local Host Probes (ARP Table, DHCP Leases & Reverse DNS)

**Files:**
- Create: `src/probe.rs`
- Modify: `src/lib.rs`
- Test: `tests/probe_test.rs`

**Interfaces:**
- Consumes: Host `/proc/net/arp`, DHCP lease files, and IP addresses for reverse DNS.
- Produces:
  - `pub fn read_arp_table(path: &str) -> HashMap<String, Vec<String>>`
  - `pub fn read_dhcp_leases(globs: &[&str]) -> (HashMap<String, Vec<String>>, HashMap<String, String>)`
  - `pub async fn reverse_dns(ip: &str, timeout_secs: f64) -> String`

- [ ] **Step 1: Write failing unit test for ARP and DHCP lease file parsers**

Create `tests/probe_test.rs`:
```rust
use proxmox_inventory_extract::probe::{read_arp_table, read_dhcp_leases};
use std::io::Write;

#[test]
fn test_read_arp_table() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "IP address       HW type     Flags       HW address            Mask     Device").unwrap();
    writeln!(file, "192.168.1.50     0x1         0x2         AA:BB:CC:DD:EE:FF     *        vmbr0").unwrap();
    writeln!(file, "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        vmbr0").unwrap();

    let res = read_arp_table(file.path().to_str().unwrap());
    assert_eq!(res.get("aa:bb:cc:dd:ee:ff").unwrap(), &vec!["192.168.1.50".to_string()]);
    assert!(!res.contains_key("00:00:00:00:00:00"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test probe_test`
Expected: FAIL

- [ ] **Step 3: Implement `src/probe.rs`**

Write `src/probe.rs`:
- `read_arp_table(path)`: reads file, skips header, skips `flags == "0x0"` and `00:00:00:00:00:00`, normalizes MAC to lowercase, checks `valid_ipv4`.
- `read_dhcp_leases(globs)`: uses `glob::glob` to scan `/var/lib/misc/dnsmasq.*.leases` and `/var/lib/dnsmasq/*.leases`, parses `expiry mac ip hostname clientid`, maps mac -> ips and mac -> hostname (if hostname contains `.` and not `"localhost"`).
- `reverse_dns(ip, timeout_secs)`: spawns `dns_lookup::lookup_addr` on blocking thread with `tokio::time::timeout`. Returns hostname if non-empty, contains `.`, and does not start with `"localhost"`.

Register in `src/lib.rs`:
```rust
pub mod cli;
pub mod model;
pub mod csv;
pub mod probe;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test probe_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/probe.rs src/lib.rs tests/probe_test.rs
git commit -m "feat(rust): add local ARP, DHCP lease, and reverse DNS probes"
```

---

### Task 5: Proxmox HTTP Client & Authentication

**Files:**
- Create: `src/client.rs`
- Modify: `src/lib.rs`
- Test: `tests/client_test.rs`

**Interfaces:**
- Consumes: `cli::AuthMethod`, host, TLS options, and Proxmox REST API endpoints.
- Produces: `pub struct ProxmoxClient` with methods:
  - `pub fn new(host: &str, auth: AuthMethod, verify_ssl: bool, timeout_secs: u64) -> Result<Self, reqwest::Error>`
  - `pub async fn authenticate(&mut self, user: &str) -> Result<(), String>`
  - `pub async fn get_cluster_name(&self) -> Result<String, String>`
  - `pub async fn get_nodes(&self) -> Result<Vec<String>, String>`
  - `pub async fn get_cluster_vms(&self) -> Result<Vec<serde_json::Value>, String>`
  - `pub async fn get_vms_for_node(&self, node: &str) -> Result<Vec<serde_json::Value>, String>`
  - `pub async fn get_vm_config(&self, node: &str, vmid: u64) -> Result<serde_json::Map<String, serde_json::Value>, String>`
  - `pub async fn get_storage_config(&self, node: &str) -> Result<Vec<serde_json::Value>, String>`
  - `pub async fn get_storage_content(&self, node: &str, storage: &str) -> Result<Vec<serde_json::Value>, String>`
  - `pub async fn get_backup_jobs(&self) -> Result<Vec<serde_json::Value>, String>`
  - `pub async fn get_ha_vmids(&self) -> HashSet<u64>`
  - `pub async fn get_agent_info(&self, node: &str, vmid: u64) -> Option<serde_json::Value>`
  - `pub async fn get_guest_ips(&self, node: &str, vmid: u64) -> Vec<String>`
  - `pub async fn get_guest_os(&self, node: &str, vmid: u64) -> HashMap<String, Option<String>>`
  - `pub async fn get_guest_fqdn(&self, node: &str, vmid: u64) -> Option<String>`

- [ ] **Step 1: Write unit tests for ProxmoxClient payload parsing and unwrapping**

Create `tests/client_test.rs`:
- Tests payload unwrapping: `{"data": [...]}` and `{"data": {"result": ...}}`.
- Tests `get_cluster_name` extracting `"type": "cluster"` name or fallback `"standalone"`.
- Tests `get_ha_vmids` parsing `sid: "vm:100"`.
- Tests `get_guest_os` parsing version, version-id, pretty-name, kernel-release combinations.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test client_test`
Expected: FAIL

- [ ] **Step 3: Implement `src/client.rs`**

Write `src/client.rs`:
- Implements `reqwest::Client` builder with `danger_accept_invalid_certs(!verify_ssl)`, cookies, and timeouts.
- Manages ticket + CSRF token or `PVEAPIToken` header.
- Implements all Proxmox endpoints with error logging to `stderr`.

Register in `src/lib.rs`:
```rust
pub mod cli;
pub mod model;
pub mod csv;
pub mod probe;
pub mod client;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test client_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/client.rs src/lib.rs tests/client_test.rs
git commit -m "feat(rust): add ProxmoxClient supporting Ticket and API Token auth"
```

---

### Task 6: Extraction Engine & Application Orchestration

**Files:**
- Create: `src/extractor.rs`
- Create: `src/main.rs`
- Modify: `src/lib.rs`
- Test: `tests/extractor_test.rs`

**Interfaces:**
- Consumes: `ProxmoxClient`, target VMs list, cached storage info, system probes.
- Produces:
  - `pub async fn extract_vm(...) -> Option<HashMap<String, String>>`
  - `pub async fn run_orchestrator(args: Args) -> i32`
  - `main()` binary entrypoint returning process exit code (0, 1, or 2).

- [ ] **Step 1: Write test for extract_vm with mock Proxmox client**

Create `tests/extractor_test.rs`:
- Tests end-to-end VM extraction with running VM, stopped VM, template VM, and agentless VM.
- Asserts deterministic row order.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test extractor_test`
Expected: FAIL

- [ ] **Step 3: Implement `src/extractor.rs` and `src/main.rs`**

Write `src/extractor.rs`:
- `extract_vm`: executes the complete extraction pipeline for one VM (config, disks, guest agent, cloud-init IP fallbacks, tag IPs, local ARP/DHCP lookups, reverse DNS, searchdomain, backup, HA).
- `serialize_vm`: maps internal values to `TEMPLATE_COLUMNS` format.

Write `src/main.rs`:
- Parses args with `Args::parse()`.
- Resolves credentials via `resolve_credentials(&args)`.
- Connects and authenticates `ProxmoxClient`.
- Discovers cluster name, online nodes, backup jobs, and HA resources.
- Checks local hostname against discovered nodes for local probe gating.
- Discovers VMs with fallback from cluster resources to per-node enumeration.
- Pre-warms storage metadata and volume sizes sequentially per unique node.
- Launches parallel extraction bounded by `tokio::sync::Semaphore` with limit `args.workers`.
- Renders progress to `stderr` if interactive and not quiet: `\r[{n}/{total}] vm {vmid} ({elapsed:.1f}s)          `.
- Preserves VM order, checks `sanitize_row`, and writes CSV.
- Prints `[ok] Wrote {n} VM(s) to {output_path}` on stdout.
- Returns exit code 0, 1, or 2.

Register in `src/lib.rs`:
```rust
pub mod cli;
pub mod model;
pub mod csv;
pub mod probe;
pub mod client;
pub mod extractor;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test extractor_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/extractor.rs src/main.rs src/lib.rs tests/extractor_test.rs
git commit -m "feat(rust): implement concurrent VM extraction engine and CLI binary"
```

---

### Task 7: Live PVE Mock Parity & End-to-End Test

**Files:**
- Create: `tests/parity_test.rs`
- Modify: `README.md` (add Rust build/run instructions)

**Interfaces:**
- Consumes: Full mock payload from Proxmox VE 9.2.10 host (192.168.0.5) matching `test_live_pve_host_payload_end_to_end`.
- Produces: Exact CSV matching the 39 columns and exact expected values.

- [ ] **Step 1: Write `tests/parity_test.rs`**

Port the entire `test_live_pve_host_payload_end_to_end` fixture from `test_proxmox_inventory_extract.py`:
- All mock endpoints for `cluster/status`, `nodes`, `cluster/resources?type=vm`, `storage`, `ZPOOL content`, `qemu/101/config`, `agent/info`, `agent/get-osinfo`, `agent/network-get-interfaces`.
- Verify the generated CSV row matches:
  `name`: "work-station"
  `external_id`: "101"
  `cpu_cores`: "6"
  `memory_mb`: "4096"
  `disks`: "vm-101-disk-0-efidisk0:1:ZPOOL:zfspool;vm-101-disk-1-scsi0:500:ZPOOL:zfspool"
  `storage_name`: "501"
  `os_family`: "linux"
  `os_distribution`: "Debian GNU/Linux 13 (trixie)"
  `os_version`: "13 (6.12.101+deb13-amd64)"
  `private_ip`: "192.168.0.17"
  `sanitize_row` warnings: empty.

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test --test parity_test`
Expected: PASS

- [ ] **Step 3: Update `README.md`**

Update `README.md` with:
- `cargo build --release` build instructions.
- Binary usage examples with both ticket auth (`-p` / `PVE_PASSWORD`) and API token auth (`--api-token` / `PVE_API_TOKEN`).
- CLI options table.

- [ ] **Step 4: Run full test suite and clippy**

Run: `cargo test && cargo clippy -- -D warnings`
Expected: 0 errors, 0 warnings, all tests passing.

- [ ] **Step 5: Commit**

```bash
git add tests/parity_test.rs README.md
git commit -m "test(rust): add live PVE 9.2 mock parity test and update README"
```
