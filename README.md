# bash-scripts

Collection of production-ready Bash scripts for system administration, security auditing, and automation.

## Scripts

### ssh-script-executor
**SSH Script Executor** — Execute local scripts on remote hosts via SSH with parallel execution, connection reuse, and CSV/JSON reporting.

```bash
# Single host
./ssh-script-executor.py --host user@server --script ./deploy.sh --args "prod us-east"

# Multiple hosts from file, parallel execution
./ssh-script-executor.py --host-file hosts.txt --script ./setup.sh --parallel 4

# Dry run to preview
./ssh-script-executor.py --host user@server --script ./setup.sh --dry-run

# With CSV output
./ssh-script-executor.py --host-file hosts.txt --script ./check.sh --csv report.csv

# With stdin input
echo "config data" | ./ssh-script-executor.py --host user@server --script ./apply.sh
```

Host file format (one per line):
```
user@host:port [key_file]
host.example.com
user@192.168.1.10 ~/.ssh/id_ed25519
```

**Features:**
- Cross-platform (macOS + Linux)
- Parallel execution with configurable concurrency
- SSH ControlMaster connection reuse for speed
- Script arguments + stdin passthrough
- Dry-run mode for safety
- CSV/JSON output for automation
- Colored output with verbosity levels
- Self-test suite (`--selftest`)

---

### dirtyfrag-scanner
**DirtyFrag/DirtClone CVE Scanner & Mitigator**

Scans for CVE-2026-43284, CVE-2026-43500, CVE-2026-46300, CVE-2026-43503 (DirtyClone/DirtyFrag chain).

```bash
# Scan only (default)
./dirtyfrag/dirtyfrag-scanner.sh

# Verbose scan with custom CSV output
./dirtyfrag/dirtyfrag-scanner.sh --verbose --csv /tmp/report.csv

# Preview mitigation (dry-run, no root needed)
./dirtyfrag/dirtyfrag-scanner.sh --mitigate --dry-run

# Apply mitigations (requires root)
sudo ./dirtyfrag/dirtyfrag-scanner.sh --mitigate --force-reboot
```

**Features:**
- Checks kernel version against per-distro fixed versions (generic fallback: 6.12.0)
- Detects exploit primitives: unprivileged user namespaces, vulnerable modules (esp4/esp6/rxrpc), CAP_NET_ADMIN obtainable
- CSV output: `hostname,ip,kernel,os_name,os_version,vulnerable,mitigation_applied,timestamp`
- Supports: Ubuntu 18.04+, Debian 11/12/13, RHEL/CentOS/Rocky/Alma 9, CloudLinux 9, openSUSE 15.6+, Fedora, Arch, Proxmox VE
- Pure Bash, no external dependencies (awk/lsmod optional)

**Mitigation actions:**
1. Kernel update via package manager
2. Blacklist `esp4`, `esp6`, `rxrpc` modules
3. Disable unprivileged user namespaces (`kernel.unprivileged_userns_clone=0`)
4. Regenerate initramfs + reload sysctl
5. Optional reboot (`--force-reboot`)

---

## Usage

```bash
git clone https://github.com/tejasach06/bash-scripts.git
cd bash-scripts
chmod +x dirtyfrag/dirtyfrag-scanner.sh pmta-log-extract.py ssh-script-executor.py
./dirtyfrag/dirtyfrag-scanner.sh --help
./pmta-log-extract.py --help
./ssh-script-executor.py --help
```

## Requirements
- Bash 4+
- Linux kernel (tested on 5.15+)
- Root for `--mitigate` (not for `--scan` or `--dry-run`)
- Python 3.8+ (for pmta-log-extract.py, ssh-script-executor.py)
- OpenSSH client (for ssh-script-executor.py)
- SSH key or password authentication configured for target hosts

## License
MIT

---

## proxmox-inventory-extract.py

**Proxmox VM Inventory Extractor** — Extract VM inventory from a Proxmox cluster via REST API and write a CSV compatible with InventoryMGR's bulk import schema.

### Quick Start

```bash
# On a Proxmox host (needs network access to API on port 8006)
export PVE_PASSWORD="your-root-password"
./proxmox-inventory-extract.py --insecure -o /tmp/inventory.csv
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output PATH` | Output CSV path | `/tmp/proxmox-inventory-<ISO-timestamp>.csv` |
| `-H, --host HOST:PORT` | Proxmox API endpoint | `127.0.0.1:8006` |
| `-u, --user USER@REALM` | Proxmox username | `root@pam` |
| `-p, --password PASS` | Password (or use `PVE_PASSWORD` env) | prompts interactively |
| `--insecure` | Disable TLS cert verification | required for self-signed certs |

### Password Precedence

1. `-p` CLI argument
2. `PVE_PASSWORD` environment variable
3. Interactive `getpass` prompt

### Output CSV Schema

Matches InventoryMGR's `ALL_HEADERS` exactly (32 columns). Key columns:

| Column | Source |
|--------|--------|
| `name` | VM config `name` |
| `platform` | always `proxmox` |
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

### IP Mapping Rules

| IP Prefix | InventoryMGR Column |
|-----------|---------------------|
| `10.*` | `backup_ip` |
| `172.*` | `private_ip` |
| `202.*` | `public_ip` |
| *other* | `private_ip` (safe default) |

Multiple IPs per role are `#`-joined in a single cell.

### Data Sources (Priority)

| Data | Primary | Fallback |
|------|---------|----------|
| Disks | VM config (`scsi*`, `virtio*`, `ide*`, `sata*`, `efidisk*`) | — |
| IPs | Guest agent `/agent/network-get-interfaces` | Scan `tags` for IPv4 regex |
| OS | Guest agent `/agent/get-osinfo` | `ostype` map (l26→linux, win10→windows, etc.) |

### Cron Example

```bash
# /etc/cron.d/proxmox-inventory
0 2 * * * root PVE_PASSWORD="***" /path/to/proxmox-inventory-extract.py --insecure -o /backups/inventory-$(date +\%F).csv
```

### Requirements

- Python 3.8+ (stdlib only: `urllib`, `csv`, `json`, `argparse`, `ssl`, `re`, `datetime`)
- Runs **on a Proxmox host** (or machine with API access to port 8006)
- Guest agent must be enabled in VM config (`agent: enabled=1`) for live IPs/OS info

### Self-Test

```bash
python3 -m pytest test_proxmox_inventory_extract.py -v
# 38 tests passing
```

---

---

## pmta-log-extract.py

**PMTA Accounting Log Extractor** — Stream-extract records from large PMTA accounting logs (CSV or line-delimited JSON) by sender (`orig`) and/or recipient (`rcpt`), without extracting compressed archives to disk.

### Features
- **Streaming extraction** from plain files, `.gz`, `.bz2`, `.tar.gz`, `.tar.bz2`, `.zip` archives
- **Nested archive support** (directories inside archives, nested `.gz`/`.bz2` members)
- **Magic-byte format detection** (not extension-based)
- **Multi-threaded decompression** via `pigz`/`lbzip2` (auto-detected, falls back to Python stdlib)
- **`grep -a -i -F` prefilter** in the pipeline — Python only parses candidate lines (critical at 300–800 GB scale)
- **Case-insensitive matching** everywhere (patterns, data, domains, `--type` values)
- **Three match modes**: `exact` (full address), `contains` (substring), `domain` (domain + subdomains)
- **Flexible logic**: `--orig` AND/OR `--rcpt`, plus `--any` (matches either field)
- **Auto-discovered output columns** — union of all fields seen in matched records, canonical PMTA fields first
- **Raw passthrough mode** (`--fields '*'`) for lossless line extraction
- **Clean Ctrl+C handling** — terminates children, removes temp files, preserves partial CSV output
- **Corrupt archive resilience** — skips bad members with warnings, continues processing
- **Self-test suite** (`--selftest`) validates all logic on any machine

### Installation
```bash
# Optional: install faster decompressors
sudo apt-get install pigz lbzip2   # Debian/Ubuntu
sudo dnf install pigz lbzip2       # RHEL/Fedora
```

### Usage Examples

```bash
# Exact sender across a dated tree of tar.bz2 archives
./pmta-log-extract.py --path '/data/pmta/*/acct-2026-07*' \
    --orig sender@example.com --out matches.csv

# Recipient list from file, whole domain incl. subdomains
./pmta-log-extract.py --path '/logs/**/*.tar.gz' \
    --rcpt @rcpt_list.txt --match domain --out m.csv

# This sender AND this recipient in the same record, bounces and deliveries only
./pmta-log-extract.py --path '/logs/*.zip' --orig a@x.com --rcpt b@y.com \
    --logic and --type d,b --out m.csv

# Field-agnostic: address/domain anywhere (sender OR recipient)
./pmta-log-extract.py --path '/logs/**/*.tar.bz2' \
    --any hdfcbank.net --match domain --out m.csv

# Lossless raw lines instead of normalized CSV
./pmta-log-extract.py --path '/logs/*' --any user@x.com \
    --fields '*' --out m.txt

# Validate everything on this machine first
./pmta-log-extract.py --selftest
```

### Key Options
| Option | Description |
|--------|-------------|
| `--path GLOB` | Glob of log files/archives (QUOTE IT). Repeatable. `**` recursive supported. |
| `--orig PAT` | Sender pattern(s): `a@x.com,b@y.com` or `@file` (one/line, # comments). Repeatable. |
| `--rcpt PAT` | Recipient pattern(s); same syntax as `--orig`. |
| `--any PAT` | Pattern(s) matched against **orig OR rcpt** (fieldless search). |
| `--match MODE` | `exact` \| `contains` \| `domain` (default: `exact`). Applies to all pattern types. |
| `--logic MODE` | How `--orig` and `--rcpt` combine when both given: `and` \| `or` (default: `or`). |
| `--type TYPES` | Keep only these record types, e.g. `d,b,t,rb` (default: all). |
| `--fields COLS` | Restrict output columns, or `*` for raw passthrough (default: auto-discover all). |
| `--out FILE` | Output file (default: `matches.csv`). |
| `--jobs N` | Parallel file workers (default: CPU cores / 2). |
| `--selftest` | Build tiny test fixtures and verify all matching logic. |

### Notes
- **QUOTE every `--path` glob** so the shell doesn't expand it.
- Matching is **case-insensitive everywhere** (patterns, data, domains, `--type` values).
- Install `pigz` and `lbzip2` for multi-threaded decompression; the script auto-detects them and falls back to `gzip`/`bzip2`, then Python's built-in modules.
- Matches are spooled to a temp file next to `--out` during the scan, then written with the union of all discovered columns; the temp file is removed automatically.
- Corrupt/unreadable archives are skipped with a warning, listed in the end-of-run summary.
- Ctrl+C aborts cleanly: children are terminated, temp files removed, partial results kept in `--out`.

---

## fs-corruption-rca-collector.py

Comprehensive filesystem corruption RCA log collector for Ubuntu 22.04 on Proxmox. Collects 8 categories of diagnostic data and outputs structured JSON + human-readable report + compressed archive.

### Usage
```bash
sudo python3 fs-corruption-rca-collector.py
```

### Outputs
- `rca-data.json` — Structured JSON for programmatic/LLM analysis
- `rca-report.txt` — Human-readable report
- `fs-corruption-rca-<host>-<timestamp>.tar.gz` — Compressed archive

### Prerequisites
```bash
sudo apt update && sudo apt install -y smartmontools nvme-cli xfsprogs btrfs-progs e2fsprogs util-linux systemd zfsutils-linux
```
