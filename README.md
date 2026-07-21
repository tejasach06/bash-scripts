# bash-scripts

Collection of production-ready Bash scripts for system administration, security auditing, and automation.

## Scripts

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
chmod +x dirtyfrag/dirtyfrag-scanner.sh pmta-log-extract.py
./dirtyfrag/dirtyfrag-scanner.sh --help
./pmta-log-extract.py --help
```

## Requirements
- Bash 4+
- Linux kernel (tested on 5.15+)
- Root for `--mitigate` (not for `--scan` or `--dry-run`)
- Python 3.8+ (for pmta-log-extract.py)

## License
MIT

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
