# PMTA Log Extract

Stream-extract records from large PowerMTA (PMTA) accounting logs (CSV or line-delimited JSON) by sender (`orig`) and/or recipient (`rcpt`). Supports compressed archives (`.tar.gz`, `.tar.bz2`, `.zip`), glob patterns, substring matching, Cartesian AND for multiple orig/rcpt values, and type filtering.

## Quick Start

```bash
# Extract all records for a sender (CONTAINS match)
./pmta-log-extract.py --orig "example.com" --path "/var/log/pmta/acct-*.csv" --out matches.csv

# Extract for specific recipient
./pmta-log-extract.py --rcpt "user@domain.com" --path "/var/log/pmta/*.csv.gz" --out out.csv

# Cartesian AND: multiple senders AND multiple recipients
# Matches records where orig∈{alerts@,billing@} AND rcpt∈{@company.com,@partner.com}
./pmta-log-extract.py --orig "alerts@,billing@" --rcpt "@company.com,@partner.com" --path logs/ --out filtered.csv

# Field-agnostic: match anywhere (sender or recipient), AND-combined with orig/rcpt
./pmta-log-extract.py --any "example.com" --path logs/ --out filtered.csv
```

## Options

### Input
| Flag | Description |
|------|-------------|
| `--path GLOB` | Input file(s), directory, or glob pattern (required). Repeatable. Supports `*` and recursive `**`. |
| `--format {csv,json,auto}` | Force input format (default: auto-detect by magic bytes) |

### Matching
| Flag | Description |
|------|-------------|
| `--orig PATTERN` | Match sender (orig) field. Case-insensitive. Repeatable. Supports `@file` for pattern files. Multiple values create Cartesian AND with `--rcpt`. |
| `--rcpt PATTERN` | Match recipient (rcpt) field. Case-insensitive. Repeatable. Supports `@file` for pattern files. Multiple values create Cartesian AND with `--orig`. |
| `--any PATTERN` | Match against orig OR rcpt. Same syntax as `--orig`/`--rcpt`. AND-combined with orig/rcpt result. |
| `--type TYPE` | Filter by record type (e.g., `d`, `b`, `t`, `q`). Repeatable. |
| `--fields F[,F...]` | Output fields. Default: auto-discovered union. Use `*` for all. |

### Output
| Flag | Description |
|------|-------------|
| `--output FILE`, `-o` | Output CSV file (default: stdout) |
| `--columns COLS` | Comma-separated output columns (default: auto-discover union) |
| `--no-header` | Suppress CSV header row |
| `--raw` | Raw passthrough mode (no CSV parsing, line-oriented grep) |
| `--pattern REGEX` | Regex pattern for raw mode |

### Processing
| Flag | Description |
|------|-------------|
| `--workers N` | Parallel workers for multi-file (default: CPU count) |
| `--buffer-size BYTES` | Read buffer size (default: 1MB) |
| `--max-files N` | Limit files processed (0 = no limit) |
| `--skip-corrupt` | Skip corrupt archive entries (default: stop on error) |

### Other
| Flag | Description |
|------|-------------|
| `--selftest` | Run internal test suite |
| `--version` | Show version and exit |
| `--help` | Show help and exit |
| `--verbose`, `-v` | Verbose progress |
| `--quiet`, `-q` | Suppress progress |

## Pattern Matching Details

All matching is **case-insensitive substring (CONTAINS)** by default.

```
--orig "example.com"
```
Matches: `user@example.com`, `alerts@sub.example.com`, `myexample@domain.com`

To match a full domain suffix, include the `@` in the pattern:
```
--orig "@example.com"
```
Matches: `user@example.com`, `alerts@sub.example.com`
Does not match: `user@fake-example.com`

For exact address matching, the pattern must match the entire address:
```
--orig "alerts@example.com"
```
Matches only: `alerts@example.com`

### Cartesian AND with Multiple Values

When multiple `--orig` and `--rcpt` values are given, **all combinations are tested** (Cartesian product):

```
--orig "a@x.com,b@x.com" --rcpt "c@y.com,d@y.com"
```
Matches records where:
- orig = a@x.com AND rcpt = c@y.com
- orig = a@x.com AND rcpt = d@y.com
- orig = b@x.com AND rcpt = c@y.com
- orig = b@x.com AND rcpt = d@y.com
```

## Record Types (PMTA Accounting)

| Type | Description |
|------|-------------|
| `d` | Delivered |
| `b` | Bounced |
| `t` | Transient failure |
| `q` | Queued |
| `f` | Failed (permanent) |
| `r` | Received |

## Input Formats

### CSV (accounting files)
Expected columns: `timeQueued`, `timeLogged`, `orig`, `rcpt`, `dsnAction`, `dsnStatus`, `dsnDiag`, `type`, `vmta`, `jobId`, `envId`, `header_*`, ...

### JSON Lines (accounting.json)
Each line: `{"timeQueued": "...", "orig": "...", "rcpt": "...", "type": "d", ...}`

### Compressed Archives
- `.tar.gz`, `.tgz` — tar + gzip
- `.tar.bz2`, `.tbz2` — tar + bzip2
- `.zip` — zip archive
- `.gz`, `.bz2` — single compressed file

Glob patterns work: `--input "/var/log/pmta/acct-*.csv.gz"`

## Output

### CSV (default)
All matched records with unified columns (union of all fields seen). Original field casing preserved.

### Column Selection
```bash
# Only specific columns
./pmta-log-extract.py --orig "@example.com" --input logs/ --output out.csv --columns "timeLogged,orig,rcpt,type,dsnAction,dsnStatus"
```

## Examples

### Daily bounce report
```bash
./pmta-log-extract.py --type b --input /var/log/pmta/acct-$(date -d yesterday +%Y%m%d)*.csv --output bounces-$(date -d yesterday +%F).csv
```

### Complaint tracking
```bash
./pmta-log-extract.py --type f --rcpt "@complaint.example.com" --input /var/log/pmta/*.csv.gz --output complaints.csv
```

### Large archive processing with pigz
```bash
# Uses pigz/lbzip2 automatically if available for faster decompression
./pmta-log-extract.py --orig "marketing@" --input /mnt/archives/pmta-2024-*.tar.gz --output marketing-2024.csv --workers 8
```

### Find specific campaign
```bash
./pmta-log-extract.py --any "campaign-123" --input /var/log/pmta/ --recursive --output campaign-123-all.csv
```

### Raw grep mode for non-CSV logs
```bash
./pmta-log-extract.py --raw --pattern "TLS.*failed" --input /var/log/pmta/*.log --output tls-failures.txt
```

## Performance Tips

1. **Use `--workers`** for multi-file processing (default: CPU cores)
2. **Install `pigz` / `lbzip2`** for faster decompression
3. **Use `--format csv`** to skip auto-detection on known CSV files
4. **Limit columns** with `--columns` to reduce memory
5. **Use `--max-files`** for testing on large directories

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (matches found or no matches) |
| `1` | Error (invalid args, I/O error, corrupt archive) |
| `2` | Usage error |
| `130` | Interrupted (Ctrl+C) — partial results preserved in output |

## Requirements

- Python 3.10+
- Standard library only (no external deps)
- Optional: `pigz`, `lbzip2` for faster decompression

## Ctrl+C Handling

Clean shutdown:
- Terminates child decompression processes
- Cancels pending file reads
- Removes temporary files
- Preserves partial results in output CSV
- Exits with code 130

## License

MIT License — see [LICENSE](../LICENSE) in repo root.