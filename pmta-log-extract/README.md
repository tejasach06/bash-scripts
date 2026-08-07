# PMTA Log Extract

Stream-extract records from large PowerMTA (PMTA) accounting logs (CSV or line-delimited JSON) by sender (`orig`) and/or recipient (`rcpt`). Supports compressed archives (`.tar.gz`, `.tar.bz2`, `.zip`), glob patterns, exact/contains/domain matching, AND/OR logic, and type filtering.

## Quick Start

```bash
# Extract all records for a sender domain
./pmta-log-extract.py --orig "@example.com" --input /var/log/pmta/acct-*.csv --output matches.csv

# Extract for specific recipient with domain matching
./pmta-log-extract.py --rcpt "user@domain.com" --input /var/log/pmta/*.csv.gz --output out.csv

# Multiple patterns with AND logic (match orig AND rcpt)
./pmta-log-extract.py --orig "alerts@" --rcpt "@company.com" --match all --input logs/ --output filtered.csv

# OR logic (match orig OR rcpt)
./pmta-log-extract.py --orig "bounce@" --rcpt "complaint@" --match any --input logs/ --output filtered.csv

# Raw passthrough mode (no parsing, just grep)
./pmta-log-extract.py --raw --pattern "error" --input /var/log/pmta/*.log --output errors.txt
```

## Options

### Input
| Flag | Description |
|------|-------------|
| `--input PATH` | Input file(s), directory, or glob pattern (required) |
| `--recursive`, `-r` | Recurse into directories | 
| `--format {csv,json,auto}` | Force input format (default: auto-detect) |

### Matching
| Flag | Description |
|------|-------------|
| `--orig PATTERN` | Match sender (orig) field |
| `--rcpt PATTERN` | Match recipient (rcpt) field |
| `--any PATTERN` | Match against orig OR rcpt (shorthand) |
| `--match {all,any}` | `all` = AND logic, `any` = OR logic (default: `all` when both `--orig` and `--rcpt` given) |
| `--type TYPE` | Filter by record type (e.g., `d`, `b`, `t`, `q`) |
| `--exact` | Exact match (default: contains) |
| `--domain` | Domain-style match (pattern treated as domain suffix) |
| `--case-sensitive` | Case-sensitive matching (default: case-insensitive) |

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

### Domain Matching (`--domain`)
```
--orig "@example.com" --domain
```
Matches: `user@example.com`, `alerts@sub.example.com`, `mail.example.com`
Does not match: `user@fake-example.com`

### Contains Matching (default)
```
--orig "alerts"
```
Matches: `alerts@example.com`, `server-alerts@domain.com`, `myalerts@test.com`

### Exact Matching (`--exact`)
```
--orig "alerts@example.com" --exact
```
Matches only: `alerts@example.com`

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