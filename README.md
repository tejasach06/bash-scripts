# bash-scripts

Collection of production-ready scripts for system administration, security auditing, monitoring, and automation. Each script lives in its own directory with a dedicated README.

## Scripts

| Script | Language | Purpose |
|--------|----------|---------|
| [**ssh-script-executor**](./ssh-script-executor/) | Python | Execute local scripts on remote hosts via SSH with parallel execution, connection reuse, and CSV/JSON reporting |
| [**dirtyfrag**](./dirtyfrag/) | Bash | Scan for and mitigate DirtyFrag/DirtClone CVE chain (CVE-2026-43284, 43500, 46300, 43503) |
| [**fs-corruption-rca-collector**](./fs-corruption-rca-collector/) | Python | Collect comprehensive logs for filesystem corruption root cause analysis on Ubuntu/Proxmox |
| [**pmta-log-extract**](./pmta-log-extract/) | Python | Stream-extract records from large PowerMTA accounting logs by sender/recipient |
| [**proxmox-inventory-extract**](./proxmox-inventory-extract/) | Python | Extract VM inventory from Proxmox cluster via REST API, output CSV for InventoryMGR import |
| [**checkmk-deploy-multisite**](./checkmk-deploy-multisite/) | Bash | Deploy Checkmk Central + Remote sites for monitoring Proxmox clusters on openSUSE |

## Quick Navigation

### SSH Script Executor
```bash
cd ssh-script-executor
./ssh-script-executor.py --host user@server --script ./deploy.sh --args "prod"
```
[**→ Full README**](./ssh-script-executor/README.md)

### DirtyFrag Scanner
```bash
cd dirtyfrag
./dirtyfrag-scanner.sh --verbose --csv report.csv
sudo ./dirtyfrag-scanner.sh --mitigate --dry-run
```
[**→ Full README**](./dirtyfrag/README.md)

### Filesystem Corruption RCA Collector
```bash
cd fs-corruption-rca-collector
sudo ./fs-corruption-rca-collector.py
```
[**→ Full README**](./fs-corruption-rca-collector/README.md)

### PMTA Log Extract
```bash
cd pmta-log-extract
./pmta-log-extract.py --orig "@example.com" --input /var/log/pmta/*.csv.gz --output matches.csv
```
[**→ Full README**](./pmta-log-extract/README.md)

### Proxmox Inventory Extract
```bash
cd proxmox-inventory-extract
export PVE_PASSWORD="your-password"
./proxmox-inventory-extract.py --insecure -o /tmp/inventory.csv
```
[**→ Full README**](./proxmox-inventory-extract/README.md)

### Checkmk Multi-Site Deployment
```bash
cd checkmk-deploy-multisite
# Edit configuration in script first
sudo ./checkmk-deploy-multisite.sh
```
[**→ Full README**](./checkmk-deploy-multisite/README.md)

## Repository Structure

```
bash-scripts/
├── ssh-script-executor/
│   ├── ssh-script-executor.py
│   └── README.md
├── dirtyfrag/
│   ├── dirtyfrag-scanner.sh
│   └── README.md
├── fs-corruption-rca-collector/
│   ├── fs-corruption-rca-collector.py
│   └── README.md
├── pmta-log-extract/
│   ├── pmta-log-extract.py
│   └── README.md
├── proxmox-inventory-extract/
│   ├── proxmox-inventory-extract.py
│   └── README.md
├── checkmk-deploy-multisite/
│   ├── checkmk-deploy-multisite.sh
│   └── README.md
├── test_proxmox_inventory_extract.py    # Test suite for proxmox-inventory
├── test-script.sh                        # Generic test helper
├── conftest.py                           # Pytest configuration
└── README.md                             # This file
```

## Common Requirements

- **Python** 3.10+ (for Python scripts)
- **Bash** 4+ (for shell scripts)
- **Linux** (tested on Ubuntu 22.04, Debian 12, openSUSE Leap 15.6+, RHEL 9)
- Root/sudo for system-level operations

## Contributing

1. Each script in its own directory with `README.md`
2. Follow existing code style (type hints for Python, `set -euo pipefail` for Bash)
3. Include `--help`, `--version`, `--selftest` where applicable
4. Update this index README when adding new scripts

## License

MIT License — see individual script directories for details.