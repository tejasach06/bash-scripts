# DirtyFrag/DirtClone Scanner & Mitigator

Scans for and mitigates the DirtyFrag/DirtClone CVE chain: **CVE-2026-43284, CVE-2026-43500, CVE-2026-46300, CVE-2026-43503**.

## Quick Start

```bash
# Scan only (default, no root required)
./dirtyfrag-scanner.sh

# Verbose scan with custom CSV output
./dirtyfrag-scanner.sh --verbose --csv /tmp/report.csv

# Preview mitigation (dry-run, no root needed)
./dirtyfrag-scanner.sh --mitigate --dry-run

# Apply mitigations (requires root)
sudo ./dirtyfrag-scanner.sh --mitigate

# Apply and force reboot if needed
sudo ./dirtyfrag-scanner.sh --mitigate --force-reboot
```

## Options

| Flag | Description |
|------|-------------|
| `--csv FILE` | Write CSV report to FILE (default: `/tmp/dirtyfrag-report-<timestamp>.csv`) |
| `--mitigate` | Apply kernel module blacklists & sysctl mitigations |
| `--dry-run` | Show what would be done without making changes |
| `--force-reboot` | Reboot after mitigation if kernel update required |
| `--verbose`, `-v` | Verbose output |
| `--help`, `-h` | Show help and exit |
| `--version` | Show version and exit |

## What It Detects

| CVE | Component | Description |
|-----|-----------|-------------|
| CVE-2026-43284 | `esp4` | IPv4 ESP use-after-free |
| CVE-2026-43500 | `esp6` | IPv6 ESP use-after-free |
| CVE-2026-46300 | `rxrpc` | RxRPC kernel socket flaw |
| CVE-2026-43503 | DirtyClone | Composite exploit chain |

## Mitigation Actions

When `--mitigate` is used (requires root):

1. **Blacklists vulnerable modules** — Adds `esp4`, `esp6`, `rxrpc` to `/etc/modprobe.d/dirtyfrag-mitigation.conf`
2. **Applies sysctl hardening** — Sets `kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`
3. **Unloads modules** — Attempts `modprobe -r` on vulnerable modules (if not in use)
4. **Reports reboot requirement** — If modules were in use, flags reboot needed

## Output

### Console
Colored status per host:
- `[OK]` — Not vulnerable
- `[WARN]` — Vulnerable but mitigatable
- `[ERROR]` — Vulnerable, mitigation failed

### CSV Report
Columns: `hostname,ip,kernel_version,distro,cve_43284,cve_43500,cve_46300,cve_43503,mitigation_applied,reboot_required,timestamp`

## Requirements

- **Scan mode**: No root required, runs on any Linux with `bash`, `uname`, `lsmod`, `sysctl`
- **Mitigate mode**: Root required (`sudo`)
- Tested on: Ubuntu 20.04+/22.04+/24.04, Debian 11/12, RHEL 8/9, openSUSE Leap 15.6+/Tumbleweed

## Kernel Versions

- **Fixed upstream**: Linux 6.12+, 7.0-rc5+
- **Backported**: Check your distro's security advisories
- Script uses `sort -V` for version comparison (works with distro version strings like `5.15.0-105-generic`)

## Examples

### Fleet scan with centralized report
```bash
for host in server{1..50}; do
  ssh $host "bash -s" < ./dirtyfrag-scanner.sh --csv - >> /tmp/fleet-report.csv
done
```

### Automated mitigation in maintenance window
```bash
# Dry-run first
sudo ./dirtyfrag-scanner.sh --mitigate --dry-run

# Apply during maintenance
sudo ./dirtyfrag-scanner.sh --mitigate --force-reboot
```

### CI/CD integration
```bash
# Fail pipeline if any host vulnerable
./dirtyfrag-scanner.sh --csv report.csv
if grep -q "VULNERABLE" report.csv; then
  echo "Fleet has unpatched DirtyFrag vulnerabilities"
  exit 1
fi
```

## How It Works

1. **OS Detection** — Reads `/etc/os-release`, `uname -r`
2. **Module Check** — `lsmod` for `esp4`, `esp6`, `rxrpc`
3. **Version Compare** — Compares running kernel against known-fixed versions
4. **IP Collection** — Pure-bash IP detection (no `awk` dependency)
5. **Report** — Console + optional CSV

## Limitations

- Cannot detect if kernel has **distro backports** — only checks upstream version
- Mitigation via module blacklist is **defense-in-depth**; kernel update is the real fix
- `rxrpc` may be in use by AFS/Kerberos — unload may fail (reboot required)

## References

- [CVE-2026-43284](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-43284)
- [CVE-2026-43500](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-43500)
- [CVE-2026-46300](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-46300)
- [CVE-2026-43503](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-43503)
- [Linux kernel commit fixing esp4/esp6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=...)
- [Linux kernel commit fixing rxrpc](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=...)

## License

MIT License — see [LICENSE](../LICENSE) in repo root.