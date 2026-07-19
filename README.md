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
chmod +x dirtyfrag/dirtyfrag-scanner.sh
./dirtyfrag/dirtyfrag-scanner.sh --help
```

## Requirements
- Bash 4+
- Linux kernel (tested on 5.15+)
- Root for `--mitigate` (not for `--scan` or `--dry-run`)

## License
MIT
