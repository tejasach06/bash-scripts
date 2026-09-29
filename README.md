# bash-scripts

Independent tools for remote execution, host diagnostics and hardening, monitoring deployment, and log and inventory export. Each directory has its own README. Review a tool's options and effects before running it on a host.

| Tool | Implementation | What it does |
| --- | --- | --- |
| [ssh-script-executor](ssh-script-executor/README.md) | Python | Runs local Bash scripts on SSH hosts concurrently and writes CSV or JSON results. |
| [dirtyfrag](dirtyfrag/README.md) | Bash | Checks kernel and module indicators; optional mitigation blacklists modules and rebuilds initramfs. |
| [fs-corruption-rca-collector](fs-corruption-rca-collector/README.md) | Python | Collects filesystem, storage, kernel, and Proxmox diagnostics into reports and an archive. |
| [pmta-log-extract](pmta-log-extract/README.md) | Rust and Python | Filters PowerMTA accounting records and exports matching rows to CSV. |
| [proxmox-inventory-extract](proxmox-inventory-extract/README.md) | Rust and Python | Exports Proxmox QEMU VM inventory to a 39-column InventoryMGR CSV. |
| [checkmk-deploy-multisite](checkmk-deploy-multisite/README.md) | Bash | Configures Checkmk central and remote OMD sites through SSH. |
| [sysdiag](sysdiag/README.md) | Bash | Applies a Linux host-hardening baseline; despite its name, it is not a diagnostic collector. |

## Run a tool

The tools have separate requirements. Use the linked README for setup and full options. The commands below run from the repository root.

### Remote scripts and diagnostics

Preview an SSH run without connecting:

```bash
python3 ssh-script-executor/ssh-script-executor.py --host user@server --script ssh-script-executor/test-script.sh --dry-run
```

Collect filesystem evidence on a Linux host. The collector writes its report under `/tmp` and an archive in the current directory; review the archive before sharing it.

```bash
sudo python3 fs-corruption-rca-collector/fs-corruption-rca-collector.py
```

### Rust exporters

Build and run the Rust implementations with Cargo. The Python implementations remain in the same directories; Rust does not require Python.

```bash
cargo run --release --manifest-path pmta-log-extract/Cargo.toml -- \
  --path '/var/log/pmta/acct-*.csv' --orig example.com --out matches.csv

cargo run --release --manifest-path proxmox-inventory-extract/Cargo.toml -- \
  -H pve.example.com:8006 -u inventory@pam -o inventory.csv
```

The PMTA example needs readable matching CSV files. For compressed PMTA inputs, consult the tool's column options. The Proxmox example requires API access and prompts for a password in an interactive terminal; you can also provide `PVE_API_TOKEN` or `PVE_PASSWORD` in the environment. The Rust Proxmox CLI does not verify TLS certificates by default; use `--verify-ssl` with a trusted certificate.

### Host-changing scripts

Read the source and target-host configuration before running `dirtyfrag`, `checkmk-deploy-multisite`, or `sysdiag`. The DirtyFrag scanner and Checkmk deployment script have known CLI or execution defects; do not treat their documented commands as verified deployment procedures. DirtyFrag mitigation can change module loading and initramfs. Checkmk deployment targets root SSH sessions. `sysdiag/harden.sh` changes accounts, SSH, and system policy immediately when run as root; it has no dry-run mode, and `--help` does not prevent changes.

## Requirements

- Rust and Cargo for the two native exporters.
- Python for the Python tools and retained exporter implementations. Version and optional dependencies vary by tool.
- Bash and Linux host utilities for the shell tools. The SSH executor also needs an SSH client and Bash on its targets.
- Appropriate host access for remote tools; privileged access for system-level collection or changes.

No repository-wide installer or shared runtime is required.