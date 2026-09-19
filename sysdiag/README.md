# Linux Hardening Script

Applies a fixed security baseline to a Linux host in one run: SSH banner, a
passwordless-sudo admin account, session idle timeouts, IPv6 disabled on
real network interfaces, a default umask, monitoring/time-sync packages, and
a password policy. Supports Debian/Ubuntu (`apt`), RHEL/CentOS/Rocky
(`yum`/`dnf`), and openSUSE (`zypper`).

## Quick Start

```bash
# Edit the variables at the top of the script first (banner text, password)
sudo ./harden.sh
```

The script is idempotent: every step checks current state before changing
it, so re-running it is safe and just reconfirms the baseline.

## Configuration

Edit these variables at the top of `harden.sh` before running:

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_BANNER_TEXT` | `AUTHORIZED USE ONLY - <COMPANY_NAME>` | Pre-login (`/etc/issue.net`) and post-login (`/etc/motd`) banner. Replace `<COMPANY_NAME>`. |
| `LINUXTEAM_USER` | `linuxteam` | Admin account created with passwordless sudo |
| `LINUXTEAM_PASSWORD` | `ChangeMe123!` | **Change before running** — stored in plaintext in the script |
| `IDLE_TIMEOUT_SECONDS` | `600` | Shell (`TMOUT`) and SSH (`ClientAliveInterval`) idle timeout |
| `UMASK_VALUE` | `022` | System-wide default umask |
| `PASS_MIN_LEN` | `8` | Minimum password length, enforced via PAM |
| `PASS_MAX_DAYS` | `99999` | Password max age — effectively never expires |

## What It Does

1. **SSH banner** — writes `SSH_BANNER_TEXT` to `/etc/issue.net` (pre-login)
   and `/etc/motd` (post-login), sets `Banner /etc/issue.net` in
   `sshd_config`.
2. **Admin user** — creates `linuxteam` if absent, sets its password, and
   grants `NOPASSWD:ALL` sudo via a `visudo`-validated
   `/etc/sudoers.d/linuxteam`.
3. **Idle timeout** — sets `TMOUT` in `/etc/profile.d/99-tmout.sh` for
   interactive shells and `ClientAliveInterval`/`ClientAliveCountMax` in
   `sshd_config` so idle SSH sessions are dropped.
4. **IPv6 disabled** — `net.ipv6.conf.{all,default}.disable_ipv6=1` via
   `/etc/sysctl.d/99-disable-ipv6.conf`, applied immediately. Loopback
   (`lo`) is deliberately **left enabled** (`disable_ipv6=0`) so local-only
   services that bind `::1` by default (e.g. `snmpd`) keep working — no
   real network interface ever gets an IPv6 address.
5. **Default umask** — `022` in `/etc/login.defs`, `/etc/profile`, and the
   distro's system-wide bashrc.
6. **Packages** — if outbound internet is reachable, installs and starts
   `qemu-guest-agent`, `snmpd` (`net-snmp` on RHEL/SUSE), and `chrony`
   (`chronyd` service on RHEL/SUSE). Skipped entirely, with a log line, if
   there's no connectivity.
7. **Password policy** — `PASS_MIN_LEN` enforced via PAM (`pam_unix
   minlen=` on Debian, `pwquality.conf minlen=` on RHEL/SUSE) and
   `PASS_MAX_DAYS=99999` applied both in `/etc/login.defs` (future
   accounts) and via `chage --maxdays` for every existing UID ≥ 1000
   account plus `root`.

All actions are logged to `/var/log/harden-script.log`.

## Requirements

- Root (the script refuses to run otherwise)
- Tested against real Proxmox VE guests: Ubuntu 24.04 (`apt`) and Rocky
  Linux 9 (`dnf`)
- Outbound internet access is optional — package installation is skipped
  cleanly without it, everything else still applies

## Known Interactions

- **IPv6 off + `snmpd`**: `snmpd`'s stock config binds `udp6:[::1]:161` by
  default. Disabling IPv6 everywhere (including loopback) breaks that bind
  and crash-loops the service — a real bug hit while validating this
  script, and it's also a known upstream net-snmp issue where a single
  explicit IPv4-only `agentAddress` gets double-registered internally and
  fails `EADDRINUSE`, so pinning the config to IPv4-only is not a safe fix
  either. Keeping IPv6 on loopback only sidesteps both problems without
  touching `snmpd`'s config or opening any real-interface attack surface.
- **RHEL package installs**: `dnf install` does not auto-start services the
  way Debian's `apt` postinst does. The script explicitly `systemctl
  enable --now`s `qemu-guest-agent`, `snmpd`, and chrony's real unit name
  per distro (`chronyd` on RHEL/SUSE, `chrony` on Debian) so "installed"
  means "running" on every supported family.

## Limitations

- No `--dry-run` mode — every run applies changes directly.
- No revert/backup of prior config values; re-running with different
  variable values overwrites the previous baseline.
- Only tested on Debian/Ubuntu and RHEL/Rocky family images; the openSUSE
  (`zypper`) path shares the same code but has not been booted and
  verified end-to-end.

## License

MIT License — see [LICENSE](../LICENSE) in repo root.
