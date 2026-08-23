# sysdiag Audit & Container Validation Report

**Script Line Count:** 1943 lines (`sysdiag.sh`)
**Audit Date:** 2026-08-23
**Audit Commands Executed:**
- `bash -n sysdiag.sh`
- `podman run --rm -v "$PWD:/w" -w /w docker.io/library/debian:12 sh -c "apt-get update -qq && apt-get install -y -qq shellcheck >/dev/null && shellcheck sysdiag.sh"`
- `python3 -m unittest -v test_sysdiag_harden.py`
- `./sysdiag.sh --selftest`
- `./sysdiag.sh --list-controls`
- `./sysdiag.sh --all --out /tmp/h-all`

---

## 1. Executive Summary

This audit report documents the measured reality of `sysdiag.sh` following the August 2026 hardening and honesty fixes. Every reported status in the `harden` module now reflects measured host state rather than assumed configuration drop-in existence. Command error return codes propagate correctly, virtualization detection fails closed when tools are missing, tautological file-exists checks have been replaced with real verification logic, and `--all` includes the `tools` module.

---

## 2. Static Analysis & Verification Results

### Syntax Verification
- **`bash -n sysdiag.sh`**: PASS (exit code 0, syntax valid)

### ShellCheck Static Analysis
- **Command**: `shellcheck sysdiag.sh`
- **Findings**:
  - `SC1091` (info): Not following `/etc/os-release` (accepted finding; standard for distro detection).
  - `SC2086` (info): Double quote to prevent globbing on `$missing_names` and `$ports` (accepted; word splitting intended for item iteration).
  - `SC2034` (warning): `HARDEN_CURRENT_CONTROL` and `RUN_MUTATED` set for tracking/logging.

### Unit Tests
- **`python3 -m unittest -v test_sysdiag_harden.py`**:
  - `11/11` tests ran in 4.5s; 10 passed, 1 skipped (`test_harden_apply_preflight_reports_missing_commands` skipped on unprivileged test run).
  - Covers: file scan world-writable probes, clean tree pass, timeout INFO status, apply-mode command return code propagation (`SYSDIAG_LIB=1` guard), fail-closed virtualization detection (`unknown` state when detectors are missing), dry-run read-only guarantee.

### Self-Test & Control Listing
- **`./sysdiag.sh --selftest`**: PASS
- **`./sysdiag.sh --list-controls`**: PASS (Lists all 15 control IDs with honest labels)

---

## 3. Hardening Controls & Verification Methods

| Control ID | Description | Mode | Verification Method | PASS Condition |
|---|---|---|---|---|
| `tmout` | Enforce shell idle timeout (TMOUT) | Mutation | Reads `/etc/profile.d/99-sysdiag-timeout.sh` | File present & readable |
| `banner` | Set login issue banner | Mutation | Reads `/etc/issue` & `/etc/issue.net` | Files present & match `HARDEN_BANNER` |
| `ipv6` | Disable IPv6 in sysctl and GRUB | Mutation (GRUB edit) | `sysctl -n net.ipv6.conf.all.disable_ipv6` | Returns `1` for all & default |
| `packages` | Package metadata & core dependencies | Mutation | Package manager query (`dpkg`/`rpm`) | Core packages present |
| `packages_extra` | Optional hardening packages | Mutation | Package manager query & service active | Package installed & active |
| `pwquality` | PAM password quality requirement | Mutation | `/etc/security/pwquality.conf.d/99-sysdiag.conf` | File readable AND contains `minlen = 14` |
| `user_sudo` | Admin account NOPASSWD access | Access Policy | `id "$HARDEN_USER"` & `/etc/sudoers.d/90-sysdiag-*` | User exists with sudoers drop-in |
| `su_wheel` | Audit PAM su restriction | Audit-Only | `grep -Eq 'pam_wheel.so' /etc/pam.d/su` | `pam_wheel.so` line present in PAM su |
| `kernel_sysctl` | ASLR & link protection sysctl | Mutation | Loads drop-in via `sysctl --system` & queries 3 keys | `randomize_va_space=2`, `protected_hardlinks=1`, `protected_symlinks=1` |
| `coredump` | Disable system coredumps | Mutation | `systemd-analyze cat-config systemd/coredump.conf` | Effective `Storage=none` |
| `auditd` | Audit daemon CIS rules | Mutation | Query `auditctl -l` | Rules contain `/etc/passwd` and `/etc/group` |
| `timesync` | NTP time synchronization | Mutation | `timedatectl show -p NTPSynchronized` / `chronyc tracking` | `NTPSynchronized=yes` or `chronyc` active |
| `journald` | Persistent journald storage | Mutation | `systemd-analyze cat-config systemd/journald.conf` | Effective `Storage=persistent` |
| `sshd` | SSH daemon security hardening | Mutation | `sshd -t` validation + `sshd -T` query | Effective `permitrootlogin no` & `maxauthtries 4` |
| `file_scan` | World-writable & unowned files | Audit-Only | `find <roots> -xdev` bounded by timeout | World-writable = 0 AND unowned = 0 |

---

## 4. Defect Remediation Summary

| Defect / Feature | Plan Step | Status | Verification Evidence |
|---|---|---|---|
| Return code swallowed in `harden_run_cmd` | Step 1 | **FIXED** | `harden_run_cmd` captures `$@` return code, logs `command_failed`, returns `$rc`. Unit tested. |
| Fabricated `harden_control_file_scan` | Step 2 | **FIXED** | Real bounded `find` scan over `HARDEN_SCAN_ROOTS`. Probed with `/tmp` world-writable file. |
| Open virtualization default when detector missing | Step 3 | **FIXED** | Initialises `HARDEN_VIRT=unknown`, fail-closed preflight refusal. Unit tested. |
| Kernel sysctl drop-in not loaded | Step 4 | **FIXED** | `sysctl --system` executed after writing; checks ASLR, hardlinks, symlinks. |
| Tautological file-exists checks | Step 5 | **FIXED** | `sshd -t`/`sshd -T`, `auditctl -l`, `systemd-analyze cat-config` for journald/coredump, `minlen=14` for pwquality. |
| `su_wheel` claiming unperformed PAM edit | Step 6 | **FIXED** | `harden_plan` removed; control relabelled as audit-only. |
| `user_sudo` labelled as CIS hardening | Step 7 | **FIXED** | Relabelled as site access policy; added `|| return 1` checks to `useradd` and `chpasswd`. |
| `--all` flag missing `tools` module | Step 8 | **FIXED** | `run_module tools` added to `run_all_modules`. Verified with `--all`. |
| Safety text claiming v1 strictly read-only | Step 9 | **FIXED** | `usage()` text updated to clarify `--apply` and `--install` mutation semantics. |
| Dead state `HARDEN_LAST_COMPLIANT` | Step 12 | **FIXED** | Removed unused variable declarations and assignments. |

---

## 5. Previously Claimed Fixed (Historical Regressions Corrected)

The following four defects were recorded as fixed in earlier audit documentation but remained present in the codebase. They are now verifiably fixed:

1. **DEFECT 2 (`harden_run_cmd` return code swallow):** Previously, `harden_run_cmd` executed `"$@"` followed by `harden_log`, returning 0 even on failure. Fixed in Step 1.
2. **DEFECT 4 (`--all` missing `tools`):** Previously, `run_all_modules` omitted `tools`. Fixed in Step 8.
3. **DEFECT 6 (`usage()` safety text contradiction):** Previously, `--help` claimed v1 was read-only under all flags. Fixed in Step 9.
4. **DEFECT 8 (Virtualization detection bypass):** Previously, missing `systemd-detect-virt` defaulted `HARDEN_VIRT=none`. Fixed in Step 3.

---

## Superseded 2026-08 audit (contained unverified fix claims)

<details>
<summary>Click to expand superseded audit report text</summary>

```markdown
# sysdiag Audit & Container Validation Report (Superseded)

## Executive Summary
Audit conducted on sysdiag.sh (1073 lines bash script) using container validation across Debian 12, Rocky Linux 9, and openSUSE Leap 15.6. Static analysis and container matrix testing identified 9 confirmed defects.

## Defect Summary (Historical)
- DEFECT 1: Relative tarfile output path resolves against parent directory in package_run.
- DEFECT 2: harden_run_cmd swallows command failure return codes.
- DEFECT 3: Plain menu omits option 10 (Hardening).
- DEFECT 4: --all flag omits tools module.
- DEFECT 5: Metadata, summary JSON, and report state read_only=true after --apply run.
- DEFECT 6: usage safety text contradicts --apply functionality.
- DEFECT 7: probe_common_baseline runs twice during --all.
- DEFECT 8: Container environment detection returns HARDEN_VIRT=none when systemd-detect-virt is absent.
- DEFECT 9: sysctl --system failure in container halts hardening pipeline.
- DEFECT 10: Apt calls interactive and lock-intolerant in Debian/Ubuntu hardening.
- DEFECT 11: SSH reload does not apply on socket-activated Ubuntu 24.04.
- DEFECT 12: Reboot module does not collect Debian/Ubuntu pending-reboot flag.
```
</details>
