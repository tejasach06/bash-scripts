#!/bin/bash
set -u

FAILURES=0
check() {
  local desc="$1"
  shift
  if "$@"; then
    printf 'PASS\t%s\n' "$desc"
  else
    printf 'FAIL\t%s\n' "$desc"
    FAILURES=$((FAILURES+1))
  fi
}

echo "=== APPLY PHASE GUEST START ==="
ID="unknown"
[ -r /etc/os-release ] && . /etc/os-release

# 1. Install missing commands required by preflight
case "$ID" in
  debian|ubuntu)
    apt-get update -qq && apt-get install -y -qq passwd sudo openssl procps coreutils tar gzip openssh-server >/dev/null 2>&1 || true
    ;;
  rocky|rhel|fedora|centos|almalinux)
    dnf -y install --allowerasing shadow-utils sudo openssl procps-ng tar gzip openssh-server >/dev/null 2>&1 || true
    ;;
  opensuse*|suse|leap)
    zypper --non-interactive install shadow sudo openssl procps tar gzip openssh systemd >/dev/null 2>&1 || true
    ;;
esac
ssh-keygen -A >/dev/null 2>&1 || true

cp /src/sysdiag.sh /work/sysdiag.sh
chmod +x /work/sysdiag.sh

# 2. Run harden --apply
apply_out=$(printf 'AuditPassw0rd!x\n' | bash /work/sysdiag.sh --run harden --apply --allow-virtualization --controls sshd,su_wheel,kernel_sysctl,coredump,journald,tmout,banner,ipv6,pwquality,user_sudo --out /work/out-apply 2>&1)
apply_rc=$?

echo "sysdiag --apply exit code: $apply_rc"

# 3. Assert observable post-conditions
check "Timeout profile contains TMOUT=900" bash -c "grep -q 'TMOUT=900' /etc/profile.d/99-sysdiag-timeout.sh 2>/dev/null && grep -q 'readonly TMOUT' /etc/profile.d/99-sysdiag-timeout.sh 2>/dev/null"
check "/etc/issue contains banner" bash -c "grep -qi 'Authorized' /etc/issue 2>/dev/null"
check "/etc/issue.net contains banner" bash -c "grep -qi 'Authorized' /etc/issue.net 2>/dev/null"
check "/etc/sysctl.d/99-sysdiag-ipv6.conf contains disable_ipv6=1 lines" bash -c "grep -q 'net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.d/99-sysdiag-ipv6.conf 2>/dev/null && grep -q 'net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.d/99-sysdiag-ipv6.conf 2>/dev/null"
check "/etc/security/pwquality.conf.d/99-sysdiag.conf contains minlen = 14" bash -c "grep -q 'minlen = 14' /etc/security/pwquality.conf.d/99-sysdiag.conf 2>/dev/null"
check "/etc/ssh/sshd_config.d/00-sysdiag.conf exists" test -f /etc/ssh/sshd_config.d/00-sysdiag.conf
check "hardening-actions.tsv records an sshd reload/restart path or non-bare-metal skip" bash -c "grep -Eq 'ssh\\.socket restarted|ssh(d)?\\.service reloaded|ssh(d)?( reload| \\.socket restart)? failed' /work/out-apply/evidence/hardening-actions.tsv || ! grep -q '^virtualization=none$' /work/out-apply/evidence/hardening-environment.txt"
check "pam_wheel in /etc/pam.d/su" bash -c "grep -q 'pam_wheel.so' /etc/pam.d/su 2>/dev/null"
check "group wheel exists" getent group wheel
check "/etc/sysctl.d/99-sysdiag-kernel.conf exists" test -f /etc/sysctl.d/99-sysdiag-kernel.conf
check "/etc/security/limits.d/99-sysdiag-coredump.conf exists" test -f /etc/security/limits.d/99-sysdiag-coredump.conf
check "hardening-status.tsv has no ERROR status" bash -c "! grep -q $'\tERROR\t' /work/out-apply/evidence/hardening-status.tsv"

check "id linuxteam succeeds" id linuxteam
check "/etc/sudoers.d/90-sysdiag-linuxteam contains NOPASSWD" bash -c "grep -q 'linuxteam ALL=(ALL) NOPASSWD:ALL' /etc/sudoers.d/90-sysdiag-linuxteam 2>/dev/null"
check "visudo -cf /etc/sudoers exits 0" visudo -cf /etc/sudoers
check "sudo -u linuxteam true succeeds" sudo -u linuxteam true
check "hardening-actions.tsv has changed rows" bash -c "grep -q 'changed' /work/out-apply/evidence/hardening-actions.tsv"
check "hardening-environment.txt has mode=apply" bash -c "grep -q 'mode=apply' /work/out-apply/evidence/hardening-environment.txt"
check "backups directory created under out-apply/evidence/backups" test -d /work/out-apply/evidence/backups

# Check honest reporting (Defect 5 check)
check "summary.json reports read_only=false after apply" bash -c "grep -q '\"read_only\": false' /work/out-apply/summary.json"
check "metadata.env reports READ_ONLY=false after apply" bash -c "grep -q 'READ_ONLY=false' /work/out-apply/metadata.env"
check "report.md reports non read-only mode after apply" bash -c "grep -q 'Safety Mode: changes-executed' /work/out-apply/report.md || grep -q 'Safety Mode: applied' /work/out-apply/report.md"

# 4. Idempotency test
apply2_out=$(printf 'AuditPassw0rd!x\n' | bash /work/sysdiag.sh --run harden --apply --allow-virtualization --controls sshd,su_wheel,kernel_sysctl,coredump,journald,tmout,banner,ipv6,pwquality,user_sudo --out /work/out-apply2 2>&1)
check "Second apply run reports unchanged for modified files" bash -c "grep -q 'unchanged' /work/out-apply2/evidence/hardening-actions.tsv"
echo "=== APPLY PHASE GUEST COMPLETE. Failures: $FAILURES ==="
exit $((FAILURES > 0))
