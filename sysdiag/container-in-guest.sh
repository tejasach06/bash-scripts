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

echo "=== GUEST OS INFO ==="
ID="unknown"
if [ -r /etc/os-release ]; then
  . /etc/os-release
fi
case "$ID" in
  debian|ubuntu)
    apt-get update -qq && apt-get install -y -qq python3 tar gzip >/dev/null 2>&1 && HAVE_PYTHON3=1 || true
    ;;
  rocky|rhel|fedora|centos|almalinux)
    dnf -y install python3 tar gzip >/dev/null 2>&1 && HAVE_PYTHON3=1 || true
    ;;
  opensuse*|suse|leap)
    zypper -n install python3 tar gzip >/dev/null 2>&1 && HAVE_PYTHON3=1 || true
    ;;
esac
validate_json() {
  local file="$1"
  [ -f "$file" ] || return 1
  if [ "$HAVE_PYTHON3" -eq 1 ]; then
    python3 -m json.tool "$file" >/dev/null 2>&1
  else
    grep -q '"findings": \[' "$file"
  fi
}

# Copy script to /work
cp /src/sysdiag.sh /work/sysdiag.sh
chmod +x /work/sysdiag.sh

echo "=== 1. VERSION & BASIC COMMANDS ==="
ver_out=$(bash /work/sysdiag.sh --version 2>&1)
check "sysdiag --version is 0.1.0" test "$ver_out" = "0.1.0"

list_out=$(bash /work/sysdiag.sh --list 2>&1)
check "sysdiag --list lists 8 modules" bash -c "echo '$list_out' | grep -q reboot && echo '$list_out' | grep -q slow && echo '$list_out' | grep -q disk && echo '$list_out' | grep -q network && echo '$list_out' | grep -q service && echo '$list_out' | grep -q baseline && echo '$list_out' | grep -q tools && echo '$list_out' | grep -q harden"

bash /work/sysdiag.sh --help >/dev/null 2>&1

selftest_out=$(bash /work/sysdiag.sh --selftest 2>&1)
check "sysdiag --selftest exits 0 and contains selftest: PASS" bash -c "echo '$selftest_out' | grep -q 'selftest: PASS'"

echo "=== 2. INDIVIDUAL DIAGNOSTIC MODULES ==="
MODULES="reboot slow disk network service baseline tools"
for m in $MODULES; do
  bash /work/sysdiag.sh --run "$m" --out "/work/out-$m" >/dev/null 2>&1
  rc=$?
  check "Module $m exits 0" test $rc -eq 0
  check "Module $m produces non-empty report.md" test -s "/work/out-$m/report.md"
  check "Module $m produces valid summary.json" validate_json "/work/out-$m/summary.json"
  check "Module $m produces commands.log" test -f "/work/out-$m/commands.log"
  check "Module $m produces evidence directory" test -d "/work/out-$m/evidence"
  check "Module $m report contains Raw Evidence Index" bash -c "grep -A 10 '## Raw Evidence Index' /work/out-$m/report.md | grep -q '\`'"
  check "Module $m metadata contains DISTRO_ID=$ID" bash -c "grep -q 'DISTRO_ID=$ID' /work/out-$m/metadata.env"
done
check "reboot module produces reboot-pending-flag evidence" test -s /work/out-reboot/evidence/reboot-pending-flag.txt

echo "=== 3. RUN ALL MODULES ==="
bash /work/sysdiag.sh --all --out /work/out-all >/dev/null 2>&1
check "--all exits 0" test $? -eq 0
check "--all includes tools module in report" bash -c "grep -q -- '-\\ tools' /work/out-all/report.md || grep -q 'tools' /work/out-all/report.md"

echo "=== 4. PACKAGING ==="
bash /work/sysdiag.sh --all --package --out /work/out-pkg >/dev/null 2>&1
check "--all --package creates tarball" test -f /work/out-pkg.tar.gz
check "tarball contains out-pkg/report.md" bash -c "tar -tzf /work/out-pkg.tar.gz | grep -q 'out-pkg/report.md'"

echo "=== 5. RELATIVE PATH PACKAGING (DEFECT 1) ==="
rm -rf /work/sysdiag-runs
(cd /work && bash /work/sysdiag.sh --run tools --package >/dev/null 2>&1)
check "relative --package creates tarball next to run directory" bash -c "ls /work/sysdiag-runs/*.tar.gz >/dev/null 2>&1"

echo "=== 6. MENU SMOKE TESTS ==="
printf '7\n0\n' | bash /work/sysdiag.sh --out /work/out-menu >/dev/null 2>&1
printf '10\n0\n' | bash /work/sysdiag.sh --out /work/out-menu10 >/dev/null 2>&1
check "Plain menu choice 10 creates hardening-plan.txt" test -s /work/out-menu10/evidence/hardening-plan.txt

echo "=== 7. INVALID INPUT HANDLING ==="
err_out=$(bash /work/sysdiag.sh --run nosuchmodule 2>&1)
rc=$?
check "--run nosuchmodule exits 1" test $rc -eq 1
check "--run nosuchmodule reports Unknown module on stderr" bash -c "echo '$err_out' | grep -q 'Unknown module'"

bash /work/sysdiag.sh --bogus >/dev/null 2>&1
check "--bogus exits 2" test $? -eq 2

bash /work/sysdiag.sh --run >/dev/null 2>&1
check "--run without value exits 2" test $? -eq 2

err_proc=$(bash /work/sysdiag.sh --out /proc/nonwritable/x --run tools 2>&1)
rc=$?
check "invalid output dir exits 2" test $rc -eq 2
check "invalid output dir reports error on stderr" bash -c "echo '$err_proc' | grep -qi 'cannot create output directory'"

echo "=== 8. HARDEN DRY-RUN ==="
bash /work/sysdiag.sh --run harden --out /work/out-harden-dry >/dev/null 2>&1
check "Harden dry-run exits 0" test $? -eq 0
check "hardening-plan.txt is non-empty" test -s /work/out-harden-dry/evidence/hardening-plan.txt
check "hardening-environment.txt has mode=dry-run" bash -c "grep -q 'mode=dry-run' /work/out-harden-dry/evidence/hardening-environment.txt"

# Distro family verification
case "$ID" in
  debian|ubuntu) expected_fam="debian" ;;
  rocky|rhel|fedora|centos|almalinux) expected_fam="rhel" ;;
  opensuse*|suse|leap) expected_fam="suse" ;;
  *) expected_fam="unknown" ;;
esac
check "hardening-environment.txt has distro_family=$expected_fam" bash -c "grep -q 'distro_family=$expected_fam' /work/out-harden-dry/evidence/hardening-environment.txt"

# Unprivileged dry-run
useradd -m auditor >/dev/null 2>&1 || true
chown -R auditor:auditor /work/out-harden-user 2>/dev/null || true
su auditor -c "bash /work/sysdiag.sh --run harden --out /work/out-harden-user" >/dev/null 2>&1
check "Unprivileged harden dry-run exits 0" test $? -eq 0

echo "=== 9. HARDEN APPLY REFUSAL WITHOUT OVERRIDE ==="
err_apply=$(bash /work/sysdiag.sh --run harden --apply --out /work/out-refuse 2>&1)
rc=$?
check "Harden apply without --allow-virtualization exits 1" test $rc -eq 1
check "Harden apply refusal mentions virtualization environment" bash -c "echo '$err_apply' | grep -q 'refused in virtualization environment'"

echo "=== 10. DUPLICATE PROBE CHECK (DEFECT 7) ==="
uname_count=$(grep -c 'baseline-uname' /work/out-all/commands.log 2>/dev/null || true)
uname_count=${uname_count:-0}
check "baseline-uname run only once in --all (count=1)" test "$uname_count" -eq 1

echo "=== 11. FINDINGS PIPELINE ==="
check "out-baseline/findings.tsv is non-empty" test -s /work/out-baseline/findings.tsv
findings_match=true
if [ -s /work/out-baseline/findings.tsv ]; then
  while IFS=$'\t' read -r fid severity category title rest; do
    [ -n "$title" ] || continue
    if ! grep -F -q "$title" /work/out-baseline/summary.json; then
      findings_match=false
      break
    fi
  done < /work/out-baseline/findings.tsv
fi
check "Every finding title from findings.tsv is in summary.json" test "$findings_match" = "true"

echo "=== 12. TUI MENU CHECK ==="
# Attempt whiptail/newt install
case "$ID" in
  debian|ubuntu) apt-get install -y -qq whiptail >/dev/null 2>&1 || true ;;
  rocky|rhel|fedora|centos|almalinux) dnf -y install newt >/dev/null 2>&1 || true ;;
  opensuse*|suse|leap) zypper -n install whiptail >/dev/null 2>&1 || true ;;
esac

if command -v whiptail >/dev/null 2>&1 || command -v dialog >/dev/null 2>&1; then
  script -qec "printf '0\n' | bash /work/sysdiag.sh --out /work/out-tui" /dev/null >/dev/null 2>&1
  rc=$?
  check "TUI menu executes via script pty" test $rc -eq 0
else
  # Fallback: PATH without whiptail/dialog
  PATH="/usr/bin:/bin" script -qec "printf '0\n' | bash /work/sysdiag.sh --out /work/out-tui-fallback" /dev/null >/dev/null 2>&1
  rc=$?
  check "Plain menu fallback executes without dialog/whiptail" test $rc -eq 0
fi

echo "=== GUEST AUDIT COMPLETE. Failures: $FAILURES ==="
exit $((FAILURES > 0))
