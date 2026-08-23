#!/bin/bash
set -u
set -o pipefail

IMAGES=(
  "docker.io/library/debian:12"
  "docker.io/library/ubuntu:22.04"
  "docker.io/library/ubuntu:24.04"
  "quay.io/rockylinux/rockylinux:9"
  "docker.io/opensuse/leap:15.6"
)

mkdir -p audit-results

if [ -f .gitignore ]; then
  if ! grep -q 'audit-results/' .gitignore; then
    echo "audit-results/" >> .gitignore
  fi
else
  echo "audit-results/" > .gitignore
fi

OVERALL_FAIL=0

for img in "${IMAGES[@]}"; do
  # Generate clean tag name (e.g., debian-12, rockylinux-9, leap-15.6)
  tag=$(echo "$img" | sed -E 's|.*/||; s|:|-|')
  
  echo "=================================================="
  echo ">>> RUNNING READ-ONLY MATRIX FOR: $img ($tag)"
  echo "=================================================="
  
  log_file="audit-results/${tag}.log"
  
  if podman run --rm --name "sysdiag-audit-${tag}" --tmpfs /work:rw,exec -v "$PWD":/src:ro,Z -w /work "$img" bash /src/container-in-guest.sh 2>&1 | tee "$log_file"; then
    echo ">>> $tag Read-only phase: PASS"
  else
    echo ">>> $tag Read-only phase: FAIL"
    OVERALL_FAIL=1
  fi
  
  echo "=================================================="
  echo ">>> RUNNING APPLY PHASE FOR: $img ($tag)"
  echo "=================================================="
  
  apply_log="audit-results/${tag}-apply.log"
  
  if podman run --rm --name "sysdiag-audit-apply-${tag}" --tmpfs /work:rw,exec -v "$PWD":/src:ro,Z -w /work "$img" bash /src/container-in-guest-apply.sh 2>&1 | tee "$apply_log"; then
    echo ">>> $tag Apply phase: PASS"
  else
    echo ">>> $tag Apply phase: FAIL"
    OVERALL_FAIL=1
  fi
done

echo "=================================================="
if [ $OVERALL_FAIL -eq 0 ]; then
  echo "CONTAINER MATRIX AUDIT COMPLETE: ALL PASSED"
  exit 0
else
  echo "CONTAINER MATRIX AUDIT COMPLETE: FAILURES OBSERVED"
  exit 1
fi
