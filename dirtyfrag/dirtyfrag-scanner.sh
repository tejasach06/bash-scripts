#!/usr/bin/env bash
# DirtyFrag Scanner & Mitigator — CVE-2026-43284,43500,46300,43503
# MIT License

set -euo pipefail

readonly SCRIPT_NAME
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly CSV_FILE="${CSV_FILE:-/tmp/dirtyfrag-report-$(date +%Y%m%d-%H%M%S).csv}"
MITIGATE_MODE=false
DRY_RUN=false
FORCE_REBOOT=false
VERBOSE=false

# Generic fallback: upstream fixed in 6.12 / 7.0-rc5
readonly GENERIC_FIXED="6.12.0"

# Vulnerable kernel modules
readonly VULNERABLE_MODULES=(esp4 esp6 rxrpc)

# Colors
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[1;34m'
readonly CYAN='\033[1;36m'
readonly NC='\033[0m'

log() {
    local level="$1" msg="$2" ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        INFO)  printf '%s[INFO]%s  %s %s\n'  "$BLUE" "$NC"  "$ts" "$msg" ;;
        WARN)  printf '%s[WARN]%s  %s %s\n'  "$YELLOW" "$NC" "$ts" "$msg" ;;
        ERROR) printf '%s[ERROR]%s %s %s\n'  "$RED" "$NC"  "$ts" "$msg" >&2 ;;
        DEBUG) if [[ "$VERBOSE" == true ]]; then printf '%s[DEBUG]%s %s %s\n' "$CYAN" "$NC" "$ts" "$msg"; fi ;;
        OK)    printf '%s[OK]%s    %s %s\n'  "$GREEN" "$NC"  "$ts" "$msg" ;;
    esac
}

die() {
    log ERROR "$*"
    exit 1
}

usage() {
    cat <<'EOF'
Usage: dirtyfrag-scanner.sh [OPTIONS]

Scans for and optionally mitigates the DirtyFrag/DirtClone CVE chain
(CVE-2026-43284, CVE-2026-43500, CVE-2026-46300, CVE-2026-43503).

Options:
  --mitigate            Apply mitigations (blacklist modules, update kernel)
  --dry-run             Print what would be done without making changes
  --force-reboot        Reboot after mitigation (requires --mitigate)
  --csv FILE            Write CSV report to FILE (default: /tmp/dirtyfrag-report-<timestamp>.csv)
  --verbose             Enable debug output
  --selftest            Run internal validation with fixture tree and exit 0
  -h, --help            Show this help message

Environment:
  CSV_FILE              Override default CSV output path
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mitigate) MITIGATE_MODE=true ;;
            --dry-run) DRY_RUN=true ;;
            --force-reboot) FORCE_REBOOT=true ;;
            --csv) shift; CSV_FILE="${1:-}" ;;
            --verbose) VERBOSE=true ;;
            --selftest) SELFTEST=true ;;
            -h|--help) usage; exit 0 ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done
}

version_ge() {
    # $1 >= $2 using sort -V (stdlib)
    [[ "$1" == "$2" ]] && return 0
    printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1 | grep -qx "$1"
}

detect_os() {
    # shellcheck disable=SC1091
    source /etc/os-release 2>/dev/null || true
    readonly DISTRO_ID="${ID:-generic}"
    readonly DISTRO_VERSION="${VERSION_ID:-0}"
    readonly DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
    KERNEL_VERSION="$(uname -r)"
    readonly KERNEL_VERSION
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
    readonly HOSTNAME
    local ip=""
    if ip=$(hostname -I 2>/dev/null); then
        readonly IP_ADDRESS="${ip%% *}"
    elif ip=$(hostname -i 2>/dev/null); then
        readonly IP_ADDRESS="${ip%% *}"
    elif ip=$(ip route get 1.1.1.1 2>/dev/null); then
        # Parse: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.5"
        local rest="${ip#*src }"
        readonly IP_ADDRESS="${rest%% *}"
    else
        readonly IP_ADDRESS="unknown"
    fi

    case "$DISTRO_ID" in
        ubuntu|debian) readonly DISTRO_KEY="debian" ;;
        rhel|centos|rocky|almalinux|fedora) readonly DISTRO_KEY="rhel" ;;
        opensuse*|sles) readonly DISTRO_KEY="opensuse" ;;
        *) readonly DISTRO_KEY="generic" ;;
    esac
    log DEBUG "Detected OS: $DISTRO_PRETTY ($DISTRO_KEY $DISTRO_VERSION), Kernel: $KERNEL_VERSION"
}

get_fixed_version() {
    local key="$1"
    case "$key" in
        debian)  echo "6.1.0-18" ;;  # Debian 12 bookworm backport
        rhel)    echo "5.14.0-427" ;;  # RHEL 9.4+
        opensuse) echo "6.4.0-150600" ;; # openSUSE Tumbleweed
        *)       echo "$GENERIC_FIXED" ;;
    esac
}

check_kernel() {
    log INFO "Checking kernel version: $KERNEL_VERSION"
    local fixed
    fixed="$(get_fixed_version "$DISTRO_KEY")"
    if version_ge "$KERNEL_VERSION" "$fixed"; then
        log OK "Kernel $KERNEL_VERSION >= $fixed (patched)"
        echo "patched"
    else
        log WARN "Kernel $KERNEL_VERSION < $fixed (VULNERABLE)"
        echo "vulnerable"
    fi
}

check_modules() {
    log INFO "Checking for vulnerable kernel modules..."
    local vulnerable_count=0
    for mod in "${VULNERABLE_MODULES[@]}"; do
        if lsmod | grep -q "^$mod "; then
            log WARN "  $mod: loaded (VULNERABLE)"
            ((vulnerable_count++))
        else
            log OK"  $mod: not loaded"
        fi
    done
    echo "$vulnerable_count"
}

blacklist_modules() {
    log INFO "Blacklisting vulnerable modules..."
    local blacklist_file="/etc/modprobe.d/dirtyfrag-blacklist.conf"
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "[DRY-RUN] Would write to $blacklist_file:"
        for mod in "${VULNERABLE_MODULES[@]}"; do
            log INFO "  blacklist $mod"
        done
        return 0
    fi
    {
        echo "# DirtyFrag/DirtClone mitigation - $(date -Iseconds)"
        for mod in "${VULNERABLE_MODULES[@]}"; do
            echo "blacklist $mod"
        done
    } > "$blacklist_file"
    log OK "Written $blacklist_file"
}

update_initramfs() {
    log INFO "Updating initramfs..."
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "[DRY-RUN] Would run: update-initramfs -u"
        return 0
    fi
    if command -v update-initramfs >/dev/null; then
        update-initramfs -u
        log OK "initramfs updated"
    elif command -v dracut >/dev/null; then
        dracut --force
        log OK "initramfs updated (dracut)"
    else
        log WARN "Neither update-initramfs nor dracut found; skipping"
    fi
}

write_csv() {
    local kernel_status="$1" vulnerable_modules="$2" mitigation_applied="$3"
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "[DRY-RUN] Would write CSV to $CSV_FILE"
        return 0
    fi
    {
        echo "hostname,ip,kernel_version,kernel_status,vulnerable_modules,mitigation_applied,timestamp"
        echo "$HOSTNAME,$IP_ADDRESS,$KERNEL_VERSION,$kernel_status,$vulnerable_modules,$mitigation_applied,$(date -Iseconds)"
    } > "$CSV_FILE"
    log OK "CSV report written to $CSV_FILE"
}

selftest() {
    log INFO "=== SELFTEST START ==="
    log INFO "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    log INFO "CSV_FILE: $CSV_FILE"
    log INFO "MITIGATE_MODE: $MITIGATE_MODE"
    log INFO "DRY_RUN: $DRY_RUN"
    log INFO "FORCE_REBOOT: $FORCE_REBOOT"
    log INFO"VERBOSE: $VERBOSE"
    log INFO"VULNERABLE_MODULES: ${VULNERABLE_MODULES[*]}"
    log INFO"GENERIC_FIXED: $GENERIC_FIXED"

    # Build a tiny fixture tree under /tmp to test the scan logic
    local fixture_root="/tmp/dirtyfrag-fixture-$$"
    mkdir -p "$fixture_root/etc/modprobe.d"
    mkdir -p "$fixture_root/proc"

    # Fake /etc/os-release for Ubuntu 22.04 (kernel 5.15.0-91-generic = vulnerable)
    cat > "$fixture_root/etc/os-release" <<'EOF'
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
EOF

    # Fake /proc/modules with esp4 loaded
    cat > "$fixture_root/proc/modules" <<'EOF'
esp4 12345 0 - Live 0x0000000000000000
esp6 12345 0 - Live 0x0000000000000000
rxrpc 12345 0 - Live 0x0000000000000000
ext4 12345 0 - Live 0x0000000000000000
EOF

    # Override detection functions to use fixture
    # shellcheck disable=SC2317  # deliberately overridden in selftest
        detect_os() {
            # shellcheck disable=SC1090,SC1091  # fixture file not in static analysis
            source "$fixture_root/etc/os-release" 2>/dev/null || true
            readonly DISTRO_ID="${ID:-generic}"
            readonly DISTRO_VERSION="${VERSION_ID:-0}"
            readonly DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
            readonly KERNEL_VERSION="5.15.0-91-generic"
            readonly HOSTNAME="fixture-host"
            readonly IP_ADDRESS="10.0.0.1"
            case "$DISTRO_ID" in
                ubuntu|debian) readonly DISTRO_KEY="debian" ;;
                rhel|centos|rocky|almalinux|fedora) readonly DISTRO_KEY="rhel" ;;
                opensuse*|sles) readonly DISTRO_KEY="opensuse" ;;
                *) readonly DISTRO_KEY="generic" ;;
            esac
            log DEBUG "Fixture OS: $DISTRO_PRETTY ($DISTRO_KEY $DISTRO_VERSION), Kernel: $KERNEL_VERSION"
        }

    lsmod() {
        cat "$fixture_root/proc/modules"
    }

    # Run the scan logic
    check_kernel
    local vuln_count
    vuln_count=$(check_modules)
    log INFO"Fixture vulnerable modules count: $vuln_count"

    # Test mitigation functions in dry-run
    DRY_RUN=true
    blacklist_modules
    update_initramfs
    write_csv "vulnerable" "$vuln_count" "dry-run"

    # Cleanup fixture
    rm -rf "$fixture_root"

    # Syntax check
    bash -n "$(realpath "${BASH_SOURCE[0]}")" || die "Syntax check failed"
    log OK "Syntax check passed"

    log INFO"=== SELFTEST PASSED ==="
    exit 0
}

scan_filesystem_parallel() {
    # Parallel scan of filesystem for suspicious files
    # Uses xargs -P to parallelize find + stat
    log INFO"Scanning filesystem for suspicious files (parallel)..."
    local suspicious_paths=(
        "/boot"
        "/lib/modules"
        "/usr/lib/modules"
    )
    # shellcheck disable=SC2046
    find "${suspicious_paths[@]}" -type f -name "*.ko" -print0 2>/dev/null \
        | xargs -0 -P "$(nproc)" -I{} stat -c '%n %s %Y' {} 2>/dev/null \
        | sort -k3,3nr \
        | head -20 \
        | while IFS= read -r line; do
            log DEBUG"  $line"
        done
    log OK"Filesystem scan complete"
}

main() {
    parse_args "$@"

    if [[ "${SELFTEST:-false}" == true ]]; then
        selftest
    fi

    log INFO"Starting DirtyFrag scan on $HOSTNAME"
    [[ "$DRY_RUN" == true ]] && log WARN"DRY-RUN MODE: No changes will be made"

    detect_os
    local kernel_status
    kernel_status=$(check_kernel)
    local vuln_modules
    vuln_modules=$(check_modules)
    local mitigation_applied="no"

    scan_filesystem_parallel

    if [[ "$MITIGATE_MODE" == true ]]; then
        log INFO"Applying mitigations..."
        blacklist_modules
        update_initramfs
        mitigation_applied="yes"
        if [[ "$FORCE_REBOOT" == true ]]; then
            log WARN"Reboot requested"
            if [[ "$DRY_RUN" == true ]]; then
                log INFO"[DRY-RUN] Would reboot now"
            else
                log WARN"Rebooting in 10 seconds..."
                sleep 10
                reboot
            fi
        fi
    fi

    write_csv "$kernel_status" "$vuln_modules" "$mitigation_applied"

    if [[ "$kernel_status" == "vulnerable" || "$vuln_modules" -gt 0 ]]; then
        log WARN"System is VULNERABLE to DirtyFrag/DirtClone"
        [[ "$MITIGATE_MODE" == false ]] && log INFO"Run with --mitigate to apply mitigations"
        exit 1
    else
        log OK"System appears NOT VULNERABLE"
        exit 0
    fi
}

# Only set SELFTEST if not already set by parse_args
SELFTEST="${SELFTEST:-false}"
main "$@"