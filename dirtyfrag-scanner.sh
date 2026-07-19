#!/usr/bin/env bash
# DirtyFrag Scanner & Mitigator — CVE-2026-43284,43500,46300,43503
# MIT License

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0.0"
CSV_FILE="${CSV_FILE:-/tmp/dirtyfrag-report-$(date +%Y%m%d-%H%M%S).csv}"
MITIGATE_MODE=false
DRY_RUN=false
FORCE_REBOOT=false
VERBOSE=false

# Generic fallback: upstream fixed in 6.12 / 7.0-rc5
GENERIC_FIXED="6.12.0"

# Vulnerable kernel modules
VULNERABLE_MODULES=(esp4 esp6 rxrpc)

log() {
    local level="$1" msg="$2" ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        INFO)  printf '\033[1;34m[INFO]\033[0m  %s %s\n' "$ts" "$msg" ;;
        WARN)  printf '\033[1;33m[WARN]\033[0m  %s %s\n' "$ts" "$msg" ;;
        ERROR) printf '\033[1;31m[ERROR]\033[0m %s %s\n' "$ts" "$msg" >&2 ;;
        DEBUG) [[ "$VERBOSE" == true ]] && printf '\033[1;36m[DEBUG]\033[0m %s %s\n' "$ts" "$msg" ; true ;;
        OK)    printf '\033[1;32m[OK]\033[0m    %s %s\n' "$ts" "$msg" ;;
    esac
}

version_ge() {
    # $1 >= $2 using sort -V (stdlib)
    [[ "$1" == "$2" ]] && return 0
    printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1 | grep -qx "$1"
}

detect_os() {
    source /etc/os-release 2>/dev/null || true
    DISTRO_ID="${ID:-generic}"
    DISTRO_VERSION="${VERSION_ID:-0}"
    DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
    KERNEL_VERSION="$(uname -r)"
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
    # IP address - pure bash, no awk
    local ip=""
    if ip=$(hostname -I 2>/dev/null); then
        IP_ADDRESS="${ip%% *}"
    elif ip=$(hostname -i 2>/dev/null); then
        IP_ADDRESS="${ip%% *}"
    elif ip=$(ip route get 1.1.1.1 2>/dev/null); then
        # Parse: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100"
        ip="${ip#*src }"
        IP_ADDRESS="${ip%% *}"
    else
        IP_ADDRESS="unknown"
    fi

    # Normalize distro key for version lookup
    case "$DISTRO_ID" in
        ubuntu)       DISTRO_KEY="ubuntu-${DISTRO_VERSION}"; [[ "$DISTRO_VERSION" =~ ^24\. ]] && DISTRO_KEY="ubuntu" ;;
        debian)       DISTRO_KEY="debian-${DISTRO_VERSION}" ;;
        proxmox|pve)  DISTRO_KEY="proxmox-${DISTRO_VERSION%%.*}" ;;
        rhel|centos|rocky|almalinux) DISTRO_KEY="rhel-${DISTRO_VERSION%%.*}" ;;
        cloudlinux)   DISTRO_KEY="cloudlinux-${DISTRO_VERSION%%.*}" ;;
        opensuse*|sles|opensuse-microos) DISTRO_KEY="${DISTRO_ID}-${DISTRO_VERSION%%.*}" ;;
        fedora)       DISTRO_KEY="fedora-${DISTRO_VERSION}" ;;
        arch)         DISTRO_KEY="arch" ;;
        *)            DISTRO_KEY="generic" ;;
    esac
    log DEBUG "Detected: $DISTRO_PRETTY ($DISTRO_KEY) kernel=$KERNEL_VERSION"
}

# Minimal per-distro overrides (only where vendor fixed ≠ upstream 6.12)
declare -A OVERRIDES=(
    ["ubuntu:CVE-2026-43284"]="6.8.0-59.59"
    ["ubuntu:CVE-2026-43500"]="6.8.0-59.59"
    ["ubuntu:CVE-2026-46300"]="6.8.0-59.59"
    ["ubuntu:CVE-2026-43503"]="6.8.0-59.59"
    ["ubuntu-22.04:CVE-2026-43284"]="5.15.0-117.127"
    ["ubuntu-22.04:CVE-2026-43500"]="5.15.0-117.127"
    ["ubuntu-22.04:CVE-2026-46300"]="5.15.0-117.127"
    ["ubuntu-22.04:CVE-2026-43503"]="5.15.0-117.127"
    ["debian-12:CVE-2026-43284"]="6.1.0-30"
    ["debian-12:CVE-2026-43500"]="6.1.0-30"
    ["debian-12:CVE-2026-46300"]="6.1.0-30"
    ["debian-12:CVE-2026-43503"]="6.1.0-30"
    ["debian-13:CVE-2026-43284"]="6.12.0-1"
    ["debian-13:CVE-2026-43500"]="6.12.0-1"
    ["debian-13:CVE-2026-46300"]="6.12.0-1"
    ["debian-13:CVE-2026-43503"]="6.12.0-1"
    ["proxmox-8:CVE-2026-43284"]="6.8.12-4"
    ["proxmox-8:CVE-2026-43500"]="6.8.12-4"
    ["proxmox-8:CVE-2026-46300"]="6.8.12-4"
    ["proxmox-8:CVE-2026-43503"]="6.8.12-4"
    ["rhel-9:CVE-2026-43284"]="5.14.0-503.11.1.el9_5"
    ["rhel-9:CVE-2026-43500"]="5.14.0-503.11.1.el9_5"
    ["rhel-9:CVE-2026-46300"]="5.14.0-503.11.1.el9_5"
    ["rhel-9:CVE-2026-43503"]="5.14.0-503.11.1.el9_5"
    ["cloudlinux-9:CVE-2026-43284"]="5.14.0-611.54.5.el9_7"
    ["cloudlinux-9:CVE-2026-43500"]="5.14.0-611.54.5.el9_7"
    ["cloudlinux-9:CVE-2026-46300"]="5.14.0-611.54.5.el9_7"
    ["cloudlinux-9:CVE-2026-43503"]="5.14.0-611.54.5.el9_7"
    ["opensuse-15.6:CVE-2026-43284"]="6.4.0-150600.9.35.1"
    ["opensuse-15.6:CVE-2026-43500"]="6.4.0-150600.9.35.1"
    ["opensuse-15.6:CVE-2026-46300"]="6.4.0-150600.9.35.1"
    ["opensuse-15.6:CVE-2026-43503"]="6.4.0-150600.9.35.1"
)

check_cve() {
    local cve="$1"
    local key="${DISTRO_KEY}:${cve}"
    local fixed="${OVERRIDES[$key]:-${OVERRIDES[${DISTRO_ID}:${cve}]:-$GENERIC_FIXED}}"
    version_ge "$KERNEL_VERSION" "$fixed" && echo fixed || echo vulnerable
}

scan() {
    local cves=(CVE-2026-43284 CVE-2026-43500 CVE-2026-46300 CVE-2026-43503)
    KERNEL_VULNERABLE=false
    CVE_RESULTS=()

    for cve in "${cves[@]}"; do
        local status; status=$(check_cve "$cve")
        CVE_RESULTS+=("$cve=$status")
        [[ "$status" == "vulnerable" ]] && KERNEL_VULNERABLE=true
    done

    # Exploit primitives (single pass)
    local userns_val; userns_val=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)
    local modules_loaded=()
    if command -v lsmod >/dev/null 2>&1; then
        for mod in "${VULNERABLE_MODULES[@]}"; do lsmod | grep -q "^$mod " && modules_loaded+=("$mod"); done
    fi

    EXPLOIT_PRIMITIVES_PRESENT=true
    PRIMITIVE_DETAILS="unprivileged_userns=$([[ $userns_val == 1 ]] && echo enabled || echo disabled) "
    PRIMITIVE_DETAILS+="vulnerable_modules_loaded=${modules_loaded[*]:-none} "
    PRIMITIVE_DETAILS+="cap_net_admin=$([[ $userns_val == 1 ]] && echo obtainable_via_userns || echo not_obtainable)"
    [[ $userns_val != 1 || ${#modules_loaded[@]} -gt 0 ]] || EXPLOIT_PRIMITIVES_PRESENT=false
}

report() {
    local overall="no"
    [[ "$KERNEL_VULNERABLE" == true && "$EXPLOIT_PRIMITIVES_PRESENT" == true ]] && overall="yes"

    echo
    log INFO "=== Scan Results ==="
    log INFO "Host: $HOSTNAME ($IP_ADDRESS)"
    log INFO "OS: $DISTRO_PRETTY ($DISTRO_VERSION)"
    log INFO "Kernel: $KERNEL_VERSION"
    echo
    log INFO "CVE Status:"
    for r in "${CVE_RESULTS[@]}"; do
        local c="${r%%=*}" s="${r#*=}"
        [[ "$s" == vulnerable ]] && log WARN "  $c: $s" || log OK "  $c: $s"
    done
    echo
    log INFO "Exploit Primitives: $PRIMITIVE_DETAILS"
    echo
    [[ "$overall" == yes ]] && log WARN "OVERALL: VULNERABLE (kernel + primitives)" || log OK "OVERALL: NOT VULNERABLE"

    # Write CSV header only on first call
    if [[ ! -f "$CSV_FILE" ]]; then
        echo "hostname,ip,kernel,os_name,os_version,vulnerable,mitigation_applied,timestamp" > "$CSV_FILE"
    fi
    printf '"%s","%s","%s","%s","%s","%s","%s","%s"\n' \
        "$HOSTNAME" "$IP_ADDRESS" "$KERNEL_VERSION" "$DISTRO_PRETTY" "$DISTRO_VERSION" \
        "$overall" "$([[ "$MITIGATE_MODE" == true ]] && echo yes || echo no)" "$(date -Iseconds)" >> "$CSV_FILE"
    log INFO "CSV: $CSV_FILE"
    cat "$CSV_FILE"
}

mitigate() {
    [[ "$DRY_RUN" == true || $EUID -eq 0 ]] || { log ERROR "mitigate requires root (or use --dry-run)"; exit 1; }
    log INFO "=== Mitigation ${DRY_RUN:+[DRY-RUN] }==="

    local cmds=()

    # 1. Kernel update (if needed)
    if [[ "$KERNEL_VULNERABLE" == true ]]; then
        case "$DISTRO_ID" in
            ubuntu|debian|proxmox) cmds+=("apt-get update && apt-get install -y linux-image-generic linux-headers-generic") ;;
            rhel|centos|rocky|almalinux|cloudlinux|fedora) cmds+=("dnf update -y kernel") ;;
            opensuse*|sles) cmds+=("zypper refresh && zypper update -y kernel-default") ;;
            arch) cmds+=("pacman -Syu --noconfirm linux linux-headers") ;;
            *) log WARN "Unknown distro - manual kernel update needed" ;;
        esac
    fi

    # 2. Blacklist modules
    cmds+=("echo -e 'blacklist esp4\nblacklist esp6\nblacklist rxrpc' > /etc/modprobe.d/dirtyfrag-mitigation.conf")
    cmds+=("modprobe -r esp4 esp6 rxrpc 2>/dev/null || true")
    case "$DISTRO_ID" in
        ubuntu|debian|proxmox) cmds+=("update-initramfs -u") ;;
        rhel|centos|rocky|almalinux|cloudlinux|fedora) cmds+=("dracut -f") ;;
        opensuse*|sles) cmds+=("dracut -f") ;;
        arch) cmds+=("mkinitcpio -P") ;;
    esac

    # 3. Disable unprivileged userns
    cmds+=("sysctl -w kernel.unprivileged_userns_clone=0")
    cmds+=("echo 'kernel.unprivileged_userns_clone = 0' > /etc/sysctl.d/99-dirtyfrag-userns.conf")
    cmds+=("sysctl --system")

    if [[ "$DRY_RUN" == true ]]; then
        log INFO "Would execute:"
        for c in "${cmds[@]}"; do echo "  $c"; done
        [[ "$KERNEL_VULNERABLE" == true ]] && log WARN "Reboot required after kernel update"
        log OK "DRY-RUN complete"
    else
        for c in "${cmds[@]}"; do log INFO "Running: $c"; eval "$c"; done
        [[ "$KERNEL_VULNERABLE" == true && "$FORCE_REBOOT" == true ]] && { log WARN "Rebooting in 10s"; sleep 10; reboot; }
        [[ "$KERNEL_VULNERABLE" == true ]] && log WARN "Reboot manually to load new kernel"
        log OK "Mitigation applied"
    fi
}

parse_args() {
    MITIGATE_MODE=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scan) MITIGATE_MODE=false ;;
            --mitigate) MITIGATE_MODE=true ;;
            --dry-run) DRY_RUN=true ;;
            --force-reboot) FORCE_REBOOT=true ;;
            --csv) CSV_FILE="$2"; shift ;;
            --verbose) VERBOSE=true ;;
            --help) usage; exit 0 ;;
            *) log ERROR "Unknown option: $1"; exit 1 ;;
        esac
        shift
    done
}

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

DirtyFrag Scanner for CVE-2026-43284,43500,46300,43503

Options:
    --scan              Scan only (default)
    --mitigate          Apply mitigations (requires root, may reboot)
    --dry-run           Preview mitigation without executing
    --force-reboot      Auto-reboot after kernel update
    --csv FILE          Output CSV (default: /tmp/dirtyfrag-report-YYYYMMDD-HHMMSS.csv)
    --verbose           Debug output
    --help              Show help
EOF
}

main() {
    parse_args "$@"
    log INFO "=== DirtyFrag Scanner v$SCRIPT_VERSION ==="
    log INFO "Target: CVE-2026-43284,43500,46300,43503"

    detect_os
    scan
    report

    if [[ "$MITIGATE_MODE" == true ]]; then
        mitigate
        scan
        report
    fi
}

main "$@"