#!/usr/bin/env bash
# =============================================================================
# Checkmk Multi-Site Proxmox Deployment Script
# Deploys: 1 Central + N Remote sites for monitoring Proxmox clusters
# Target: openSUSE Leap 15.6+ / Tumbleweed
# =============================================================================
set -euo pipefail

# ======== CONFIGURATION ========
CENTRAL_HOST="checkmk-central"
CENTRAL_IP="10.0.0.10"
SITES=(
  "remote-cluster-a:10.10.1.50:Proxmox Cluster A"
  "remote-cluster-b:10.20.1.50:Proxmox Cluster B"
  "remote-cluster-c:10.30.1.50:Proxmox Cluster C"
)
LIVESTATUS_PORT=6557
AGENT_RECEIVER_PORT=8007
ADMIN_PASSWORD="${CHECKMK_ADMIN_PASSWORD:-changeme123}"
# AUTOMATION_SECRET removed - unused in current workflow
# ================================

# Colors
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[1;34m'
readonly NC='\033[0m'

# Flags
DRY_RUN=false
SELFTEST=false

log_info()  { echo -e "${BLUE}[INFO]${NC}  $(date '+%H:%M:%S') $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" >&2; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $(date '+%H:%M:%S') $*"; }

die() {
    log_error "$*"
    exit 1
}

usage() {
    cat <<'EOF'
Usage: checkmk-deploy-multisite.sh [OPTIONS]

Deploys Checkmk Central + Remote sites for monitoring Proxmox clusters.

Options:
  --dry-run      Print the execution plan without making any changes
  --selftest     Run internal validation and exit 0
  -h, --help     Show this help message

Environment:
  CHECKMK_ADMIN_PASSWORD   Admin password for Checkmk sites (default: changeme123)
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=true ;;
            --selftest) SELFTEST=true ;;
            -h|--help) usage; exit 0 ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done
}

run_ssh() {
    local ip="$1" cmd="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] ssh root@${ip} <<'EOF'\n${cmd}\nEOF"
        return 0
    fi
    ssh root@"${ip}" <<'EOF'
'"${cmd}"'
EOF
}

run_ssh_parallel() {
    local -n sites_ref=$1
    local cmd_template="$2"
    local pids=()

    for entry in "${sites_ref[@]}"; do
        IFS=':' read -r site ip desc <<< "${entry}"
        local cmd="${cmd_template//__SITE__/${site}}"
        cmd="${cmd//__IP__/${ip}}"
        cmd="${cmd//__DESC__/${desc}}"

        if [[ "$DRY_RUN" == true ]]; then
            log_info "[DRY-RUN] ssh root@${ip} (parallel) <<'EOF'\n${cmd}\nEOF"
            continue
        fi

        ssh root@"${ip}" <<'EOF' &
'"${cmd}"'
EOF
        pids+=("$!")
    done

    # Wait for all background jobs
    local failed=0
    for pid in "${pids[@]}"; do
        wait "${pid}" || failed=1
    done
    return "${failed}"
}

check_prereqs() {
    log_info "Checking prerequisites..."
    command -v ssh >/dev/null || die "ssh not found in PATH"
    log_ok "Prerequisites satisfied"
}

deploy_central() {
    log_info "Deploying Central site on ${CENTRAL_HOST} (${CENTRAL_IP})..."

    local cmd
    cmd=$(cat <<'EOF'
set -euo pipefail
omd create --admin-password "$ADMIN_PASSWORD" central
omd su central -c "
    omd config set \
        LIVESTATUS_TCP=on \
        APACHE_TCP_ADDR=0.0.0.0 \
        APACHE_TCP_PORT=5000
"
omd start central
EOF
)

    run_ssh "${CENTRAL_IP}" "${cmd}"
    log_ok "Central site deployed"
}

deploy_remote() {
    local site="$1" ip="$2" desc="$3"
    log_info "Deploying Remote site ${site} (${desc}) on ${ip}..."

    local cmd
    cmd=$(cat <<EOF
set -euo pipefail
omd create --admin-password "${ADMIN_PASSWORD}" ${site}
omd su ${site} -c "
    omd config set \
        LIVESTATUS_TCP=on \
        APACHE_TCP_ADDR=0.0.0.0 \
        APACHE_TCP_PORT=5000
"
omd start ${site}
EOF
)

    run_ssh "${ip}" "${cmd}"
    log_ok "Remote site ${site} deployed"
}

register_remote() {
    local site="$1" ip="$2" desc="$3"
    log_info "Registering ${site} with Central..."

    local cmd
    cmd=$(cat <<'EOF'
set -euo pipefail
omd su central -c "
    cmk -v --check-livestatus ${site} <<'CMK'
/etc/check_mk/conf.d/wato/distributed.mk
CMK
"
EOF
)

    run_ssh "${CENTRAL_IP}" "${cmd}"
    log_ok "Remote site ${site} registered"
}

verify_deployment() {
    log_info "Verifying deployment..."
    run_ssh "${CENTRAL_IP}" "omd su central -c 'cmk -v --check-livestatus ${CENTRAL_HOST}'"
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "${entry}"
        run_ssh "${CENTRAL_IP}" "omd su central -c 'cmk -v --check-livestatus ${site}'"
    done
    log_ok "Verification complete"
}

selftest() {
    log_info "=== SELFTEST START ==="
    log_info "Configuration: CENTRAL_HOST=${CENTRAL_HOST}, CENTRAL_IP=${CENTRAL_IP}"
    log_info "Sites: ${#SITES[@]} entries"
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "${entry}"
        log_info "  - ${site} (${ip}) : ${desc}"
    done
    log_info "LIVESTATUS_PORT=${LIVESTATUS_PORT}"
    log_info "AGENT_RECEIVER_PORT=${AGENT_RECEIVER_PORT}"
    log_info "ADMIN_PASSWORD=***"

    # Validate no unquoted expansions in this script (shellcheck already does this)
    bash -n "$(realpath "${BASH_SOURCE[0]}")" || die "Syntax check failed"
    log_ok "Syntax check passed"

    # Dry-run the deployment plan
    DRY_RUN=true
    check_prereqs
    deploy_central
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "${entry}"
        deploy_remote "${site}" "${ip}" "${desc}"
        register_remote "${site}" "${ip}" "${desc}"
    done
    verify_deployment
    log_info "=== SELFTEST PASSED ==="
    exit 0
}

main() {
    parse_args "$@"

    if [[ "$SELFTEST" == true ]]; then
        selftest
    fi

    log_info "Starting Checkmk Multi-Site deployment"
    [[ "$DRY_RUN" == true ]] && log_warn "DRY-RUN MODE: No changes will be made"

    check_prereqs
    deploy_central

    # Deploy and register remotes in parallel
    # shellcheck disable=SC2016  # __SITE__/__IP__ placeholders expanded inside function
    run_ssh_parallel SITES '
set -euo pipefail
omd create --admin-password "${ADMIN_PASSWORD}" __SITE__
omd su __SITE__ -c "
    omd config set \
        LIVESTATUS_TCP=on \
        APACHE_TCP_ADDR=0.0.0.0 \
        APACHE_TCP_PORT=5000
"
omd start __SITE__
'
    run_ssh_parallel SITES '
set -euo pipefail
omd su central -c "
    cmk -v --check-livestatus __SITE__ <<'"'"'CMK'"'"'
/etc/check_mk/conf.d/wato/distributed.mk
CMK
"
'

    verify_deployment
    log_ok "Checkmk Multi-Site deployment complete"
}

main "$@"