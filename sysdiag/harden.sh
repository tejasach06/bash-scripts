#!/usr/bin/env bash
#
# harden.sh - Linux distro hardening script
# Supports: Debian/Ubuntu (apt), RHEL/CentOS/Rocky (yum/dnf), openSUSE (zypper)
#
# Safe to re-run: every step checks current state before changing it.

set -euo pipefail

# ----------------------------- Variables -----------------------------------

SSH_BANNER_TEXT="AUTHORIZED USE ONLY - <COMPANY_NAME>
This system is restricted to authorized users only. All activity is
monitored and logged. Unauthorized access is prohibited and will be
prosecuted to the fullest extent of the law."

LINUXTEAM_USER="linuxteam"
LINUXTEAM_PASSWORD="ChangeMe123!"   # CHANGE BEFORE RUNNING

IDLE_TIMEOUT_SECONDS=600            # 10 minutes, used for TMOUT and sshd ClientAliveInterval
UMASK_VALUE="022"
PASS_MIN_LEN=8
PASS_MAX_DAYS=99999                 # effectively "never expires"

LOG_FILE="/var/log/harden-script.log"

# ----------------------------- Helpers --------------------------------------

log() {
    local msg
    msg="$(date '+%Y-%m-%d %H:%M:%S') $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        case "${ID}${ID_LIKE:-}" in
            *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
            *rhel*|*centos*|*fedora*|*rocky*|*almalinux*) DISTRO_FAMILY="rhel" ;;
            *suse*|*opensuse*) DISTRO_FAMILY="suse" ;;
            *)
                log "Unable to map distro '${ID}' to a known family. Aborting."
                exit 1
                ;;
        esac
    else
        log "/etc/os-release not found. Cannot detect distro. Aborting."
        exit 1
    fi
    log "Detected distro family: ${DISTRO_FAMILY}"
}

# Returns 0 if outbound internet connectivity is available, 1 otherwise.
has_internet() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 5 https://example.com >/dev/null 2>&1 && return 0
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q --timeout=5 -O /dev/null https://example.com >/dev/null 2>&1 && return 0
    fi
    # fall back to a raw TCP probe against a stable resolver
    timeout 5 bash -c "cat < /dev/null > /dev/tcp/1.1.1.1/443" >/dev/null 2>&1 && return 0
    return 1
}

pkg_install() {
    local pkg="$1"
    case "${DISTRO_FAMILY}" in
        debian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}"
            ;;
        rhel)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${pkg}"
            else
                yum install -y "${pkg}"
            fi
            ;;
        suse)
            zypper --non-interactive install "${pkg}"
            ;;
    esac
}

pkg_update_cache() {
    case "${DISTRO_FAMILY}" in
        debian) apt-get update -y ;;
        rhel)
            if command -v dnf >/dev/null 2>&1; then dnf makecache -y; else yum makecache -y; fi
            ;;
        suse) zypper --non-interactive refresh ;;
    esac
}

# ----------------------------- Steps ----------------------------------------

step_ssh_banner() {
    log "Configuring SSH banner"
    printf '%s\n' "${SSH_BANNER_TEXT}" > /etc/issue.net
    printf '%s\n' "${SSH_BANNER_TEXT}" > /etc/motd

    local sshd_config="/etc/ssh/sshd_config"
    if grep -qE '^[[:space:]]*Banner[[:space:]]' "${sshd_config}" 2>/dev/null; then
        sed -i -E 's|^[[:space:]]*Banner[[:space:]].*|Banner /etc/issue.net|' "${sshd_config}"
    else
        echo "Banner /etc/issue.net" >> "${sshd_config}"
    fi
    log "SSH banner configured (pre-login: /etc/issue.net, post-login: /etc/motd)"
}

step_create_linuxteam_user() {
    log "Ensuring user '${LINUXTEAM_USER}' exists"
    if id "${LINUXTEAM_USER}" >/dev/null 2>&1; then
        log "User '${LINUXTEAM_USER}' already exists, skipping creation"
    else
        useradd -m -s /bin/bash "${LINUXTEAM_USER}"
        log "Created user '${LINUXTEAM_USER}'"
    fi
    echo "${LINUXTEAM_USER}:${LINUXTEAM_PASSWORD}" | chpasswd
    log "Password set for '${LINUXTEAM_USER}'"

    local sudoers_file="/etc/sudoers.d/${LINUXTEAM_USER}"
    echo "${LINUXTEAM_USER} ALL=(ALL) NOPASSWD:ALL" > "${sudoers_file}"
    chmod 0440 "${sudoers_file}"
    visudo -cf "${sudoers_file}" || { log "Invalid sudoers file for ${LINUXTEAM_USER}, removing"; rm -f "${sudoers_file}"; exit 1; }
    log "Passwordless sudo granted to '${LINUXTEAM_USER}'"
}

step_idle_timeout() {
    log "Configuring 10-minute idle timeout (shell TMOUT + sshd ClientAlive)"

    local tmout_file="/etc/profile.d/99-tmout.sh"
    cat > "${tmout_file}" <<EOF
export TMOUT=${IDLE_TIMEOUT_SECONDS}
readonly TMOUT
EOF
    chmod 0644 "${tmout_file}"

    local sshd_config="/etc/ssh/sshd_config"
    if grep -qE '^[[:space:]]*ClientAliveInterval[[:space:]]' "${sshd_config}"; then
        sed -i -E "s|^[[:space:]]*ClientAliveInterval[[:space:]].*|ClientAliveInterval ${IDLE_TIMEOUT_SECONDS}|" "${sshd_config}"
    else
        echo "ClientAliveInterval ${IDLE_TIMEOUT_SECONDS}" >> "${sshd_config}"
    fi
    if grep -qE '^[[:space:]]*ClientAliveCountMax[[:space:]]' "${sshd_config}"; then
        sed -i -E "s|^[[:space:]]*ClientAliveCountMax[[:space:]].*|ClientAliveCountMax 0|" "${sshd_config}"
    else
        echo "ClientAliveCountMax 0" >> "${sshd_config}"
    fi
    log "Idle timeout configured (TMOUT=${IDLE_TIMEOUT_SECONDS}s, sshd disconnects after ${IDLE_TIMEOUT_SECONDS}s idle)"
}

step_disable_ipv6() {
    log "Disabling IPv6 on real network interfaces (loopback kept for local-only services)"
    local sysctl_file="/etc/sysctl.d/99-disable-ipv6.conf"
    cat > "${sysctl_file}" <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0
EOF
    sysctl -p "${sysctl_file}"
    log "IPv6 disabled on all/default (no NIC gets an IPv6 address); lo keeps ::1 so local-only services (e.g. snmpd) that bind it by default still start"
}

step_default_umask() {
    log "Setting default umask to ${UMASK_VALUE}"

    if grep -qE '^[[:space:]]*UMASK[[:space:]]' /etc/login.defs; then
        sed -i -E "s|^[[:space:]]*UMASK[[:space:]].*|UMASK           ${UMASK_VALUE}|" /etc/login.defs
    else
        echo "UMASK           ${UMASK_VALUE}" >> /etc/login.defs
    fi

    local umask_line="umask ${UMASK_VALUE}"
    local marker="# harden.sh: default umask"

    set_umask_in_file() {
        local file="$1"
        [[ -f "${file}" ]] || return 0
        if grep -qF "${marker}" "${file}"; then
            sed -i -E "/${marker}/{n;s|^umask .*|${umask_line}|}" "${file}"
        else
            printf '\n%s\n%s\n' "${marker}" "${umask_line}" >> "${file}"
        fi
    }

    set_umask_in_file /etc/profile
    if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
        set_umask_in_file /etc/bash.bashrc
    else
        set_umask_in_file /etc/bashrc
    fi
    log "Default umask set to ${UMASK_VALUE} in login.defs, /etc/profile, and system bashrc"
}

enable_and_start() {
    local service="$1"
    systemctl enable --now "${service}" 2>/dev/null || service "${service}" start 2>/dev/null || true
}

step_install_packages() {
    if has_internet; then
        log "Internet connectivity confirmed, proceeding with package installs"
        pkg_update_cache

        log "Installing qemu-guest-agent"
        pkg_install qemu-guest-agent
        enable_and_start qemu-guest-agent

        log "Installing snmpd"
        local snmp_service="snmpd"
        case "${DISTRO_FAMILY}" in
            rhel|suse) pkg_install net-snmp ;;
            *) pkg_install snmpd ;;
        esac
        enable_and_start "${snmp_service}"

        log "Installing chrony"
        pkg_install chrony
        local chrony_service="chronyd"
        [[ "${DISTRO_FAMILY}" == "debian" ]] && chrony_service="chrony"
        enable_and_start "${chrony_service}"
    else
        log "No internet connectivity detected. Skipping qemu-guest-agent, snmpd, and chrony installation."
    fi
}

step_password_policy() {
    log "Setting password policy: min length ${PASS_MIN_LEN}, max age ${PASS_MAX_DAYS} (never expires)"

    if grep -qE '^[[:space:]]*PASS_MAX_DAYS[[:space:]]' /etc/login.defs; then
        sed -i -E "s|^[[:space:]]*PASS_MAX_DAYS[[:space:]].*|PASS_MAX_DAYS   ${PASS_MAX_DAYS}|" /etc/login.defs
    else
        echo "PASS_MAX_DAYS   ${PASS_MAX_DAYS}" >> /etc/login.defs
    fi

    if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
        local pam_common="/etc/pam.d/common-password"
        if [[ -f "${pam_common}" ]]; then
            if grep -qE 'pam_unix\.so.*minlen=' "${pam_common}"; then
                sed -i -E "s|(pam_unix\.so[^\n]*)minlen=[0-9]+|\1minlen=${PASS_MIN_LEN}|" "${pam_common}"
            elif grep -qE 'pam_unix\.so' "${pam_common}"; then
                sed -i -E "s|(pam_unix\.so[^\n]*)|\1 minlen=${PASS_MIN_LEN}|" "${pam_common}"
            fi
        fi
    else
        local login_defs="/etc/login.defs"
        if grep -qE '^[[:space:]]*PASS_MIN_LEN[[:space:]]' "${login_defs}"; then
            sed -i -E "s|^[[:space:]]*PASS_MIN_LEN[[:space:]].*|PASS_MIN_LEN    ${PASS_MIN_LEN}|" "${login_defs}"
        else
            echo "PASS_MIN_LEN    ${PASS_MIN_LEN}" >> "${login_defs}"
        fi
    fi

    log "Applying PASS_MAX_DAYS=${PASS_MAX_DAYS} to existing user accounts (UID >= 1000, plus root)"
    while IFS=: read -r uname _ uid _; do
        if [[ "${uid}" -ge 1000 || "${uname}" == "root" ]] && [[ "${uname}" != "nobody" ]]; then
            chage --maxdays "${PASS_MAX_DAYS}" "${uname}" 2>/dev/null || true
        fi
    done < /etc/passwd
    log "Password policy applied"
}

restart_sshd() {
    log "Restarting sshd to apply configuration changes"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    else
        service sshd restart 2>/dev/null || service ssh restart 2>/dev/null || true
    fi
}

# ----------------------------- Main -----------------------------------------

main() {
    require_root
    touch "${LOG_FILE}"
    log "=== Starting hardening run ==="

    detect_distro
    step_ssh_banner
    step_create_linuxteam_user
    step_idle_timeout
    step_disable_ipv6
    step_default_umask
    step_install_packages
    step_password_policy
    restart_sshd

    log "=== Hardening run complete ==="
}

main "$@"
