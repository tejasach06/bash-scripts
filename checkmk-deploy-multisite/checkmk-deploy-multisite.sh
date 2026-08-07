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
AUTOMATION_SECRET="${CHECKMK_AUTOMATION_SECRET:-auto-secret-$(openssl rand -hex 16)}"
# ================================

log() { echo -e "\033[1;32m[$(date '+%H:%M:%S')]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

# --- 1. Install Checkmk on all hosts ---
install_checkmk() {
    local host=$1 ip=$2
    log "Installing Checkmk on $host ($ip)..."
    
    ssh root@$ip << 'EOF'
# Add Checkmk repository
zypper --non-interactive addrepo -f https://download.opensuse.org/repositories/server:/monitoring/openSUSE_Tumbleweed/server:monitoring.repo
zypper --non-interactive refresh
zypper --non-interactive install check-mk-raw

# Enable and start required services
systemctl enable --now apache2
systemctl enable --now xinetd
EOF
}

# --- 2. Create Central Site ---
create_central() {
    log "Creating central site on $CENTRAL_HOST..."
    ssh root@$CENTRAL_IP << EOF
omd create --admin-password "$ADMIN_PASSWORD" central
omd su central -c "
    omd config set \
        LIVESTATUS_TCP=on \
        LIVESTATUS_TCP_PORT=$LIVESTATUS_PORT \
        LIVESTATUS_TCP_TLS=on \
        PIGGYBACK_HUB=on \
        APACHE_TCP_PORT=80 \
        APACHE_TCP_SSL_PORT=443
    omd start
"
# Create automation user
omd su central -c "
    cmk-user add automation --automation-secret '$AUTOMATION_SECRET' --role admin
"
EOF
    log "Central site created. UI: http://$CENTRAL_IP/central/"
}

# --- 3. Create Remote Sites ---
create_remote_sites() {
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip description <<< "$entry"
        log "Creating remote site: $site ($description) on $ip..."
        
        ssh root@$ip << EOF
omd create --admin-password "$ADMIN_PASSWORD" $site
omd su $site -c "
    omd config set \
        LIVESTATUS_TCP=on \
        LIVESTATUS_TCP_PORT=$LIVESTATUS_PORT \
        LIVESTATUS_TCP_TLS=on \
        PIGGYBACK_HUB=on \
        APACHE_TCP_PORT=80 \
        APACHE_TCP_SSL_PORT=443
    omd start
"
EOF
        log "Remote site $site created. UI: http://$ip/$site/"
    done
}

# --- 4. Configure Firewall ---
configure_firewall() {
    log "Configuring firewalls..."
    
    # Central: Allow outbound to all remotes
    ssh root@$CENTRAL_IP << EOF
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
for entry in "${SITES[@]}"; do
    IFS=':' read -r site ip desc <<< "\$entry"
    firewall-cmd --permanent --add-rich-rule="rule family=ipv4 destination address=\$ip port port=$LIVESTATUS_PORT protocol=tcp accept"
done
firewall-cmd --reload
EOF
    
    # Remotes: Allow inbound from central only
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        ssh root@$ip << EOF
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$CENTRAL_IP port port=$LIVESTATUS_PORT protocol=tcp accept"
firewall-cmd --permanent --add-port=$AGENT_RECEIVER_PORT/tcp
firewall-cmd --reload
EOF
    done
}

# --- 5. Connect Remote Sites to Central ---
connect_sites() {
    log "Connecting remote sites to central..."
    
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        log "Connecting $site..."
        
        # Get remote site's CA cert
        REMOTE_CERT=$(ssh root@$ip "omd su $site -c 'cat ~/var/check_mk/ca/ca.pem'")
        
        # Add to central
        ssh root@$CENTRAL_IP << EOF
omd su central -c "
    echo '$REMOTE_CERT' > ~/var/check_mk/ca/remote-$site.pem
    cmk-connect-site \
        --remote-site $site \
        --remote-host $ip \
        --remote-port $LIVESTATUS_PORT \
        --encryption tls \
        --trust-cert ~/var/check_mk/ca/remote-$site.pem
    cmk -O
"
EOF
    done
}

# --- 6. Deploy Proxmox Monitoring on Remotes ---
deploy_proxmox_monitoring() {
    log "Deploying Proxmox monitoring on remote sites..."
    
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        log "Configuring Proxmox monitoring for $site..."
        
        ssh root@$ip << 'EOF'
# Install Proxmox special agent dependencies
zypper --non-interactive install python3 python3-requests python3-urllib3

# The Proxmox special agent is included in Checkmk 2.x
# Configure via API after site is connected
EOF
    done
}

# --- 7. Configure Proxmox Special Agent via REST API ---
configure_proxmox_agent() {
    log "Configuring Proxmox special agent via REST API..."
    
    # This requires Proxmox cluster details - customize per site
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        
        # Example: Create Proxmox VE rule via API
        # You'll need to customize hostnames, credentials per cluster
        log "Create Proxmox VE rule for $site manually via UI or API"
        log "  Setup -> Agents -> VM, cloud, container -> Proxmox VE -> Add rule"
        log "  Username: checkmk@pve"
        log "  Conditions: Explicit hosts -> Select all Proxmox nodes in this cluster"
    done
}

# --- 8. Verify Deployment ---
verify_deployment() {
    log "Verifying deployment..."
    
    # Check all sites running
    ssh root@$CENTRAL_IP "omd su central -c 'omd status'"
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        ssh root@$ip "omd su $site -c 'omd status'"
    done
    
    # Verify Livestatus connectivity
    log "Testing Livestatus connectivity from central..."
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        ssh root@$CENTRAL_IP "omd su central -c 'cmk -v --check-livestatus $site'"
    done
    
    log "Verification complete!"
    echo
    echo "=== ACCESS URLS ==="
    echo "Central:    https://$CENTRAL_IP/central/    (cmkadmin / $ADMIN_PASSWORD)"
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        echo "Remote $site: https://$ip/$site/  (cmkadmin / $ADMIN_PASSWORD)"
    done
    echo
    echo "Automation user: automation / $AUTOMATION_SECRET"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    log "Starting Checkmk Multi-Site Proxmox Deployment"
    log "Central: $CENTRAL_HOST ($CENTRAL_IP)"
    log "Remotes: ${#SITES[@]} sites"
    
    # Install on all hosts
    install_checkmk "$CENTRAL_HOST" "$CENTRAL_IP"
    for entry in "${SITES[@]}"; do
        IFS=':' read -r site ip desc <<< "$entry"
        install_checkmk "$site" "$ip"
    done
    
    # Create sites
    create_central
    create_remote_sites
    
    # Network
    configure_firewall
    
    # Connect
    connect_sites
    
    # Proxmox monitoring
    deploy_proxmox_monitoring
    configure_proxmox_agent
    
    # Verify
    verify_deployment
    
    log "Deployment complete! See quick reference: ~/LLM_wiki/references/checkmk-multi-site-quickref.md"
}

# Run if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi