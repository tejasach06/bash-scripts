# Checkmk Multi-Site Proxmox Deployment

Deploys a Checkmk monitoring setup with **1 Central site + N Remote sites** for monitoring Proxmox clusters. Target: openSUSE Leap 15.6+ / Tumbleweed.

## Quick Start

```bash
# Review and edit configuration in the script first
vim checkmk-deploy-multisite.sh

# Run deployment (as root, from a machine with SSH access to all targets)
sudo ./checkmk-deploy-multisite.sh
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CHECKMK CENTRAL                          │
│  checkmk-central (10.0.0.10)                                │
│  - Livestatus TCP: 6557                                     │
│  - Agent Receiver: 8007                                     │
│  - Web UI: https://checkmk-central/central                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Livestatus + Agent Receiver
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  REMOTE SITE A  │ │  REMOTE SITE B  │ │  REMOTE SITE C  │
│  Cluster A      │ │  Cluster B      │ │  Cluster C      │
│  10.10.1.50     │ │  10.20.1.50     │ │  10.30.1.50     │
│  - Agent        │ │  - Agent        │ │  - Agent        │
│  - PVE Plugin   │ │  - PVE Plugin   │ │  - PVE Plugin   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Configuration

Edit the **CONFIGURATION** section at the top of the script:

```bash
# Central site
CENTRAL_HOST="checkmk-central"
CENTRAL_IP="10.0.0.10"

# Remote sites (name:ip:description)
SITES=(
  "remote-cluster-a:10.10.1.50:Proxmox Cluster A"
  "remote-cluster-b:10.20.1.50:Proxmox Cluster B"
  "remote-cluster-c:10.30.1.50:Proxmox Cluster C"
)

# Ports
LIVESTATUS_PORT=6557
AGENT_RECEIVER_PORT=8007

# Credentials (override via env)
ADMIN_PASSWORD="${CHECKMK_ADMIN_PASSWORD:-changeme123}"
AUTOMATION_SECRET="${CHECKMK_AUTOMATION_SECRET:-auto-secret-$(openssl rand -hex 16)}"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CHECKMK_ADMIN_PASSWORD` | Central site admin password | `changeme123` |
| `CHECKMK_AUTOMATION_SECRET` | Automation API secret | auto-generated |

## What It Does

### 1. Install Checkmk on All Hosts
- Adds Checkmk repository (openSUSE Tumbleweed)
- Installs `check-mk-raw` package
- Enables `apache2` and `xinetd`

### 2. Create Central Site
- `omd create central`
- Configures:
  - `LIVESTATUS_TCP=on` + port 6557
  - `AGENT_RECEIVER_TCP=on` + port 8007
  - `AUTOMATION_SECRET`
- Creates automation user for API access

### 3. Create Remote Sites
- `omd create <site-name>` on each remote
- Configures Livestatus to forward to central
- Configures Agent Receiver to forward to central

### 4. Deploy Checkmk Agent + PVE Plugin
On each Proxmox node in each cluster:
- Installs `check-mk-agent`
- Configures `xinetd` for agent (port 6556)
- Deploys **Proxmox VE monitoring plugin** (`mk_pve`) via agent plugins
- Plugin collects: VM status, storage, Ceph, cluster health, backup status

### 5. Register Remotes in Central
- Uses automation API to create host entries for each remote site
- Configures Livestatus connection to each remote
- Sets up host groups per cluster

### 6. Configure Proxmox Host Monitoring
- Adds each Proxmox node as a host in central
- Assigns `pve` host tag for plugin detection
- Creates service discovery rules for PVE services

## Requirements

- **Controller machine**: SSH access to all targets as root
- **Target OS**: openSUSE Leap 15.6+ or Tumbleweed
- **Network**: All hosts reachable on ports 22, 6556, 6557, 8007, 443
- **Proxmox**: VE 7.x/8.x with guest agent on VMs (for VM monitoring)

## Ports Reference

| Service | Port | Direction |
|---------|------|-----------|
| SSH | 22 | Controller → All |
| Checkmk Agent | 6556 | Central/Remote → Proxmox nodes |
| Livestatus | 6557 | Central ↔ Remotes |
| Agent Receiver | 8007 | Remotes → Central |
| HTTPS (Web UI) | 443 | Users → Central |

## Post-Deployment

### Access Web UI
```
https://checkmk-central/central
User: cmkadmin
Password: $CHECKMK_ADMIN_PASSWORD
```

### Verify Livestatus
```bash
# From central
echo 'GET hosts\nColumns: name address\nOutput: json' | nc localhost 6557

# From remote
echo 'GET hosts\nColumns: name address\nOutput: json' | nc localhost 6557
```

### Verify Agent Receiver
```bash
# On central
ss -ltnp | grep 8007

# Test from remote
echo '<<<check_mk>>> Version: 2.3.0p1' | nc central-ip 8007
```

### Service Discovery
```bash
# On central (via automation)
omd su central -c "cmk -II <hostname>"
omd su central -c "cmk -O"
```

## Customization

### Add More Remote Sites
Add entries to `SITES` array:
```bash
SITES=(
  "existing-site:10.10.1.50:Existing Cluster"
  "new-cluster-d:10.40.1.50:Proxmox Cluster D"
  "new-cluster-e:10.50.1.50:Proxmox Cluster E"
)
```

### Use Different Checkmk Version
Edit repository URL in `install_checkmk()` function.

### Custom Agent Plugins
Add plugins to `/usr/lib/check_mk_agent/plugins/` on Proxmox nodes before running, or extend `deploy_agent_plugin()`.

## Troubleshooting

**Site creation fails**
- Check `omd create` output
- Ensure hostname resolves: `getent hosts checkmk-central`
- Port conflicts: `ss -ltnp | grep -E '655[67]|8007'`

**Livestatus not connecting**
- Firewall: `firewall-cmd --add-port=6557/tcp --permanent`
- Check `LIVESTATUS_TCP=on` in `omd config show`

**Agent plugin not executing**
- Verify plugin is executable: `chmod +x /usr/lib/check_mk_agent/plugins/mk_pve`
- Test manually: `/usr/lib/check_mk_agent/plugins/mk_pve`
- Check xinetd config: `cat /etc/xinetd.d/check_mk`

**Automation API errors**
- Verify `AUTOMATION_SECRET` matches on central
- Check `omd su central -c "cmk -l"` lists automation user

## Security Notes

- Change default `ADMIN_PASSWORD` before production use
- Use strong `AUTOMATION_SECRET` (32+ chars)
- Restrict port 6557/8007 to monitoring network only
- Consider TLS for Livestatus (Checkmk 2.3+ supports it)

## License

MIT License — see [LICENSE](../LICENSE) in repo root.