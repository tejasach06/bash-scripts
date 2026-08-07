#!/usr/bin/env python3
"""
proxmox-inventory-extract.py

Extract VM inventory from a Proxmox cluster via REST API and write a CSV
compatible with InventoryMGR's bulk import schema.

Runs directly on a Proxmox host; authenticates as root@pam via the ticket API.
"""
import argparse
import csv
import datetime
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request


# CSV column order: required first, then the rest from InventoryMGR's ALL_HEADERS.
# This must match `app/services/csv_import.py` exactly or import will fail.
CSV_HEADERS = [
    "name", "platform", "cluster",
    "backup_enabled", "backup_ip", "backup_location", "business_owner", "cpu_cores",
    "criticality", "datacenter", "decommission_date", "description", "disks",
    "environment", "external_id", "fqdn", "ha_enabled", "last_patch_date", "last_vuln_scan_date",
    "lifecycle", "memory_mb", "monitoring_enabled", "node", "os_distribution",
    "os_family", "os_version", "owner", "pmp_enabled", "private_ip", "public_ip",
    "security_remarks", "status", "tags", "technical_owner",
]

# IP prefix → InventoryMGR column name. Longest match wins.
IP_PREFIX_MAP = {
    "10.":  "backup_ip",
    "172.": "private_ip",
    "202.": "public_ip",
}

# VM config keys that represent virtual disks.
DISK_KEYS = (
    "efidisk0", "tpmstate0",
    *[f"scsi{i}" for i in range(31)],
    *[f"virtio{i}" for i in range(31)],
    *[f"ide{i}" for i in range(5)],
    *[f"sata{i}" for i in range(6)],
)

# Proxmox ostype values that map to OS family.
OSTYPE_FAMILY = {
    "l24": "linux", "l26": "linux",
    "wxp": "windows", "w2k": "windows", "w2k3": "windows", "w2k8": "windows",
    "wvista": "windows", "win7": "windows", "win8": "windows",
    "win10": "windows", "win11": "windows",
}

# Proxmox status → InventoryMGR status.
STATUS_MAP = {
    "running": "running",
    "stopped": "powered_off",
    "paused":  "suspended",
}

# Multi-value separator inside a single CSV cell.
# InventoryMGR's csv_import.py _parse_disks splits on ";"
MULTI_SEP = ";"

# IPv4 regex for extracting IPs from free-form tag strings.
IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Size suffix → bytes multiplier (Proxmox stores disk size as "50G", "100M", etc.).
SIZE_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}

# Proxmox block-storage plugin types that use LV-style naming (vm-<vmid>-disk-N).
BLOCK_PLUGIN_TYPES = {
    "lvm", "lvmthin", "iscsi", "iscsidirect", "zfspool", "ceph-rbd",
}

# Regex for Proxmox LV name pattern.
LV_NAME_RE = re.compile(r"^vm-\d+-disk-\d+$")


def split_disk_value(val):
    """Parse a Proxmox disk config value into (storage_name, vol_name, attrs).

    Example: "ssdpool:vm-100-disk-0,size=50G,format=raw"
    Returns: ("ssdpool", "vm-100-disk-0", {"size": "50G", "format": "raw"})
    If no colon separator separates storage:vol, returns (None, first_token, attrs).
    """
    if not val:
        return None, None, {}
    attrs = {}
    parts = val.split(",")
    first = parts[0]
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k] = v
    if ":" in first:
        storage, vol = first.split(":", 1)
        return storage, vol, attrs
    return None, first, attrs


def get_storage_plugins(host, node, ticket, csrf, verify_ssl):
    """Fetch storage plugin types for a node. Returns {storage_name: plugin_type}."""
    data = api_get(
        host, f"/api2/json/nodes/{node}/storage", ticket, csrf, verify_ssl
    ) or []
    plugins = {}
    for entry in data:
        name = entry.get("storage")
        ptype = entry.get("type")
        if name and ptype:
            plugins[name] = ptype
    return plugins


def format_disk_provenance(key, storage, vol_name, plugin, size_gb):
    """Format a single disk provenance line for the description field."""
    return f"{key}\u2192{plugin}/{storage}/{vol_name}"


def format_storage_tags(storage_plugins):
    """Convert {storage: plugin} to sorted list of 'storage:<plugin>:<storage>' tags."""
    seen = set()
    tags = []
    for storage, plugin in sorted(storage_plugins.items()):
        pair = (plugin, storage)
        if pair not in seen:
            seen.add(pair)
            tags.append(f"storage:{plugin}:{storage}")
    return tags


def is_block_plugin(plugin):
    return plugin in BLOCK_PLUGIN_TYPES


def is_lv_name(name):
    return bool(LV_NAME_RE.match(name))


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Extract Proxmox VM inventory to InventoryMGR-compatible CSV."
    )
    p.add_argument("-o", "--output", default=None,
                   help="Output CSV path (default: /tmp/proxmox-inventory-<ts>.csv)")
    p.add_argument("-H", "--host", default="127.0.0.1:8006",
                   help="Proxmox host:port (default: 127.0.0.1:8006)")
    p.add_argument("-u", "--user", default="root@pam",
                   help="Proxmox username@realm (default: root@pam)")
    p.add_argument("-p", "--password", default=None,
                   help="Password. If omitted, reads PVE_PASSWORD env var, then prompts.")
    p.add_argument("--insecure", action="store_true",
                   help="Disable TLS certificate verification")
    return p.parse_args(argv)


def get_ticket(host, user, password, verify_ssl=True):
    """Authenticate against /access/ticket and return (ticket, csrf_token)."""
    url = f"https://{host}/api2/json/access/ticket"
    data = urllib.parse.urlencode({"username": user, "password": password}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    ctx = None if verify_ssl else ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body["data"]["ticket"], body["data"]["CSRFPreventionToken"]


def api_get(host, path, ticket, csrf=None, verify_ssl=True, timeout=15):
    """GET a Proxmox API endpoint and return the `data` field.

    Returns {} on HTTP 404 (so callers can check truthiness). Re-raises on
    other errors so the caller can decide whether to skip or fail.
    """
    from urllib.error import HTTPError
    url = f"https://{host}{path}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Cookie", f"PVEAuthCookie={ticket}")
    if csrf:
        req.add_header("CSRFPreventionToken", csrf)
    ctx = None if verify_ssl else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("data", {})
    except HTTPError as e:
        if e.code == 404:
            return {}
        raise


def get_cluster_name(host, ticket, csrf, verify_ssl):
    """Return the Proxmox cluster name, or 'standalone' if not clustered."""
    data = api_get(host, "/api2/json/cluster/status", ticket, csrf, verify_ssl) or []
    for entry in data:
        if entry.get("type") == "cluster":
            return entry.get("name", "standalone")
    return "standalone"


def get_nodes(host, ticket, csrf, verify_ssl):
    """Return list of node names from /nodes."""
    data = api_get(host, "/api2/json/nodes", ticket, csrf, verify_ssl) or []
    return [n["node"] for n in data if "node" in n]


def get_vms_for_node(host, node, ticket, csrf, verify_ssl):
    """Return list of VM IDs for a specific node."""
    data = api_get(
        host, f"/api2/json/nodes/{node}/qemu", ticket, csrf, verify_ssl
    ) or []
    return [v["vmid"] for v in data if "vmid" in v]


def get_vm_status(host, node, vmid, ticket, csrf, verify_ssl):
    """Fetch and return the VM status string (running/stopped/paused)."""
    data = api_get(
        host, f"/api2/json/nodes/{node}/qemu/{vmid}/status/current",
        ticket, csrf, verify_ssl
    ) or {}
    return data.get("status", "unknown")


def parse_disks(config, storage_plugins=None):
    """Extract (name, size_gb) tuples from VM config.

    Walks DISK_KEYS in order. For block storage (lvm, zfspool, iscsi, etc.),
    emits disk_name = "<plugin>:<lv_name>" instead of the bus key. File-based
    storage (dir, nfs, cifs) falls back to the bus key.

    When storage_plugins is None (e.g. API call failed), falls back to legacy
    key-only output.

    Output format: "name:sizeGB" joined by MULTI_SEP (semicolon).
    """
    out = []
    for key in DISK_KEYS:
        val = config.get(key)
        if not val or val == "none":
            continue
        m = re.search(r"size=(\d+(?:\.\d+)?)\s*([KMGT])?", val)
        if not m:
            continue
        size_num = float(m.group(1))
        unit = m.group(2) or "G"
        size_bytes = int(size_num * SIZE_UNITS[unit])
        size_gb = size_bytes // SIZE_UNITS["G"]

        # Determine disk name: extract storage and LV from the value string
        storage, vol_name, _attrs = split_disk_value(val)
        if (storage_plugins is not None
                and storage is not None
                and vol_name is not None
                and is_lv_name(vol_name)
                and is_block_plugin(storage_plugins.get(storage, ""))):
            plugin = storage_plugins[storage]
            name = f"{plugin}:{vol_name}"
        else:
            name = key  # legacy/fallback

        out.append((name, int(size_gb)))
    return out


def parse_tags(config):
    """Split Proxmox tags string on ';' and strip whitespace."""
    raw = config.get("tags", "")
    if not raw:
        return []
    return [t.strip() for t in raw.split(";") if t.strip()]


def get_vm_config(host, node, vmid, ticket, csrf, verify_ssl):
    """Fetch the full config of a single VM."""
    return api_get(
        host, f"/api2/json/nodes/{node}/qemu/{vmid}/config",
        ticket, csrf, verify_ssl,
    ) or {}


def extract_ips_from_guest_agent(iface_data):
    """Pull IPv4 addresses out of /agent/network-get-interfaces response.

    Skips loopback (127/8) and link-local (169.254/16). Ignores IPv6.
    """
    if not iface_data:
        return []
    out = []
    for iface in iface_data:
        for entry in iface.get("ip-addresses", []) or []:
            if entry.get("ip-address-type") != "ipv4":
                continue
            addr = entry.get("ip-address", "")
            if addr.startswith("127.") or addr.startswith("169.254."):
                continue
            out.append(addr)
    return out


def classify_ips(ips):
    """Group IPs into private_ip / public_ip / backup_ip buckets.

    Longest prefix match wins; unmatched IPs default to private_ip.
    """
    buckets = {"private_ip": [], "public_ip": [], "backup_ip": []}
    for ip in ips:
        best = "private_ip"  # default
        best_len = 0
        for prefix, role in IP_PREFIX_MAP.items():
            if ip.startswith(prefix) and len(prefix) > best_len:
                best = role
                best_len = len(prefix)
        buckets[best].append(ip)
    return buckets


def extract_ips_from_tags(tags):
    """Scan tags for IP addresses using IPV4_RE."""
    return list(dict.fromkeys(IPV4_RE.findall(" ".join(tags))))


def get_guest_agent_ips(host, node, vmid, ticket, csrf, verify_ssl):
    """Fetch IPs from the qemu-guest-agent."""
    data = api_get(
        host, f"/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
        ticket, csrf, verify_ssl,
    )
    return extract_ips_from_guest_agent(data)


def detect_os(host, node, vmid, config, ticket, csrf, verify_ssl):
    """Detect OS family/distribution/version from guest agent, falling back to ostype."""
    if "agent" in config:
        try:
            data = api_get(
                host,
                f"/api2/json/nodes/{node}/qemu/{vmid}/agent/get-osinfo",
                ticket, csrf, verify_ssl,
            )
            result = data.get("result", {}) if data else {}
            pretty = result.get("pretty-name", "")
            if pretty:
                family = "windows" if "windows" in pretty.lower() else "linux"
                parts = pretty.split()
                version = ""
                if len(parts) >= 2:
                    version = parts[1] if parts[1].replace(".", "").isdigit() else parts[-1]
                    distro_base = parts[0]  # e.g. "Ubuntu", "Debian", etc.
                    # Keep "Windows Server" as distro base
                    if family == "windows" and len(parts) >= 2 and parts[1].lower() == "server":
                        distro_base = "Windows Server"
                        version = parts[-1]
                else:
                    distro_base = parts[0]
                    version = ""
                return {"os_family": family, "os_distribution": distro_base, "os_version": version}
        except Exception:
            pass

    ostype = config.get("ostype", "")
    family = OSTYPE_FAMILY.get(ostype)
    return {"os_family": family, "os_distribution": None, "os_version": None}


def build_row(data):
    """Assemble a single CSV row dict matching CSV_HEADERS order."""
    name = data["name"]
    node = data["node"]
    config = data["config"]
    status = data["status"]
    os_info = data["os"]
    ips_by_role = data["ips_by_role"]
    disks = data["disks"]
    tags = data["tags"]
    fqdn = data["fqdn"]
    cluster = data["cluster"]
    vmid = data.get("vmid")  # Proxmox VMID; emitted as external_id per InventoryMGR schema
    memory_mb = data.get("memory_mb", 0)
    cpu_cores = data.get("cpu_cores", 0)
    description = data.get("description", "")
    extra_tags = data.get("extra_tags", [])

    row = {h: "" for h in CSV_HEADERS}

    row["name"] = name
    row["platform"] = "proxmox"
    row["cluster"] = cluster
    row["node"] = node
    row["external_id"] = str(vmid) if vmid is not None else ""
    row["disks"] = MULTI_SEP.join(f"{d[0]}:{d[1]}" for d in disks)
    row["status"] = STATUS_MAP.get(status, "unknown")
    row["cpu_cores"] = cpu_cores
    row["memory_mb"] = memory_mb
    row["os_family"] = os_info.get("os_family") or ""
    row["os_distribution"] = os_info.get("os_distribution") or ""
    row["os_version"] = os_info.get("os_version") or ""
    row["tags"] = MULTI_SEP.join(tags + extra_tags)
    row["fqdn"] = fqdn
    row["private_ip"] = MULTI_SEP.join(ips_by_role.get("private_ip", []))
    row["public_ip"] = MULTI_SEP.join(ips_by_role.get("public_ip", []))
    row["backup_ip"] = MULTI_SEP.join(ips_by_role.get("backup_ip", []))
    row["description"] = description
    return row


def extract_vm(host, node, vmid, ticket, csrf, verify_ssl, cluster, storage_plugins=None):
    """Orchestrate per-VM data collection and return a CSV row dict."""
    config = get_vm_config(host, node, vmid, ticket, csrf, verify_ssl)
    if not config:
        raise RuntimeError(f"empty config for VM {vmid} on {node}")

    status = get_vm_status(host, node, vmid, ticket, csrf, verify_ssl)

    try:
        cpu_cores = int(config.get("cores", 0))
    except (TypeError, ValueError):
        cpu_cores = 0
    try:
        memory_mb = int(config.get("memory", 0))
    except (TypeError, ValueError):
        memory_mb = 0

    disks, disk_provenance, storage_used = parse_disks_with_provenance(
        config, storage_plugins
    )
    tags = parse_tags(config)

    agent_enabled = config.get("agent", "")
    ips = []
    if agent_enabled and agent_enabled not in ("0", "none", ""):
        try:
            ips = get_guest_agent_ips(host, node, vmid, ticket, csrf, verify_ssl)
        except Exception as e:
            print(f"[warn] guest agent IP fetch failed for VM {vmid}: {e}", file=sys.stderr)
    if not ips:
        ips = extract_ips_from_tags(tags)
    ips_by_role = classify_ips(ips)

    os_info = detect_os(host, node, vmid, config, ticket, csrf, verify_ssl) if agent_enabled \
              else {"os_family": OSTYPE_FAMILY.get(config.get("ostype", "")),
                    "os_distribution": None, "os_version": None}

    extra_tags = format_storage_tags(storage_used)
    description = MULTI_SEP.join(disk_provenance) if disk_provenance else ""

    return build_row({
        "name": config.get("name", f"vm-{vmid}"),
        "node": node,
        "config": config,
        "status": status,
        "os": os_info,
        "ips_by_role": ips_by_role,
        "disks": disks,
        "tags": tags,
        "fqdn": config.get("name", f"vm-{vmid}"),
        "cluster": cluster,
        "vmid": vmid,  # Proxmox VMID → CSV external_id per InventoryMGR schema
        "memory_mb": memory_mb,
        "cpu_cores": cpu_cores,
        "description": description,
        "extra_tags": extra_tags,
    })


def parse_disks_with_provenance(config, storage_plugins):
    """Parse disks like parse_disks but also return provenance lines and storage tags.

    Returns (disks, provenance_lines, storage_plugins_seen) where:
      disks: list of (name, size_gb) tuples
      provenance_lines: list of provenance description strings
      storage_plugins_seen: {storage_name: plugin} for unique storages used
    """
    out_disks = []
    provenance = []
    seen_plugins = {}

    for key in DISK_KEYS:
        val = config.get(key)
        if not val or val == "none":
            continue
        m = re.search(r"size=(\d+(?:\.\d+)?)\s*([KMGT])?", val)
        if not m:
            continue
        size_num = float(m.group(1))
        unit = m.group(2) or "G"
        size_bytes = int(size_num * SIZE_UNITS[unit])
        size_gb = size_bytes // SIZE_UNITS["G"]

        storage, vol_name, _attrs = split_disk_value(val)

        if (storage_plugins is not None
                and storage is not None
                and vol_name is not None
                and is_lv_name(vol_name)
                and is_block_plugin(storage_plugins.get(storage, ""))):
            plugin = storage_plugins[storage]
            name = f"{plugin}:{vol_name}"
            seen_plugins[storage] = plugin
            provenance.append(
                format_disk_provenance(key, storage, vol_name, plugin, size_gb)
            )
        else:
            name = key  # legacy / file storage

        out_disks.append((name, int(size_gb)))
    
    return out_disks, provenance, seen_plugins


def write_csv(rows, path):
    """Write a list of row dicts to a CSV file. Returns number of data rows written."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def get_password(cli_password):
    """Resolve password: CLI arg > env var > interactive prompt."""
    if cli_password:
        return cli_password
    if "PVE_PASSWORD" in os.environ:
        return os.environ["PVE_PASSWORD"]
    import getpass
    return getpass.getpass("Proxmox password: ")


def main():
    """Entry point: parse args, authenticate, iterate nodes/VMs, write CSV."""
    args = parse_args(sys.argv[1:])

    verify_ssl = not args.insecure

    print(f"Connecting to {args.host} as {args.user}...", file=sys.stderr)
    ticket, csrf = get_ticket(args.host, args.user, args.password, verify_ssl)

    print("Fetching PLUGIN info...", file=sys.stderr)
    cluster = get_cluster_name(args.host, ticket, csrf, verify_ssl)

    print("Enumerating nodes...", file=sys.stderr)
    nodes = get_nodes(args.host, ticket, csrf, verify_ssl)

    all_rows = []
    for node in nodes:
        print(f"Scanning VMs on {node}...", file=sys.stderr)

        # Fetch storage plugins once per node
        try:
            storage_plugins = get_storage_plugins(args.host, node, ticket, csrf, verify_ssl)
        except Exception as e:
            print(f"  [warn] storage plugin fetch failed for {node}: {e}", file=sys.stderr)
            storage_plugins = None

        vmids = get_vms_for_node(args.host, node, ticket, csrf, verify_ssl)
        for vmid in vmids:
            try:
                row = extract_vm(args.host, node, vmid, ticket, csrf, verify_ssl, cluster, storage_plugins)
                all_rows.append(row)
                print(f"  VM {vmid} ({row['name']}): {row['status']}", file=sys.stderr)
            except Exception as e:
                print(f"  [error] VM {vmid} on {node}: {e}", file=sys.stderr)

    if args.output:
        out_path = args.output
    else:
        ts = datetime.datetime.now().isoformat(timespec="seconds").replace(":", "-")
        out_path = f"/tmp/proxmox-inventory-{ts}.csv"

    write_csv(all_rows, out_path)
    print(f"Wrote {len(all_rows)} VMs to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()