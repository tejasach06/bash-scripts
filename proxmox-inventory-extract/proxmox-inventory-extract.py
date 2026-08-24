#!/usr/bin/env python3
"""
proxmox-inventory-extract.py

Extract VM inventory from a Proxmox cluster via REST API and write a CSV
compatible with InventoryMGR's bulk import schema.

Runs directly on a Proxmox host; authenticates as root@pam via the ticket API.
"""
import argparse
import csv
import dataclasses
import datetime
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from typing import Any, Optional

# InventoryMGR TEMPLATE_COLUMNS from origin/main (ea6f8b6) - exact order required
TEMPLATE_COLUMNS = (
    "name", "external_id", "fqdn", "sr_id", "platform", "datacenter", "cluster", "node",
    "status", "environment", "criticality", "vm_type", "cpu_cores", "memory_mb", "disks",
    "storage_name", "storage_type", "os_family", "os_distribution", "os_version",
    "private_ip", "public_ip", "backup_ip", "owner", "business_owner", "technical_owner",
    "applications", "monitoring_enabled", "pmp_enabled", "ha_enabled", "backup_enabled",
    "backup_location", "tags", "last_patch_date", "last_vuln_scan_date", "last_verified_at",
    "decommission_date", "security_remarks", "description",
)

# IP prefix → InventoryMGR column name. Longest match wins.
IP_PREFIX_MAP = {
    "10.":  "backup_ip",
    "172.": "private_ip",
    "202.": "public_ip",
}

# Proxmox ostype values that map to OS family.
OSTYPE_FAMILY = {
    "l24": "linux", "l26": "linux",
    "wxp": "windows", "w2k": "windows", "w2k3": "windows",
    "w2k8": "windows", "wvista": "windows", "w7": "windows",
    "w8": "windows", "w10": "windows", "w11": "windows",
    "w2008": "windows", "w2012": "windows", "w2016": "windows",
    "w2019": "windows", "w2022": "windows",
    "solaris": "solaris", "openbsd": "bsd", "freebsd": "bsd", "netbsd": "bsd",
}

# Supported disk config keys in Proxmox VM config
DISK_KEY_PATTERNS = (
    "efidisk", "tpmstate",
    "scsi", "virtio", "ide", "sata", "unused",
)

# Proxmox status → InventoryMGR status mapping
STATUS_MAP = {
    "running": "running",
    "stopped": "powered_off",
}

MULTI_SEP = ";"
API_TIMEOUT = 30  # seconds, per HTTP request

@dataclasses.dataclass
class DiskRecord:
    lv_name: str
    config_key: str
    size_gib: int
    storage_id: str
    storage_name: str
    storage_type: str

    @property
    def disk_name(self) -> str:
        return f"{self.lv_name}-{self.config_key}"

    def to_csv_field(self) -> str:
        return f"{self.disk_name}:{self.size_gib}:{self.storage_name}:{self.storage_type}"


@dataclasses.dataclass
class ProxmoxClient:
    host: str
    user: str
    password: str
    verify_ssl: bool
    timeout: int = API_TIMEOUT
    ticket: str = ""
    csrf: str = ""
    def get_ticket(self) -> None:
        url = f"https://{self.host}/api2/json/access/ticket"
        data = urllib.parse.urlencode({"username": self.user, "password": self.password}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        ctx = self._ssl_context()
        with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode())
        self.ticket = body["data"]["ticket"]
        self.csrf = body["data"]["CSRFPreventionToken"]

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _headers(self) -> dict[str, str]:
        return {
            "Cookie": f"PVEAuthCookie={self.ticket}",
            "CSRFPreventionToken": self.csrf,
        }

    def api_get(self, path: str) -> Any:
        url = f"https://{self.host}{path}"
        req = urllib.request.Request(url, headers=self._headers())
        ctx = self._ssl_context()
        with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode())
        return body.get("data", [])

    def get_cluster_name(self) -> str:
        data = self.api_get("/api2/json/cluster/status")
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and entry.get("type") == "cluster":
                    return entry.get("name", "standalone")
        return "standalone"

    def get_nodes(self) -> list[str]:
        data = self.api_get("/api2/json/nodes")
        return [n["node"] for n in data if n.get("status") == "online"]

    def get_cluster_vms(self) -> list[dict]:
        """All QEMU guests cluster-wide: vmid, node, name, status, template, pool, hastate."""
        return [r for r in self.api_get("/api2/json/cluster/resources?type=vm")
                if str(r.get("id", "")).startswith("qemu/")]

    def get_vms_for_node(self, node: str) -> list[dict]:
        return self.api_get(f"/api2/json/nodes/{node}/qemu")

    def get_vm_config(self, node: str, vmid: int) -> dict:
        return self.api_get(f"/api2/json/nodes/{node}/qemu/{vmid}/config")

    def get_storage_config(self, node: str) -> list[dict]:
        return self.api_get(f"/api2/json/nodes/{node}/storage")

    def get_storage_content(self, node: str, storage: str) -> list[dict]:
        return self.api_get(f"/api2/json/nodes/{node}/storage/{storage}/content?content=images")

    def get_backup_jobs(self) -> list[dict]:
        return self.api_get("/api2/json/cluster/backup")

    def get_guest_ips(self, node: str, vmid: int) -> list[str]:
        data = self.api_get(f"/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
        ips: list[str] = []
        if not data:
            return ips
        for iface in data:
            for entry in iface.get("ip-addresses", []) or []:
                ip = entry.get("ip-address", "")
                if ip and not ip.startswith("127.") and not ip.startswith("169.254.") and ":" not in ip:
                    ips.append(ip)
        return ips

    def get_guest_os(self, node: str, vmid: int) -> dict[str, Optional[str]]:
        data = self.api_get(f"/api2/json/nodes/{node}/qemu/{vmid}/agent/get-osinfo")
        if not data:
            return {"os_family": None, "os_distribution": None, "os_version": None}
        version = data.get("version-id") or data.get("version") or None
        kernel = data.get("kernel-release") or None
        if version and kernel:
            version = f"{version} ({kernel})"
        elif not version and kernel:
            version = kernel
        return {
            "os_family": (data.get("id") or "").lower() or None,
            "os_distribution": data.get("pretty-name") or data.get("name") or None,
            "os_version": version,
        }

    def get_guest_fqdn(self, node: str, vmid: int) -> Optional[str]:
        data = self.api_get(f"/api2/json/nodes/{node}/qemu/{vmid}/agent/get-hostname")
        if not data:
            return None
        hostname = data.get("hostname") or data.get("name") or ""
        if hostname and not hostname.startswith("localhost"):
            return hostname
        return None

    def get_agent_info(self, node: str, vmid: int) -> Optional[dict]:
        """qemu-ga probe. Returns agent info dict when the agent answers, else None."""
        data = self.api_get(f"/api2/json/nodes/{node}/qemu/{vmid}/agent/info")
        if isinstance(data, dict) and data.get("version"):
            return data
        return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract Proxmox VM inventory as InventoryMGR-compatible CSV",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-o", "--output", help="Output CSV path (default: /tmp/proxmox-inventory-<ts>.csv)")
    parser.add_argument("-H", "--host", default="127.0.0.1:8006", help="Proxmox API endpoint")
    parser.add_argument("-u", "--user", default="root@pam", help="Proxmox username")
    parser.add_argument("-p", "--password", help="Password (or use PVE_PASSWORD env)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS cert verification")
    parser.add_argument("--version", action="version", version="proxmox-inventory-extract 2026-08-15")
    parser.add_argument("--timeout", type=int, default=API_TIMEOUT, help="Per-request HTTP timeout in seconds")
    return parser.parse_args(argv)


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    if "PVE_PASSWORD" in os.environ:
        return os.environ["PVE_PASSWORD"]
    try:
        import getpass
        return getpass.getpass("Proxmox password: ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(1)


def build_storage_meta(client: ProxmoxClient, node: str) -> dict[str, dict]:
    """Fetch storage config and build metadata map keyed by storage ID."""
    meta = {}
    try:
        storages = client.get_storage_config(node)
    except Exception as e:
        print(f"[warn] Failed to fetch storage config for {node}: {e}", file=sys.stderr)
        return meta
    for s in storages:
        sid = s.get("storage")
        if not sid:
            continue
        meta[sid] = {
            "storage_id": sid,
            "type": s.get("type", ""),
            "vgname": s.get("vgname", ""),
        }
    return meta


def build_volume_usage(client: ProxmoxClient, node: str, storage_ids: list[str]) -> dict[str, int]:
    """volid -> allocated GiB from storage content 'used'; 0 when unreported."""
    usage: dict[str, int] = {}
    for sid in storage_ids:
        try:
            content = client.get_storage_content(node, sid)
        except Exception as e:
            print(f"[warn] Failed to fetch content for storage {sid} on {node}: {e}", file=sys.stderr)
            continue
        if isinstance(content, list):
            for vol in content:
                volid = vol.get("volid")
                if volid:
                    usage[volid] = int(vol.get("used") or 0) // (1024 ** 3)
    return usage


def parse_disks(config: dict, storage_meta: dict, volume_usage: dict[str, int]) -> list[DiskRecord]:
    """Parse all supported disk config keys into structured DiskRecord list."""
    disks: list[DiskRecord] = []
    for key, value in config.items():
        if not any(key.startswith(p) for p in DISK_KEY_PATTERNS):
            continue
        if not value or value == "none":
            continue
        if isinstance(value, str) and "media=cdrom" in value:
            continue

        lv_name, provisioned_size_gib, storage_id, size_found = parse_disk_value(value)
        volid = str(value).split(",")[0]
        size_gib = volume_usage.get(volid) or provisioned_size_gib

        if not lv_name or (size_gib == 0 and not size_found and (volid not in volume_usage or volume_usage.get(volid, 0) == 0)):
            print(f"[warn] Skipping malformed disk {key}={value}", file=sys.stderr)
            continue

        meta = storage_meta.get(storage_id, {})
        storage_name = meta.get("vgname") or storage_id
        storage_type = meta.get("type", "")

        disks.append(DiskRecord(
            lv_name=lv_name,
            config_key=key,
            size_gib=size_gib,
            storage_id=storage_id,
            storage_name=storage_name,
            storage_type=storage_type,
        ))
    return disks


def parse_disk_value(value: str) -> tuple[str, int, str, bool]:
    """Parse Proxmox disk config value into (lv_name, size_gib, storage_id, size_found)."""
    if not value:
        return "", 0, "", False

    parts = value.split(",")
    main = parts[0]
    if ":" not in main:
        return "", 0, "", False

    storage_id, volume = main.split(":", 1)
    lv_name = volume.split("/")[-1]

    size_gib = 0
    size_found = False
    for part in parts[1:]:
        part = part.strip()
        if part.startswith("size="):
            size_str = part[5:]
            size_gib = parse_size_to_gib(size_str)
            size_found = True
            break

    return lv_name, size_gib, storage_id, size_found


def parse_size_to_gib(size_str: str) -> int:
    """Parse Proxmox size string (e.g., '50G', '512M', '1T') to GiB."""
    size_str = size_str.strip().upper()
    if not size_str:
        return 0
    match = re.match(r"^(\d+(?:\.\d+)?)([KMGT]?)B?$", size_str)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2) or "B"
    if unit == "K":
        return int(value / (1024 * 1024))
    elif unit == "M":
        return int(value / 1024)
    elif unit == "G":
        return int(value)
    elif unit == "T":
        return int(value * 1024)
    return 0


def classify_ips(ips: list[str]) -> dict[str, list[str]]:
    """Classify IPs by prefix map into InventoryMGR role columns."""
    result = {"private_ip": [], "public_ip": [], "backup_ip": []}
    for ip in ips:
        matched = False
        for prefix, column in IP_PREFIX_MAP.items():
            if ip.startswith(prefix):
                result[column].append(ip)
                matched = True
                break
        if not matched:
            result["private_ip"].append(ip)
    return result


def extract_ips_from_tags(tags: str) -> list[str]:
    """Fallback: extract IP-like strings from Proxmox tags."""
    if not tags:
        return []
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return ip_pattern.findall(tags)


def parse_tags(config: dict) -> str:
    """Extract and join Proxmox tags with semicolon."""
    raw = config.get("tags", "")
    if not raw:
        return ""
    return MULTI_SEP.join(t.strip() for t in raw.split(";") if t.strip())


def map_status(proxmox_status: str) -> str:
    return STATUS_MAP.get(proxmox_status, "unknown")

def total_vcpus(config: dict) -> str:
    """Proxmox vCPU count = cores * sockets; sockets defaults to 1."""
    try:
        cores = int(config.get("cores", 0) or 0)
        sockets = int(config.get("sockets", 1) or 1)
    except (TypeError, ValueError):
        return ""
    if cores <= 0:
        return ""
    return str(cores * sockets)



def map_os_family(ostype: str, guest_os_family: Optional[str]) -> Optional[str]:
    if guest_os_family:
        return guest_os_family
    if ostype in OSTYPE_FAMILY:
        return OSTYPE_FAMILY[ostype]
    if ostype:
        return "other"
    return ""


def add_tag(tags: str, tag: str) -> str:
    parts = [t for t in tags.split(MULTI_SEP) if t]
    if tag not in parts:
        parts.append(tag)
    return MULTI_SEP.join(parts)


def backup_coverage(jobs: list[dict], vmid: int, pool: str) -> tuple[str, str]:
    """(backup_enabled, backup_location) from vzdump job config."""
    for job in jobs:
        if str(job.get("enabled", 1)) == "0":
            continue

        vmids = set()
        for v in str(job.get("vmid", "")).split(","):
            v = v.strip()
            if v.isdigit():
                vmids.add(int(v))

        excludes = set()
        for v in str(job.get("exclude", "")).split(","):
            v = v.strip()
            if v.isdigit():
                excludes.add(int(v))

        job_all = bool(job.get("all"))
        job_pool = str(job.get("pool", ""))

        is_covered = (
            (vmid in vmids)
            or (job_all and vmid not in excludes)
            or (bool(pool) and job_pool == pool)
        )
        if is_covered:
            return ("true", str(job.get("storage", "")))

    return ("false", "")


def serialize_vm(
    vmid: int,
    config: dict,
    status: str,
    node: str,
    cluster_name: str,
    disks: list[DiskRecord],
    ips_by_role: dict[str, list[str]],
    os_info: dict[str, Optional[str]],
    fqdn: Optional[str],
    description: str,
    tags: str,
    resource: dict,
    backup_enabled: str,
    backup_location: str,
    verified_at: str,
) -> dict[str, str]:
    """Map internal VM data to InventoryMGR CSV row (all TEMPLATE_COLUMNS)."""
    row = {col: "" for col in TEMPLATE_COLUMNS}

    # Identity
    row["name"] = config.get("name", f"vm-{vmid}")
    row["external_id"] = str(vmid)
    row["fqdn"] = fqdn or ""
    row["sr_id"] = ""
    row["platform"] = "proxmox"

    # Placement
    row["datacenter"] = ""
    row["cluster"] = cluster_name
    row["node"] = node

    # Classification
    row["status"] = map_status(status)
    row["environment"] = ""
    row["criticality"] = ""
    row["vm_type"] = ""

    # Capacity
    row["cpu_cores"] = total_vcpus(config)
    row["memory_mb"] = str(config.get("memory", ""))
    row["disks"] = MULTI_SEP.join(d.to_csv_field() for d in disks)
    row["storage_name"] = ""  # per-disk storage in disks column
    row["storage_type"] = ""

    # OS
    ostype = config.get("ostype", "")
    row["os_family"] = map_os_family(ostype, os_info.get("os_family")) or ""
    row["os_distribution"] = os_info.get("os_distribution") or ""
    row["os_version"] = os_info.get("os_version") or ""

    # Network
    row["private_ip"] = MULTI_SEP.join(ips_by_role["private_ip"])
    row["public_ip"] = MULTI_SEP.join(ips_by_role["public_ip"])
    row["backup_ip"] = MULTI_SEP.join(ips_by_role["backup_ip"])

    # Ownership
    row["owner"] = ""
    row["business_owner"] = ""
    row["technical_owner"] = ""
    row["applications"] = ""

    # Operations
    row["monitoring_enabled"] = ""
    row["pmp_enabled"] = ""
    row["ha_enabled"] = "true" if resource.get("hastate") else "false"
    row["backup_enabled"] = backup_enabled
    row["backup_location"] = backup_location
    if resource.get("template") == 1 or resource.get("template") == "1":
        tags = add_tag(tags, "template")
    row["tags"] = tags

    # Compliance dates
    row["last_patch_date"] = ""
    row["last_vuln_scan_date"] = ""
    row["last_verified_at"] = verified_at
    row["decommission_date"] = ""

    # Notes
    row["security_remarks"] = ""
    row["description"] = description

    return row


def write_csv(rows: list[dict], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=TEMPLATE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def extract_vm(
    client: ProxmoxClient,
    node: str,
    vmid: int,
    cluster_name: str,
    storage_meta: dict,
    resource: dict,
    backup_jobs: list[dict],
    volume_usage: dict[str, int],
    verified_at: str,
    status: str = "unknown",
) -> Optional[dict]:
    """Extract a single VM's inventory. Returns None on skip."""
    try:
        config = client.get_vm_config(node, vmid)
    except Exception as e:
        print(f"[warn] Failed to get config for VM {vmid} on {node}: {e}", file=sys.stderr)
        return None

    if status not in ("running", "stopped"):
        # Still try to extract; status will be 'unknown'
        pass
    description = config.get("description", "")
    tags = parse_tags(config)

    # Disks
    disks = parse_disks(config, storage_meta, volume_usage)

    # Guest agent data (probed on running VMs)
    agent_live = False
    ips: list[str] = []
    os_info: dict[str, Optional[str]] = {"os_family": None, "os_distribution": None, "os_version": None}
    fqdn: Optional[str] = None

    if status == "running":
        try:
            if client.get_agent_info(node, vmid):
                agent_live = True
        except Exception as e:
            print(f"[warn] Guest agent probe failed for VM {vmid}: {e}", file=sys.stderr)

    if agent_live:
        try:
            ips = client.get_guest_ips(node, vmid)
        except Exception as e:
            print(f"[warn] Guest agent IP fetch failed for VM {vmid}: {e}", file=sys.stderr)

        if not ips:
            ips = extract_ips_from_tags(tags)

        try:
            os_info = client.get_guest_os(node, vmid)
        except Exception as e:
            print(f"[warn] Guest agent OS fetch failed for VM {vmid}: {e}", file=sys.stderr)

        try:
            fqdn = client.get_guest_fqdn(node, vmid)
        except Exception as e:
            print(f"[warn] Guest agent FQDN fetch failed for VM {vmid}: {e}", file=sys.stderr)
    else:
        ips = extract_ips_from_tags(tags)
    ips_by_role = classify_ips(ips)

    pool = str(resource.get("pool") or config.get("pool") or "")
    backup_enabled, backup_location = backup_coverage(backup_jobs, vmid, pool)

    return serialize_vm(
        vmid=vmid,
        config=config,
        status=status,
        node=node,
        cluster_name=cluster_name,
        disks=disks,
        ips_by_role=ips_by_role,
        os_info=os_info,
        fqdn=fqdn,
        description=description,
        tags=tags,
        resource=resource,
        backup_enabled=backup_enabled,
        backup_location=backup_location,
        verified_at=verified_at,
    )


def main() -> int:
    args = parse_args(sys.argv[1:])
    password = resolve_password(args)

    client = ProxmoxClient(
        host=args.host,
        user=args.user,
        password=password,
        verify_ssl=not args.insecure,
        timeout=args.timeout,
    )
    try:
        client.get_ticket()
    except Exception as e:
        print(f"[error] Authentication failed: {e}", file=sys.stderr)
        return 1

    cluster_name = client.get_cluster_name()

    nodes = client.get_nodes()
    if not nodes:
        print("[warn] No online nodes found", file=sys.stderr)

    partial_failure = False

    try:
        backup_jobs = client.get_backup_jobs()
    except Exception as e:
        print(f"[warn] Failed to fetch backup jobs: {e}", file=sys.stderr)
        backup_jobs = []
        partial_failure = True

    verified_at = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    all_rows: list[dict] = []
    storage_meta_cache: dict[str, dict[str, dict]] = {}
    volume_usage_cache: dict[str, dict[str, int]] = {}

    def get_node_caches(node: str) -> tuple[dict[str, dict], dict[str, int]]:
        if node not in storage_meta_cache:
            sm = build_storage_meta(client, node)
            storage_meta_cache[node] = sm
            volume_usage_cache[node] = build_volume_usage(client, node, list(sm.keys()))
        return storage_meta_cache[node], volume_usage_cache[node]

    # VM discovery via cluster resources with per-node fallback
    use_fallback = False
    try:
        cluster_vms = client.get_cluster_vms()
    except Exception as e:
        print(f"[warn] cluster/resources unavailable, falling back to per-node enumeration: {e}", file=sys.stderr)
        partial_failure = True
        use_fallback = True
        cluster_vms = []

    if not use_fallback:
        for resource in cluster_vms:
            vmid = resource.get("vmid")
            if vmid is None:
                continue
            node = resource.get("node", "")
            status = resource.get("status", "unknown")
            storage_meta, volume_usage = get_node_caches(node)
            row = extract_vm(
                client=client,
                node=node,
                vmid=vmid,
                cluster_name=cluster_name,
                storage_meta=storage_meta,
                resource=resource,
                backup_jobs=backup_jobs,
                volume_usage=volume_usage,
                verified_at=verified_at,
                status=status,
            )
            if row is not None:
                all_rows.append(row)
            else:
                partial_failure = True
    else:
        for node in nodes:
            storage_meta, volume_usage = get_node_caches(node)
            try:
                vms = client.get_vms_for_node(node)
            except Exception as e:
                print(f"[warn] Failed to enumerate VMs on node {node}: {e}", file=sys.stderr)
                partial_failure = True
                continue

            for vm in vms:
                vmid = vm.get("vmid")
                if vmid is None:
                    continue
                status = vm.get("status", "unknown")
                resource = vm
                row = extract_vm(
                    client=client,
                    node=node,
                    vmid=vmid,
                    cluster_name=cluster_name,
                    storage_meta=storage_meta,
                    resource=resource,
                    backup_jobs=backup_jobs,
                    volume_usage=volume_usage,
                    verified_at=verified_at,
                    status=status,
                )
                if row is not None:
                    all_rows.append(row)
                else:
                    partial_failure = True

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        ts = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
        output_path = f"/tmp/proxmox-inventory-{ts}.csv"

    try:
        write_csv(all_rows, output_path)
    except Exception as e:
        print(f"[error] Failed to write CSV: {e}", file=sys.stderr)
        return 1

    print(f"[ok] Wrote {len(all_rows)} VM(s) to {output_path}")
    if partial_failure:
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())