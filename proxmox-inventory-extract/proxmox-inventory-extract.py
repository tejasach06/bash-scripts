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
import glob
import ipaddress
import json
import os
import re
import socket
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

# Guest-agent os ids that are Linux distributions. Agent ids outside this set
# are matched by the windows keyword check, then give up (blank).
AGENT_LINUX_IDS = {
    "alpine", "almalinux", "amzn", "arch", "centos", "debian", "fedora",
    "gentoo", "linuxmint", "ol", "opensuse", "opensuse-leap",
    "opensuse-tumbleweed", "rhel", "rocky", "sles", "suse", "ubuntu",
}

# Supported disk config key regex in Proxmox VM config
DISK_KEY_RE = re.compile(r"^(?:scsi|virtio|ide|sata|unused|efidisk|tpmstate)\d+$")

# Proxmox status → InventoryMGR status mapping
STATUS_MAP = {
    "running": "running",
    "stopped": "powered_off",
}
MULTI_SEP = ";"
API_TIMEOUT = 30  # seconds, per HTTP request

ENUM_COLUMNS = {
    "status": {"running", "powered_off", "decommissioned", "unknown"},
    "environment": {"production", "development", "testing", "uat", "dr", "staging", "sandbox"},
    "criticality": {"low", "medium", "high", "critical"},
    "os_family": {"linux", "windows"},
    "vm_type": {"permanent", "temporary"},
}
BOOL_COLUMNS = ("monitoring_enabled", "pmp_enabled", "ha_enabled", "backup_enabled")
INT_COLUMNS = ("cpu_cores", "memory_mb")
DATE_COLUMNS = ("last_patch_date", "last_vuln_scan_date", "last_verified_at", "decommission_date")
REQUIRED_COLUMNS = ("name", "platform", "cluster")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def sanitize_row(row: dict[str, str]) -> list[str]:
    """Blank any cell InventoryMGR's importer would reject; return warnings."""
    warnings = []
    for col, valid_set in ENUM_COLUMNS.items():
        val = row.get(col, "")
        if val and val not in valid_set:
            warnings.append(f"{col} '{val}' not importable, blanked")
            row[col] = ""

    for col in BOOL_COLUMNS:
        val = row.get(col, "")
        if val and val.lower() not in {"true", "false", "yes", "no", "1", "0"}:
            warnings.append(f"{col} '{val}' not a valid boolean, blanked")
            row[col] = ""

    for col in INT_COLUMNS:
        val = row.get(col, "")
        if val and not (val.isdigit() and int(val) >= 0):
            warnings.append(f"{col} '{val}' not a valid integer >= 0, blanked")
            row[col] = ""

    for col in DATE_COLUMNS:
        val = row.get(col, "")
        if val and not ISO_DATE_RE.match(val):
            warnings.append(f"{col} '{val}' not a valid ISO date YYYY-MM-DD, blanked")
            row[col] = ""

    for col in REQUIRED_COLUMNS:
        if not row.get(col, ""):
            warnings.append(f"{col} is blank; InventoryMGR will reject this row")

    return warnings
@dataclasses.dataclass
class DiskRecord:
    lv_name: str
    config_key: str
    size_gib: int
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
    _ctx: Optional[ssl.SSLContext] = None
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
        if self._ctx is None:
            self._ctx = ssl.create_default_context()
            if not self.verify_ssl:
                self._ctx.check_hostname = False
                self._ctx.verify_mode = ssl.CERT_NONE
        return self._ctx

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

    def get_ha_vmids(self) -> set[int]:
        """VMIDs managed by HA, from /cluster/ha/resources (sid like 'vm:100')."""
        try:
            data = self.api_get("/api2/json/cluster/ha/resources")
        except Exception:
            return set()
        vmids = set()
        if isinstance(data, list):
            for entry in data:
                sid = str(entry.get("sid", ""))
                if sid.startswith("vm:"):
                    v_str = sid[3:]
                    if v_str.isdigit():
                        vmids.add(int(v_str))
        return vmids
    def agent_get(self, node: str, vmid: int, command: str) -> Any:
        """GET a guest-agent command. PVE wraps qemu-ga output as
        {"data": {"result": ...}}; bare payloads are passed through unchanged."""
        data = self.api_get(f"/api2/json/nodes/{node}/qemu/{vmid}/agent/{command}")
        if isinstance(data, dict) and "result" in data:
            return data["result"]
        return data

    def get_guest_ips(self, node: str, vmid: int) -> list[str]:
        data = self.agent_get(node, vmid, "network-get-interfaces")
        ips: list[str] = []
        if not data:
            return ips
        for iface in data:
            for entry in iface.get("ip-addresses", []) or []:
                ip = valid_ipv4(entry.get("ip-address", ""))
                if ip and ip not in ips:
                    ips.append(ip)
        return ips

    def get_guest_os(self, node: str, vmid: int) -> dict[str, Optional[str]]:
        data = self.agent_get(node, vmid, "get-osinfo")
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
        data = self.agent_get(node, vmid, "get-host-name")
        if not data:
            return None
        hostname = data.get("host-name") or data.get("hostname") or ""
        if hostname and "." in hostname and not hostname.startswith("localhost"):
            return hostname
        return None

    def get_agent_info(self, node: str, vmid: int) -> Optional[dict]:
        """qemu-ga probe. Returns agent info dict when the agent answers, else None."""
        data = self.agent_get(node, vmid, "info")
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
    parser.add_argument("--no-probe", action="store_true", help="Disable reverse DNS and local ARP/DHCP lease lookups")
    parser.add_argument("--probe-timeout", type=float, default=2.0, help="Reverse DNS timeout in seconds")
    return parser.parse_args(argv)


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    env_pw = os.environ.get("PVE_PASSWORD")
    if env_pw:
        return env_pw
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


def build_volume_sizes(client: ProxmoxClient, node: str, storage_ids: list[str]) -> dict[str, int]:
    """volid -> provisioned GiB from storage content 'size'; 0 when unreported."""
    sizes: dict[str, int] = {}
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
                    sizes[volid] = int(vol.get("size") or 0) // (1024 ** 3)
    return sizes


def parse_disks(config: dict, storage_meta: dict, volume_sizes: dict[str, int]) -> list[DiskRecord]:
    """Parse all supported disk config keys into structured DiskRecord list."""
    disks: list[DiskRecord] = []
    for key in sorted(config.keys()):
        value = config[key]
        if not DISK_KEY_RE.match(key):
            continue
        if not value or value == "none":
            continue
        if isinstance(value, str) and "media=cdrom" in value:
            continue

        lv_name, size_gib, storage_id, volid = parse_disk_value(value)
        if not size_gib:
            size_gib = volume_sizes.get(volid, 0)

        if not lv_name:
            print(f"[warn] Skipping malformed disk {key}={value}", file=sys.stderr)
            continue

        meta = storage_meta.get(storage_id, {})
        storage_name = meta.get("vgname") or storage_id
        storage_type = meta.get("type", "")

        disks.append(DiskRecord(
            lv_name=lv_name,
            config_key=key,
            size_gib=size_gib,
            storage_name=storage_name,
            storage_type=storage_type,
        ))
    return disks

def parse_disk_value(value: str) -> tuple[str, int, str, str]:
    """Parse a Proxmox disk config value into (lv_name, size_gib, storage_id, volid).

    size_gib is 0 when the config carries no size= (caller falls back to storage content).
    """
    parts = str(value or "").split(",")
    main = parts[0]
    if not main or ":" not in main:
        return "", 0, "", ""
    storage_id, volume = main.split(":", 1)
    size_gib = next((parse_size_to_gib(p.strip()[5:]) for p in parts[1:]
                     if p.strip().startswith("size=")), 0)
    return volume.split("/")[-1], size_gib, storage_id, main


_UNIT_BYTES = {"": 1, "B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


def parse_size_to_gib(size_str: str) -> int:
    """Parse Proxmox size string (e.g., '50G', '512M', '1T') to GiB; round up sub-GiB non-zero to 1."""
    size_str = size_str.strip().upper()
    m = re.match(r"^(\d+(?:\.\d+)?)([KMGT]?)B?$", size_str)
    if not m:
        return 0
    total = float(m.group(1)) * _UNIT_BYTES[m.group(2)]
    if total <= 0:
        return 0
    return max(1, int(total // (1024 ** 3)))


def valid_ipv4(value: str) -> str:
    """Canonical IPv4 string, or '' when the value is not a usable address.

    Strips a /CIDR suffix; rejects loopback, link-local, multicast,
    unspecified and IPv6, matching what the guest-agent path already filters.
    """
    val = (value or "").strip().split("/", 1)[0].strip()
    if not val:
        return ""
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        return ""
    if ip.version != 4:
        return ""
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return ""
    return str(ip)


def config_ips(config: dict) -> list[str]:
    """IPv4 addresses declared in cloud-init ipconfigN keys (ip=10.0.0.5/24)."""
    ips = []
    keys = sorted(
        [k for k in config if re.match(r"^ipconfig\d+$", k)],
        key=lambda k: int(k[8:])
    )
    for k in keys:
        val = str(config[k])
        for part in val.split(","):
            part = part.strip()
            if part.startswith("ip="):
                raw_ip = part[3:]
                if raw_ip.lower() == "dhcp":
                    continue
                v_ip = valid_ipv4(raw_ip)
                if v_ip and v_ip not in ips:
                    ips.append(v_ip)
    return ips


def config_macs(config: dict) -> list[str]:
    """Lowercase MACs from netN keys, e.g. 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0'."""
    macs = []
    mac_re = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
    keys = sorted(
        [k for k in config if re.match(r"^net\d+$", k)],
        key=lambda k: int(k[3:])
    )
    for k in keys:
        val = str(config[k])
        m = mac_re.search(val)
        if m:
            mac = m.group(1).lower()
            if mac not in macs:
                macs.append(mac)
    return macs


def classify_ips(ips: list[str]) -> dict[str, list[str]]:
    """10/8 is the backup network; every other usable IPv4 is private. public_ip stays human-curated."""
    result = {"private_ip": [], "backup_ip": []}
    for raw_ip in dict.fromkeys(ips):
        ip = valid_ipv4(raw_ip)
        if not ip:
            continue
        result["backup_ip" if ip.startswith("10.") else "private_ip"].append(ip)
    return result
ARP_PATH = "/proc/net/arp"
DNSMASQ_LEASE_GLOBS = ("/var/lib/misc/dnsmasq.*.leases", "/var/lib/dnsmasq/*.leases")


def read_arp_table(path: str = ARP_PATH) -> dict[str, list[str]]:
    """mac (lowercase) -> IPv4s from /proc/net/arp, skipping incomplete (flags 0x0) rows."""
    res: dict[str, list[str]] = {}
    if not os.path.isfile(path):
        return res
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception:
        return res
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        ip_raw, flags_raw, mac_raw = parts[0], parts[2], parts[3]
        if flags_raw == "0x0":
            continue
        v_ip = valid_ipv4(ip_raw)
        mac = mac_raw.lower()
        if v_ip and mac and mac != "00:00:00:00:00:00":
            if mac not in res:
                res[mac] = []
            if v_ip not in res[mac]:
                res[mac].append(v_ip)
    return res


def read_dhcp_leases(globs: tuple[str, ...] = DNSMASQ_LEASE_GLOBS) -> tuple[dict[str, list[str]], dict[str, str]]:
    """(mac -> IPv4s, mac -> hostname) from dnsmasq leases: 'expiry mac ip hostname clientid'."""
    mac_to_ips: dict[str, list[str]] = {}
    mac_to_host: dict[str, str] = {}
    seen_files: set[str] = set()
    for g in globs:
        for filepath in glob.glob(g):
            if filepath in seen_files:
                continue
            seen_files.add(filepath)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
            except Exception as e:
                print(f"[warn] Failed to read lease file {filepath}: {e}", file=sys.stderr)
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mac_raw, ip_raw, host_raw = parts[1], parts[2], parts[3]
                mac = mac_raw.lower()
                v_ip = valid_ipv4(ip_raw)
                if v_ip and mac:
                    if mac not in mac_to_ips:
                        mac_to_ips[mac] = []
                    if v_ip not in mac_to_ips[mac]:
                        mac_to_ips[mac].append(v_ip)
                if host_raw and host_raw != "*" and mac and "." in host_raw and not host_raw.startswith("localhost"):
                    mac_to_host[mac] = host_raw
    return mac_to_ips, mac_to_host


def reverse_dns(ip: str) -> str:
    """PTR name for ip when it is a dotted non-localhost name, else ''."""
    if not ip:
        return ""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, IndexError):
        return ""
    if name and "." in name and not name.startswith("localhost"):
        return name
    return ""


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


def resource_num(resource: dict, key: str, divisor: int = 1) -> str:
    """Positive integer from a cluster/resources field, floor-divided by divisor, else ''."""
    val = resource.get(key)
    if val is None or val == "":
        return ""
    try:
        num = int(float(val)) // divisor
    except (TypeError, ValueError):
        return ""
    return str(num) if num > 0 else ""


def total_vcpus(config: dict) -> str:
    """Proxmox vCPU count = cores * sockets; both default to 1 when at least one is present."""
    c_val = config.get("cores")
    s_val = config.get("sockets")
    if c_val is None and s_val is None:
        return ""
    try:
        cores = int(1 if c_val is None or c_val == "" else c_val)
        sockets = int(1 if s_val is None or s_val == "" else s_val)
    except (TypeError, ValueError):
        return ""
    if cores <= 0 or sockets <= 0:
        return ""
    return str(cores * sockets)

def map_os_family(ostype: str, guest_os_family: Optional[str]) -> str:
    """InventoryMGR os_family ('linux' | 'windows' | '').

    Proxmox ostype values are l24/l26 (linux), w*/win* (windows), and
    solaris/other/*bsd (unmappable). The guest-agent id only resolves a
    missing ostype.
    """
    ot = (ostype or "").lower()
    if ot.startswith("l"):
        return "linux"
    if ot.startswith("w"):
        return "windows"
    if ot:
        return ""  # solaris, other, *bsd: not importable
    g_fam = (guest_os_family or "").lower()
    if g_fam in AGENT_LINUX_IDS:
        return "linux"
    if "windows" in g_fam or "mswin" in g_fam:
        return "windows"
    return ""


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
    ha_vmids: Optional[set[int]] = None,
) -> dict[str, str]:
    """Map internal VM data to InventoryMGR CSV row (all TEMPLATE_COLUMNS)."""
    row = {col: "" for col in TEMPLATE_COLUMNS}

    # Identity
    row["name"] = config.get("name") or resource.get("name") or f"vm-{vmid}"
    row["external_id"] = str(vmid)
    row["fqdn"] = fqdn or ""
    row["sr_id"] = ""
    row["platform"] = "proxmox"
    # Placement
    row["datacenter"] = ""
    row["cluster"] = cluster_name
    row["node"] = node

    # Classification
    row["status"] = STATUS_MAP.get(status, "unknown")
    row["environment"] = ""
    row["criticality"] = ""
    row["vm_type"] = ""

    # Capacity
    row["cpu_cores"] = total_vcpus(config) or resource_num(resource, "maxcpu")
    row["memory_mb"] = str(config.get("memory") or "") or resource_num(resource, "maxmem", 1024 * 1024)
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
    row["backup_ip"] = MULTI_SEP.join(ips_by_role.get("backup_ip", []))

    # Ownership
    row["owner"] = ""
    row["business_owner"] = ""
    row["technical_owner"] = ""
    row["applications"] = ""

    # Operations
    row["monitoring_enabled"] = ""
    row["pmp_enabled"] = ""
    row["ha_enabled"] = "true" if (resource.get("hastate") or (ha_vmids and vmid in ha_vmids)) else "false"
    row["backup_enabled"] = backup_enabled
    row["backup_location"] = backup_location
    parts = [t for t in tags.split(MULTI_SEP) if t]
    if str(resource.get("template", "")) == "1" and "template" not in parts:
        parts.append("template")
    row["tags"] = MULTI_SEP.join(parts)

    # Compliance dates
    row["last_patch_date"] = ""
    row["last_vuln_scan_date"] = ""
    row["last_verified_at"] = ""
    row["decommission_date"] = ""

    # Notes
    row["security_remarks"] = ""
    row["description"] = description

    return row


def write_csv(rows: list[dict], output_path: str) -> None:
    for row in rows:
        for warning in sanitize_row(row):
            print(f"[warn] VM {row.get('external_id', '?')}: {warning}", file=sys.stderr)
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
    volume_sizes: dict[str, int],
    status: str = "unknown",
    local_node: str = "",
    arp_map: Optional[dict[str, list[str]]] = None,
    lease_ips: Optional[dict[str, list[str]]] = None,
    lease_hosts: Optional[dict[str, str]] = None,
    probe_enabled: bool = True,
    ha_vmids: Optional[set[int]] = None,
) -> Optional[dict]:
    """Extract a single VM's inventory. Returns None on skip."""
    try:
        config = client.get_vm_config(node, vmid)
    except Exception as e:
        print(f"[warn] Failed to get config for VM {vmid} on {node}: {e}", file=sys.stderr)
        return None

    description = config.get("description", "")
    tags = parse_tags(config)
    # Disks
    disks = parse_disks(config, storage_meta, volume_sizes)

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
        ips = config_ips(config)

    if not ips:
        ips = extract_ips_from_tags(tags)

    if not ips and probe_enabled and node == local_node:
        macs = config_macs(config)
        probe_ips: list[str] = []
        for mac in macs:
            for ip in (arp_map or {}).get(mac, []):
                if ip not in probe_ips:
                    probe_ips.append(ip)
            for ip in (lease_ips or {}).get(mac, []):
                if ip not in probe_ips:
                    probe_ips.append(ip)
        ips = probe_ips

    if agent_live:
        try:
            os_info = client.get_guest_os(node, vmid)
        except Exception as e:
            print(f"[warn] Guest agent OS fetch failed for VM {vmid}: {e}", file=sys.stderr)

        try:
            fqdn = client.get_guest_fqdn(node, vmid)
        except Exception as e:
            print(f"[warn] Guest agent FQDN fetch failed for VM {vmid}: {e}", file=sys.stderr)

    ips_by_role = classify_ips(ips)

    # FQDN resolution fallbacks
    macs = config_macs(config)
    if not fqdn and probe_enabled and node == local_node and lease_hosts:
        for mac in macs:
            h = lease_hosts.get(mac, "")
            if h and "." in h and not h.startswith("localhost"):
                fqdn = h
                break

    if not fqdn and probe_enabled:
        for ip in ips_by_role["private_ip"] + ips_by_role.get("backup_ip", []):
            ptr = reverse_dns(ip)
            if ptr:
                fqdn = ptr
                break

    if not fqdn:
        searchdomain = str(config.get("searchdomain", "")).strip()
        vm_name = str(config.get("name") or resource.get("name") or "").strip()
        if searchdomain and vm_name:
            fqdn = f"{vm_name}.{searchdomain}"
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
        ha_vmids=ha_vmids,
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

    partial_failure = False

    try:
        cluster_name = client.get_cluster_name()
    except Exception as e:
        print(f"[warn] cluster status unavailable, using 'standalone': {e}", file=sys.stderr)
        cluster_name = "standalone"
        partial_failure = True

    nodes = client.get_nodes()
    if not nodes:
        print("[warn] No online nodes found", file=sys.stderr)
    try:
        backup_jobs = client.get_backup_jobs()
    except Exception as e:
        print(f"[warn] Failed to fetch backup jobs: {e}", file=sys.stderr)
        backup_jobs = []
        partial_failure = True

    local_node = socket.gethostname().split(".")[0]
    probe_enabled = not args.no_probe
    arp_map: dict[str, list[str]] = {}
    lease_ips: dict[str, list[str]] = {}
    lease_hosts: dict[str, str] = {}

    try:
        ha_vmids = client.get_ha_vmids()
    except Exception as e:
        print(f"[warn] Failed to fetch HA resources: {e}", file=sys.stderr)
        ha_vmids = set()
    if probe_enabled:
        socket.setdefaulttimeout(args.probe_timeout)
        arp_map = read_arp_table()
        lease_ips, lease_hosts = read_dhcp_leases()

    all_rows: list[dict] = []
    storage_meta_cache: dict[str, dict[str, dict]] = {}
    volume_sizes_cache: dict[str, dict[str, int]] = {}

    def get_node_caches(node: str) -> tuple[dict[str, dict], dict[str, int]]:
        if node not in storage_meta_cache:
            sm = build_storage_meta(client, node)
            storage_meta_cache[node] = sm
            volume_sizes_cache[node] = build_volume_sizes(client, node, list(sm.keys()))
        return storage_meta_cache[node], volume_sizes_cache[node]

    # VM discovery via cluster resources with per-node fallback
    use_fallback = False
    try:
        cluster_vms = client.get_cluster_vms()
    except Exception as e:
        print(f"[warn] cluster/resources unavailable, falling back to per-node enumeration: {e}", file=sys.stderr)
        partial_failure = True
        use_fallback = True
        cluster_vms = []

    if not use_fallback and not cluster_vms:
        print("[warn] cluster/resources returned no VMs, falling back to per-node enumeration", file=sys.stderr)
        partial_failure = True
        use_fallback = True
    targets: list[tuple[str, int, str, dict]] = []
    if not use_fallback:
        for resource in cluster_vms:
            if resource.get("vmid") is not None:
                targets.append((resource.get("node", ""), resource["vmid"],
                                resource.get("status", "unknown"), resource))
    else:
        for node in nodes:
            try:
                vms = client.get_vms_for_node(node)
            except Exception as e:
                print(f"[warn] Failed to enumerate VMs on node {node}: {e}", file=sys.stderr)
                partial_failure = True
                continue
            for vm in vms:
                if vm.get("vmid") is not None:
                    targets.append((node, vm["vmid"], vm.get("status", "unknown"), vm))

    for node, vmid, status, resource in targets:
        storage_meta, volume_sizes = get_node_caches(node)
        row = extract_vm(
            client=client,
            node=node,
            vmid=vmid,
            cluster_name=cluster_name,
            storage_meta=storage_meta,
            resource=resource,
            backup_jobs=backup_jobs,
            volume_sizes=volume_sizes,
            status=status,
            local_node=local_node,
            arp_map=arp_map,
            lease_ips=lease_ips,
            lease_hosts=lease_hosts,
            probe_enabled=probe_enabled,
            ha_vmids=ha_vmids,
        )
        if row is not None:
            all_rows.append(row)
        else:
            partial_failure = True
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