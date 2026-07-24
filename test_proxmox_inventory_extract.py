"""Tests for proxmox-inventory-extract.py.

The script filename contains a hyphen, so we use a conftest.py to load it
by path with importlib and inject it into sys.modules. That lets test
functions write ordinary `from proxmox_inventory_extract import ...`.

Run with: python3 -m pytest test_proxmox_inventory_extract.py -v
"""
from proxmox_inventory_extract import (
    parse_args,
    get_ticket,
    IP_PREFIX_MAP,
    CSV_HEADERS,
)


def test_parse_args_defaults():
    args = parse_args(["-p", "secret"])
    assert args.host == "127.0.0.1:8006"
    assert args.user == "root@pam"
    assert args.password == "secret"
    assert args.insecure is False
    assert args.output is None


def test_parse_args_full():
    args = parse_args([
        "-o", "/tmp/foo.csv",
        "-H", "10.0.0.5:8006",
        "-u", "admin@pve",
        "-p", "secret",
        "--insecure",
    ])
    assert args.output == "/tmp/foo.csv"
    assert args.host == "10.0.0.5:8006"
    assert args.user == "admin@pve"
    assert args.password == "secret"
    assert args.insecure is True


def test_ip_prefix_map_keys():
    assert IP_PREFIX_MAP["10."] == "backup_ip"
    assert IP_PREFIX_MAP["172."] == "private_ip"
    assert IP_PREFIX_MAP["202."] == "public_ip"


def test_csv_headers_first_three():
    assert CSV_HEADERS[:3] == ["name", "platform", "cluster"]


def test_get_ticket_parses_response(monkeypatch):
    """Verify get_ticket extracts ticket and CSRF from a Proxmox ticket response."""
    class FakeResp:
        def __init__(self, body, status=200):
            self._body = body
            self.status = status
        def read(self):
            return self._body.encode("utf-8")
        def __enter__(self): return self
        def __exit__(self, *a): pass

    body = '{"data":{"ticket":"PVE:ticket:abc","CSRFPreventionToken":"csrf123"}}'
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: FakeResp(body))
    ticket, csrf = get_ticket("127.0.0.1:8006", "root@pam", "pw", verify_ssl=True)
    assert ticket == "PVE:ticket:abc"
    assert csrf == "csrf123"


def test_api_get_returns_data(monkeypatch):
    class FakeResp:
        def __init__(self, body, status=200):
            self._body = body; self.status = status
        def read(self): return self._body.encode("utf-8")
        def __enter__(self): return self
        def __exit__(self, *a): pass

    body = '{"data":[{"node":"pve1"},{"node":"pve2"}]}'
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: FakeResp(body))
    from proxmox_inventory_extract import api_get
    out = api_get("127.0.0.1:8006", "/api2/json/nodes", ticket="PVE:ticket:x")
    assert out == [{"node": "pve1"}, {"node": "pve2"}]


def test_api_get_404_returns_empty(monkeypatch):
    from urllib.error import HTTPError
    from proxmox_inventory_extract import api_get
    def raise_404(*a, **kw):
        raise HTTPError("https://x/api2/json/n", 404, "Not Found", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", raise_404)
    assert api_get("127.0.0.1:8006", "/api2/json/n", ticket="t") == {}


def test_get_cluster_name_when_clustered(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [
            {"name": "pve1", "type": "node"},
            {"name": "mycluster", "type": "cluster"},
        ],
    )
    from proxmox_inventory_extract import get_cluster_name
    assert get_cluster_name("h", "t", "c", True) == "mycluster"


def test_get_cluster_name_when_standalone(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [{"name": "pve1", "type": "node"}],
    )
    from proxmox_inventory_extract import get_cluster_name
    assert get_cluster_name("h", "t", "c", True) == "standalone"


def test_get_nodes_extracts_names(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [{"node": "pve1"}, {"node": "pve2"}],
    )
    from proxmox_inventory_extract import get_nodes
    assert get_nodes("h", "t", "c", True) == ["pve1", "pve2"]


def test_get_vms_for_node_returns_vmids(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [{"vmid": 100}, {"vmid": 101}],
    )
    from proxmox_inventory_extract import get_vms_for_node
    assert get_vms_for_node("h", "pve1", "t", "c", True) == [100, 101]


def test_parse_disks_basic():
    from proxmox_inventory_extract import parse_disks
    cfg = {
        "scsi0": "local-lvm:vm-100-disk-0,size=50G",
        "scsi1": "local-lvm:vm-100-disk-1,size=100G",
        "ide2": "none,media=cdrom",
        "net0": "virtio=AA:BB:CC:DD:EE:FF",
        "efidisk0": "local-lvm:vm-100-disk-2,efitype=4m,size=4M",
    }
    out = parse_disks(cfg)
    names_sizes = {name: size for name, size in out}
    assert names_sizes["scsi0"] == 50
    assert names_sizes["scsi1"] == 100
    assert names_sizes["efidisk0"] == 0  # 4M rounds down to 0 GB
    assert "ide2" not in names_sizes
    assert "net0" not in names_sizes


def test_parse_disks_empty():
    from proxmox_inventory_extract import parse_disks
    assert parse_disks({}) == []


def test_parse_tags_simple():
    from proxmox_inventory_extract import parse_tags
    assert parse_tags({"tags": "web;prod;nginx"}) == ["web", "prod", "nginx"]


def test_parse_tags_empty():
    from proxmox_inventory_extract import parse_tags
    assert parse_tags({}) == []
    assert parse_tags({"tags": ""}) == []


def test_parse_tags_whitespace():
    from proxmox_inventory_extract import parse_tags
    assert parse_tags({"tags": " web ; prod "}) == ["web", "prod"]


def test_get_vm_config_returns_dict(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {"name": "web01", "ostype": "l26", "tags": "web;prod"},
    )
    from proxmox_inventory_extract import get_vm_config
    cfg = get_vm_config("h", "pve1", 100, "t", "c", True)
    assert cfg["name"] == "web01"
    assert cfg["ostype"] == "l26"
    assert cfg["tags"] == "web;prod"


def test_extract_ips_from_guest_agent_filters_loopback_and_ipv6():
    """Loopback (127.x) and link-local (169.254.x) are skipped; IPv6 ignored."""
    data = [
        {
            "name": "lo",
            "ip-addresses": [
                {"ip-address": "127.0.0.1", "ip-address-type": "ipv4"},
            ],
        },
        {
            "name": "eth0",
            "ip-addresses": [
                {"ip-address": "172.16.0.10", "ip-address-type": "ipv4"},
                {"ip-address": "172.16.0.11", "ip-address-type": "ipv4"},
                {"ip-address": "fe80::1",     "ip-address-type": "ipv6"},
            ],
        },
    ]
    from proxmox_inventory_extract import extract_ips_from_guest_agent
    out = extract_ips_from_guest_agent(data)
    assert out == ["172.16.0.10", "172.16.0.11"]


def test_extract_ips_from_guest_agent_empty():
    from proxmox_inventory_extract import extract_ips_from_guest_agent
    assert extract_ips_from_guest_agent([]) == []
    assert extract_ips_from_guest_agent(None) == []


def test_classify_ips_routes_by_prefix():
    from proxmox_inventory_extract import classify_ips
    ips = ["10.1.2.3", "172.16.0.1", "202.10.20.30", "8.8.8.8"]
    out = classify_ips(ips)
    assert out["backup_ip"]  == ["10.1.2.3"]
    assert out["private_ip"] == ["172.16.0.1", "8.8.8.8"]  # 8.8.8.8 → default private
    assert out["public_ip"]  == ["202.10.20.30"]


def test_extract_ips_from_tags():
    from proxmox_inventory_extract import extract_ips_from_tags
    tags = ["web", "172.16.0.5", "10.0.0.1", "prod", "not-an-ip", "202.1.2.3"]
    out = extract_ips_from_tags(tags)
    assert out == ["172.16.0.5", "10.0.0.1", "202.1.2.3"]


def test_extract_ips_from_tags_empty():
    from proxmox_inventory_extract import extract_ips_from_tags
    assert extract_ips_from_tags([]) == []


def test_detect_os_from_agent(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {
            "result": {
                "name": "Ubuntu 22.04 LTS",
                "version": "22.04",
                "version-id": "22.04 (Jammy Jellyfish)",
                "pretty-name": "Ubuntu 22.04 LTS",
            }
        },
    )
    cfg = {"ostype": "l26", "agent": "enabled=1"}
    from proxmox_inventory_extract import detect_os
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] == "linux"
    assert out["os_distribution"] == "Ubuntu 22.04 LTS"
    assert out["os_version"] == "22.04"


def test_detect_os_windows_from_agent(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {"result": {"pretty-name": "Windows Server 2019"}},
    )
    from proxmox_inventory_extract import detect_os
    out = detect_os("h", "n", 100, {"agent": "1"}, "t", "c", True)
    assert out["os_family"] == "windows"
    assert "Windows" in (out["os_distribution"] or "")


def test_detect_os_falls_back_to_ostype_linux():
    from proxmox_inventory_extract import detect_os
    cfg = {"ostype": "l26"}
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] == "linux"
    assert out["os_distribution"] is None
    assert out["os_version"] is None


def test_detect_os_falls_back_to_ostype_windows():
    from proxmox_inventory_extract import detect_os
    cfg = {"ostype": "win10"}
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] == "windows"


def test_detect_os_unknown_ostype():
    from proxmox_inventory_extract import detect_os
    cfg = {"ostype": "other"}
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] is None


def test_detect_os_agent_call_fails(monkeypatch):
    """If guest agent call raises, fall back to ostype silently."""
    def boom(*a, **kw):
        raise RuntimeError("agent down")
    monkeypatch.setattr("proxmox_inventory_extract.api_get", boom)
    from proxmox_inventory_extract import detect_os
    out = detect_os("h", "n", 100, {"ostype": "l26"}, "t", "c", True)
    assert out["os_family"] == "linux"


def test_build_row_all_fields():
    from proxmox_inventory_extract import build_row
    data = {
        "name": "web01",
        "node": "pve1",
        "config": {},
        "status": "running",
        "os": {"os_family": "linux", "os_distribution": "Ubuntu 22.04", "os_version": "22.04"},
        "ips_by_role": {"private_ip": ["172.16.0.10"], "public_ip": ["202.10.20.30"], "backup_ip": ["10.0.0.1"]},
        "disks": [("scsi0", 50), ("scsi1", 100)],
        "tags": ["web", "prod"],
        "fqdn": "web01.example.com",
        "cluster": "mycluster",
        "memory_mb": 4096,
        "cpu_cores": 2,
    }
    row = build_row(data)
    assert row["name"] == "web01"
    assert row["platform"] == "proxmox"
    assert row["cluster"] == "mycluster"
    assert row["node"] == "pve1"
    assert row["disks"] == "scsi0:50#scsi1:100"
    assert row["status"] == "running"
    assert row["private_ip"] == "172.16.0.10"
    assert row["public_ip"] == "202.10.20.30"
    assert row["backup_ip"] == "10.0.0.1"
    assert row["tags"] == "web#prod"
    assert row["fqdn"] == "web01.example.com"
    assert row["os_family"] == "linux"
    assert row["os_distribution"] == "Ubuntu 22.04"
    assert row["os_version"] == "22.04"
    assert row["memory_mb"] == 4096
    assert row["cpu_cores"] == 2
    # Empty fields should be present
    assert row["backup_enabled"] == ""
    assert row["lifecycle"] == ""
    assert row["environment"] == ""


def test_build_row_minimal():
    from proxmox_inventory_extract import build_row
    data = {
        "name": "vm100",
        "node": "pve1",
        "config": {},
        "status": "stopped",
        "os": {"os_family": None, "os_distribution": None, "os_version": None},
        "ips_by_role": {"private_ip": [], "public_ip": [], "backup_ip": []},
        "disks": [],
        "tags": [],
        "fqdn": "vm100",
        "cluster": "standalone",
        "memory_mb": 0,
        "cpu_cores": 0,
    }
    row = build_row(data)
    assert row["name"] == "vm100"
    assert row["status"] == "powered_off"  # mapped from 'stopped'
    assert row["disks"] == ""
    assert row["tags"] == ""
    assert row["private_ip"] == ""
    assert row["public_ip"] == ""
    assert row["backup_ip"] == ""
    assert row["os_family"] == ""
    assert row["os_distribution"] == ""
    assert row["os_version"] == ""
