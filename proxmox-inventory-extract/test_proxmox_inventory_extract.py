"""Tests for proxmox-inventory-extract.py.

The script filename contains a hyphen, so we use a conftest.py to load it
by path with importlib and inject it into sys.modules. That lets test
functions write ordinary `from proxmox_inventory_extract import ...`.

Run with: python3 -m pytest test_proxmox_inventory_extract.py -v
"""
import csv
from proxmox_inventory_extract import (
    parse_args,
    get_ticket,
    api_get,
    get_cluster_name,
    get_nodes,
    get_vms_for_node,
    parse_disks,
    parse_tags,
    get_vm_config,
    get_vm_status,
    extract_ips_from_guest_agent,
    classify_ips,
    extract_ips_from_tags,
    get_guest_agent_ips,
    detect_os,
    build_row,
    extract_vm,
    write_csv,
    IP_PREFIX_MAP,
    CSV_HEADERS,
    MULTI_SEP,
    format_storage_tags,
    format_disk_provenance,
    split_disk_value,
    get_storage_plugins,
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
    out = api_get("127.0.0.1:8006", "/api2/json/nodes", ticket="PVE:ticket:x")
    assert out == [{"node": "pve1"}, {"node": "pve2"}]


def test_api_get_404_returns_empty(monkeypatch):
    from urllib.error import HTTPError
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
    assert get_cluster_name("h", "t", "c", True) == "mycluster"


def test_get_cluster_name_when_standalone(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [{"name": "pve1", "type": "node"}],
    )
    assert get_cluster_name("h", "t", "c", True) == "standalone"


def test_get_nodes_extracts_names(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [{"node": "pve1"}, {"node": "pve2"}],
    )
    assert get_nodes("h", "t", "c", True) == ["pve1", "pve2"]


def test_get_vms_for_node_returns_vmids(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: [{"vmid": 100}, {"vmid": 101}],
    )
    assert get_vms_for_node("h", "pve1", "t", "c", True) == [100, 101]


def test_parse_disks_basic():
    cfg = {
        "scsi0": "local-lvm:vm-100-disk-0,size=50G",
        "scsi1": "local-lvm:vm-100-disk-1,size=100G",
        "ide2": "none,media=cdrom",
        "net0": "virtio=AA:BB:CC:DD:EE:FF",
    }
    out = parse_disks(cfg)
    assert out == [("scsi0", 50), ("scsi1", 100)]
    # Should not include ide2 (no size) or net0 (not a disk)
    names = [d[0] for d in out]
    assert "ide2" not in names
    assert "net0" not in names


def test_parse_disks_empty():
    assert parse_disks({}) == []



def test_parse_disks_lvm_block():
    cfg = {
        "scsi0": "ssdpool:vm-100-disk-0,size=50G",
        "scsi1": "ssdpool:vm-100-disk-1,size=100G",
        "ide2": "none,media=cdrom",
    }
    storage_plugins = {"ssdpool": "lvm"}
    out = parse_disks(cfg, storage_plugins=storage_plugins)
    assert out == [("lvm:vm-100-disk-0", 50), ("lvm:vm-100-disk-1", 100)]
    names = [d[0] for d in out]
    assert "ide2" not in names


def test_parse_disks_zfspool_block():
    cfg = {
        "scsi0": "zfspool:vm-100-disk-0,size=100G",
    }
    storage_plugins = {"zfspool": "zfspool"}
    out = parse_disks(cfg, storage_plugins=storage_plugins)
    assert out == [("zfspool:vm-100-disk-0", 100)]


def test_parse_disks_no_lv_name():
    cfg = {
        "scsi0": "local:100/vm-100-disk-2.raw,size=10G",
    }
    storage_plugins = {"local": "dir"}
    out = parse_disks(cfg, storage_plugins=storage_plugins)
    assert out == [("scsi0", 10)]


def test_parse_disks_no_storage_cache():
    cfg = {
        "scsi0": "ssdpool:vm-100-disk-0,size=50G",
    }
    out = parse_disks(cfg, storage_plugins=None)
    assert out == [("scsi0", 50)]


def test_split_disk_value():
    storage, vol, attrs = split_disk_value("ssdpool:vm-100-disk-0,size=50G,format=raw")
    assert storage == "ssdpool"
    assert vol == "vm-100-disk-0"
    assert attrs["size"] == "50G"
    assert attrs["format"] == "raw"
    cfg2, vol2, attrs2 = split_disk_value("local:100/vm-100-disk-2.raw,size=10G")
    assert cfg2 == "local"
    assert vol2 == "100/vm-100-disk-2.raw"
    assert attrs2["size"] == "10G"
    cfg3, vol3, attrs3 = split_disk_value("ssdpool:vm-100-disk-0,format=raw")
    assert attrs3.get("size") is None


def test_format_storage_tags():
    assert format_storage_tags({"ssdpool": "lvm"}) == ["storage:lvm:ssdpool"]
    assert format_storage_tags({"ssdpool": "lvm", "backuppool": "lvm"}) == [
        "storage:lvm:backuppool",
        "storage:lvm:ssdpool",
    ]
    assert format_storage_tags({"ssdpool": "lvm", "ssdpool": "lvm"}) == ["storage:lvm:ssdpool"]
    assert format_storage_tags({"ssdpool": "lvm", "zfspool": "zfspool"}) == [
        "storage:lvm:ssdpool",
        "storage:zfspool:zfspool",
    ]


def test_format_disk_provenance():
    assert format_disk_provenance("scsi0", "ssdpool", "vm-100-disk-0", "lvm", 50) == \
        "scsi0\u2192lvm/ssdpool/vm-100-disk-0"
    assert format_disk_provenance("scsi1", "backuppool", "vm-100-disk-1", "lvm", 100) == \
        "scsi1\u2192lvm/backuppool/vm-100-disk-1"


def test_parse_tags_simple():
    assert parse_tags({"tags": "web;prod;nginx"}) == ["web", "prod", "nginx"]


def test_parse_tags_empty():
    assert parse_tags({}) == []
    assert parse_tags({"tags": ""}) == []


def test_parse_tags_whitespace():
    assert parse_tags({"tags": " web ; prod "}) == ["web", "prod"]


def test_get_vm_config_returns_dict(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {"name": "web01", "ostype": "l26", "tags": "web;prod"},
    )
    cfg = get_vm_config("h", "pve1", 100, "t", "c", True)
    assert cfg["name"] == "web01"
    assert cfg["ostype"] == "l26"
    assert cfg["tags"] == "web;prod"


def test_get_vm_status(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {"status": "running"} if "status/current" in a[1] else {},
    )
    status = get_vm_status("h", "pve1", 100, "t", "c", True)
    assert status == "running"


def test_get_vm_status_stopped(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {"status": "stopped"},
    )
    status = get_vm_status("h", "pve1", 101, "t", "c", True)
    assert status == "stopped"


def test_get_vm_status_unknown(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {},
    )
    status = get_vm_status("h", "pve1", 102, "t", "c", True)
    assert status == "unknown"


def test_extract_ips_from_guest_agent_filters_loopback_and_ipv6():
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
    out = extract_ips_from_guest_agent(data)
    assert out == ["172.16.0.10", "172.16.0.11"]


def test_extract_ips_from_guest_agent_empty():
    assert extract_ips_from_guest_agent([]) == []
    assert extract_ips_from_guest_agent(None) == []


def test_classify_ips_routes_by_prefix():
    ips = ["10.1.2.3", "172.16.0.1", "202.10.20.30", "8.8.8.8"]
    out = classify_ips(ips)
    assert out["backup_ip"]  == ["10.1.2.3"]
    assert out["private_ip"] == ["172.16.0.1", "8.8.8.8"]
    assert out["public_ip"]  == ["202.10.20.30"]


def test_extract_ips_from_tags():
    tags = ["web", "172.16.0.5", "10.0.0.1", "prod", "not-an-ip", "202.1.2.3"]
    out = extract_ips_from_tags(tags)
    assert out == ["172.16.0.5", "10.0.0.1", "202.1.2.3"]


def test_extract_ips_from_tags_empty():
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
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] == "linux"
    assert out["os_distribution"] == "Ubuntu"
    assert out["os_version"] == "22.04"


def test_detect_os_windows_from_agent(monkeypatch):
    monkeypatch.setattr(
        "proxmox_inventory_extract.api_get",
        lambda *a, **kw: {"result": {"pretty-name": "Windows Server 2019"}},
    )
    out = detect_os("h", "n", 100, {"agent": "1"}, "t", "c", True)
    assert out["os_family"] == "windows"
    assert out["os_distribution"] == "Windows Server"


def test_detect_os_falls_back_to_ostype_linux():
    cfg = {"ostype": "l26"}
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] == "linux"
    assert out["os_distribution"] is None
    assert out["os_version"] is None


def test_detect_os_falls_back_to_ostype_windows():
    cfg = {"ostype": "win10"}
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] == "windows"


def test_detect_os_unknown_ostype():
    cfg = {"ostype": "other"}
    out = detect_os("h", "n", 100, cfg, "t", "c", True)
    assert out["os_family"] is None


def test_detect_os_agent_call_fails(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("agent down")
    monkeypatch.setattr("proxmox_inventory_extract.api_get", boom)
    out = detect_os("h", "n", 100, {"ostype": "l26"}, "t", "c", True)
    assert out["os_family"] == "linux"


def test_build_row_all_fields():
    data = {
        "name": "web01",
        "node": "pve1",
        "config": {},
        "status": "running",
        "os": {"os_family": "linux", "os_distribution": "Ubuntu", "os_version": "22.04"},
        "ips_by_role": {"private_ip": ["172.16.0.10"], "public_ip": ["202.10.20.30"], "backup_ip": ["10.0.0.1"]},
        "disks": [("scsi0", 50), ("scsi1", 100)],
        "tags": ["web", "prod"],
        "fqdn": "web01.example.com",
        "cluster": "mycluster",
        "vmid": 100,  # Proxmox VMID → external_id per InventoryMGR schema
        "memory_mb": 4096,
        "cpu_cores": 2,
    }
    row = build_row(data)
    assert row["name"] == "web01"
    assert row["platform"] == "proxmox"
    assert row["cluster"] == "mycluster"
    assert row["node"] == "pve1"
    assert row["external_id"] == "100"  # VMID stringified
    assert row["disks"] == "scsi0:50;scsi1:100"
    assert row["status"] == "running"
    assert row["private_ip"] == "172.16.0.10"
    assert row["public_ip"] == "202.10.20.30"
    assert row["backup_ip"] == "10.0.0.1"
    assert row["tags"] == "web;prod"
    assert row["fqdn"] == "web01.example.com"
    assert row["os_family"] == "linux"
    assert row["os_distribution"] == "Ubuntu"
    assert row["os_version"] == "22.04"
    assert row["memory_mb"] == 4096
    assert row["cpu_cores"] == 2
    assert row["backup_enabled"] == ""
    assert row["lifecycle"] == ""
    assert row["environment"] == ""


def test_build_row_minimal():
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
    assert row["status"] == "powered_off"
    assert row["disks"] == ""
    assert row["tags"] == ""
    assert row["private_ip"] == ""
    assert row["public_ip"] == ""
    assert row["backup_ip"] == ""
    assert row["os_family"] == ""
    assert row["os_distribution"] == ""
    assert row["os_version"] == ""


def test_extract_vm_full(monkeypatch):
    def fake_api(*a, **kw):
        path = a[1] if len(a) > 1 else ""
        if path.endswith("/config"):
            return {
                "name": "web01",
                "ostype": "l26",
                "tags": "web;prod",
                "scsi0": "local-lvm:vm-100-disk-0,size=50G",
                "scsi1": "local-lvm:vm-100-disk-1,size=100G",
                "cores": 4,
                "memory": 4096,
                "agent": "enabled=1",
                "status": "running",
            }
        if "network-get-interfaces" in path:
            return [{"name": "eth0", "ip-addresses": [
                {"ip-address": "172.16.0.10", "ip-address-type": "ipv4"},
                {"ip-address": "10.0.0.1",    "ip-address-type": "ipv4"},
            ]}]
        if "get-osinfo" in path:
            return {"result": {"pretty-name": "Ubuntu 22.04 LTS", "version-id": "22.04"}}
        return {}
    monkeypatch.setattr("proxmox_inventory_extract.api_get", fake_api)
    monkeypatch.setattr("proxmox_inventory_extract.get_vm_status", lambda *a, **kw: "running")
    row = extract_vm("h", "pve1", 100, "t", "c", True, "mycluster", None)
    assert row["name"] == "web01"
    assert row["external_id"] == "100"  # VMID → external_id per InventoryMGR schema
    assert row["cluster"] == "mycluster"
    assert row["node"] == "pve1"
    assert row["disks"] == "scsi0:50;scsi1:100"
    assert row["private_ip"] == "172.16.0.10"
    assert row["backup_ip"] == "10.0.0.1"
    assert row["os_family"] == "linux"
    assert row["os_distribution"] == "Ubuntu"
    assert row["status"] == "running"
    assert row["tags"] == "web;prod"


def test_extract_vm_no_agent_uses_tags(monkeypatch):
    def fake_api(*a, **kw):
        path = a[1] if len(a) > 1 else ""
        if path.endswith("/config"):
            return {"name": "legacy", "ostype": "l26",
                    "tags": "172.16.0.99;web;legacy-vm",
                    "cores": 2, "memory": 2048, "status": "running"}
        return {}
    monkeypatch.setattr("proxmox_inventory_extract.api_get", fake_api)
    monkeypatch.setattr("proxmox_inventory_extract.get_vm_status", lambda *a, **kw: "running")
    row = extract_vm("h", "pve1", 101, "t", "c", True, "c", None)
    assert row["private_ip"] == "172.16.0.99"
    assert row["os_family"] == "linux"
    assert row["os_distribution"] == ""


def test_write_csv_roundtrip(tmp_path):
    rows = [
        {"name": "a", "platform": "proxmox", "cluster": "c", "disks": "scsi0:50;scsi1:100"},
        {"name": "b", "platform": "proxmox", "cluster": "c", "disks": ""},
    ]
    out = tmp_path / "out.csv"
    n = write_csv(rows, str(out))
    assert n == 2
    with open(out) as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == CSV_HEADERS
        data = list(reader)
    assert data[0]["disks"] == "scsi0:50;scsi1:100"
    assert data[1]["disks"] == ""


def test_write_csv_escapes_special_chars(tmp_path):
    rows = [{"name": 'a,vm', "platform": "proxmox", "cluster": 'c"1', "description": "line1\nline2"}]
    out = tmp_path / "out.csv"
    write_csv(rows, str(out))
    with open(out) as f:
        content = f.read()
    assert '"a,vm"' in content
    assert '"c""1"' in content


def test_password_from_env(monkeypatch):
    monkeypatch.setenv("PVE_PASSWORD", "envsecret")
    from proxmox_inventory_extract import get_password
    assert get_password(None) == "envsecret"


def test_password_from_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("PVE_PASSWORD", "envsecret")
    from proxmox_inventory_extract import get_password
    assert get_password("clisecret") == "clisecret"


def test_password_prompt_called(monkeypatch):
    """If no env and no CLI, getpass.getpass is called."""
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "typedsecret")
    from proxmox_inventory_extract import get_password
    assert get_password(None) == "typedsecret"


def test_main_dry_run_prints_help(capsys):
    from proxmox_inventory_extract import main
    # No real Proxmox, but --help should exit 0
    import sys
    sys.argv = ["proxmox-inventory-extract.py", "--help"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    out = capsys.readouterr().out
    assert "usage:" in out.lower()