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
