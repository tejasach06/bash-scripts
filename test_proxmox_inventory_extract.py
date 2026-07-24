"""Tests for proxmox-inventory-extract.py.

The script filename contains a hyphen, which prevents normal `import`. We
load it by path with importlib.

Run with: python3 -m pytest test_proxmox_inventory_extract.py -v
"""
import importlib.util
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPT_PATH = os.path.join(_THIS_DIR, "proxmox-inventory-extract.py")

_spec = importlib.util.spec_from_file_location("proxmox_inventory_extract", _SCRIPT_PATH)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["proxmox_inventory_extract"] = _mod
_spec.loader.exec_module(_mod)

parse_args = _mod.parse_args
get_ticket = _mod.get_ticket
IP_PREFIX_MAP = _mod.IP_PREFIX_MAP
CSV_HEADERS = _mod.CSV_HEADERS


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
