"""Shared test loader for the proxmox-inventory-extract hyphen-named script.

Loaded automatically by pytest via conftest.py.
"""
import importlib.util
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPT_PATH = os.path.join(_THIS_DIR, "proxmox-inventory-extract.py")

_spec = importlib.util.spec_from_file_location("proxmox_inventory_extract", _SCRIPT_PATH)
_mod = importlib.util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None
sys.modules["proxmox_inventory_extract"] = _mod
_spec.loader.exec_module(_mod)
