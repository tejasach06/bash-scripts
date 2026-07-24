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
    "environment", "fqdn", "ha_enabled", "last_patch_date", "last_vuln_scan_date",
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
MULTI_SEP = "#"

# IPv4 regex for extracting IPs from free-form tag strings.
IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Size suffix → bytes multiplier (Proxmox stores disk size as "50G", "100M", etc.).
SIZE_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


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


if __name__ == "__main__":
    # Module loaded only to import constants and stubs in tests.
    pass
