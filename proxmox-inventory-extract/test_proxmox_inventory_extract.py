"""Tests for proxmox-inventory-extract.py.

The script filename contains a hyphen, so we use a conftest.py to load it
by path with importlib and inject it into sys.modules. That lets test
functions write ordinary `from proxmox_inventory_extract import ...`.

Run with: python3 -m pytest test_proxmox_inventory_extract.py -v
"""
import csv
import tempfile
from pathlib import Path
from proxmox_inventory_extract import (
    parse_args,
    parse_disks,
    parse_disk_value,
    parse_size_to_gib,
    classify_ips,
    extract_ips_from_tags,
    parse_tags,
    map_status,
    map_os_family,
    TEMPLATE_COLUMNS,
    IP_PREFIX_MAP,
    MULTI_SEP,
    DiskRecord,
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


def test_parse_size_to_gib():
    assert parse_size_to_gib("50G") == 50
    assert parse_size_to_gib("512M") == 0  # 512M = 0.5G -> 0 in integer GiB
    assert parse_size_to_gib("1024M") == 1
    assert parse_size_to_gib("1T") == 1024
    assert parse_size_to_gib("100") == 0  # bytes -> 0 GiB
    assert parse_size_to_gib("") == 0


def test_parse_disk_value():
    # LVM format
    lv, size, sid, found = parse_disk_value("vg01:vm-100-disk-0,size=50G")
    assert lv == "vm-100-disk-0"
    assert size == 50
    assert sid == "vg01"
    assert found is True

    # LVM-thin format
    lv, size, sid, found = parse_disk_value("local-lvm:vm-101-disk-1,size=100G,format=raw")
    assert lv == "vm-101-disk-1"
    assert size == 100
    assert sid == "local-lvm"
    assert found is True

    # iSCSI format
    lv, size, sid, found = parse_disk_value("iscsi0:vm-102-disk-0,size=200G")
    assert lv == "vm-102-disk-0"
    assert size == 200
    assert sid == "iscsi0"
    assert found is True

    # Empty
    lv, size, sid, found = parse_disk_value("")
    assert lv == ""
    assert size == 0
    assert sid == ""
    assert found is False

    # Malformed (no colon)
    lv, size, sid, found = parse_disk_value("no-colon-here")
    assert lv == ""
    assert size == 0
    assert sid == ""
    assert found is False

    # No size parameter
    lv, size, sid, found = parse_disk_value("vg01:vm-100-disk-2")
    assert lv == "vm-100-disk-2"
    assert size == 0
    assert sid == "vg01"
    assert found is False


def test_parse_disks():
    # Build storage meta
    storage_meta = {
        "vg01": {"vgname": "vg01", "type": "lvm"},
        "local-lvm": {"vgname": "vg02", "type": "lvm-thin"},
        "iscsi0": {"vgname": "", "type": "iscsi"},
    }

    config = {
        "scsi0": "vg01:vm-100-disk-0,size=50G",
        "scsi1": "vg01:vm-100-disk-1,size=100G",
        "virtio0": "local-lvm:vm-100-disk-2,size=32G",
        "efidisk0": "vg01:vm-100-disk-efi,size=4M",
        "tpmstate0": "vg01:vm-100-disk-tpm,size=4M",
        "ide0": "none",
        "ide2": "local:iso/ubuntu.iso,media=cdrom",  # Should be skipped
        "unused": "some-value",
    }

    disks = parse_disks(config, storage_meta)

    assert len(disks) == 5  # scsi0, scsi1, virtio0, efidisk0, tpmstate0

    # Check scsi0
    d0 = next(d for d in disks if d.config_key == "scsi0")
    assert d0.lv_name == "vm-100-disk-0"
    assert d0.size_gib == 50
    assert d0.storage_name == "vg01"
    assert d0.storage_type == "lvm"
    assert d0.disk_name == "vm-100-disk-0-scsi0"
    assert d0.to_csv_field() == "vm-100-disk-0-scsi0:50:vg01:lvm"

    # Check scsi1
    d1 = next(d for d in disks if d.config_key == "scsi1")
    assert d1.lv_name == "vm-100-disk-1"
    assert d1.size_gib == 100
    assert d1.to_csv_field() == "vm-100-disk-1-scsi1:100:vg01:lvm"

    # Check virtio0
    dv = next(d for d in disks if d.config_key == "virtio0")
    assert dv.lv_name == "vm-100-disk-2"
    assert dv.size_gib == 32
    assert dv.storage_name == "vg02"
    assert dv.storage_type == "lvm-thin"
    assert dv.to_csv_field() == "vm-100-disk-2-virtio0:32:vg02:lvm-thin"

    # Check efidisk0
    de = next(d for d in disks if d.config_key == "efidisk0")
    assert de.lv_name == "vm-100-disk-efi"
    assert de.size_gib == 0  # 4M -> 0 GiB
    assert de.to_csv_field() == "vm-100-disk-efi-efidisk0:0:vg01:lvm"

    # Check tpmstate0
    dt = next(d for d in disks if d.config_key == "tpmstate0")
    assert dt.lv_name == "vm-100-disk-tpm"
    assert dt.size_gib == 0
    assert dt.to_csv_field() == "vm-100-disk-tpm-tpmstate0:0:vg01:lvm"


def test_parse_disks_storage_fallback():
    """When vgname not available, storage_name falls back to storage_id."""
    storage_meta = {
        "iscsi0": {"vgname": "", "type": "iscsi"},
        "ceph0": {"vgname": "", "type": "rbd"},
    }

    config = {
        "scsi0": "iscsi0:vm-100-disk-0,size=50G",
        "virtio0": "ceph0:vm-100-disk-1,size=100G",
    }

    disks = parse_disks(config, storage_meta)

    assert len(disks) == 2
    for d in disks:
        assert d.storage_name == d.storage_id  # fallback
        assert d.storage_type in ("iscsi", "rbd")


def test_parse_disks_malformed():
    """Malformed disks should be skipped with warning (no exception)."""
    storage_meta = {"vg01": {"vgname": "vg01", "type": "lvm"}}
    config = {
        "scsi0": "vg01:vm-100-disk-0,size=50G",
        "scsi1": "not-a-valid-format",
        "scsi2": "vg01:vm-100-disk-2",  # no size
    }

    # Should not raise
    disks = parse_disks(config, storage_meta)
    assert len(disks) == 1  # Only scsi0 valid
    assert disks[0].config_key == "scsi0"


def test_classify_ips():
    ips = ["10.0.0.1", "10.0.0.2", "172.16.0.1", "202.1.2.3", "192.168.1.1", "8.8.8.8"]
    result = classify_ips(ips)

    assert result["backup_ip"] == ["10.0.0.1", "10.0.0.2"]
    assert result["private_ip"] == ["172.16.0.1", "192.168.1.1", "8.8.8.8"]
    assert result["public_ip"] == ["202.1.2.3"]


def test_extract_ips_from_tags():
    tags = "prod;ip=10.0.0.5;web;172.16.0.10;backup"
    ips = extract_ips_from_tags(tags)
    assert "10.0.0.5" in ips
    assert "172.16.0.10" in ips


def test_parse_tags():
    assert parse_tags({"tags": "prod;web;db"}) == "prod;web;db"
    assert parse_tags({"tags": "prod;;web"}) == "prod;web"  # empty elements skipped
    assert parse_tags({"tags": ""}) == ""
    assert parse_tags({"tags": "  prod ; web  "}) == "prod;web"
    assert parse_tags({}) == ""


def test_map_status():
    assert map_status("running") == "running"
    assert map_status("stopped") == "powered_off"
    assert map_status("paused") == "unknown"
    assert map_status("unknown") == "unknown"
    assert map_status("") == "unknown"


def test_map_os_family():
    # Guest agent takes precedence
    assert map_os_family("l26", "ubuntu") == "ubuntu"
    # Fallback to ostype mapping
    assert map_os_family("l26", None) == "linux"
    assert map_os_family("w2022", None) == "windows"
    assert map_os_family("w10", "windows") == "windows"
    # Unknown ostype defaults to linux
    assert map_os_family("unknown", None) == "linux"


def test_disk_record_csv_field():
    d = DiskRecord(
        lv_name="vm-100-disk-0",
        config_key="scsi0",
        size_gib=50,
        storage_id="vg01",
        storage_name="vg01",
        storage_type="lvm",
    )
    assert d.disk_name == "vm-100-disk-0-scsi0"
    assert d.to_csv_field() == "vm-100-disk-0-scsi0:50:vg01:lvm"


def test_template_columns_order():
    """Verify TEMPLATE_COLUMNS matches InventoryMGR expected order."""
    expected = (
        "name", "external_id", "fqdn", "sr_id", "platform", "datacenter", "cluster", "node",
        "status", "environment", "criticality", "vm_type", "cpu_cores", "memory_mb", "disks",
        "storage_name", "storage_type", "os_family", "os_distribution", "os_version",
        "private_ip", "public_ip", "backup_ip", "owner", "business_owner", "technical_owner",
        "applications", "monitoring_enabled", "pmp_enabled", "ha_enabled", "backup_enabled",
        "backup_location", "tags", "last_patch_date", "last_vuln_scan_date", "last_verified_at",
        "decommission_date", "security_remarks", "description",
    )
    assert TEMPLATE_COLUMNS == expected


def test_multi_sep():
    assert MULTI_SEP == ";"


def test_full_csv_write():
    """Integration test: write CSV and verify header + row structure."""
    from proxmox_inventory_extract import write_csv

    # Create a minimal row
    row = {col: "" for col in TEMPLATE_COLUMNS}
    row["name"] = "test-vm"
    row["external_id"] = "100"
    row["platform"] = "proxmox"
    row["cluster"] = "test-cluster"
    row["node"] = "node1"
    row["status"] = "running"
    row["cpu_cores"] = "4"
    row["memory_mb"] = "8192"
    row["disks"] = "vm-100-disk-0-scsi0:50:vg01:lvm"
    row["os_family"] = "linux"
    row["private_ip"] = "172.16.0.10"
    row["tags"] = "prod;web"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        tmp_path = f.name

    try:
        write_csv([row], tmp_path)

        with open(tmp_path, newline="") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            rows = list(reader)

        assert headers == list(TEMPLATE_COLUMNS)
        assert len(rows) == 1
        assert rows[0]["name"] == "test-vm"
        assert rows[0]["external_id"] == "100"
        assert rows[0]["disks"] == "vm-100-disk-0-scsi0:50:vg01:lvm"
        assert rows[0]["private_ip"] == "172.16.0.10"
    finally:
        Path(tmp_path).unlink(missing_ok=True)