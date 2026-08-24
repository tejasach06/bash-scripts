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
    total_vcpus,
    add_tag,
    backup_coverage,
    extract_vm,
    serialize_vm,
    write_csv,
    TEMPLATE_COLUMNS,
    IP_PREFIX_MAP,
    MULTI_SEP,
    DiskRecord,
    ProxmoxClient,
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
    assert parse_size_to_gib("100.5G") == 100
    assert parse_size_to_gib("2.5T") == 2560
    assert parse_size_to_gib("512M") == 1
    assert parse_size_to_gib("1024M") == 1
    assert parse_size_to_gib("1T") == 1024
    assert parse_size_to_gib("100") == 1
    assert parse_size_to_gib("") == 0
    assert parse_size_to_gib("garbage") == 0

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

    disks = parse_disks(config, storage_meta, {})

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
    assert de.size_gib == 1
    assert de.to_csv_field() == "vm-100-disk-efi-efidisk0:1:vg01:lvm"

    # Check tpmstate0
    dt = next(d for d in disks if d.config_key == "tpmstate0")
    assert dt.lv_name == "vm-100-disk-tpm"
    assert dt.size_gib == 1
    assert dt.to_csv_field() == "vm-100-disk-tpm-tpmstate0:1:vg01:lvm"


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

    disks = parse_disks(config, storage_meta, {})

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
    disks = parse_disks(config, storage_meta, {})
    assert len(disks) == 2  # scsi0 valid, scsi2 valid with size 0 (scsi1 malformed string skipped)
    assert set(d.config_key for d in disks) == {"scsi0", "scsi2"}


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
    # Unknown ostype defaults to "other"
    assert map_os_family("unknown", None) == "other"
    assert map_os_family("", None) == ""

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

def test_total_vcpus():
    assert total_vcpus({"cores": 4, "sockets": 2}) == "8"
    assert total_vcpus({"cores": 2}) == "2"
    assert total_vcpus({}) == "1"
    assert total_vcpus({"cores": 0}) == ""


def test_backup_coverage():
    jobs = [{"enabled": 1, "all": 1, "exclude": "101", "storage": "pbs"}]
    assert backup_coverage(jobs, 100, "") == ("true", "pbs")
    assert backup_coverage(jobs, 101, "") == ("false", "")

    disabled_jobs = [{"enabled": 0, "all": 1, "storage": "pbs"}]
    assert backup_coverage(disabled_jobs, 100, "") == ("false", "")

    pool_jobs = [{"enabled": 1, "pool": "prod", "storage": "nfs1"}]
    assert backup_coverage(pool_jobs, 100, "prod") == ("true", "nfs1")
    assert backup_coverage(pool_jobs, 100, "") == ("false", "")


def test_add_tag():
    assert add_tag("web;prod", "template") == "web;prod;template"
    assert add_tag("template", "template") == "template"
    assert add_tag("", "template") == "template"


def test_parse_disks_volume_sizes():
    storage_meta = {"local-lvm": {"vgname": "vg02", "type": "lvm-thin"}}
    config = {"scsi0": "local-lvm:vm-100-disk-0,size=50G"}

    disks_prov = parse_disks(config, storage_meta, {"local-lvm:vm-100-disk-0": 12})
    assert len(disks_prov) == 1
    assert disks_prov[0].size_gib == 50
    assert disks_prov[0].to_csv_field() == "vm-100-disk-0-scsi0:50:vg02:lvm-thin"

    disks_fallback = parse_disks({"scsi0": "local-lvm:vm-100-disk-0"}, storage_meta, {"local-lvm:vm-100-disk-0": 12})
    assert len(disks_fallback) == 1
    assert disks_fallback[0].size_gib == 12

def test_parse_disks_unused():
    storage_meta = {"local-lvm": {"vgname": "vg02", "type": "lvm-thin"}}
    config = {"unused0": "local-lvm:vm-100-disk-1"}

    # With volume usage -> emitted
    disks = parse_disks(config, storage_meta, {"local-lvm:vm-100-disk-1": 20})
    assert len(disks) == 1
    assert disks[0].config_key == "unused0"
    assert disks[0].size_gib == 20
    assert disks[0].lv_name == "vm-100-disk-1"

    # Without volume usage -> emitted with size 0
    disks_empty = parse_disks(config, storage_meta, {})
    assert len(disks_empty) == 1
    assert disks_empty[0].size_gib == 0


def test_get_cluster_name_resolution():
    class MockClient(ProxmoxClient):
        def __init__(self, data):
            self.data = data
        def api_get(self, path: str):
            return self.data

    # Node listed first before cluster
    c1 = MockClient([
        {"type": "node", "name": "pve-node-1"},
        {"type": "cluster", "name": "production-cluster"},
    ])
    assert c1.get_cluster_name() == "production-cluster"

    # Standalone (no cluster type)
    c2 = MockClient([{"type": "node", "name": "pve-node-1"}])
    assert c2.get_cluster_name() == "standalone"


class StubClient:
    def __init__(self, template=0, hastate="started", agent=1):
        self.template = template
        self.hastate = hastate
        self.agent = agent

    def get_agent_info(self, node, vmid):
        return {"version": "8.2.2"} if self.agent else None

    def get_cluster_vms(self):
        return [{
            "id": "qemu/100",
            "vmid": 100,
            "name": "prod-web-01",
            "node": "node1",
            "status": "running",
            "template": self.template,
            "pool": "prod",
            "hastate": self.hastate,
        }]

    def get_vm_config(self, node, vmid):
        return {
            "name": "prod-web-01",
            "cores": 2,
            "sockets": 2,
            "memory": 8192,
            "scsi0": "local-lvm:vm-100-disk-0,size=50G",
            "tags": "web",
            "ostype": "l26",
            "agent": str(self.agent),
        }

    def get_storage_config(self, node):
        return [{"storage": "local-lvm", "type": "lvm-thin", "vgname": "pve-thin"}]

    def get_storage_content(self, node, storage):
        return [{"volid": "local-lvm:vm-100-disk-0", "used": 15 * (1024**3)}]

    def get_backup_jobs(self):
        return [{"enabled": 1, "all": 1, "storage": "pbs-storage"}]

    def get_cluster_name(self):
        return "prod-cluster"

    def get_guest_ips(self, node, vmid):
        return ["172.16.10.50", "10.0.0.50"]

    def get_guest_os(self, node, vmid):
        return {"os_family": "linux", "os_distribution": "Ubuntu 22.04", "os_version": "22.04"}

    def get_guest_fqdn(self, node, vmid):
        return "prod-web-01.example.com"


def test_end_to_end_extract_vm():
    stub = StubClient(template=0, hastate="started")
    storage_meta = {"local-lvm": {"vgname": "pve-thin", "type": "lvm-thin"}}
    volume_sizes = {"local-lvm:vm-100-disk-0": 15}
    backup_jobs = stub.get_backup_jobs()
    resource = stub.get_cluster_vms()[0]
    verified_at = "2026-08-24T16:00:00Z"

    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=backup_jobs,
        volume_sizes=volume_sizes,
        verified_at=verified_at,
        status="running",
    )

    assert row is not None
    assert row["name"] == "prod-web-01"
    assert row["external_id"] == "100"
    assert row["cluster"] == "prod-cluster"
    assert row["node"] == "node1"
    assert row["status"] == "running"
    assert row["cpu_cores"] == "4"  # 2 cores * 2 sockets
    assert row["memory_mb"] == "8192"
    assert row["disks"] == "vm-100-disk-0-scsi0:50:pve-thin:lvm-thin"
    assert row["ha_enabled"] == "true"
    assert row["backup_enabled"] == "true"
    assert row["backup_location"] == "pbs-storage"
    assert row["tags"] == "web"
    assert row["last_verified_at"] == verified_at
    assert row["fqdn"] == "prod-web-01.example.com"
    assert row["os_distribution"] == "Ubuntu 22.04"
    assert row["private_ip"] == "172.16.10.50"
    assert row["backup_ip"] == "10.0.0.50"


def test_template_handling():
    stub = StubClient(template=1, hastate="")
    storage_meta = {"local-lvm": {"vgname": "pve-thin", "type": "lvm-thin"}}
    volume_sizes = {"local-lvm:vm-100-disk-0": 15}
    backup_jobs = stub.get_backup_jobs()
    resource = stub.get_cluster_vms()[0]
    verified_at = "2026-08-24T16:00:00Z"

    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=backup_jobs,
        volume_sizes=volume_sizes,
        verified_at=verified_at,
        status="running",
    )

    assert row is not None
    assert row["tags"] == "web;template"
    assert row["status"] in ("running", "powered_off", "unknown")
    assert row["ha_enabled"] == "false"


def test_header_stability():
    stub = StubClient()
    storage_meta = {"local-lvm": {"vgname": "pve-thin", "type": "lvm-thin"}}
    volume_sizes = {"local-lvm:vm-100-disk-0": 15}
    resource = stub.get_cluster_vms()[0]
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=stub.get_backup_jobs(),
        volume_sizes=volume_sizes,
        verified_at="2026-08-24T16:00:00Z",
        status="running",
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        tmp_path = f.name
    try:
        write_csv([row], tmp_path)
        first_line = Path(tmp_path).read_text().splitlines()[0]
        assert first_line == ",".join(TEMPLATE_COLUMNS)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

def test_get_guest_os_version_composition():
    class OsMockClient(ProxmoxClient):
        def __init__(self, data):
            self.data = data
        def api_get(self, path: str):
            return self.data

    # Version + kernel
    c1 = OsMockClient({
        "id": "ubuntu",
        "pretty-name": "Ubuntu 22.04.3 LTS",
        "version-id": "22.04",
        "kernel-release": "5.15.0-91-generic",
    })
    os1 = c1.get_guest_os("node1", 100)
    assert os1["os_family"] == "ubuntu"
    assert os1["os_distribution"] == "Ubuntu 22.04.3 LTS"
    assert os1["os_version"] == "22.04 (5.15.0-91-generic)"

    # Version without kernel (e.g. Windows)
    c2 = OsMockClient({
        "id": "mswindows",
        "pretty-name": "Windows Server 2022",
        "version-id": "2022",
    })
    os2 = c2.get_guest_os("node1", 100)
    assert os2["os_version"] == "2022"

    # Kernel only
    c3 = OsMockClient({"kernel-release": "6.1.0"})
    os3 = c3.get_guest_os("node1", 100)
    assert os3["os_version"] == "6.1.0"


def test_extract_vm_agent_gating_agent_disabled():
    stub = StubClient(agent=0)
    storage_meta = {"local-lvm": {"vgname": "pve-thin", "type": "lvm-thin"}}
    volume_sizes = {"local-lvm:vm-100-disk-0": 15}
    resource = stub.get_cluster_vms()[0]
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=stub.get_backup_jobs(),
        volume_sizes=volume_sizes,
        verified_at="2026-08-24T16:00:00Z",
        status="running",
    )
    assert row is not None
    assert row["fqdn"] == ""
    assert row["os_distribution"] == ""
    assert row["private_ip"] == ""
    assert row["public_ip"] == ""
    assert row["backup_ip"] == ""


def test_extract_vm_stopped_vm_never_probes_agent():
    class UnreachableStub(StubClient):
        def get_agent_info(self, node, vmid):
            raise AssertionError("Agent probe should not be called on stopped VM")

    stub = UnreachableStub(agent=1)
    storage_meta = {"local-lvm": {"vgname": "pve-thin", "type": "lvm-thin"}}
    volume_sizes = {"local-lvm:vm-100-disk-0": 15}
    resource = stub.get_cluster_vms()[0]
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=stub.get_backup_jobs(),
        volume_sizes=volume_sizes,
        verified_at="2026-08-24T16:00:00Z",
        status="stopped",
    )
    assert row is not None
    assert row["fqdn"] == ""
    assert row["status"] == "powered_off"


def test_extract_vm_config_omits_agent_flag():
    class NoAgentFlagStub(StubClient):
        def get_vm_config(self, node, vmid):
            cfg = super().get_vm_config(node, vmid)
            cfg.pop("agent", None)
            return cfg

    stub = NoAgentFlagStub(agent=1)
    storage_meta = {"local-lvm": {"vgname": "pve-thin", "type": "lvm-thin"}}
    volume_sizes = {"local-lvm:vm-100-disk-0": 15}
    resource = stub.get_cluster_vms()[0]
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=stub.get_backup_jobs(),
        volume_sizes=volume_sizes,
        verified_at="2026-08-24T16:00:00Z",
        status="running",
    )
    assert row is not None
    assert row["fqdn"] == "prod-web-01.example.com"
def test_scsihw_not_matched_as_disk(capsys):
    config = {"scsihw": "virtio-scsi-single", "scsi0": "local-lvm:vm-100-disk-0,size=50G"}
    disks = parse_disks(config, {}, {})
    assert len(disks) == 1
    assert disks[0].config_key == "scsi0"
    captured = capsys.readouterr()
    assert "Skipping malformed disk" not in captured.err


def test_parse_size_to_gib_sub_gib_and_bytes():
    assert parse_size_to_gib("4M") == 1
    assert parse_size_to_gib("512K") == 1
    assert parse_size_to_gib("1073741824") == 1
    assert parse_size_to_gib("50G") == 50
    assert parse_size_to_gib("1T") == 1024
    assert parse_size_to_gib("bogus") == 0
    assert parse_size_to_gib("0") == 0


def test_parse_disks_provisioned_size_over_used():
    disks = parse_disks({"scsi0": "lvm:vm-1-disk-0,size=100G"}, {}, {"lvm:vm-1-disk-0": 3})
    assert len(disks) == 1
    assert disks[0].to_csv_field() == "vm-1-disk-0-scsi0:100:lvm:"


def test_total_vcpus_defaults():
    assert total_vcpus({"sockets": 2}) == "2"
    assert total_vcpus({"cores": 4}) == "4"
    assert total_vcpus({"cores": 2, "sockets": 2}) == "4"
    assert total_vcpus({"cores": "x"}) == ""


def test_main_empty_cluster_vms_fallback(monkeypatch, tmp_path):
    from proxmox_inventory_extract import main

    class FallbackClient(ProxmoxClient):
        def __init__(self):
            pass
        def get_ticket(self):
            pass
        def get_cluster_name(self):
            return "cluster1"
        def get_nodes(self):
            return ["node1"]
        def get_backup_jobs(self):
            return []
        def get_cluster_vms(self):
            return []
        def get_storage_config(self, node):
            return []
        def get_storage_content(self, node, storage):
            return []
        def get_vms_for_node(self, node):
            return [{"vmid": 100, "status": "running"}]
        def get_vm_config(self, node, vmid):
            return {"name": "vm100", "cores": 2}
        def get_agent_info(self, node, vmid):
            return None

    csv_out = str(tmp_path / "out.csv")
    monkeypatch.setattr("sys.argv", ["proxmox-inventory-extract.py", "-o", csv_out, "-p", "dummy"])
    monkeypatch.setattr("proxmox_inventory_extract.ProxmoxClient", lambda **kw: FallbackClient())

    rc = main()
    assert rc == 2
    content = Path(csv_out).read_text()
    assert "vm100" in content


def test_resolve_password_empty_env_prompts(monkeypatch):
    from proxmox_inventory_extract import resolve_password
    monkeypatch.setenv("PVE_PASSWORD", "")
    monkeypatch.setattr("getpass.getpass", lambda prompt: "prompted_pw")

    class Args:
        password = None

    assert resolve_password(Args()) == "prompted_pw"


def test_classify_ips_deduplication():
    res = classify_ips(["172.16.0.5", "172.16.0.5"])
    assert res["private_ip"] == ["172.16.0.5"]