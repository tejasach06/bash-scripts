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
    map_os_family,
    total_vcpus,
    backup_coverage,
    extract_vm,
    serialize_vm,
    write_csv,
    TEMPLATE_COLUMNS,
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
    lv, size, sid, volid = parse_disk_value("vg01:vm-100-disk-0,size=50G")
    assert lv == "vm-100-disk-0"
    assert size == 50
    assert sid == "vg01"
    assert volid == "vg01:vm-100-disk-0"

    # LVM-thin format
    lv, size, sid, volid = parse_disk_value("local-lvm:vm-101-disk-1,size=100G,format=raw")
    assert lv == "vm-101-disk-1"
    assert size == 100
    assert sid == "local-lvm"
    assert volid == "local-lvm:vm-101-disk-1"

    # iSCSI format
    lv, size, sid, volid = parse_disk_value("iscsi0:vm-102-disk-0,size=200G")
    assert lv == "vm-102-disk-0"
    assert size == 200
    assert sid == "iscsi0"
    assert volid == "iscsi0:vm-102-disk-0"

    # Empty
    lv, size, sid, volid = parse_disk_value("")
    assert lv == ""
    assert size == 0
    assert sid == ""
    assert volid == ""

    # Malformed (no colon)
    lv, size, sid, volid = parse_disk_value("no-colon-here")
    assert lv == ""
    assert size == 0
    assert sid == ""
    assert volid == ""

    # No size parameter
    lv, size, sid, volid = parse_disk_value("vg01:vm-100-disk-2")
    assert lv == "vm-100-disk-2"
    assert size == 0
    assert sid == "vg01"
    assert volid == "vg01:vm-100-disk-2"


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
        assert d.storage_name in ("iscsi0", "ceph0")
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


def test_valid_ipv4():
    from proxmox_inventory_extract import valid_ipv4
    assert valid_ipv4("10.0.0.5/24") == "10.0.0.5"
    assert valid_ipv4("999.1.2.3") == ""
    assert valid_ipv4("127.0.0.1") == ""
    assert valid_ipv4("fe80::1") == ""


def test_config_ips():
    from proxmox_inventory_extract import config_ips
    assert config_ips({"ipconfig0": "ip=172.16.5.9/24,gw=172.16.5.1", "ipconfig1": "ip=dhcp"}) == ["172.16.5.9"]


def test_config_macs():
    from proxmox_inventory_extract import config_macs
    assert config_macs({"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"}) == ["aa:bb:cc:dd:ee:ff"]


def test_classify_ips():
    ips = ["10.1.1.1", "172.16.5.9", "203.0.113.7"]
    result = classify_ips(ips)
    assert result == {"backup_ip": ["10.1.1.1"], "private_ip": ["172.16.5.9", "203.0.113.7"]}
    assert "public_ip" not in result


def test_read_arp_table(tmp_path):
    from proxmox_inventory_extract import read_arp_table
    arp_file = tmp_path / "arp"
    arp_file.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:ff     *        vmbr0\n"
        "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        vmbr0\n"
    )
    res = read_arp_table(str(arp_file))
    assert res == {"aa:bb:cc:dd:ee:ff": ["192.168.1.50"]}


def test_get_ha_vmids():
    class HaMockClient(ProxmoxClient):
        def __init__(self):
            pass
        def api_get(self, path: str):
            if path == "/api2/json/cluster/ha/resources":
                return [{"sid": "vm:100"}, {"sid": "vm:102"}, {"sid": "ct:105"}]
            return []

    client = HaMockClient()
    assert client.get_ha_vmids() == {100, 102}
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



def test_map_os_family():
    assert map_os_family("l26", "ubuntu") == "linux"
    assert map_os_family("freebsd", None) == ""
    assert map_os_family("", "ubuntu") == "linux"
    assert map_os_family("", "mswindows") == "windows"
    assert map_os_family("", None) == ""

def test_disk_record_csv_field():
    d = DiskRecord(
        lv_name="vm-100-disk-0",
        config_key="scsi0",
        size_gib=50,
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



def test_sanitize_row():
    from proxmox_inventory_extract import sanitize_row
    row = {
        "name": "vm1",
        "platform": "proxmox",
        "cluster": "c1",
        "os_family": "bsd",
        "last_verified_at": "2026-08-27T13:00:00Z",
        "cpu_cores": "4.0",
    }
    warnings = sanitize_row(row)
    assert len(warnings) == 3
    assert row["os_family"] == ""
    assert row["last_verified_at"] == ""
    assert row["cpu_cores"] == ""
    assert row["name"] == "vm1"

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
    assert total_vcpus({}) == ""
    assert total_vcpus({"cores": 0}) == ""

def test_resource_num():
    from proxmox_inventory_extract import resource_num
    assert resource_num({"maxmem": 4294967296}, "maxmem", 1024 * 1024) == "4096"
    assert resource_num({"maxcpu": 4.0}, "maxcpu") == "4"
    assert resource_num({}, "maxcpu") == ""
    assert resource_num({}, "maxmem", 1024 * 1024) == ""


def test_backup_coverage():
    jobs = [{"enabled": 1, "all": 1, "exclude": "101", "storage": "pbs"}]
    assert backup_coverage(jobs, 100, "") == ("true", "pbs")
    assert backup_coverage(jobs, 101, "") == ("false", "")

    disabled_jobs = [{"enabled": 0, "all": 1, "storage": "pbs"}]
    assert backup_coverage(disabled_jobs, 100, "") == ("false", "")

    pool_jobs = [{"enabled": 1, "pool": "prod", "storage": "nfs1"}]
    assert backup_coverage(pool_jobs, 100, "prod") == ("true", "nfs1")
    assert backup_coverage(pool_jobs, 100, "") == ("false", "")



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
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=backup_jobs,
        volume_sizes=volume_sizes,
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
    assert row["last_verified_at"] == ""
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
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta=storage_meta,
        resource=resource,
        backup_jobs=backup_jobs,
        volume_sizes=volume_sizes,
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
    c1 = OsMockClient({"result": {
        "id": "ubuntu",
        "pretty-name": "Ubuntu 22.04.3 LTS",
        "version-id": "22.04",
        "kernel-release": "5.15.0-91-generic",
    }})
    os1 = c1.get_guest_os("node1", 100)
    assert os1["os_family"] == "ubuntu"
    assert os1["os_distribution"] == "Ubuntu 22.04.3 LTS"
    assert os1["os_version"] == "22.04 (5.15.0-91-generic)"

    # Version without kernel (e.g. Windows)
    c2 = OsMockClient({"result": {
        "id": "mswindows",
        "pretty-name": "Windows Server 2022",
        "version-id": "2022",
    }})
    os2 = c2.get_guest_os("node1", 100)
    assert os2["os_version"] == "2022"

    # Kernel only
    c3 = OsMockClient({"result": {"kernel-release": "6.1.0"}})
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
    assert total_vcpus({}) == ""

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


def test_stopped_agentless_vm_multi_source():
    class StoppedAgentlessStub(StubClient):
        def __init__(self):
            pass
        def get_vm_config(self, node, vmid):
            return {
                "name": "app01",
                "ipconfig0": "ip=172.16.5.9/24",
                "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
                "searchdomain": "corp.example.com",
            }
        def get_backup_jobs(self):
            return []

    stub = StoppedAgentlessStub()
    resource = {"maxcpu": 4.0, "maxmem": 4294967296}
    row = extract_vm(
        client=stub,
        node="node1",
        vmid=100,
        cluster_name="prod-cluster",
        storage_meta={},
        resource=resource,
        backup_jobs=[],
        volume_sizes={},
        status="stopped",
        local_node="node1",
    )
    assert row is not None
    assert row["private_ip"] == "172.16.5.9"
    assert row["backup_ip"] == ""
    assert row["public_ip"] == ""
    assert row["fqdn"] == "app01.corp.example.com"
    assert row["cpu_cores"] == "4"
    assert row["memory_mb"] == "4096"
    assert row["status"] == "powered_off"
    assert row["last_verified_at"] == ""

    # Human-curated columns stay empty
    human_curated = [
        "sr_id", "datacenter", "environment", "criticality", "vm_type",
        "public_ip", "owner", "business_owner", "technical_owner",
        "applications", "monitoring_enabled", "pmp_enabled",
        "last_patch_date", "last_vuln_scan_date", "last_verified_at",
        "decommission_date", "security_remarks",
    ]
    for col in human_curated:
        assert row[col] == "", f"Expected {col} to be empty, got {row[col]!r}"


def test_classify_ips_deduplication():
    res = classify_ips(["172.16.0.5", "172.16.0.5"])
    assert res["private_ip"] == ["172.16.0.5"]


def test_agent_get_unwraps_result_and_path():
    class UnwrappingMockClient(ProxmoxClient):
        def __init__(self, payload):
            self.payload = payload
            self.requested_path = None
        def api_get(self, path: str):
            self.requested_path = path
            return self.payload

    c1 = UnwrappingMockClient({"result": {"version": "8.2.2"}})
    res1 = c1.agent_get("pve", 101, "info")
    assert res1 == {"version": "8.2.2"}
    assert c1.requested_path == "/api2/json/nodes/pve/qemu/101/agent/info"

    c2 = UnwrappingMockClient({"version": "8.2.2"})
    res2 = c2.agent_get("pve", 101, "info")
    assert res2 == {"version": "8.2.2"}


def test_get_guest_fqdn_uses_host_name_key_and_path():
    class FqdnMockClient(ProxmoxClient):
        def __init__(self, payload):
            self.payload = payload
            self.requested_path = None
        def api_get(self, path: str):
            self.requested_path = path
            return self.payload

    c1 = FqdnMockClient({"result": {"host-name": "web01.corp.example"}})
    fqdn1 = c1.get_guest_fqdn("pve", 101)
    assert fqdn1 == "web01.corp.example"
    assert c1.requested_path == "/api2/json/nodes/pve/qemu/101/agent/get-host-name"

    c2 = FqdnMockClient({"result": {"host-name": "workStation"}})
    fqdn2 = c2.get_guest_fqdn("pve", 101)
    assert fqdn2 is None


def test_get_guest_ips_unwraps_result():
    class IpsMockClient(ProxmoxClient):
        def __init__(self, payload):
            self.payload = payload
        def api_get(self, path: str):
            return self.payload

    payload = {
        "result": [
            {
                "name": "lo",
                "ip-addresses": [
                    {"ip-address": "127.0.0.1"},
                    {"ip-address": "::1"},
                ],
            },
            {
                "name": "ens18",
                "ip-addresses": [
                    {"ip-address": "192.168.0.17"},
                    {"ip-address": "fe80::4c4a:aab9:505f:af94"},
                ],
            },
        ]
    }
    c = IpsMockClient(payload)
    ips = c.get_guest_ips("pve", 101)
    assert ips == ["192.168.0.17"]
def test_ostype_family_win_prefix():
    from proxmox_inventory_extract import map_os_family
    assert map_os_family("win11", None) == "windows"
    assert map_os_family("win10", None) == "windows"
    assert map_os_family("win2022", None) == "windows"


def test_parse_disks_sorted_keys():
    from proxmox_inventory_extract import parse_disks
    config = {
        "scsi1": "local-lvm:vm-100-disk-1,size=20G",
        "efidisk0": "local-lvm:vm-100-disk-0,size=1M",
        "scsi0": "local-lvm:vm-100-disk-0,size=10G",
    }
    disks = parse_disks(config, {}, {})
    keys = [d.config_key for d in disks]
    assert keys == ["efidisk0", "scsi0", "scsi1"]


def test_main_no_probe_option(tmp_path, monkeypatch):
    import sys
    from proxmox_inventory_extract import main, ProxmoxClient

    class StubClient:
        def __init__(self, *args, **kwargs):
            pass
        def get_ticket(self):
            pass
        def get_cluster_name(self):
            return "standalone"
        def get_nodes(self):
            return ["node1"]
        def get_backup_jobs(self):
            return []
        def get_ha_vmids(self):
            return set()
        def get_storage_config(self, node):
            return []
        def get_storage_content(self, node, sid):
            return []
        def get_cluster_vms(self):
            return [{"vmid": 100, "node": "node1", "status": "running"}]
        def get_vm_config(self, node, vmid):
            return {"name": "test-vm", "cores": 1, "memory": 512}
        def get_agent_info(self, node, vmid):
            return None

    monkeypatch.setattr("proxmox_inventory_extract.ProxmoxClient", StubClient)
    out_csv = str(tmp_path / "out.csv")
    monkeypatch.setattr(sys, "argv", ["script", "--no-probe", "-o", out_csv, "-p", "pass"])
    ret = main()
    assert ret == 0
    assert (tmp_path / "out.csv").exists()


def test_live_pve_host_payload_end_to_end(tmp_path, monkeypatch):
    """Exact live API payloads from Proxmox VE 9.2.10 host (192.168.0.5)."""
    import sys
    from proxmox_inventory_extract import main, ProxmoxClient, sanitize_row, TEMPLATE_COLUMNS
    import csv

    LIVE_ENDPOINTS = {
        "/api2/json/cluster/status": [
            {"id": "node/pve", "ip": "192.168.0.5", "level": "", "local": 1, "name": "pve", "nodeid": 0, "online": 1, "type": "node"}
        ],
        "/api2/json/nodes": [
            {"node": "pve", "status": "online"}
        ],
        "/api2/json/cluster/ha/resources": [],
        "/api2/json/cluster/backup": [],
        "/api2/json/cluster/resources?type=vm": [
            {"id": "lxc/100", "name": "adguard", "node": "pve", "status": "running", "type": "lxc", "vmid": 100, "template": 0},
            {"id": "qemu/101", "name": "work-station", "node": "pve", "status": "running", "type": "qemu", "vmid": 101, "template": 0, "maxcpu": 6, "maxmem": 4294967296}
        ],
        "/api2/json/nodes/pve/storage": [
            {"active": 1, "storage": "local", "type": "dir", "content": "backup,iso,snippets,vztmpl,rootdir"},
            {"active": 1, "storage": "local-lvm", "type": "lvmthin", "content": "images,rootdir"},
            {"active": 1, "storage": "ZPOOL", "type": "zfspool", "content": "rootdir,images"}
        ],
        "/api2/json/nodes/pve/storage/local/content?content=images": [],
        "/api2/json/nodes/pve/storage/local-lvm/content?content=images": [],
        "/api2/json/nodes/pve/storage/ZPOOL/content?content=images": [
            {"content": "rootdir", "format": "subvol", "name": "subvol-100-disk-0", "size": 1073741824, "vmid": 100, "volid": "ZPOOL:subvol-100-disk-0"},
            {"content": "images", "format": "raw", "name": "vm-101-disk-0", "size": 1048576, "vmid": 101, "volid": "ZPOOL:vm-101-disk-0"},
            {"content": "images", "format": "raw", "name": "vm-101-disk-1", "size": 536870912000, "vmid": 101, "volid": "ZPOOL:vm-101-disk-1"}
        ],
        "/api2/json/nodes/pve/qemu/101/config": {
            "agent": "1",
            "bios": "ovmf",
            "boot": "order=scsi0;ide2;net0",
            "cores": 3,
            "cpu": "x86-64-v2-AES",
            "efidisk0": "ZPOOL:vm-101-disk-0,efitype=4m,size=1M",
            "ide2": "local:iso/debian-13.6.0-amd64-netinst.iso,media=cdrom,size=755M",
            "memory": "4096",
            "name": "work-station",
            "net0": "virtio=BC:24:11:F0:25:EB,bridge=vmbr0,firewall=1",
            "ostype": "l26",
            "scsi0": "ZPOOL:vm-101-disk-1,discard=on,iothread=1,size=500G",
            "scsihw": "virtio-scsi-single",
            "sockets": 2
        },
        "/api2/json/nodes/pve/qemu/101/agent/info": {
            "result": {
                "version": "10.0.11",
                "supported_commands": [{"enabled": True, "name": "guest-get-osinfo", "success-response": True}]
            }
        },
        "/api2/json/nodes/pve/qemu/101/agent/get-osinfo": {
            "result": {
                "id": "debian",
                "kernel-release": "6.12.101+deb13-amd64",
                "name": "Debian GNU/Linux",
                "pretty-name": "Debian GNU/Linux 13 (trixie)",
                "version": "13 (trixie)",
                "version-id": "13"
            }
        },
        "/api2/json/nodes/pve/qemu/101/agent/get-host-name": {
            "result": {
                "host-name": "workStation"
            }
        },
        "/api2/json/nodes/pve/qemu/101/agent/network-get-interfaces": {
            "result": [
                {
                    "name": "lo",
                    "ip-addresses": [
                        {"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8},
                        {"ip-address": "::1", "ip-address-type": "ipv6", "prefix": 128}
                    ]
                },
                {
                    "name": "ens18",
                    "hardware-address": "bc:24:11:f0:25:eb",
                    "ip-addresses": [
                        {"ip-address": "192.168.0.17", "ip-address-type": "ipv4", "prefix": 24},
                        {"ip-address": "fe80::4c4a:aab9:505f:af94", "ip-address-type": "ipv6", "prefix": 64}
                    ]
                }
            ]
        }
    }

    class LiveMockClient(ProxmoxClient):
        def __init__(self, *args, **kwargs):
            pass
        def get_ticket(self):
            pass
        def api_get(self, path: str):
            if path in LIVE_ENDPOINTS:
                return LIVE_ENDPOINTS[path]
            raise AssertionError(f"Unexpected path requested: {path}")

    monkeypatch.setattr("proxmox_inventory_extract.ProxmoxClient", LiveMockClient)
    out_csv = str(tmp_path / "live-mock.csv")
    monkeypatch.setattr(sys, "argv", ["script", "--insecure", "-H", "127.0.0.1:8006", "-o", out_csv, "-p", "dummy"])

    ret = main()
    assert ret == 0

    with open(out_csv) as f:
        reader = csv.DictReader(f)
        hdr = tuple(reader.fieldnames or [])
        assert hdr == TEMPLATE_COLUMNS
        rows = list(reader)

    assert len(rows) == 1
    r = rows[0]
    assert r["name"] == "work-station"
    assert r["external_id"] == "101"
    assert r["platform"] == "proxmox"
    assert r["node"] == "pve"
    assert r["cluster"] == "standalone"
    assert r["status"] == "running"
    assert r["cpu_cores"] == "6"
    assert r["memory_mb"] == "4096"
    assert r["disks"] == "vm-101-disk-0-efidisk0:1:ZPOOL:zfspool;vm-101-disk-1-scsi0:500:ZPOOL:zfspool"
    assert r["os_family"] == "linux"
    assert r["os_distribution"] == "Debian GNU/Linux 13 (trixie)"
    assert r["os_version"] == "13 (6.12.101+deb13-amd64)"
    assert r["private_ip"] == "192.168.0.17"
    assert r["fqdn"] == ""
    assert r["ha_enabled"] == "false"
    assert r["backup_enabled"] == "false"
    assert sanitize_row(dict(r)) == []