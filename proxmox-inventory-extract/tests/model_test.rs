use std::collections::HashMap;
use serde_json::json;
use proxmox_inventory_extract::model::*;

#[test]
fn test_template_columns_count() {
    assert_eq!(TEMPLATE_COLUMNS.len(), 39);
    assert_eq!(TEMPLATE_COLUMNS[0], "name");
    assert_eq!(TEMPLATE_COLUMNS[14], "disks");
    assert_eq!(TEMPLATE_COLUMNS[38], "description");
}

#[test]
fn test_parse_size_to_gib_cases() {
    assert_eq!(parse_size_to_gib("50G"), 50);
    assert_eq!(parse_size_to_gib("100.5G"), 100);
    assert_eq!(parse_size_to_gib("2.5T"), 2560);
    assert_eq!(parse_size_to_gib("512M"), 1);
    assert_eq!(parse_size_to_gib("4M"), 1);
    assert_eq!(parse_size_to_gib("0"), 0);
    assert_eq!(parse_size_to_gib("0G"), 0);
    assert_eq!(parse_size_to_gib("invalid"), 0);
    assert_eq!(parse_size_to_gib(""), 0);
    assert_eq!(parse_size_to_gib("32GB"), 32);
    assert_eq!(parse_size_to_gib("1024K"), 1);
}

#[test]
fn test_parse_disk_value_cases() {
    // LVM thin
    let (lv, size, storage, volid) = parse_disk_value("local-lvm:vm-100-disk-0,size=32G");
    assert_eq!(lv, "vm-100-disk-0");
    assert_eq!(size, 32);
    assert_eq!(storage, "local-lvm");
    assert_eq!(volid, "local-lvm:vm-100-disk-0");

    // iSCSI
    let (lv, size, storage, volid) = parse_disk_value("iscsi-storage:0.0.1.scsi-36001405,size=100G,backup=0");
    assert_eq!(lv, "0.0.1.scsi-36001405");
    assert_eq!(size, 100);
    assert_eq!(storage, "iscsi-storage");
    assert_eq!(volid, "iscsi-storage:0.0.1.scsi-36001405");

    // Raw path / passthrough (no colon in storage:volume)
    let (lv, size, storage, volid) = parse_disk_value("/dev/disk/by-id/ata-ST3000DM001,size=500G");
    assert_eq!(lv, "");
    assert_eq!(size, 0);
    assert_eq!(storage, "");
    assert_eq!(volid, "");

    // Nested volume path
    let (lv, size, storage, volid) = parse_disk_value("ceph:images/101/vm-101-disk-0.raw,size=50G");
    assert_eq!(lv, "vm-101-disk-0.raw");
    assert_eq!(size, 50);
    assert_eq!(storage, "ceph");
    assert_eq!(volid, "ceph:images/101/vm-101-disk-0.raw");

    // Missing size parameter
    let (lv, size, storage, volid) = parse_disk_value("local-zfs:vm-102-disk-0");
    assert_eq!(lv, "vm-102-disk-0");
    assert_eq!(size, 0);
    assert_eq!(storage, "local-zfs");
    assert_eq!(volid, "local-zfs:vm-102-disk-0");
}

#[test]
fn test_disk_record_to_csv_field() {
    let rec = DiskRecord {
        lv_name: "vm-101-disk-0".to_string(),
        config_key: "efidisk0".to_string(),
        size_gib: 1,
        storage_name: "ZPOOL".to_string(),
        storage_type: "zfspool".to_string(),
    };
    assert_eq!(rec.disk_name(), "vm-101-disk-0-efidisk0");
    assert_eq!(rec.to_csv_field(), "vm-101-disk-0-efidisk0:1:ZPOOL:zfspool");
}

#[test]
fn test_parse_disks_cases() {
    let mut config = serde_json::Map::new();
    config.insert("scsi0".to_string(), json!("local-zfs:vm-100-disk-1,size=50G"));
    config.insert("efidisk0".to_string(), json!("local-zfs:vm-100-disk-0,size=1G"));
    config.insert("scsihw".to_string(), json!("virtio-scsi-pci"));
    config.insert("ide2".to_string(), json!("local:iso/debian.iso,media=cdrom"));
    config.insert("unused0".to_string(), json!("none"));
    config.insert("scsi1".to_string(), json!("/dev/sdb,backup=0")); // passthrough without colon
    config.insert("virtio0".to_string(), json!("ceph:vm-100-disk-2")); // missing size, fallback to volume_sizes

    let mut storage_meta = HashMap::new();
    storage_meta.insert(
        "local-zfs".to_string(),
        StorageMeta::new("local-zfs", "zfspool", "ZPOOL"),
    );
    storage_meta.insert(
        "ceph".to_string(),
        StorageMeta::new("ceph", "rbd", ""),
    );

    let mut volume_sizes = HashMap::new();
    volume_sizes.insert("ceph:vm-100-disk-2".to_string(), 120);

    let disks = parse_disks(&config, &storage_meta, &volume_sizes);

    // efidisk0 sorted before scsi0, scsihw skipped, ide2 cdrom skipped, unused0 none skipped,
    // scsi1 passthrough skipped, virtio0 uses fallback volume size 120
    assert_eq!(disks.len(), 3);

    // 1st: efidisk0
    assert_eq!(disks[0].config_key, "efidisk0");
    assert_eq!(disks[0].lv_name, "vm-100-disk-0");
    assert_eq!(disks[0].size_gib, 1);
    assert_eq!(disks[0].storage_name, "ZPOOL"); // vgname overrides storage_id
    assert_eq!(disks[0].storage_type, "zfspool");

    // 2nd: scsi0
    assert_eq!(disks[1].config_key, "scsi0");
    assert_eq!(disks[1].lv_name, "vm-100-disk-1");
    assert_eq!(disks[1].size_gib, 50);
    assert_eq!(disks[1].storage_name, "ZPOOL");
    assert_eq!(disks[1].storage_type, "zfspool");

    // 3rd: virtio0
    assert_eq!(disks[2].config_key, "virtio0");
    assert_eq!(disks[2].lv_name, "vm-100-disk-2");
    assert_eq!(disks[2].size_gib, 120);
    assert_eq!(disks[2].storage_name, "ceph"); // vgname is empty, fallback to storage_id
    assert_eq!(disks[2].storage_type, "rbd");
}

#[test]
fn test_valid_ipv4_cases() {
    assert_eq!(valid_ipv4("192.168.1.100/24"), "192.168.1.100");
    assert_eq!(valid_ipv4("10.0.0.1"), "10.0.0.1");
    assert_eq!(valid_ipv4("127.0.0.1"), "");
    assert_eq!(valid_ipv4("169.254.10.20"), "");
    assert_eq!(valid_ipv4("224.0.0.1"), "");
    assert_eq!(valid_ipv4("0.0.0.0"), "");
    assert_eq!(valid_ipv4("fe80::1/64"), "");
    assert_eq!(valid_ipv4("::1"), "");
    assert_eq!(valid_ipv4("not-an-ip"), "");
    assert_eq!(valid_ipv4(""), "");
}

#[test]
fn test_classify_ips_cases() {
    let ips = vec![
        "192.168.1.50".to_string(),
        "10.10.0.1".to_string(),
        "192.168.1.50/24".to_string(), // duplicate canonical IP
        "10.20.0.1".to_string(),
        "127.0.0.1".to_string(), // invalid/loopback
        "172.16.0.2".to_string(),
    ];
    let classified = classify_ips(&ips);
    assert_eq!(
        classified.get("backup_ip").unwrap(),
        &vec!["10.10.0.1".to_string(), "10.20.0.1".to_string()]
    );
    assert_eq!(
        classified.get("private_ip").unwrap(),
        &vec!["192.168.1.50".to_string(), "172.16.0.2".to_string()]
    );
}

#[test]
fn test_total_vcpus_cases() {
    let mut config = serde_json::Map::new();
    // both missing
    assert_eq!(total_vcpus(&config), "");

    // cores only -> sockets defaults to 1
    config.insert("cores".to_string(), json!(4));
    assert_eq!(total_vcpus(&config), "4");

    // sockets only -> cores defaults to 1
    config.remove("cores");
    config.insert("sockets".to_string(), json!(2));
    assert_eq!(total_vcpus(&config), "2");

    // both present
    config.insert("cores".to_string(), json!(6));
    assert_eq!(total_vcpus(&config), "12");

    // string values
    config.insert("cores".to_string(), json!("4"));
    config.insert("sockets".to_string(), json!("2"));
    assert_eq!(total_vcpus(&config), "8");

    // invalid values
    config.insert("cores".to_string(), json!("invalid"));
    assert_eq!(total_vcpus(&config), "");
}

#[test]
fn test_resource_num_cases() {
    let mut res = serde_json::Map::new();
    res.insert("maxmem".to_string(), json!(4294967296u64));
    assert_eq!(resource_num(&res, "maxmem", 1024 * 1024), "4096");

    // zero returns empty
    res.insert("maxmem".to_string(), json!(0));
    assert_eq!(resource_num(&res, "maxmem", 1024 * 1024), "");

    // missing key
    assert_eq!(resource_num(&res, "nonexistent", 1), "");

    // string number
    res.insert("cpus".to_string(), json!("4"));
    assert_eq!(resource_num(&res, "cpus", 1), "4");
}

#[test]
fn test_map_os_family_cases() {
    // ostype takes precedence
    assert_eq!(map_os_family("l26", None), "linux");
    assert_eq!(map_os_family("l24", None), "linux");
    assert_eq!(map_os_family("win11", None), "windows");
    assert_eq!(map_os_family("w2k8", None), "windows");
    assert_eq!(map_os_family("solaris", None), "");
    assert_eq!(map_os_family("other", None), "");
    assert_eq!(map_os_family("freebsd", None), "");

    // fallback to guest_os_family when ostype is empty
    assert_eq!(map_os_family("", Some("debian")), "linux");
    assert_eq!(map_os_family("", Some("ubuntu")), "linux");
    assert_eq!(map_os_family("", Some("alpine")), "linux");
    assert_eq!(map_os_family("", Some("windows 11")), "windows");
    assert_eq!(map_os_family("", Some("mswin10")), "windows");
    assert_eq!(map_os_family("", Some("unknown")), "");
    assert_eq!(map_os_family("", None), "");
}

#[test]
fn test_parse_tags_cases() {
    let mut config = serde_json::Map::new();
    assert_eq!(parse_tags(&config), "");

    config.insert("tags".to_string(), json!("tag1; tag2 ; tag3 "));
    assert_eq!(parse_tags(&config), "tag1;tag2;tag3");

    config.insert("tags".to_string(), json!(";;tag1;;;tag2;"));
    assert_eq!(parse_tags(&config), "tag1;tag2");
}

#[test]
fn test_backup_coverage_cases() {
    let jobs = vec![
        // disabled job
        json!({
            "enabled": 0,
            "vmid": "100",
            "storage": "backup-storage-disabled"
        }),
        // direct vmid job
        json!({
            "enabled": 1,
            "vmid": "100, 101",
            "storage": "backup-direct"
        }),
        // all with exclude
        json!({
            "enabled": 1,
            "all": 1,
            "exclude": "200, 201",
            "storage": "backup-all"
        }),
        // pool match
        json!({
            "enabled": 1,
            "pool": "production",
            "storage": "backup-pool"
        }),
    ];

    // disabled job skipped, direct vmid match for 100
    assert_eq!(
        backup_coverage(&jobs, 100, ""),
        ("true".to_string(), "backup-direct".to_string())
    );

    // direct vmid match for 101
    assert_eq!(
        backup_coverage(&jobs, 101, ""),
        ("true".to_string(), "backup-direct".to_string())
    );

    // 102 matches "all" job (not excluded)
    assert_eq!(
        backup_coverage(&jobs, 102, ""),
        ("true".to_string(), "backup-all".to_string())
    );

    // 200 is excluded from "all" job, and pool is empty -> not covered
    assert_eq!(
        backup_coverage(&jobs, 200, ""),
        ("false".to_string(), "".to_string())
    );

    // 200 with pool "production" matches pool job
    assert_eq!(
        backup_coverage(&jobs, 200, "production"),
        ("true".to_string(), "backup-pool".to_string())
    );

    // empty jobs
    assert_eq!(
        backup_coverage(&[], 100, ""),
        ("false".to_string(), "".to_string())
    );
}

#[test]
fn test_config_ips_and_macs() {
    let mut config = serde_json::Map::new();
    config.insert("ipconfig0".to_string(), json!("ip=192.168.0.50/24,gw=192.168.0.1"));
    config.insert("ipconfig1".to_string(), json!("ip=dhcp"));
    config.insert("ipconfig2".to_string(), json!("ip=10.0.0.50/8"));
    config.insert("net0".to_string(), json!("virtio=BC:24:11:AA:BB:CC,bridge=vmbr0"));
    config.insert("net1".to_string(), json!("e1000=00:11:22:33:44:55,bridge=vmbr1"));

    let ips = config_ips(&config);
    assert_eq!(ips, vec!["192.168.0.50", "10.0.0.50"]);

    let macs = config_macs(&config);
    assert_eq!(macs, vec!["bc:24:11:aa:bb:cc", "00:11:22:33:44:55"]);

    let tag_ips = extract_ips_from_tags("app; 192.168.1.15; web; 10.0.0.25");
    assert_eq!(tag_ips, vec!["192.168.1.15", "10.0.0.25"]);
}

