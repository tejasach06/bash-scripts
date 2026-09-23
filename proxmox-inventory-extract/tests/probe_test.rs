use proxmox_inventory_extract::probe::{read_arp_table, read_dhcp_leases, reverse_dns};
use std::io::Write;

#[test]
fn test_read_arp_table() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "IP address       HW type     Flags       HW address            Mask     Device").unwrap();
    writeln!(file, "192.168.1.50     0x1         0x2         AA:BB:CC:DD:EE:FF     *        vmbr0").unwrap();
    writeln!(file, "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        vmbr0").unwrap();
    writeln!(file, "127.0.0.1        0x1         0x2         11:22:33:44:55:66     *        vmbr0").unwrap();
    writeln!(file, "192.168.1.52     0x1         0x2         AA:BB:CC:DD:EE:FF     *        vmbr0").unwrap();
    writeln!(file, "short line").unwrap();

    let res = read_arp_table(file.path().to_str().unwrap());
    assert_eq!(
        res.get("aa:bb:cc:dd:ee:ff").unwrap(),
        &vec!["192.168.1.50".to_string(), "192.168.1.52".to_string()]
    );
    assert!(!res.contains_key("00:00:00:00:00:00"));
    assert!(!res.contains_key("11:22:33:44:55:66"));
}

#[test]
fn test_read_arp_table_nonexistent_file() {
    let res = read_arp_table("/nonexistent/path/arp");
    assert!(res.is_empty());
}

#[test]
fn test_read_dhcp_leases() {
    let dir = tempfile::tempdir().unwrap();
    let lease_file1 = dir.path().join("dnsmasq.leases");
    let mut file1 = std::fs::File::create(&lease_file1).unwrap();

    writeln!(file1, "1700000000 52:54:00:12:34:56 192.168.1.101 vm101.example.com 01:52:54:00:12:34:56").unwrap();
    writeln!(file1, "1700000001 52:54:00:12:34:57 192.168.1.102 * *").unwrap();
    writeln!(file1, "1700000002 52:54:00:12:34:58 192.168.1.103 nodot 01:52:54:00:12:34:58").unwrap();
    writeln!(file1, "1700000003 52:54:00:12:34:59 192.168.1.104 localhost.localdomain 01:52:54:00:12:34:59").unwrap();
    writeln!(file1, "1700000004 52:54:00:12:34:56 192.168.1.105 vm101-alt.example.com 01:52:54:00:12:34:56").unwrap();
    writeln!(file1, "bad line").unwrap();

    let glob_pattern = format!("{}/dnsmasq*.leases", dir.path().to_str().unwrap());
    let (mac_to_ips, mac_to_host) = read_dhcp_leases(&[&glob_pattern]);

    // mac_to_ips checks
    let ips_56 = mac_to_ips.get("52:54:00:12:34:56").unwrap();
    assert_eq!(ips_56, &vec!["192.168.1.101".to_string(), "192.168.1.105".to_string()]);
    assert_eq!(mac_to_ips.get("52:54:00:12:34:57").unwrap(), &vec!["192.168.1.102".to_string()]);

    // mac_to_host checks
    // 52:54:00:12:34:56 was updated by the last valid dotted entry
    assert_eq!(mac_to_host.get("52:54:00:12:34:56").unwrap(), "vm101-alt.example.com");
    // "*" ignored
    assert!(!mac_to_host.contains_key("52:54:00:12:34:57"));
    // "nodot" ignored (no dot)
    assert!(!mac_to_host.contains_key("52:54:00:12:34:58"));
    // "localhost.localdomain" ignored (starts with localhost)
    assert!(!mac_to_host.contains_key("52:54:00:12:34:59"));
}

#[test]
fn test_read_dhcp_leases_duplicate_file_in_globs() {
    let dir = tempfile::tempdir().unwrap();
    let lease_file = dir.path().join("dnsmasq.leases");
    let mut file = std::fs::File::create(&lease_file).unwrap();
    writeln!(file, "1700000000 AA:BB:CC:11:22:33 192.168.1.200 host.local *").unwrap();

    let glob1 = format!("{}/dnsmasq.leases", dir.path().to_str().unwrap());
    let glob2 = format!("{}/*.leases", dir.path().to_str().unwrap());

    let (mac_to_ips, _) = read_dhcp_leases(&[&glob1, &glob2]);
    let ips = mac_to_ips.get("aa:bb:cc:11:22:33").unwrap();
    // Should only have processed the file once
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], "192.168.1.200");
}

#[tokio::test]
async fn test_reverse_dns_empty_and_invalid() {
    assert_eq!(reverse_dns("", 1.0).await, "");
    assert_eq!(reverse_dns("not-an-ip", 1.0).await, "");
    assert_eq!(reverse_dns("127.0.0.1", 1.0).await, "");
}

#[tokio::test]
async fn test_reverse_dns_timeout() {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737), which won't answer reverse DNS.
    // With 1 millisecond timeout, it should timeout quickly and return "".
    let start = std::time::Instant::now();
    let res = reverse_dns("192.0.2.1", 0.001).await;
    assert_eq!(res, "");
    assert!(start.elapsed().as_secs_f64() < 1.0);
}
