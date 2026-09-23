use proxmox_inventory_extract::cli::Args;
use proxmox_inventory_extract::csv::sanitize_row;
use proxmox_inventory_extract::extractor::run_orchestrator;
use proxmox_inventory_extract::model::TEMPLATE_COLUMNS;
use serde_json::json;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawns a mock Proxmox server serving exact live API payloads from
/// Proxmox VE 9.2.10 host (192.168.0.5) matching `test_live_pve_host_payload_end_to_end`.
async fn spawn_live_pve_mock_server() -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Ok((mut stream, _)) = listener.accept() => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        let n = match stream.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_str.lines().next().unwrap_or("");
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        if parts.len() < 2 {
                            return;
                        }
                        let path = parts[1];

                        let (status, body) = match path {
                            "/api2/json/access/ticket" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "ticket": "PVE:root@pam:MOCK_TICKET_LIVE_PVE",
                                        "CSRFPreventionToken": "MOCK_CSRF_TOKEN_LIVE_PVE"
                                    }
                                })
                                .to_string(),
                            ),
                            "/api2/json/cluster/status" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {
                                            "id": "node/pve",
                                            "ip": "192.168.0.5",
                                            "level": "",
                                            "local": 1,
                                            "name": "pve",
                                            "nodeid": 0,
                                            "online": 1,
                                            "type": "node"
                                        }
                                    ]
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"node": "pve", "status": "online"}
                                    ]
                                })
                                .to_string(),
                            ),
                            "/api2/json/cluster/ha/resources" => (
                                "200 OK",
                                json!({
                                    "data": []
                                })
                                .to_string(),
                            ),
                            "/api2/json/cluster/backup" => (
                                "200 OK",
                                json!({
                                    "data": []
                                })
                                .to_string(),
                            ),
                            "/api2/json/cluster/resources?type=vm" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {
                                            "id": "lxc/100",
                                            "name": "adguard",
                                            "node": "pve",
                                            "status": "running",
                                            "type": "lxc",
                                            "vmid": 100,
                                            "template": 0
                                        },
                                        {
                                            "id": "qemu/101",
                                            "name": "work-station",
                                            "node": "pve",
                                            "status": "running",
                                            "type": "qemu",
                                            "vmid": 101,
                                            "template": 0,
                                            "maxcpu": 6,
                                            "maxmem": 4294967296u64
                                        }
                                    ]
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/storage" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {
                                            "active": 1,
                                            "storage": "local",
                                            "type": "dir",
                                            "content": "backup,iso,snippets,vztmpl,rootdir"
                                        },
                                        {
                                            "active": 1,
                                            "storage": "local-lvm",
                                            "type": "lvmthin",
                                            "content": "images,rootdir"
                                        },
                                        {
                                            "active": 1,
                                            "storage": "ZPOOL",
                                            "type": "zfspool",
                                            "content": "rootdir,images"
                                        }
                                    ]
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/storage/local/content?content=images" => (
                                "200 OK",
                                json!({
                                    "data": []
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/storage/local-lvm/content?content=images" => (
                                "200 OK",
                                json!({
                                    "data": []
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/storage/ZPOOL/content?content=images" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {
                                            "content": "rootdir",
                                            "format": "subvol",
                                            "name": "subvol-100-disk-0",
                                            "size": 1073741824u64,
                                            "vmid": 100,
                                            "volid": "ZPOOL:subvol-100-disk-0"
                                        },
                                        {
                                            "content": "images",
                                            "format": "raw",
                                            "name": "vm-101-disk-0",
                                            "size": 1048576u64,
                                            "vmid": 101,
                                            "volid": "ZPOOL:vm-101-disk-0"
                                        },
                                        {
                                            "content": "images",
                                            "format": "raw",
                                            "name": "vm-101-disk-1",
                                            "size": 536870912000u64,
                                            "vmid": 101,
                                            "volid": "ZPOOL:vm-101-disk-1"
                                        }
                                    ]
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/qemu/101/config" => (
                                "200 OK",
                                json!({
                                    "data": {
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
                                    }
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/qemu/101/agent/info" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": {
                                            "version": "10.0.11",
                                            "supported_commands": [
                                                {
                                                    "enabled": true,
                                                    "name": "guest-get-osinfo",
                                                    "success-response": true
                                                }
                                            ]
                                        }
                                    }
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/qemu/101/agent/get-osinfo" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": {
                                            "id": "debian",
                                            "kernel-release": "6.12.101+deb13-amd64",
                                            "name": "Debian GNU/Linux",
                                            "pretty-name": "Debian GNU/Linux 13 (trixie)",
                                            "version": "13 (trixie)",
                                            "version-id": "13"
                                        }
                                    }
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/qemu/101/agent/get-host-name" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": {
                                            "host-name": "workStation"
                                        }
                                    }
                                })
                                .to_string(),
                            ),
                            "/api2/json/nodes/pve/qemu/101/agent/network-get-interfaces" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": [
                                            {
                                                "name": "lo",
                                                "ip-addresses": [
                                                    {
                                                        "ip-address": "127.0.0.1",
                                                        "ip-address-type": "ipv4",
                                                        "prefix": 8
                                                    },
                                                    {
                                                        "ip-address": "::1",
                                                        "ip-address-type": "ipv6",
                                                        "prefix": 128
                                                    }
                                                ]
                                            },
                                            {
                                                "name": "ens18",
                                                "hardware-address": "bc:24:11:f0:25:eb",
                                                "ip-addresses": [
                                                    {
                                                        "ip-address": "192.168.0.17",
                                                        "ip-address-type": "ipv4",
                                                        "prefix": 24
                                                    },
                                                    {
                                                        "ip-address": "fe80::4c4a:aab9:505f:af94",
                                                        "ip-address-type": "ipv6",
                                                        "prefix": 64
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                })
                                .to_string(),
                            ),
                            _ => (
                                "404 Not Found",
                                json!({"errors": format!("Endpoint not found: {}", path)})
                                    .to_string(),
                            ),
                        };

                        let resp = format!(
                            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            status,
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
            }
        }
    });

    (format!("http://127.0.0.1:{}", addr.port()), shutdown_tx)
}

#[tokio::test]
async fn test_live_pve_host_payload_end_to_end_ticket_auth() {
    let (server_url, shutdown_tx) = spawn_live_pve_mock_server().await;

    let temp_csv = tempfile::NamedTempFile::new().unwrap();
    let csv_path = temp_csv.path().to_str().unwrap().to_string();

    let args = Args {
        output: Some(csv_path.clone()),
        host: server_url,
        user: "root@pam".to_string(),
        password: Some("dummy".to_string()),
        api_token: None,
        verify_ssl: false,
        timeout: 5,
        no_probe: true,
        probe_timeout: 1.0,
        workers: 2,
        quiet: true,
    };

    let exit_code = run_orchestrator(args).await;
    let _ = shutdown_tx.send(());

    assert_eq!(exit_code, 0, "run_orchestrator must exit with 0");

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(&csv_path)
        .expect("CSV must be readable");

    // Verify all 39 header columns match TEMPLATE_COLUMNS in exact order
    let headers: Vec<String> = rdr
        .headers()
        .unwrap()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let expected_headers: Vec<String> = TEMPLATE_COLUMNS.iter().map(|&s| s.to_string()).collect();
    assert_eq!(headers, expected_headers, "CSV headers must match TEMPLATE_COLUMNS exactly");
    assert_eq!(headers.len(), 39);

    // Verify records
    let mut records: Vec<HashMap<String, String>> = Vec::new();
    for result in rdr.deserialize::<HashMap<String, String>>() {
        let record = result.expect("Valid record");
        records.push(record);
    }

    assert_eq!(records.len(), 1, "Exactly 1 VM record expected (LXC adguard excluded)");
    let r = &records[0];

    // Assert exact values matching Python test_live_pve_host_payload_end_to_end
    assert_eq!(r.get("name").unwrap(), "work-station");
    assert_eq!(r.get("external_id").unwrap(), "101");
    assert_eq!(r.get("platform").unwrap(), "proxmox");
    assert_eq!(r.get("node").unwrap(), "pve");
    assert_eq!(r.get("cluster").unwrap(), "standalone");
    assert_eq!(r.get("status").unwrap(), "running");
    assert_eq!(r.get("cpu_cores").unwrap(), "6");
    assert_eq!(r.get("memory_mb").unwrap(), "4096");
    assert_eq!(
        r.get("disks").unwrap(),
        "vm-101-disk-0-efidisk0:1:ZPOOL:zfspool;vm-101-disk-1-scsi0:500:ZPOOL:zfspool"
    );
    assert_eq!(r.get("storage_name").unwrap(), "501");
    assert_eq!(r.get("storage_type").unwrap(), "");
    assert_eq!(r.get("os_family").unwrap(), "linux");
    assert_eq!(
        r.get("os_distribution").unwrap(),
        "Debian GNU/Linux 13 (trixie)"
    );
    assert_eq!(
        r.get("os_version").unwrap(),
        "13 (6.12.101+deb13-amd64)"
    );
    assert_eq!(r.get("private_ip").unwrap(), "192.168.0.17");
    assert_eq!(r.get("fqdn").unwrap(), "");
    assert_eq!(r.get("ha_enabled").unwrap(), "false");
    assert_eq!(r.get("backup_enabled").unwrap(), "false");

    // All empty template columns must be empty strings
    let empty_columns = [
        "sr_id",
        "datacenter",
        "environment",
        "criticality",
        "vm_type",
        "public_ip",
        "backup_ip",
        "owner",
        "business_owner",
        "technical_owner",
        "applications",
        "monitoring_enabled",
        "pmp_enabled",
        "backup_location",
        "tags",
        "last_patch_date",
        "last_vuln_scan_date",
        "last_verified_at",
        "decommission_date",
        "security_remarks",
        "description",
    ];
    for col in empty_columns {
        assert_eq!(
            r.get(col).map(|s| s.as_str()).unwrap_or(""),
            "",
            "Column {} should be empty string",
            col
        );
    }

    // Verify sanitize_row returns no warnings for this record
    let mut check_row = r.clone();
    let warnings = sanitize_row(&mut check_row);
    assert!(
        warnings.is_empty(),
        "sanitize_row warnings must be empty, got: {:?}",
        warnings
    );
}

#[tokio::test]
async fn test_live_pve_host_payload_end_to_end_api_token_auth() {
    let (server_url, shutdown_tx) = spawn_live_pve_mock_server().await;

    let temp_csv = tempfile::NamedTempFile::new().unwrap();
    let csv_path = temp_csv.path().to_str().unwrap().to_string();

    let args = Args {
        output: Some(csv_path.clone()),
        host: server_url,
        user: "root@pam".to_string(),
        password: None,
        api_token: Some("root@pam!token=12345678-1234-1234-1234-123456789abc".to_string()),
        verify_ssl: false,
        timeout: 5,
        no_probe: true,
        probe_timeout: 1.0,
        workers: 2,
        quiet: true,
    };

    let exit_code = run_orchestrator(args).await;
    let _ = shutdown_tx.send(());

    assert_eq!(exit_code, 0, "run_orchestrator must exit with 0 using API token");

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(&csv_path)
        .expect("CSV must be readable");

    let mut records: Vec<HashMap<String, String>> = Vec::new();
    for result in rdr.deserialize::<HashMap<String, String>>() {
        let record = result.expect("Valid record");
        records.push(record);
    }

    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.get("name").unwrap(), "work-station");
    assert_eq!(r.get("external_id").unwrap(), "101");
    assert_eq!(r.get("cpu_cores").unwrap(), "6");
    assert_eq!(r.get("memory_mb").unwrap(), "4096");
    assert_eq!(r.get("storage_name").unwrap(), "501");
    assert_eq!(r.get("os_family").unwrap(), "linux");
    assert_eq!(r.get("private_ip").unwrap(), "192.168.0.17");

    let mut check_row = r.clone();
    assert!(sanitize_row(&mut check_row).is_empty());
}
