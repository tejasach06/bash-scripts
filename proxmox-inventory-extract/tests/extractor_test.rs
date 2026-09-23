use proxmox_inventory_extract::cli::{Args, AuthMethod};
use proxmox_inventory_extract::client::ProxmoxClient;
use proxmox_inventory_extract::extractor::{
    build_storage_meta, build_volume_sizes, extract_vm, run_orchestrator, serialize_vm,
};
use proxmox_inventory_extract::model::DiskRecord;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Helper: spawns a mock Proxmox server for testing extraction
async fn spawn_mock_extractor_server() -> (String, tokio::sync::oneshot::Sender<()>) {
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
                                        "ticket": "MOCK_TICKET",
                                        "CSRFPreventionToken": "MOCK_CSRF"
                                    }
                                }).to_string(),
                            ),
                            "/api2/json/cluster/status" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"type": "cluster", "name": "test-cluster"}
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/nodes" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"node": "pve-node1", "status": "online"}
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/cluster/resources?type=vm" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {
                                            "id": "qemu/101",
                                            "vmid": 101,
                                            "name": "vm-running",
                                            "node": "pve-node1",
                                            "status": "running",
                                            "maxcpu": 4,
                                            "maxmem": 4294967296u64,
                                            "hastate": "started"
                                        },
                                        {
                                            "id": "qemu/102",
                                            "vmid": 102,
                                            "name": "vm-stopped",
                                            "node": "pve-node1",
                                            "status": "stopped",
                                            "maxcpu": 2,
                                            "maxmem": 2147483648u64
                                        },
                                        {
                                            "id": "qemu/103",
                                            "vmid": 103,
                                            "name": "vm-template",
                                            "node": "pve-node1",
                                            "status": "stopped",
                                            "template": 1
                                        },
                                        {
                                            "id": "qemu/104",
                                            "vmid": 104,
                                            "name": "vm-agentless",
                                            "node": "pve-node1",
                                            "status": "running"
                                        }
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/storage" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"storage": "local-zfs", "type": "zfspool", "vgname": "rpool"}
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/storage/local-zfs/content?content=images" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"volid": "local-zfs:vm-101-disk-0", "size": 34359738368u64},
                                        {"volid": "local-zfs:vm-102-disk-0", "size": 21474836480u64}
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/cluster/backup" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {
                                            "id": "backup-all",
                                            "enabled": 1,
                                            "all": 1,
                                            "exclude": "104",
                                            "storage": "pbs-storage"
                                        }
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/cluster/ha/resources" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"sid": "vm:101"}
                                    ]
                                }).to_string(),
                            ),
                            // VM 101 configs and agent endpoints
                            "/api2/json/nodes/pve-node1/qemu/101/config" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "name": "vm-running",
                                        "cores": 4,
                                        "sockets": 1,
                                        "memory": 4096,
                                        "ostype": "l26",
                                        "scsi0": "local-zfs:vm-101-disk-0,size=32G",
                                        "tags": "production;web",
                                        "description": "Production Web Server"
                                    }
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/qemu/101/agent/info" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": {"version": "8.2.2"}
                                    }
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/qemu/101/agent/network-get-interfaces" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": [
                                            {
                                                "name": "eth0",
                                                "ip-addresses": [
                                                    {"ip-address": "192.168.1.101"},
                                                    {"ip-address": "10.0.0.101"}
                                                ]
                                            }
                                        ]
                                    }
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/qemu/101/agent/get-osinfo" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": {
                                            "id": "debian",
                                            "pretty-name": "Debian GNU/Linux 12 (bookworm)",
                                            "version-id": "12",
                                            "kernel-release": "6.1.0-18-amd64"
                                        }
                                    }
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/qemu/101/agent/get-host-name" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "result": {"host-name": "vm-running.corp.local"}
                                    }
                                }).to_string(),
                            ),
                            // VM 102 (Stopped)
                            "/api2/json/nodes/pve-node1/qemu/102/config" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "name": "vm-stopped",
                                        "cores": 2,
                                        "memory": 2048,
                                        "ostype": "win11",
                                        "scsi0": "local-zfs:vm-102-disk-0,size=20G",
                                        "ipconfig0": "ip=192.168.1.102/24,gw=192.168.1.1"
                                    }
                                }).to_string(),
                            ),
                            // VM 103 (Template)
                            "/api2/json/nodes/pve-node1/qemu/103/config" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "name": "vm-template",
                                        "cores": 1,
                                        "memory": 1024,
                                        "ostype": "l26",
                                        "tags": "golden-image"
                                    }
                                }).to_string(),
                            ),
                            // VM 104 (Agentless running VM - agent probe fails)
                            "/api2/json/nodes/pve-node1/qemu/104/config" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "name": "vm-agentless",
                                        "cores": 2,
                                        "memory": 2048,
                                        "ostype": "other",
                                        "searchdomain": "lab.example.org",
                                        "tags": "192.168.1.104;db"
                                    }
                                }).to_string(),
                            ),
                            "/api2/json/nodes/pve-node1/qemu/104/agent/info" => (
                                "500 Internal Server Error",
                                json!({"errors": "QEMU guest agent is not running"}).to_string(),
                            ),
                            _ => ("404 Not Found", json!({"errors": "not found"}).to_string()),
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
async fn test_extract_vm_running_with_agent() {
    let (server_url, _shutdown) = spawn_mock_extractor_server().await;
    let client = ProxmoxClient::new(
        &server_url,
        AuthMethod::Ticket {
            password: "test".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    let storage_meta = build_storage_meta(&client, "pve-node1").await;
    let sids: Vec<String> = storage_meta.keys().cloned().collect();
    let volume_sizes = build_volume_sizes(&client, "pve-node1", &sids).await;

    let resource = json!({
        "vmid": 101,
        "name": "vm-running",
        "hastate": "started"
    });
    let backup_jobs = client.get_backup_jobs().await.unwrap();
    let ha_vmids = client.get_ha_vmids().await;

    let row = extract_vm(
        &client,
        "pve-node1",
        101,
        "test-cluster",
        &storage_meta,
        &volume_sizes,
        &resource,
        &backup_jobs,
        "running",
        "pve-node1",
        None,
        None,
        None,
        false,
        2.0,
        Some(&ha_vmids),
    )
    .await
    .expect("Row should be extracted");

    assert_eq!(row.get("name").unwrap(), "vm-running");
    assert_eq!(row.get("external_id").unwrap(), "101");
    assert_eq!(row.get("status").unwrap(), "running");
    assert_eq!(row.get("platform").unwrap(), "proxmox");
    assert_eq!(row.get("cluster").unwrap(), "test-cluster");
    assert_eq!(row.get("node").unwrap(), "pve-node1");
    assert_eq!(row.get("cpu_cores").unwrap(), "4");
    assert_eq!(row.get("memory_mb").unwrap(), "4096");
    assert_eq!(row.get("os_family").unwrap(), "linux");
    assert_eq!(row.get("os_distribution").unwrap(), "Debian GNU/Linux 12 (bookworm)");
    assert_eq!(row.get("os_version").unwrap(), "12 (6.1.0-18-amd64)");
    assert_eq!(row.get("private_ip").unwrap(), "192.168.1.101");
    assert_eq!(row.get("backup_ip").unwrap(), "10.0.0.101");
    assert_eq!(row.get("fqdn").unwrap(), "vm-running.corp.local");
    assert_eq!(row.get("ha_enabled").unwrap(), "true");
    assert_eq!(row.get("backup_enabled").unwrap(), "true");
    assert_eq!(row.get("backup_location").unwrap(), "pbs-storage");
    assert_eq!(row.get("tags").unwrap(), "production;web");
    assert_eq!(row.get("description").unwrap(), "Production Web Server");
}

#[tokio::test]
async fn test_extract_vm_stopped_with_cloudinit_ips() {
    let (server_url, _shutdown) = spawn_mock_extractor_server().await;
    let client = ProxmoxClient::new(
        &server_url,
        AuthMethod::Ticket {
            password: "test".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    let storage_meta = build_storage_meta(&client, "pve-node1").await;
    let sids: Vec<String> = storage_meta.keys().cloned().collect();
    let volume_sizes = build_volume_sizes(&client, "pve-node1", &sids).await;

    let resource = json!({
        "vmid": 102,
        "name": "vm-stopped"
    });
    let backup_jobs = client.get_backup_jobs().await.unwrap();

    let row = extract_vm(
        &client,
        "pve-node1",
        102,
        "test-cluster",
        &storage_meta,
        &volume_sizes,
        &resource,
        &backup_jobs,
        "stopped",
        "pve-node1",
        None,
        None,
        None,
        false,
        2.0,
        None,
    )
    .await
    .expect("Row should be extracted");

    assert_eq!(row.get("status").unwrap(), "powered_off");
    assert_eq!(row.get("os_family").unwrap(), "windows");
    assert_eq!(row.get("private_ip").unwrap(), "192.168.1.102");
    assert_eq!(row.get("backup_ip").unwrap(), "");
    assert_eq!(row.get("ha_enabled").unwrap(), "false");
    assert_eq!(row.get("backup_enabled").unwrap(), "true");
}

#[tokio::test]
async fn test_extract_vm_template() {
    let (server_url, _shutdown) = spawn_mock_extractor_server().await;
    let client = ProxmoxClient::new(
        &server_url,
        AuthMethod::Ticket {
            password: "test".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    let resource = json!({
        "vmid": 103,
        "name": "vm-template",
        "template": 1
    });

    let row = extract_vm(
        &client,
        "pve-node1",
        103,
        "test-cluster",
        &HashMap::new(),
        &HashMap::new(),
        &resource,
        &[],
        "stopped",
        "pve-node1",
        None,
        None,
        None,
        false,
        2.0,
        None,
    )
    .await
    .expect("Row should be extracted");

    // "template" tag must be appended
    assert_eq!(row.get("tags").unwrap(), "golden-image;template");
}

#[tokio::test]
async fn test_extract_vm_agentless_and_fallbacks() {
    let (server_url, _shutdown) = spawn_mock_extractor_server().await;
    let client = ProxmoxClient::new(
        &server_url,
        AuthMethod::Ticket {
            password: "test".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    let resource = json!({
        "vmid": 104,
        "name": "vm-agentless"
    });
    let backup_jobs = client.get_backup_jobs().await.unwrap();

    let row = extract_vm(
        &client,
        "pve-node1",
        104,
        "test-cluster",
        &HashMap::new(),
        &HashMap::new(),
        &resource,
        &backup_jobs,
        "running",
        "pve-node1",
        None,
        None,
        None,
        false,
        2.0,
        None,
    )
    .await
    .expect("Row should be extracted");

    // Falls back to tag IP
    assert_eq!(row.get("private_ip").unwrap(), "192.168.1.104");
    // FQDN falls back to searchdomain: name.searchdomain
    assert_eq!(row.get("fqdn").unwrap(), "vm-agentless.lab.example.org");
    // Excluded from backup job 104
    assert_eq!(row.get("backup_enabled").unwrap(), "false");
}

#[test]
fn test_serialize_vm_direct() {
    let config = json!({
        "name": "custom-name",
        "cores": 8,
        "memory": 16384,
        "ostype": "l26"
    });
    let config_map = config.as_object().unwrap();
    let resource = json!({"hastate": "managed"});

    let disks = vec![DiskRecord {
        lv_name: "disk-0".to_string(),
        config_key: "scsi0".to_string(),
        size_gib: 100,
        storage_name: "rpool".to_string(),
        storage_type: "zfspool".to_string(),
    }];

    let mut ips_by_role = HashMap::new();
    ips_by_role.insert("private_ip", vec!["192.168.1.200".to_string()]);
    ips_by_role.insert("backup_ip", vec!["10.0.0.200".to_string()]);

    let mut os_info = HashMap::new();
    os_info.insert("os_family".to_string(), Some("ubuntu".to_string()));
    os_info.insert("os_distribution".to_string(), Some("Ubuntu 24.04".to_string()));
    os_info.insert("os_version".to_string(), Some("24.04".to_string()));

    let ha_set = HashSet::from([200]);

    let row = serialize_vm(
        200,
        config_map,
        "running",
        "nodeA",
        "clusterA",
        &disks,
        &ips_by_role,
        &os_info,
        Some("host.example.com"),
        "test desc",
        "tag1;tag2",
        &resource,
        "true",
        "backup-store",
        Some(&ha_set),
    );

    assert_eq!(row.get("name").unwrap(), "custom-name");
    assert_eq!(row.get("external_id").unwrap(), "200");
    assert_eq!(row.get("fqdn").unwrap(), "host.example.com");
    assert_eq!(row.get("platform").unwrap(), "proxmox");
    assert_eq!(row.get("cluster").unwrap(), "clusterA");
    assert_eq!(row.get("node").unwrap(), "nodeA");
    assert_eq!(row.get("status").unwrap(), "running");
    assert_eq!(row.get("cpu_cores").unwrap(), "8");
    assert_eq!(row.get("memory_mb").unwrap(), "16384");
    assert_eq!(row.get("disks").unwrap(), "disk-0-scsi0:100:rpool:zfspool");
    assert_eq!(row.get("storage_name").unwrap(), "rpool");
    assert_eq!(row.get("storage_type").unwrap(), "zfspool");
    assert_eq!(row.get("os_family").unwrap(), "linux");
    assert_eq!(row.get("os_distribution").unwrap(), "Ubuntu 24.04");
    assert_eq!(row.get("os_version").unwrap(), "24.04");
    assert_eq!(row.get("private_ip").unwrap(), "192.168.1.200");
    assert_eq!(row.get("backup_ip").unwrap(), "10.0.0.200");
    assert_eq!(row.get("ha_enabled").unwrap(), "true");
    assert_eq!(row.get("backup_enabled").unwrap(), "true");
    assert_eq!(row.get("backup_location").unwrap(), "backup-store");
    assert_eq!(row.get("tags").unwrap(), "tag1;tag2");
    assert_eq!(row.get("description").unwrap(), "test desc");
}

#[tokio::test]
async fn test_orchestrator_deterministic_order_and_csv() {
    let (server_url, _shutdown) = spawn_mock_extractor_server().await;
    let temp_csv = tempfile::NamedTempFile::new().unwrap();
    let csv_path = temp_csv.path().to_str().unwrap().to_string();

    let args = Args {
        output: Some(csv_path.clone()),
        host: server_url,
        user: "root@pam".to_string(),
        password: Some("secret".to_string()),
        api_token: None,
        verify_ssl: false,
        timeout: 5,
        no_probe: true,
        probe_timeout: 1.0,
        workers: 4,
        quiet: true,
    };

    let exit_code = run_orchestrator(args).await;
    assert_eq!(exit_code, 0, "run_orchestrator should return 0 on success");

    // Read CSV and check row order
    let content = std::fs::read_to_string(&csv_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 5, "Header + 4 VM rows");

    // Row 1: VM 101
    assert!(lines[1].starts_with("vm-running,101,"));
    // Row 2: VM 102
    assert!(lines[2].starts_with("vm-stopped,102,"));
    // Row 3: VM 103
    assert!(lines[3].starts_with("vm-template,103,"));
    // Row 4: VM 104
    assert!(lines[4].starts_with("vm-agentless,104,"));
}

#[tokio::test]
async fn test_orchestrator_auth_failure_exit_1() {
    let args = Args {
        output: None,
        host: "127.0.0.1:9".to_string(), // Unreachable port
        user: "root@pam".to_string(),
        password: Some("wrong".to_string()),
        api_token: None,
        verify_ssl: false,
        timeout: 1,
        no_probe: true,
        probe_timeout: 1.0,
        workers: 2,
        quiet: true,
    };

    let exit_code = run_orchestrator(args).await;
    assert_eq!(exit_code, 1, "Auth or connection failure must return 1");
}

#[tokio::test]
async fn test_orchestrator_partial_failure_exit_2() {
    // Spawn server where cluster/status returns error
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Ok((mut stream, _)) = listener.accept() => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let n = match stream.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_str.lines().next().unwrap_or("");
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        let path = parts.get(1).copied().unwrap_or("");

                        let (status, body) = match path {
                            "/api2/json/access/ticket" => (
                                "200 OK",
                                json!({
                                    "data": {
                                        "ticket": "MOCK_TICKET",
                                        "CSRFPreventionToken": "MOCK_CSRF"
                                    }
                                }).to_string(),
                            ),
                            // Cluster status fails -> triggers partial_failure = true
                            "/api2/json/cluster/status" => (
                                "500 Internal Server Error",
                                json!({"errors": "cluster unavailable"}).to_string(),
                            ),
                            "/api2/json/nodes" => (
                                "200 OK",
                                json!({"data": [{"node": "node1", "status": "online"}]}).to_string(),
                            ),
                            "/api2/json/cluster/backup" => (
                                "200 OK",
                                json!({"data": []}).to_string(),
                            ),
                            "/api2/json/cluster/ha/resources" => (
                                "200 OK",
                                json!({"data": []}).to_string(),
                            ),
                            "/api2/json/cluster/resources?type=vm" => (
                                "200 OK",
                                json!({
                                    "data": [
                                        {"id": "qemu/101", "vmid": 101, "node": "node1", "status": "stopped"}
                                    ]
                                }).to_string(),
                            ),
                            "/api2/json/nodes/node1/storage" => (
                                "200 OK",
                                json!({"data": []}).to_string(),
                            ),
                            "/api2/json/nodes/node1/qemu/101/config" => (
                                "200 OK",
                                json!({"data": {"name": "vm101"}}).to_string(),
                            ),
                            _ => ("404 Not Found", "{}".to_string()),
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

    let temp_csv = tempfile::NamedTempFile::new().unwrap();
    let csv_path = temp_csv.path().to_str().unwrap().to_string();

    let args = Args {
        output: Some(csv_path),
        host: format!("http://127.0.0.1:{}", addr.port()),
        user: "root@pam".to_string(),
        password: Some("secret".to_string()),
        api_token: None,
        verify_ssl: false,
        timeout: 5,
        no_probe: true,
        probe_timeout: 1.0,
        workers: 1,
        quiet: true,
    };

    let exit_code = run_orchestrator(args).await;
    let _ = shutdown_tx.send(());
    assert_eq!(exit_code, 2, "Partial failure must return exit code 2");
}

#[tokio::test]
async fn test_extract_vm_local_probe_arp_and_dhcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Ok((mut stream, _)) = listener.accept() => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        // VM config with net0 MAC
                        let body = json!({
                            "data": {
                                "name": "probed-vm",
                                "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0"
                            }
                        }).to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
            }
        }
    });

    let client = ProxmoxClient::new(
        &format!("http://127.0.0.1:{}", addr.port()),
        AuthMethod::ApiToken {
            token: "u@p!t=abc".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    let mut arp_map = HashMap::new();
    arp_map.insert("aa:bb:cc:dd:ee:01".to_string(), vec!["192.168.1.88".to_string()]);

    let mut lease_hosts = HashMap::new();
    lease_hosts.insert("aa:bb:cc:dd:ee:01".to_string(), "probed-vm.local.lan".to_string());

    let resource = json!({"vmid": 105, "name": "probed-vm"});

    let row = extract_vm(
        &client,
        "local-pve",
        105,
        "cluster",
        &HashMap::new(),
        &HashMap::new(),
        &resource,
        &[],
        "stopped",
        "local-pve",
        Some(&arp_map),
        None,
        Some(&lease_hosts),
        true,
        2.0,
        None,
    )
    .await
    .expect("Row should be extracted");

    let _ = shutdown_tx.send(());

    assert_eq!(row.get("private_ip").unwrap(), "192.168.1.88");
    assert_eq!(row.get("fqdn").unwrap(), "probed-vm.local.lan");
}

