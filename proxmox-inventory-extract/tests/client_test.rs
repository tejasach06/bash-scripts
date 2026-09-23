use proxmox_inventory_extract::cli::AuthMethod;
use proxmox_inventory_extract::client::{
    parse_cluster_name, parse_guest_fqdn, parse_guest_ips, parse_guest_os, parse_ha_vmids,
    unwrap_agent_result, unwrap_response, ProxmoxClient,
};
use serde_json::json;
use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_unwrap_response_and_agent_result() {
    // Standard Proxmox enveloped response: {"data": [...]}
    let raw_list = json!({
        "data": [
            {"node": "pve1", "status": "online"},
            {"node": "pve2", "status": "offline"}
        ]
    });
    let unwrapped = unwrap_response(raw_list);
    assert!(unwrapped.is_array());
    assert_eq!(unwrapped.as_array().unwrap().len(), 2);

    // QEMU guest agent enveloped response: {"data": {"result": {...}}}
    let raw_agent = json!({
        "data": {
            "result": {
                "version": "8.2.2"
            }
        }
    });
    let unwrapped_agent = unwrap_agent_result(raw_agent);
    assert_eq!(unwrapped_agent, json!({"version": "8.2.2"}));

    // Guest agent response already unwrapped once or without "data" wrapper
    let partial_agent = json!({
        "result": {
            "version": "8.2.2"
        }
    });
    assert_eq!(unwrap_agent_result(partial_agent), json!({"version": "8.2.2"}));

    // Bare payload without result wrapper
    let bare_agent = json!({
        "version": "8.2.2"
    });
    assert_eq!(unwrap_agent_result(bare_agent), json!({"version": "8.2.2"}));

    // Bare array payload inside data
    let array_agent = json!({
        "data": [
            {"name": "ens18"}
        ]
    });
    assert_eq!(unwrap_agent_result(array_agent), json!([{"name": "ens18"}]));
}

#[test]
fn test_parse_cluster_name() {
    // Node listed before cluster in cluster/status
    let status_cluster = json!([
        {"type": "node", "name": "pve-node-1"},
        {"type": "cluster", "name": "production-cluster"}
    ]);
    assert_eq!(parse_cluster_name(&status_cluster), "production-cluster");

    // Standalone node (no type == "cluster")
    let status_standalone = json!([
        {"type": "node", "name": "pve-node-1"}
    ]);
    assert_eq!(parse_cluster_name(&status_standalone), "standalone");

    // Enveloped payload {"data": [...]}
    let status_enveloped = json!({
        "data": [
            {"type": "cluster", "name": "lab-cluster"}
        ]
    });
    assert_eq!(parse_cluster_name(&status_enveloped), "lab-cluster");

    // Empty list or invalid JSON
    assert_eq!(parse_cluster_name(&json!([])), "standalone");
    assert_eq!(parse_cluster_name(&json!(null)), "standalone");
}

#[test]
fn test_parse_ha_vmids() {
    let ha_data = json!([
        {"sid": "vm:100"},
        {"sid": "vm:102"},
        {"sid": "ct:105"},
        {"sid": "vm:invalid"}
    ]);
    let vmids = parse_ha_vmids(&ha_data);
    let mut expected = HashSet::new();
    expected.insert(100);
    expected.insert(102);
    assert_eq!(vmids, expected);

    // Enveloped payload {"data": [...]}
    let enveloped = json!({
        "data": [
            {"sid": "vm:200"}
        ]
    });
    let vmids_env = parse_ha_vmids(&enveloped);
    assert_eq!(vmids_env, HashSet::from([200]));

    // Empty or null
    assert_eq!(parse_ha_vmids(&json!([])), HashSet::new());
    assert_eq!(parse_ha_vmids(&json!(null)), HashSet::new());
}

#[test]
fn test_parse_guest_os_combinations() {
    // 1. Version + Kernel (e.g. Linux with version-id and kernel-release)
    let os1 = json!({
        "id": "ubuntu",
        "pretty-name": "Ubuntu 22.04.3 LTS",
        "version-id": "22.04",
        "kernel-release": "5.15.0-91-generic"
    });
    let res1 = parse_guest_os(&os1);
    assert_eq!(res1.get("os_family").unwrap(), &Some("ubuntu".to_string()));
    assert_eq!(
        res1.get("os_distribution").unwrap(),
        &Some("Ubuntu 22.04.3 LTS".to_string())
    );
    assert_eq!(
        res1.get("os_version").unwrap(),
        &Some("22.04 (5.15.0-91-generic)".to_string())
    );

    // 2. Version without kernel (e.g. Windows)
    let os2 = json!({
        "id": "mswindows",
        "pretty-name": "Windows Server 2022",
        "version-id": "2022"
    });
    let res2 = parse_guest_os(&os2);
    assert_eq!(res2.get("os_family").unwrap(), &Some("mswindows".to_string()));
    assert_eq!(
        res2.get("os_distribution").unwrap(),
        &Some("Windows Server 2022".to_string())
    );
    assert_eq!(res2.get("os_version").unwrap(), &Some("2022".to_string()));

    // 3. Kernel only without version
    let os3 = json!({
        "kernel-release": "6.1.0"
    });
    let res3 = parse_guest_os(&os3);
    assert_eq!(res3.get("os_family").unwrap(), &None);
    assert_eq!(res3.get("os_distribution").unwrap(), &None);
    assert_eq!(res3.get("os_version").unwrap(), &Some("6.1.0".to_string()));

    // 4. "version" fallback when "version-id" is missing, and "name" fallback when "pretty-name" is missing
    let os4 = json!({
        "id": "debian",
        "name": "Debian GNU/Linux",
        "version": "12 (bookworm)"
    });
    let res4 = parse_guest_os(&os4);
    assert_eq!(res4.get("os_family").unwrap(), &Some("debian".to_string()));
    assert_eq!(
        res4.get("os_distribution").unwrap(),
        &Some("Debian GNU/Linux".to_string())
    );
    assert_eq!(
        res4.get("os_version").unwrap(),
        &Some("12 (bookworm)".to_string())
    );

    // 5. Empty or null data
    let res_empty = parse_guest_os(&json!({}));
    assert_eq!(res_empty.get("os_family").unwrap(), &None);
    assert_eq!(res_empty.get("os_distribution").unwrap(), &None);
    assert_eq!(res_empty.get("os_version").unwrap(), &None);
}

#[test]
fn test_parse_guest_ips_and_fqdn() {
    let iface_data = json!([
        {
            "name": "lo",
            "ip-addresses": [
                {"ip-address": "127.0.0.1"},
                {"ip-address": "::1"}
            ]
        },
        {
            "name": "ens18",
            "ip-addresses": [
                {"ip-address": "192.168.0.17"},
                {"ip-address": "192.168.0.17"}, // duplicate
                {"ip-address": "fe80::4c4a:aab9:505f:af94"},
                {"ip-address": "169.254.1.1"} // link-local
            ]
        },
        {
            "name": "ens19",
            "ip-addresses": [
                {"ip-address": "10.0.0.5"}
            ]
        }
    ]);
    let ips = parse_guest_ips(&iface_data);
    assert_eq!(ips, vec!["192.168.0.17", "10.0.0.5"]);

    // FQDN valid dotted non-localhost
    let fqdn1 = json!({"host-name": "web01.corp.example"});
    assert_eq!(
        parse_guest_fqdn(&fqdn1),
        Some("web01.corp.example".to_string())
    );

    // FQDN unqualified (no dot)
    let fqdn2 = json!({"host-name": "workstation"});
    assert_eq!(parse_guest_fqdn(&fqdn2), None);

    // FQDN localhost prefix
    let fqdn3 = json!({"host-name": "localhost.localdomain"});
    assert_eq!(parse_guest_fqdn(&fqdn3), None);

    // Fallback to "hostname" key
    let fqdn4 = json!({"hostname": "db01.corp.internal"});
    assert_eq!(
        parse_guest_fqdn(&fqdn4),
        Some("db01.corp.internal".to_string())
    );
}

#[test]
fn test_scheme_normalization() {
    // Missing scheme prepends https://
    let c1 = ProxmoxClient::new(
        "127.0.0.1:8006",
        AuthMethod::Ticket {
            password: "p".to_string(),
        },
        false,
        5,
    )
    .unwrap();
    assert_eq!(c1.base_url(), "https://127.0.0.1:8006");

    // Existing https:// with trailing slash trims slash
    let c2 = ProxmoxClient::new(
        "https://pve.example.com:8006/",
        AuthMethod::Ticket {
            password: "p".to_string(),
        },
        false,
        5,
    )
    .unwrap();
    assert_eq!(c2.base_url(), "https://pve.example.com:8006");

    // Existing http:// preserved
    let c3 = ProxmoxClient::new(
        "http://127.0.0.1:8006",
        AuthMethod::Ticket {
            password: "p".to_string(),
        },
        false,
        5,
    )
    .unwrap();
    assert_eq!(c3.base_url(), "http://127.0.0.1:8006");
}

/// Helper mock HTTP server for ProxmoxClient integration tests
async fn spawn_mock_pve_server() -> (String, tokio::sync::oneshot::Sender<()>) {
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
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req.lines().next().unwrap_or("");
                        let mut parts = first_line.split_whitespace();
                        let method = parts.next().unwrap_or("");
                        let path = parts.next().unwrap_or("");

                        let has_ticket_cookie = req.to_lowercase().contains("pveauthcookie=mock_ticket_123") || req.contains("PVEAuthCookie=MOCK_TICKET_123");
                        let has_csrf = req.to_lowercase().contains("csrfpreventiontoken: mock_csrf_456") || req.contains("CSRFPreventionToken: MOCK_CSRF_456");
                        let has_api_token = req.contains("PVEAPIToken=root@pam!token1=abc-123");

                        let (status, body) = match (method, path) {
                            ("POST", "/api2/json/access/ticket") => {
                                if req.contains("username=root%40pam") || req.contains("username=root@pam") {
                                    (
                                        "200 OK",
                                        json!({
                                            "data": {
                                                "ticket": "MOCK_TICKET_123",
                                                "CSRFPreventionToken": "MOCK_CSRF_456"
                                            }
                                        }).to_string(),
                                    )
                                } else {
                                    ("401 Unauthorized", json!({"errors": "invalid credentials"}).to_string())
                                }
                            }
                            _ => {
                                // For authenticated endpoints, verify auth header or cookie + csrf
                                let ticket_auth_valid = has_ticket_cookie && has_csrf;
                                if !ticket_auth_valid && !has_api_token {
                                    ("401 Unauthorized", json!({"errors": "unauthenticated"}).to_string())
                                } else {
                                    match path {
                                        "/api2/json/cluster/status" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"type": "node", "name": "pve1"},
                                                    {"type": "cluster", "name": "mock-cluster"}
                                                ]
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"node": "pve1", "status": "online"},
                                                    {"node": "pve2", "status": "offline"}
                                                ]
                                            }).to_string(),
                                        ),
                                        "/api2/json/cluster/resources?type=vm" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"id": "qemu/101", "name": "vm101", "node": "pve1", "status": "running"},
                                                    {"id": "lxc/102", "name": "ct102", "node": "pve1", "status": "running"}
                                                ]
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/qemu" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"vmid": 101, "name": "vm101", "status": "running"}
                                                ]
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/qemu/101/config" => (
                                            "200 OK",
                                            json!({
                                                "data": {
                                                    "name": "vm101",
                                                    "cores": 4,
                                                    "memory": 2048,
                                                    "ostype": "l26"
                                                }
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/storage" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"storage": "local-zfs", "type": "zfspool"}
                                                ]
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/storage/local-zfs/content?content=images" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"volid": "local-zfs:vm-101-disk-0", "size": 32212254720u64}
                                                ]
                                            }).to_string(),
                                        ),
                                        "/api2/json/cluster/backup" => (
                                            "200 OK",
                                            json!({
                                                "data": [
                                                    {"id": "backup-daily", "enabled": "1", "storage": "pbs-storage", "vmid": "101"}
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
                                        "/api2/json/nodes/pve1/qemu/101/agent/info" => (
                                            "200 OK",
                                            json!({
                                                "data": {
                                                    "result": {
                                                        "version": "8.2.2"
                                                    }
                                                }
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/qemu/101/agent/network-get-interfaces" => (
                                            "200 OK",
                                            json!({
                                                "data": {
                                                    "result": [
                                                        {
                                                            "name": "eth0",
                                                            "ip-addresses": [
                                                                {"ip-address": "192.168.1.150"}
                                                            ]
                                                        }
                                                    ]
                                                }
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/qemu/101/agent/get-osinfo" => (
                                            "200 OK",
                                            json!({
                                                "data": {
                                                    "result": {
                                                        "id": "debian",
                                                        "pretty-name": "Debian 12",
                                                        "version-id": "12",
                                                        "kernel-release": "6.1.0-20-amd64"
                                                    }
                                                }
                                            }).to_string(),
                                        ),
                                        "/api2/json/nodes/pve1/qemu/101/agent/get-host-name" => (
                                            "200 OK",
                                            json!({
                                                "data": {
                                                    "result": {
                                                        "host-name": "app01.corp.example"
                                                    }
                                                }
                                            }).to_string(),
                                        ),
                                        _ => ("404 Not Found", json!({"errors": "not found"}).to_string()),
                                    }
                                }
                            }
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
async fn test_client_ticket_authentication_and_all_endpoints() {
    let (server_url, _shutdown) = spawn_mock_pve_server().await;

    let mut client = ProxmoxClient::new(
        &server_url,
        AuthMethod::Ticket {
            password: "supersecret".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    // Authenticate
    client.authenticate("root@pam").await.unwrap();
    assert_eq!(client.ticket(), Some("MOCK_TICKET_123"));
    assert_eq!(client.csrf(), Some("MOCK_CSRF_456"));

    // Cluster name
    let cluster = client.get_cluster_name().await.unwrap();
    assert_eq!(cluster, "mock-cluster");

    // Nodes (only online)
    let nodes = client.get_nodes().await.unwrap();
    assert_eq!(nodes, vec!["pve1".to_string()]);

    // Cluster VMs (filtered qemu only)
    let vms = client.get_cluster_vms().await.unwrap();
    assert_eq!(vms.len(), 1);
    assert_eq!(vms[0]["id"], "qemu/101");

    // Node VMs
    let node_vms = client.get_vms_for_node("pve1").await.unwrap();
    assert_eq!(node_vms.len(), 1);
    assert_eq!(node_vms[0]["vmid"], 101);

    // VM config
    let config = client.get_vm_config("pve1", 101).await.unwrap();
    assert_eq!(config.get("name").unwrap(), "vm101");
    assert_eq!(config.get("cores").unwrap(), 4);

    // Storage config
    let storages = client.get_storage_config("pve1").await.unwrap();
    assert_eq!(storages.len(), 1);
    assert_eq!(storages[0]["storage"], "local-zfs");

    // Storage content
    let content = client.get_storage_content("pve1", "local-zfs").await.unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["volid"], "local-zfs:vm-101-disk-0");

    // Backup jobs
    let backups = client.get_backup_jobs().await.unwrap();
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0]["id"], "backup-daily");

    // HA vmids
    let ha = client.get_ha_vmids().await;
    assert_eq!(ha, HashSet::from([101]));

    // Guest agent info
    let agent_info = client.get_agent_info("pve1", 101).await;
    assert!(agent_info.is_some());
    assert_eq!(agent_info.unwrap()["version"], "8.2.2");

    // Guest agent IPs
    let ips = client.get_guest_ips("pve1", 101).await;
    assert_eq!(ips, vec!["192.168.1.150"]);

    // Guest agent OS
    let os = client.get_guest_os("pve1", 101).await;
    assert_eq!(os.get("os_family").unwrap(), &Some("debian".to_string()));
    assert_eq!(
        os.get("os_distribution").unwrap(),
        &Some("Debian 12".to_string())
    );
    assert_eq!(
        os.get("os_version").unwrap(),
        &Some("12 (6.1.0-20-amd64)".to_string())
    );

    // Guest agent FQDN
    let fqdn = client.get_guest_fqdn("pve1", 101).await;
    assert_eq!(fqdn, Some("app01.corp.example".to_string()));
}

#[tokio::test]
async fn test_client_api_token_authentication() {
    let (server_url, _shutdown) = spawn_mock_pve_server().await;

    let mut client = ProxmoxClient::new(
        &server_url,
        AuthMethod::ApiToken {
            token: "root@pam!token1=abc-123".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    // Authenticate is a no-op for API Token
    client.authenticate("root@pam").await.unwrap();

    // Calls succeed using Authorization header
    let cluster = client.get_cluster_name().await.unwrap();
    assert_eq!(cluster, "mock-cluster");

    let nodes = client.get_nodes().await.unwrap();
    assert_eq!(nodes, vec!["pve1".to_string()]);
}

#[tokio::test]
async fn test_client_agent_error_graceful_handling() {
    // Start mock server that returns 500 for agent endpoints
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
                        let body = json!({"data": null, "errors": "QEMU guest agent is not running"}).to_string();
                        let resp = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
            token: "any".to_string(),
        },
        false,
        5,
    )
    .unwrap();

    // All agent methods should return None or empty collections on 500 errors without panic
    assert_eq!(client.get_agent_info("pve1", 999).await, None);
    assert!(client.get_guest_ips("pve1", 999).await.is_empty());

    let os = client.get_guest_os("pve1", 999).await;
    assert_eq!(os.get("os_family").unwrap(), &None);
    assert_eq!(os.get("os_distribution").unwrap(), &None);
    assert_eq!(os.get("os_version").unwrap(), &None);

    assert_eq!(client.get_guest_fqdn("pve1", 999).await, None);

    let _ = shutdown_tx.send(());
}
