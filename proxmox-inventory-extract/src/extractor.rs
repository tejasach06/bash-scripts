use crate::cli::{resolve_credentials, Args};
use crate::client::ProxmoxClient;
use crate::model::{
    backup_coverage, classify_ips, config_ips, config_macs, extract_ips_from_tags, map_os_family,
    parse_disks, parse_tags, resource_num, total_vcpus, DiskRecord, StorageMeta, TEMPLATE_COLUMNS,
};
use crate::probe::reverse_dns;
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::sync::Arc;

/// Maps Proxmox VM status string to InventoryMGR status.
pub fn map_status(status: &str) -> &'static str {
    match status {
        "running" => "running",
        "stopped" => "powered_off",
        _ => "unknown",
    }
}

/// Fetch storage config for a node and build metadata map keyed by storage ID.
pub async fn build_storage_meta(
    client: &ProxmoxClient,
    node: &str,
) -> HashMap<String, StorageMeta> {
    let mut meta = HashMap::new();
    let storages = match client.get_storage_config(node).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[warn] Failed to fetch storage config for {}: {}", node, e);
            return meta;
        }
    };
    for s in storages {
        if let Some(sid) = s.get("storage").and_then(|v| v.as_str()) {
            if sid.is_empty() {
                continue;
            }
            let storage_type = s.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let vgname = s.get("vgname").and_then(|v| v.as_str()).unwrap_or("");
            meta.insert(
                sid.to_string(),
                StorageMeta::new(sid, storage_type, vgname),
            );
        }
    }
    meta
}

/// Maps volid to provisioned GiB from storage content 'size'; 0 when unreported.
pub async fn build_volume_sizes(
    client: &ProxmoxClient,
    node: &str,
    storage_ids: &[String],
) -> HashMap<String, u64> {
    let mut sizes = HashMap::new();
    for sid in storage_ids {
        let content = match client.get_storage_content(node, sid).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[warn] Failed to fetch content for storage {} on {}: {}",
                    sid, node, e
                );
                continue;
            }
        };
        for vol in content {
            if let Some(volid) = vol.get("volid").and_then(|v| v.as_str()) {
                if !volid.is_empty() {
                    let size_bytes = vol.get("size").and_then(|s| {
                        if let Some(n) = s.as_u64() {
                            Some(n)
                        } else if let Some(n) = s.as_i64() {
                            Some(n.max(0) as u64)
                        } else if let Some(str_val) = s.as_str() {
                            str_val.parse::<u64>().ok()
                        } else {
                            None
                        }
                    }).unwrap_or(0);
                    let gib = size_bytes / (1024 * 1024 * 1024);
                    sizes.insert(volid.to_string(), gib);
                }
            }
        }
    }
    sizes
}

/// Map internal VM data to InventoryMGR CSV row (all TEMPLATE_COLUMNS).
#[allow(clippy::too_many_arguments)]
pub fn serialize_vm(
    vmid: u64,
    config: &serde_json::Map<String, serde_json::Value>,
    status: &str,
    node: &str,
    cluster_name: &str,
    disks: &[DiskRecord],
    ips_by_role: &HashMap<&str, Vec<String>>,
    os_info: &HashMap<String, Option<String>>,
    fqdn: Option<&str>,
    description: &str,
    tags: &str,
    resource: &serde_json::Value,
    backup_enabled: &str,
    backup_location: &str,
    ha_vmids: Option<&HashSet<u64>>,
) -> HashMap<String, String> {
    let mut row = HashMap::new();
    for col in TEMPLATE_COLUMNS {
        row.insert(col.to_string(), String::new());
    }

    // Identity
    let res_map_opt = resource.as_object();
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            resource
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("vm-{}", vmid));
    row.insert("name".to_string(), name);
    row.insert("external_id".to_string(), vmid.to_string());
    row.insert("fqdn".to_string(), fqdn.unwrap_or("").to_string());
    row.insert("sr_id".to_string(), String::new());
    row.insert("platform".to_string(), "proxmox".to_string());

    // Placement
    row.insert("datacenter".to_string(), String::new());
    row.insert("cluster".to_string(), cluster_name.to_string());
    row.insert("node".to_string(), node.to_string());

    // Classification
    row.insert("status".to_string(), map_status(status).to_string());
    row.insert("environment".to_string(), String::new());
    row.insert("criticality".to_string(), String::new());
    row.insert("vm_type".to_string(), String::new());

    // Capacity
    let vcpus = total_vcpus(config);
    let cpu_cores = if !vcpus.is_empty() {
        vcpus
    } else if let Some(rm) = res_map_opt {
        resource_num(rm, "maxcpu", 1)
    } else {
        String::new()
    };
    row.insert("cpu_cores".to_string(), cpu_cores);

    let mem_from_cfg = config.get("memory").and_then(|v| match v {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => {
            let t = s.trim();
            if !t.is_empty() {
                Some(t.to_string())
            } else {
                None
            }
        }
        _ => None,
    });
    let memory_mb = if let Some(m) = mem_from_cfg {
        m
    } else if let Some(rm) = res_map_opt {
        resource_num(rm, "maxmem", 1024 * 1024)
    } else {
        String::new()
    };
    row.insert("memory_mb".to_string(), memory_mb);

    let disks_str = disks
        .iter()
        .map(|d| d.to_csv_field())
        .collect::<Vec<_>>()
        .join(";");
    row.insert("disks".to_string(), disks_str);

    let storage_name = disks
        .first()
        .map(|d| d.storage_name.clone())
        .unwrap_or_default();
    let storage_type = disks
        .first()
        .map(|d| d.storage_type.clone())
        .unwrap_or_default();
    row.insert("storage_name".to_string(), storage_name);
    row.insert("storage_type".to_string(), storage_type);

    // OS
    let ostype = config.get("ostype").and_then(|v| v.as_str()).unwrap_or("");
    let guest_os_fam = os_info.get("os_family").and_then(|v| v.as_deref());
    let mapped_fam = map_os_family(ostype, guest_os_fam);
    row.insert("os_family".to_string(), mapped_fam.to_string());
    row.insert(
        "os_distribution".to_string(),
        os_info
            .get("os_distribution")
            .cloned()
            .flatten()
            .unwrap_or_default(),
    );
    row.insert(
        "os_version".to_string(),
        os_info
            .get("os_version")
            .cloned()
            .flatten()
            .unwrap_or_default(),
    );

    // Network
    let priv_ips = ips_by_role
        .get("private_ip")
        .map(|v| v.join(";"))
        .unwrap_or_default();
    row.insert("private_ip".to_string(), priv_ips);
    row.insert("public_ip".to_string(), String::new());
    let backup_ips = ips_by_role
        .get("backup_ip")
        .map(|v| v.join(";"))
        .unwrap_or_default();
    row.insert("backup_ip".to_string(), backup_ips);

    // Ownership
    row.insert("owner".to_string(), String::new());
    row.insert("business_owner".to_string(), String::new());
    row.insert("technical_owner".to_string(), String::new());
    row.insert("applications".to_string(), String::new());

    // Operations
    row.insert("monitoring_enabled".to_string(), String::new());
    row.insert("pmp_enabled".to_string(), String::new());

    let hastate_present = resource
        .get("hastate")
        .map(|v| match v {
            serde_json::Value::Null => false,
            serde_json::Value::String(s) => !s.is_empty(),
            serde_json::Value::Bool(b) => *b,
            _ => true,
        })
        .unwrap_or(false);
    let ha_in_set = ha_vmids.map(|set| set.contains(&vmid)).unwrap_or(false);
    let ha_enabled = if hastate_present || ha_in_set {
        "true"
    } else {
        "false"
    };
    row.insert("ha_enabled".to_string(), ha_enabled.to_string());

    row.insert("backup_enabled".to_string(), backup_enabled.to_string());
    row.insert("backup_location".to_string(), backup_location.to_string());

    let mut parts: Vec<String> = tags
        .split(';')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|s| s.to_string())
        .collect();
    let is_template = resource
        .get("template")
        .map(|v| match v {
            serde_json::Value::Number(n) => n.as_i64() == Some(1),
            serde_json::Value::String(s) => {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true")
            }
            serde_json::Value::Bool(b) => *b,
            _ => false,
        })
        .unwrap_or(false);
    if is_template && !parts.iter().any(|t| t == "template") {
        parts.push("template".to_string());
    }
    row.insert("tags".to_string(), parts.join(";"));

    // Compliance dates
    row.insert("last_patch_date".to_string(), String::new());
    row.insert("last_vuln_scan_date".to_string(), String::new());
    row.insert("last_verified_at".to_string(), String::new());
    row.insert("decommission_date".to_string(), String::new());

    // Notes
    row.insert("security_remarks".to_string(), String::new());
    row.insert("description".to_string(), description.to_string());

    row
}

/// Extract a single VM's inventory. Returns None on skip.
#[allow(clippy::too_many_arguments)]
pub async fn extract_vm(
    client: &ProxmoxClient,
    node: &str,
    vmid: u64,
    cluster_name: &str,
    storage_meta: &HashMap<String, StorageMeta>,
    volume_sizes: &HashMap<String, u64>,
    resource: &serde_json::Value,
    backup_jobs: &[serde_json::Value],
    status: &str,
    local_node: &str,
    arp_map: Option<&HashMap<String, Vec<String>>>,
    lease_ips: Option<&HashMap<String, Vec<String>>>,
    lease_hosts: Option<&HashMap<String, String>>,
    probe_enabled: bool,
    probe_timeout: f64,
    ha_vmids: Option<&HashSet<u64>>,
) -> Option<HashMap<String, String>> {
    let config = match client.get_vm_config(node, vmid).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[warn] Failed to get config for VM {} on {}: {}",
                vmid, node, e
            );
            return None;
        }
    };

    let description = config
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tags = parse_tags(&config);
    let disks = parse_disks(&config, storage_meta, volume_sizes);

    let mut agent_live = false;
    let mut ips: Vec<String> = Vec::new();
    let mut os_info: HashMap<String, Option<String>> = HashMap::new();
    os_info.insert("os_family".to_string(), None);
    os_info.insert("os_distribution".to_string(), None);
    os_info.insert("os_version".to_string(), None);
    let mut fqdn: Option<String> = None;

    if status == "running" && client.get_agent_info(node, vmid).await.is_some() {
        agent_live = true;
    }

    if agent_live {
        ips = client.get_guest_ips(node, vmid).await;
    }

    if ips.is_empty() {
        ips = config_ips(&config);
    }

    if ips.is_empty() {
        ips = extract_ips_from_tags(&tags);
    }

    if ips.is_empty() && probe_enabled && node == local_node {
        let macs = config_macs(&config);
        let mut probe_ips: Vec<String> = Vec::new();
        for mac in &macs {
            if let Some(map) = arp_map {
                if let Some(arp_ips) = map.get(mac) {
                    for ip in arp_ips {
                        if !probe_ips.contains(ip) {
                            probe_ips.push(ip.clone());
                        }
                    }
                }
            }
            if let Some(map) = lease_ips {
                if let Some(l_ips) = map.get(mac) {
                    for ip in l_ips {
                        if !probe_ips.contains(ip) {
                            probe_ips.push(ip.clone());
                        }
                    }
                }
            }
        }
        ips = probe_ips;
    }

    if agent_live {
        os_info = client.get_guest_os(node, vmid).await;
        fqdn = client.get_guest_fqdn(node, vmid).await;
    }

    let ips_by_role = classify_ips(&ips);

    let macs = config_macs(&config);
    if fqdn.is_none() && probe_enabled && node == local_node {
        if let Some(hosts) = lease_hosts {
            for mac in &macs {
                if let Some(h) = hosts.get(mac) {
                    if h.contains('.') && !h.starts_with("localhost") {
                        fqdn = Some(h.clone());
                        break;
                    }
                }
            }
        }
    }

    if fqdn.is_none() && probe_enabled {
        let mut candidate_ips = Vec::new();
        if let Some(priv_ips) = ips_by_role.get("private_ip") {
            candidate_ips.extend(priv_ips.iter().cloned());
        }
        if let Some(back_ips) = ips_by_role.get("backup_ip") {
            candidate_ips.extend(back_ips.iter().cloned());
        }
        for ip in candidate_ips {
            let ptr = reverse_dns(&ip, probe_timeout).await;
            if !ptr.is_empty() {
                fqdn = Some(ptr);
                break;
            }
        }
    }

    if fqdn.is_none() {
        let searchdomain = config
            .get("searchdomain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let vm_name = config
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                resource
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("")
            .trim();
        if !searchdomain.is_empty() && !vm_name.is_empty() {
            fqdn = Some(format!("{}.{}", vm_name, searchdomain));
        }
    }

    let pool = resource
        .get("pool")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            config
                .get("pool")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("");
    let (backup_enabled, backup_location) = backup_coverage(backup_jobs, vmid, pool);

    Some(serialize_vm(
        vmid,
        &config,
        status,
        node,
        cluster_name,
        &disks,
        &ips_by_role,
        &os_info,
        fqdn.as_deref(),
        &description,
        &tags,
        resource,
        &backup_enabled,
        &backup_location,
        ha_vmids,
    ))
}

#[derive(Clone, Debug)]
struct TargetVm {
    node: String,
    vmid: u64,
    status: String,
    resource: serde_json::Value,
}

/// Runs the complete application orchestration pipeline, returning exit code (0, 1, or 2).
pub async fn run_orchestrator(args: Args) -> i32 {
    let auth = match resolve_credentials(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[error] Authentication failed: {}", e);
            return 1;
        }
    };

    let mut client = match ProxmoxClient::new(&args.host, auth, args.verify_ssl, args.timeout) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[error] Authentication failed: {}", e);
            return 1;
        }
    };

    if let Err(e) = client.authenticate(&args.user).await {
        eprintln!("[error] Authentication failed: {}", e);
        return 1;
    }

    let mut partial_failure = false;

    let cluster_name = match client.get_cluster_name().await {
        Ok(name) => name,
        Err(e) => {
            eprintln!(
                "[warn] cluster status unavailable, using 'standalone': {}",
                e
            );
            partial_failure = true;
            "standalone".to_string()
        }
    };

    let nodes = match client.get_nodes().await {
        Ok(n) => {
            if n.is_empty() {
                eprintln!("[warn] No online nodes found");
            }
            n
        }
        Err(e) => {
            eprintln!("[warn] Failed to fetch nodes: {}", e);
            eprintln!("[warn] No online nodes found");
            partial_failure = true;
            Vec::new()
        }
    };

    let backup_jobs = match client.get_backup_jobs().await {
        Ok(jobs) => jobs,
        Err(e) => {
            eprintln!("[warn] Failed to fetch backup jobs: {}", e);
            partial_failure = true;
            Vec::new()
        }
    };

    let local_hostname = gethostname::gethostname().to_string_lossy().to_string();
    let local_node = local_hostname.split('.').next().unwrap_or("").to_string();
    let probe_enabled = !args.no_probe;

    let mut arp_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut lease_ips: HashMap<String, Vec<String>> = HashMap::new();
    let mut lease_hosts: HashMap<String, String> = HashMap::new();

    let ha_vmids = client.get_ha_vmids().await;

    if probe_enabled {
        arp_map = crate::probe::read_arp_table(crate::probe::ARP_PATH);
        let (lips, lhosts) = crate::probe::read_dhcp_leases(crate::probe::DNSMASQ_LEASE_GLOBS);
        lease_ips = lips;
        lease_hosts = lhosts;
    }

    let mut use_fallback = false;
    let cluster_vms = match client.get_cluster_vms().await {
        Ok(vms) => vms,
        Err(e) => {
            eprintln!(
                "[warn] cluster/resources unavailable, falling back to per-node enumeration: {}",
                e
            );
            partial_failure = true;
            use_fallback = true;
            Vec::new()
        }
    };

    if !use_fallback && cluster_vms.is_empty() {
        eprintln!(
            "[warn] cluster/resources returned no VMs, falling back to per-node enumeration"
        );
        partial_failure = true;
        use_fallback = true;
    }

    let mut targets: Vec<TargetVm> = Vec::new();
    if !use_fallback {
        for res in cluster_vms {
            let vmid_opt = res.get("vmid").and_then(|v| {
                if let Some(n) = v.as_u64() {
                    Some(n)
                } else if let Some(n) = v.as_i64() {
                    Some(n as u64)
                } else if let Some(s) = v.as_str() {
                    s.parse::<u64>().ok()
                } else {
                    None
                }
            });
            if let Some(vmid) = vmid_opt {
                let node = res
                    .get("node")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let status = res
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                targets.push(TargetVm {
                    node,
                    vmid,
                    status,
                    resource: res,
                });
            }
        }
    } else {
        for node in &nodes {
            let vms = match client.get_vms_for_node(node).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[warn] Failed to enumerate VMs on node {}: {}", node, e);
                    partial_failure = true;
                    continue;
                }
            };
            for vm in vms {
                let vmid_opt = vm.get("vmid").and_then(|v| {
                    if let Some(n) = v.as_u64() {
                        Some(n)
                    } else if let Some(n) = v.as_i64() {
                        Some(n as u64)
                    } else if let Some(s) = v.as_str() {
                        s.parse::<u64>().ok()
                    } else {
                        None
                    }
                });
                if let Some(vmid) = vmid_opt {
                    let status = vm
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    targets.push(TargetVm {
                        node: node.clone(),
                        vmid,
                        status,
                        resource: vm,
                    });
                }
            }
        }
    }

    let mut unique_nodes = Vec::new();
    for t in &targets {
        if !unique_nodes.contains(&t.node) {
            unique_nodes.push(t.node.clone());
        }
    }

    let mut storage_meta_cache: HashMap<String, HashMap<String, StorageMeta>> = HashMap::new();
    let mut volume_sizes_cache: HashMap<String, HashMap<String, u64>> = HashMap::new();

    for node in &unique_nodes {
        let sm = build_storage_meta(&client, node).await;
        let sids: Vec<String> = sm.keys().cloned().collect();
        let vs = build_volume_sizes(&client, node, &sids).await;
        storage_meta_cache.insert(node.clone(), sm);
        volume_sizes_cache.insert(node.clone(), vs);
    }

    let total = targets.len();
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let show_progress = !args.quiet && std::io::stderr().is_terminal();
    let start = std::time::Instant::now();

    let max_workers = args.workers.max(1);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_workers));

    let client_arc = Arc::new(client);
    let cluster_name_arc = Arc::new(cluster_name);
    let storage_meta_arc = Arc::new(storage_meta_cache);
    let volume_sizes_arc = Arc::new(volume_sizes_cache);
    let backup_jobs_arc = Arc::new(backup_jobs);
    let local_node_arc = Arc::new(local_node);
    let arp_map_arc = Arc::new(arp_map);
    let lease_ips_arc = Arc::new(lease_ips);
    let lease_hosts_arc = Arc::new(lease_hosts);
    let ha_vmids_arc = Arc::new(ha_vmids);

    let mut handles = Vec::with_capacity(total);
    for (i, target) in targets.into_iter().enumerate() {
        let sem = semaphore.clone();
        let client = client_arc.clone();
        let cluster_name = cluster_name_arc.clone();
        let storage_meta = storage_meta_arc.clone();
        let volume_sizes = volume_sizes_arc.clone();
        let backup_jobs = backup_jobs_arc.clone();
        let local_node = local_node_arc.clone();
        let arp_map = arp_map_arc.clone();
        let lease_ips = lease_ips_arc.clone();
        let lease_hosts = lease_hosts_arc.clone();
        let ha_vmids = ha_vmids_arc.clone();
        let completed = completed.clone();
        let probe_timeout = args.probe_timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let empty_sm = HashMap::new();
            let empty_vs = HashMap::new();
            let sm = storage_meta.get(&target.node).unwrap_or(&empty_sm);
            let vs = volume_sizes.get(&target.node).unwrap_or(&empty_vs);

            let row = extract_vm(
                &client,
                &target.node,
                target.vmid,
                &cluster_name,
                sm,
                vs,
                &target.resource,
                &backup_jobs,
                &target.status,
                &local_node,
                Some(&arp_map),
                Some(&lease_ips),
                Some(&lease_hosts),
                probe_enabled,
                probe_timeout,
                Some(&ha_vmids),
            )
            .await;

            let n = completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if show_progress {
                let elapsed = start.elapsed().as_secs_f64();
                eprint!(
                    "\r[{}/{}] vm {} ({:.1}s)          ",
                    n, total, target.vmid, elapsed
                );
                let _ = std::io::stderr().flush();
            }

            (i, row)
        }));
    }

    let mut results: Vec<Option<HashMap<String, String>>> = vec![None; total];
    for handle in handles {
        if let Ok((i, row)) = handle.await {
            results[i] = row;
        } else {
            partial_failure = true;
        }
    }

    if show_progress {
        eprintln!();
    }

    let mut all_rows = Vec::new();
    for row_opt in results {
        if let Some(row) = row_opt {
            all_rows.push(row);
        } else {
            partial_failure = true;
        }
    }

    let output_path = match &args.output {
        Some(p) => p.clone(),
        None => {
            let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
            format!("/tmp/proxmox-inventory-{}.csv", ts)
        }
    };

    if let Err(e) = crate::csv::write_csv(&all_rows, &output_path) {
        eprintln!("[error] Failed to write CSV: {}", e);
        return 1;
    }

    println!("[ok] Wrote {} VM(s) to {}", all_rows.len(), output_path);
    if partial_failure {
        2
    } else {
        0
    }
}
