use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::LazyLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const TEMPLATE_COLUMNS: [&str; 39] = [
    "name",
    "external_id",
    "fqdn",
    "sr_id",
    "platform",
    "datacenter",
    "cluster",
    "node",
    "status",
    "environment",
    "criticality",
    "vm_type",
    "cpu_cores",
    "memory_mb",
    "disks",
    "storage_name",
    "storage_type",
    "os_family",
    "os_distribution",
    "os_version",
    "private_ip",
    "public_ip",
    "backup_ip",
    "owner",
    "business_owner",
    "technical_owner",
    "applications",
    "monitoring_enabled",
    "pmp_enabled",
    "ha_enabled",
    "backup_enabled",
    "backup_location",
    "tags",
    "last_patch_date",
    "last_vuln_scan_date",
    "last_verified_at",
    "decommission_date",
    "security_remarks",
    "description",
];

pub const AGENT_LINUX_IDS: &[&str] = &[
    "alpine",
    "almalinux",
    "amzn",
    "arch",
    "centos",
    "debian",
    "fedora",
    "gentoo",
    "linuxmint",
    "ol",
    "opensuse",
    "opensuse-leap",
    "opensuse-tumbleweed",
    "rhel",
    "rocky",
    "sles",
    "suse",
    "ubuntu",
];

pub static DISK_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:scsi|virtio|ide|sata|unused|efidisk|tpmstate)\d+$").unwrap()
});

static SIZE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d+(?:\.\d+)?)([KMGTPE]?)B?$").unwrap()
});

static IPCONFIG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^ipconfig\d+$").unwrap()
});

static NET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^net\d+$").unwrap()
});

static MAC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b").unwrap()
});

static TAG_IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageMeta {
    #[serde(default)]
    pub storage_id: String,
    #[serde(default, rename = "type", alias = "storage_type")]
    pub storage_type: String,
    #[serde(default)]
    pub vgname: String,
}

impl StorageMeta {
    pub fn new(
        storage_id: impl Into<String>,
        storage_type: impl Into<String>,
        vgname: impl Into<String>,
    ) -> Self {
        Self {
            storage_id: storage_id.into(),
            storage_type: storage_type.into(),
            vgname: vgname.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskRecord {
    pub lv_name: String,
    pub config_key: String,
    pub size_gib: u64,
    pub storage_name: String,
    pub storage_type: String,
}

impl DiskRecord {
    pub fn disk_name(&self) -> String {
        format!("{}-{}", self.lv_name, self.config_key)
    }

    pub fn to_csv_field(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.disk_name(),
            self.size_gib,
            self.storage_name,
            self.storage_type
        )
    }
}

/// Parse Proxmox size string (e.g. '50G', '512M', '1T') to GiB; round up sub-GiB non-zero to 1.
pub fn parse_size_to_gib(size_str: &str) -> u64 {
    let size_str = size_str.trim().to_ascii_uppercase();
    let caps = match SIZE_RE.captures(&size_str) {
        Some(c) => c,
        None => return 0,
    };

    let num: f64 = match caps.get(1).unwrap().as_str().parse() {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let multiplier: f64 = match unit {
        "" | "B" => 1.0,
        "K" => 1024.0,
        "M" => 1024.0 * 1024.0,
        "G" => 1024.0 * 1024.0 * 1024.0,
        "T" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "P" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "E" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };

    let total = num * multiplier;
    if total <= 0.0 || !total.is_finite() {
        return 0;
    }

    let gib = (total / (1024.0 * 1024.0 * 1024.0)).floor() as u64;
    std::cmp::max(1, gib)
}

/// Parse a Proxmox disk config value into (lv_name, size_gib, storage_id, volid).
/// Returns ("", 0, "", "") when the config is malformed or passthrough without standard format.
pub fn parse_disk_value(value: &str) -> (String, u64, String, String) {
    let parts: Vec<&str> = value.split(',').collect();
    if parts.is_empty() {
        return (String::new(), 0, String::new(), String::new());
    }
    let main = parts[0].trim();
    if main.is_empty() || !main.contains(':') {
        return (String::new(), 0, String::new(), String::new());
    }
    let mut split_main = main.splitn(2, ':');
    let storage_id = split_main.next().unwrap_or("").trim();
    let volume = split_main.next().unwrap_or("").trim();
    if storage_id.is_empty() {
        return (String::new(), 0, String::new(), String::new());
    }
    let lv_name = volume.rsplit('/').next().unwrap_or(volume).trim();

    let mut size_gib = 0;
    for part in &parts[1..] {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("size=") {
            size_gib = parse_size_to_gib(rest);
            break;
        }
    }

    (
        lv_name.to_string(),
        size_gib,
        storage_id.to_string(),
        main.to_string(),
    )
}

/// Parse all supported disk config keys into structured DiskRecord list.
pub fn parse_disks(
    config: &serde_json::Map<String, serde_json::Value>,
    storage_meta: &HashMap<String, StorageMeta>,
    volume_sizes: &HashMap<String, u64>,
) -> Vec<DiskRecord> {
    let mut disks = Vec::new();
    let mut keys: Vec<&String> = config.keys().collect();
    keys.sort();

    for key in keys {
        if !DISK_KEY_RE.is_match(key) {
            continue;
        }
        let val_val = match config.get(key) {
            Some(v) => v,
            None => continue,
        };
        let val_str = match val_val.as_str() {
            Some(s) => s,
            None => continue,
        };
        if val_str.is_empty() || val_str == "none" || val_str.contains("media=cdrom") {
            continue;
        }

        let (lv_name, mut size_gib, storage_id, volid) = parse_disk_value(val_str);
        if size_gib == 0 {
            if let Some(&sz) = volume_sizes.get(&volid) {
                size_gib = sz;
            }
        }

        if lv_name.is_empty() {
            eprintln!("[warn] Skipping malformed disk {}={}", key, val_str);
            continue;
        }

        let (storage_name, storage_type) = match storage_meta.get(&storage_id) {
            Some(meta) => {
                let name = if !meta.vgname.is_empty() {
                    meta.vgname.clone()
                } else {
                    storage_id.clone()
                };
                (name, meta.storage_type.clone())
            }
            None => (storage_id.clone(), String::new()),
        };

        disks.push(DiskRecord {
            lv_name,
            config_key: key.clone(),
            size_gib,
            storage_name,
            storage_type,
        });
    }

    disks
}

/// Canonical IPv4 string, or "" when the value is not a usable address.
/// Strips /CIDR suffix; rejects loopback, link-local, multicast, unspecified and IPv6.
pub fn valid_ipv4(value: &str) -> String {
    let val = value.trim();
    let host_part = val.split('/').next().unwrap_or("").trim();
    if host_part.is_empty() {
        return String::new();
    }
    let Ok(ip) = host_part.parse::<Ipv4Addr>() else {
        return String::new();
    };
    if ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() {
        return String::new();
    }
    ip.to_string()
}

/// 10/8 is the backup network; every other usable IPv4 is private. public_ip stays human-curated.
/// Deduplicates preserving encounter order.
pub fn classify_ips(ips: &[String]) -> HashMap<&'static str, Vec<String>> {
    let mut result = HashMap::new();
    let mut private_ip = Vec::new();
    let mut backup_ip = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for raw_ip in ips {
        let ip = valid_ipv4(raw_ip);
        if ip.is_empty() {
            continue;
        }
        if !seen.insert(ip.clone()) {
            continue;
        }
        if ip.starts_with("10.") {
            backup_ip.push(ip);
        } else {
            private_ip.push(ip);
        }
    }

    result.insert("private_ip", private_ip);
    result.insert("backup_ip", backup_ip);
    result
}

/// Proxmox vCPU count = cores * sockets; both default to 1 when at least one is present.
pub fn total_vcpus(config: &serde_json::Map<String, serde_json::Value>) -> String {
    let c_val = config.get("cores");
    let s_val = config.get("sockets");

    if c_val.is_none() && s_val.is_none() {
        return String::new();
    }

    let parse_num = |val: Option<&serde_json::Value>| -> Result<Option<i64>, ()> {
        match val {
            None => Ok(None),
            Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    trimmed.parse::<i64>().map(Some).map_err(|_| ())
                }
            }
            Some(serde_json::Value::Number(n)) => {
                if let Some(i) = n.as_i64() {
                    Ok(Some(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(Some(f as i64))
                } else {
                    Err(())
                }
            }
            _ => Err(()),
        }
    };

    let cores_opt = match parse_num(c_val) {
        Ok(opt) => opt,
        Err(_) => return String::new(),
    };
    let sockets_opt = match parse_num(s_val) {
        Ok(opt) => opt,
        Err(_) => return String::new(),
    };

    if cores_opt.is_none() && sockets_opt.is_none() {
        return String::new();
    }

    let cores = cores_opt.unwrap_or(1);
    let sockets = sockets_opt.unwrap_or(1);

    if cores <= 0 || sockets <= 0 {
        return String::new();
    }

    (cores * sockets).to_string()
}

/// Positive integer from a cluster/resources field, floor-divided by divisor, else "".
pub fn resource_num(
    resource: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    divisor: u64,
) -> String {
    if divisor == 0 {
        return String::new();
    }
    let val = match resource.get(key) {
        Some(v) => v,
        None => return String::new(),
    };
    if val.is_null() {
        return String::new();
    }

    let f = match val {
        serde_json::Value::Number(n) => match n.as_f64() {
            Some(f) => f,
            None => return String::new(),
        },
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return String::new();
            }
            match trimmed.parse::<f64>() {
                Ok(f) => f,
                Err(_) => return String::new(),
            }
        }
        _ => return String::new(),
    };

    if !f.is_finite() {
        return String::new();
    }

    let val_int = f as i64;
    let num = val_int / (divisor as i64);
    if num > 0 {
        num.to_string()
    } else {
        String::new()
    }
}

/// InventoryMGR os_family ('linux' | 'windows' | '').
pub fn map_os_family(ostype: &str, guest_os_family: Option<&str>) -> &'static str {
    let ot = ostype.trim().to_ascii_lowercase();
    if ot.starts_with('l') {
        return "linux";
    }
    if ot.starts_with('w') {
        return "windows";
    }
    if !ot.is_empty() {
        return "";
    }
    if let Some(g) = guest_os_family {
        let g_fam = g.trim().to_ascii_lowercase();
        if AGENT_LINUX_IDS.contains(&g_fam.as_str()) {
            return "linux";
        }
        if g_fam.contains("windows") || g_fam.contains("mswin") {
            return "windows";
        }
    }
    ""
}

/// Extract and join Proxmox tags with semicolon.
pub fn parse_tags(config: &serde_json::Map<String, serde_json::Value>) -> String {
    let raw = match config.get("tags") {
        Some(serde_json::Value::String(s)) => s.as_str(),
        _ => return String::new(),
    };
    if raw.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = raw
        .split(';')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    parts.join(";")
}

/// (backup_enabled, backup_location) from vzdump job config.
pub fn backup_coverage(jobs: &[serde_json::Value], vmid: u64, pool: &str) -> (String, String) {
    for job in jobs {
        let is_disabled = match job.get("enabled") {
            Some(serde_json::Value::Number(n)) => n.as_i64() == Some(0),
            Some(serde_json::Value::String(s)) => s.trim() == "0",
            Some(serde_json::Value::Bool(b)) => !*b,
            _ => false,
        };
        if is_disabled {
            continue;
        }

        let mut vmids = std::collections::HashSet::new();
        if let Some(v_val) = job.get("vmid") {
            match v_val {
                serde_json::Value::String(s) => {
                    for v in s.split(',') {
                        if let Ok(id) = v.trim().parse::<u64>() {
                            vmids.insert(id);
                        }
                    }
                }
                serde_json::Value::Number(n) => {
                    if let Some(id) = n.as_u64() {
                        vmids.insert(id);
                    }
                }
                _ => {}
            }
        }

        let mut excludes = std::collections::HashSet::new();
        if let Some(e_val) = job.get("exclude") {
            match e_val {
                serde_json::Value::String(s) => {
                    for v in s.split(',') {
                        if let Ok(id) = v.trim().parse::<u64>() {
                            excludes.insert(id);
                        }
                    }
                }
                serde_json::Value::Number(n) => {
                    if let Some(id) = n.as_u64() {
                        excludes.insert(id);
                    }
                }
                _ => {}
            }
        }

        let job_all = match job.get("all") {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
            Some(serde_json::Value::String(s)) => {
                let st = s.trim();
                st == "1" || st.eq_ignore_ascii_case("true")
            }
            _ => false,
        };

        let job_pool = match job.get("pool") {
            Some(serde_json::Value::String(s)) => s.as_str(),
            _ => "",
        };

        let is_covered = vmids.contains(&vmid)
            || (job_all && !excludes.contains(&vmid))
            || (!pool.is_empty() && job_pool == pool);

        if is_covered {
            let storage = match job.get("storage") {
                Some(serde_json::Value::String(s)) => s.as_str(),
                _ => "",
            };
            return ("true".to_string(), storage.to_string());
        }
    }

    ("false".to_string(), String::new())
}

/// IPv4 addresses declared in cloud-init ipconfigN keys (ip=10.0.0.5/24).
pub fn config_ips(config: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut ips = Vec::new();
    let mut keys: Vec<&String> = config.keys().filter(|k| IPCONFIG_RE.is_match(k)).collect();
    keys.sort_by_key(|k| k[8..].parse::<u32>().unwrap_or(0));

    for k in keys {
        if let Some(serde_json::Value::String(val)) = config.get(k) {
            for part in val.split(',') {
                let part = part.trim();
                if let Some(raw_ip) = part.strip_prefix("ip=") {
                    if raw_ip.eq_ignore_ascii_case("dhcp") {
                        continue;
                    }
                    let v_ip = valid_ipv4(raw_ip);
                    if !v_ip.is_empty() && !ips.contains(&v_ip) {
                        ips.push(v_ip);
                    }
                }
            }
        }
    }
    ips
}

/// Lowercase MACs from netN keys, e.g. 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0'.
pub fn config_macs(config: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut macs = Vec::new();
    let mut keys: Vec<&String> = config.keys().filter(|k| NET_RE.is_match(k)).collect();
    keys.sort_by_key(|k| k[3..].parse::<u32>().unwrap_or(0));

    for k in keys {
        if let Some(serde_json::Value::String(val)) = config.get(k) {
            if let Some(caps) = MAC_RE.captures(val) {
                if let Some(m) = caps.get(1) {
                    let mac = m.as_str().to_ascii_lowercase();
                    if !macs.contains(&mac) {
                        macs.push(mac);
                    }
                }
            }
        }
    }
    macs
}

/// Fallback: extract IP-like strings from Proxmox tags.
pub fn extract_ips_from_tags(tags: &str) -> Vec<String> {
    if tags.is_empty() {
        return Vec::new();
    }
    TAG_IP_RE
        .find_iter(tags)
        .map(|m| m.as_str().to_string())
        .collect()
}
