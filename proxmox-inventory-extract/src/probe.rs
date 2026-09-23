use crate::model::valid_ipv4;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const ARP_PATH: &str = "/proc/net/arp";
pub const DNSMASQ_LEASE_GLOBS: &[&str] = &[
    "/var/lib/misc/dnsmasq.*.leases",
    "/var/lib/dnsmasq/*.leases",
];

/// mac (lowercase) -> IPv4s from /proc/net/arp, skipping incomplete (flags 0x0) rows.
pub fn read_arp_table(path: &str) -> HashMap<String, Vec<String>> {
    let mut res: HashMap<String, Vec<String>> = HashMap::new();
    let p = Path::new(path);
    if !p.is_file() {
        return res;
    }
    let content = match std::fs::read_to_string(p) {
        Ok(c) => c,
        Err(_) => return res,
    };
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let (ip_raw, flags_raw, mac_raw) = (parts[0], parts[2], parts[3]);
        if flags_raw == "0x0" {
            continue;
        }
        let v_ip = valid_ipv4(ip_raw);
        let mac = mac_raw.to_ascii_lowercase();
        if !v_ip.is_empty() && !mac.is_empty() && mac != "00:00:00:00:00:00" {
            let entry = res.entry(mac).or_default();
            if !entry.contains(&v_ip) {
                entry.push(v_ip);
            }
        }
    }
    res
}

/// (mac -> IPv4s, mac -> hostname) from dnsmasq leases: 'expiry mac ip hostname clientid'.
pub fn read_dhcp_leases(
    globs: &[&str],
) -> (HashMap<String, Vec<String>>, HashMap<String, String>) {
    let mut mac_to_ips: HashMap<String, Vec<String>> = HashMap::new();
    let mut mac_to_host: HashMap<String, String> = HashMap::new();
    let mut seen_files: HashSet<PathBuf> = HashSet::new();

    for &pattern in globs {
        let paths = match glob::glob(pattern) {
            Ok(paths) => paths,
            Err(_) => continue,
        };
        for entry in paths {
            let filepath = match entry {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !seen_files.insert(filepath.clone()) {
                continue;
            }
            let content = match std::fs::read_to_string(&filepath) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "[warn] Failed to read lease file {}: {}",
                        filepath.display(),
                        e
                    );
                    continue;
                }
            };
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let (mac_raw, ip_raw, host_raw) = (parts[1], parts[2], parts[3]);
                let mac = mac_raw.to_ascii_lowercase();
                let v_ip = valid_ipv4(ip_raw);
                if !v_ip.is_empty() && !mac.is_empty() {
                    let entry = mac_to_ips.entry(mac.clone()).or_default();
                    if !entry.contains(&v_ip) {
                        entry.push(v_ip);
                    }
                }
                if !host_raw.is_empty()
                    && host_raw != "*"
                    && !mac.is_empty()
                    && host_raw.contains('.')
                    && !host_raw.starts_with("localhost")
                {
                    mac_to_host.insert(mac, host_raw.to_string());
                }
            }
        }
    }

    (mac_to_ips, mac_to_host)
}

/// PTR name for ip when it is a dotted non-localhost name, else ''.
pub async fn reverse_dns(ip: &str, timeout_secs: f64) -> String {
    let host_part = ip.trim().split('/').next().unwrap_or("").trim();
    if host_part.is_empty() {
        return String::new();
    }
    let ip_addr: std::net::IpAddr = match host_part.parse() {
        Ok(addr) => addr,
        Err(_) => return String::new(),
    };

    let timeout_duration = std::time::Duration::from_secs_f64(timeout_secs.max(0.0));
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr));
    let res = match tokio::time::timeout(timeout_duration, lookup).await {
        Ok(Ok(Ok(name))) => name,
        _ => return String::new(),
    };
    let trimmed = res.trim();
    if !trimmed.is_empty() && trimmed.contains('.') && !trimmed.starts_with("localhost") {
        trimmed.to_string()
    } else {
        String::new()
    }
}
