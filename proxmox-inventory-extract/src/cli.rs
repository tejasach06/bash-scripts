use clap::Parser;
use std::env;
use std::io::IsTerminal;

pub const API_TIMEOUT: u64 = 30;

#[derive(Parser, Debug, Clone)]
#[command(name = "proxmox-inventory-extract", version = "2026-08-15")]
#[command(about = "Extract Proxmox VM inventory as InventoryMGR-compatible CSV")]
pub struct Args {
    #[arg(short = 'o', long = "output", help = "Output CSV path (default: /tmp/proxmox-inventory-<ts>.csv)")]
    pub output: Option<String>,

    #[arg(short = 'H', long = "host", default_value = "127.0.0.1:8006", help = "Proxmox API endpoint")]
    pub host: String,

    #[arg(short = 'u', long = "user", default_value = "root@pam", help = "Proxmox username")]
    pub user: String,

    #[arg(short = 'p', long = "password", help = "Password (or use PVE_PASSWORD env)")]
    pub password: Option<String>,

    #[arg(long = "api-token", help = "Proxmox API Token (or use PVE_API_TOKEN env)")]
    pub api_token: Option<String>,

    #[arg(long = "verify-ssl", help = "Verify the Proxmox TLS certificate (default: false)")]
    pub verify_ssl: bool,

    #[arg(long = "timeout", default_value_t = API_TIMEOUT, help = "Per-request HTTP timeout in seconds")]
    pub timeout: u64,

    #[arg(long = "no-probe", help = "Disable reverse DNS and local ARP/DHCP lease lookups")]
    pub no_probe: bool,

    #[arg(long = "probe-timeout", default_value_t = 2.0, help = "Reverse DNS timeout in seconds")]
    pub probe_timeout: f64,

    #[arg(long = "workers", default_value_t = 8, help = "Concurrent VM extraction workers")]
    pub workers: usize,

    #[arg(long = "quiet", help = "Suppress the progress line")]
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Ticket { password: String },
    ApiToken { token: String },
}

pub fn resolve_credentials(args: &Args) -> Result<AuthMethod, String> {
    if let Some(token) = &args.api_token {
        if !token.trim().is_empty() {
            return Ok(AuthMethod::ApiToken { token: token.clone() });
        }
    }
    if let Ok(token) = env::var("PVE_API_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(AuthMethod::ApiToken { token });
        }
    }

    if let Some(pass) = &args.password {
        if !pass.is_empty() {
            return Ok(AuthMethod::Ticket { password: pass.clone() });
        }
    }
    if let Ok(pass) = env::var("PVE_PASSWORD") {
        if !pass.is_empty() {
            return Ok(AuthMethod::Ticket { password: pass });
        }
    }

    if std::io::stdin().is_terminal() {
        match rpassword::prompt_password("Proxmox password: ") {
            Ok(pass) if !pass.is_empty() => Ok(AuthMethod::Ticket { password: pass }),
            _ => Err("Password entry was aborted or empty".to_string()),
        }
    } else {
        Err("No password or API token provided and stdin is not interactive".to_string())
    }
}
