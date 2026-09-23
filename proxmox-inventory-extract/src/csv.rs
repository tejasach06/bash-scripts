use crate::model::TEMPLATE_COLUMNS;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::LazyLock;

pub const ENUM_COLUMNS: &[(&str, &[&str])] = &[
    (
        "status",
        &["running", "powered_off", "decommissioned", "unknown"],
    ),
    (
        "environment",
        &[
            "production",
            "development",
            "testing",
            "uat",
            "dr",
            "staging",
            "sandbox",
        ],
    ),
    ("criticality", &["low", "medium", "high", "critical"]),
    ("os_family", &["linux", "windows"]),
    ("vm_type", &["permanent", "temporary"]),
];

pub const BOOL_COLUMNS: &[&str] = &[
    "monitoring_enabled",
    "pmp_enabled",
    "ha_enabled",
    "backup_enabled",
];

pub const INT_COLUMNS: &[&str] = &["cpu_cores", "memory_mb"];

pub const DATE_COLUMNS: &[&str] = &[
    "last_patch_date",
    "last_vuln_scan_date",
    "last_verified_at",
    "decommission_date",
];

pub const REQUIRED_COLUMNS: &[&str] = &["name", "platform", "cluster"];

pub static ISO_DATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap());

/// Blank any cell InventoryMGR's importer would reject; return warnings.
pub fn sanitize_row(row: &mut HashMap<String, String>) -> Vec<String> {
    let mut warnings = Vec::new();

    for &(col, valid_set) in ENUM_COLUMNS {
        let val = row.get(col).map(|s| s.as_str()).unwrap_or("");
        if !val.is_empty() && !valid_set.contains(&val) {
            warnings.push(format!("{col} '{val}' not importable, blanked"));
            row.insert(col.to_string(), String::new());
        }
    }

    for &col in BOOL_COLUMNS {
        let val = row.get(col).map(|s| s.as_str()).unwrap_or("");
        if !val.is_empty() {
            let lower = val.to_ascii_lowercase();
            if !matches!(lower.as_str(), "true" | "false" | "yes" | "no" | "1" | "0") {
                warnings.push(format!("{col} '{val}' not a valid boolean, blanked"));
                row.insert(col.to_string(), String::new());
            }
        }
    }

    for &col in INT_COLUMNS {
        let val = row.get(col).map(|s| s.as_str()).unwrap_or("");
        let is_valid_int = !val.is_empty() && val.chars().all(|c| c.is_ascii_digit());
        if !val.is_empty() && !is_valid_int {
            warnings.push(format!("{col} '{val}' not a valid integer >= 0, blanked"));
            row.insert(col.to_string(), String::new());
        }
    }

    for &col in DATE_COLUMNS {
        let val = row.get(col).map(|s| s.as_str()).unwrap_or("");
        if !val.is_empty() && !ISO_DATE_RE.is_match(val) {
            warnings.push(format!(
                "{col} '{val}' not a valid ISO date YYYY-MM-DD, blanked"
            ));
            row.insert(col.to_string(), String::new());
        }
    }

    for &col in REQUIRED_COLUMNS {
        let is_blank = row.get(col).map(|s| s.trim().is_empty()).unwrap_or(true);
        if is_blank {
            warnings.push(format!("{col} is blank; InventoryMGR will reject this row"));
        }
    }

    warnings
}

/// Serialize sanitized rows to RFC 4180 CSV in exact TEMPLATE_COLUMNS order.
pub fn write_csv(
    rows: &[HashMap<String, String>],
    output_path: &str,
) -> Result<(), std::io::Error> {
    let file = File::create(output_path)?;
    let mut writer = csv::WriterBuilder::new().from_writer(file);

    writer
        .write_record(TEMPLATE_COLUMNS)
        .map_err(io::Error::other)?;

    for row in rows {
        let mut sanitized = row.clone();
        let warnings = sanitize_row(&mut sanitized);
        let id = sanitized
            .get("external_id")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("?");

        for warning in warnings {
            eprintln!("[warn] VM {id}: {warning}");
        }

        let record: Vec<&str> = TEMPLATE_COLUMNS
            .iter()
            .map(|&col| sanitized.get(col).map(|s| s.as_str()).unwrap_or(""))
            .collect();

        writer.write_record(&record).map_err(io::Error::other)?;
    }

    writer.flush().map_err(io::Error::other)?;

    Ok(())
}
