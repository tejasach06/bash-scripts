use proxmox_inventory_extract::csv::{sanitize_row, write_csv};
use proxmox_inventory_extract::model::TEMPLATE_COLUMNS;
use std::collections::HashMap;

#[test]
fn test_sanitize_row_invalid_enums_and_types() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS
        .iter()
        .map(|&c| (c.to_string(), String::new()))
        .collect();
    row.insert("name".to_string(), "vm1".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "c1".to_string());
    row.insert("os_family".to_string(), "bsd".to_string());
    row.insert(
        "last_verified_at".to_string(),
        "2026-08-27T13:00:00Z".to_string(),
    );
    row.insert("cpu_cores".to_string(), "4.0".to_string());

    let warnings = sanitize_row(&mut row);
    assert_eq!(warnings.len(), 3);
    assert_eq!(row["os_family"], "");
    assert_eq!(row["last_verified_at"], "");
    assert_eq!(row["cpu_cores"], "");
    assert_eq!(row["name"], "vm1");
}

#[test]
fn test_write_csv_headers_and_row() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS
        .iter()
        .map(|&c| (c.to_string(), String::new()))
        .collect();
    row.insert("name".to_string(), "vm100".to_string());
    row.insert("external_id".to_string(), "100".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "c1".to_string());

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();
    write_csv(&[row], path).unwrap();

    let content = std::fs::read_to_string(path).unwrap();
    let mut lines = content.lines();
    assert_eq!(lines.next().unwrap(), TEMPLATE_COLUMNS.join(","));
    assert!(lines.next().unwrap().contains("vm100,100"));
}

#[test]
fn test_sanitize_row_valid_values_no_warnings() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS
        .iter()
        .map(|&c| (c.to_string(), String::new()))
        .collect();
    row.insert("name".to_string(), "vm-valid".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "main-cluster".to_string());
    row.insert("status".to_string(), "running".to_string());
    row.insert("environment".to_string(), "production".to_string());
    row.insert("criticality".to_string(), "high".to_string());
    row.insert("os_family".to_string(), "linux".to_string());
    row.insert("vm_type".to_string(), "permanent".to_string());
    row.insert("monitoring_enabled".to_string(), "true".to_string());
    row.insert("pmp_enabled".to_string(), "no".to_string());
    row.insert("ha_enabled".to_string(), "1".to_string());
    row.insert("backup_enabled".to_string(), "0".to_string());
    row.insert("cpu_cores".to_string(), "8".to_string());
    row.insert("memory_mb".to_string(), "16384".to_string());
    row.insert("last_patch_date".to_string(), "2026-09-01".to_string());
    row.insert("last_vuln_scan_date".to_string(), "2026-09-15".to_string());
    row.insert("last_verified_at".to_string(), "2026-09-20".to_string());
    row.insert("decommission_date".to_string(), "2027-12-31".to_string());

    let warnings = sanitize_row(&mut row);
    assert!(
        warnings.is_empty(),
        "Expected no warnings, but got: {:?}",
        warnings
    );
    assert_eq!(row["status"], "running");
    assert_eq!(row["environment"], "production");
    assert_eq!(row["criticality"], "high");
    assert_eq!(row["os_family"], "linux");
    assert_eq!(row["vm_type"], "permanent");
    assert_eq!(row["monitoring_enabled"], "true");
    assert_eq!(row["cpu_cores"], "8");
    assert_eq!(row["last_patch_date"], "2026-09-01");
}

#[test]
fn test_sanitize_row_required_columns_blank() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS
        .iter()
        .map(|&c| (c.to_string(), String::new()))
        .collect();

    let warnings = sanitize_row(&mut row);
    assert_eq!(warnings.len(), 3);
    assert!(warnings.contains(&"name is blank; InventoryMGR will reject this row".to_string()));
    assert!(warnings.contains(&"platform is blank; InventoryMGR will reject this row".to_string()));
    assert!(warnings.contains(&"cluster is blank; InventoryMGR will reject this row".to_string()));
}

#[test]
fn test_sanitize_row_boolean_and_integer_validation() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS
        .iter()
        .map(|&c| (c.to_string(), String::new()))
        .collect();
    row.insert("name".to_string(), "vm-test".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "c1".to_string());
    row.insert("monitoring_enabled".to_string(), "yes_please".to_string());
    row.insert("cpu_cores".to_string(), "-2".to_string());
    row.insert("memory_mb".to_string(), "not_a_number".to_string());

    let warnings = sanitize_row(&mut row);
    assert_eq!(warnings.len(), 3);
    assert_eq!(
        warnings[0],
        "monitoring_enabled 'yes_please' not a valid boolean, blanked"
    );
    assert_eq!(
        warnings[1],
        "cpu_cores '-2' not a valid integer >= 0, blanked"
    );
    assert_eq!(
        warnings[2],
        "memory_mb 'not_a_number' not a valid integer >= 0, blanked"
    );
    assert_eq!(row["monitoring_enabled"], "");
    assert_eq!(row["cpu_cores"], "");
    assert_eq!(row["memory_mb"], "");
}

#[test]
fn test_write_csv_escapes_special_characters() {
    let mut row: HashMap<String, String> = TEMPLATE_COLUMNS
        .iter()
        .map(|&c| (c.to_string(), String::new()))
        .collect();
    row.insert("name".to_string(), "vm,with,commas".to_string());
    row.insert("external_id".to_string(), "200".to_string());
    row.insert("platform".to_string(), "proxmox".to_string());
    row.insert("cluster".to_string(), "c1".to_string());
    row.insert(
        "description".to_string(),
        "Line 1\nLine 2 with \"quotes\"".to_string(),
    );

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();
    write_csv(&[row], path).unwrap();

    let mut rdr = csv::ReaderBuilder::new().from_path(path).unwrap();
    let headers = rdr.headers().unwrap().clone();
    assert_eq!(headers.len(), TEMPLATE_COLUMNS.len());

    let records: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(&record[0], "vm,with,commas");
    let desc_idx = TEMPLATE_COLUMNS
        .iter()
        .position(|&c| c == "description")
        .unwrap();
    assert_eq!(&record[desc_idx], "Line 1\nLine 2 with \"quotes\"");
}
