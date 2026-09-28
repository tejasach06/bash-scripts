//! pmta-log-extract library
//!
//! Public API consumed by main.rs and re-exported for integration tests.

use std::collections::{HashMap, HashSet};
use std::io::Read;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Gzip,
    Bzip2,
    Zip,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Exact,
    Contains,
    Domain,
}

#[derive(Debug, Clone, Default)]
pub struct PatternSet {
    pub patterns: Vec<String>,
}

impl PatternSet {
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// All patterns lowercased for comparison.
    pub fn lower_patterns(&self) -> Vec<String> {
        self.patterns.iter().map(|p| p.to_lowercase()).collect()
    }
}

#[derive(Debug)]
pub struct Config {
    pub path: String,
    pub orig: Option<PatternSet>,
    pub rcpt: Option<PatternSet>,
    pub any_: Option<PatternSet>,
    pub match_mode: MatchMode,
    pub types: HashSet<String>,
    pub fields: Option<Vec<String>>,
    pub out: String,
    pub workers: usize,
    pub verbose: bool,
}

// ─── load_patterns ────────────────────────────────────────────────────────────

/// Load patterns from CLI values.
/// Each entry is either a literal pattern or `@filename` (one pattern per line).
pub fn load_patterns(
    values: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::new();
    for v in values {
        if let Some(path) = v.strip_prefix('@') {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("pattern file '{path}': {e}"))?;
            for line in text.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
            }
        } else {
            out.push(v.clone());
        }
    }
    Ok(out)
}

// ─── classify ─────────────────────────────────────────────────────────────────

/// Detect file kind by magic bytes (first 4 bytes).
pub fn classify(path: &str) -> FileKind {
    let head = match read_magic(path) {
        Ok(h) => h,
        Err(_) => return FileKind::Plain,
    };
    if head.starts_with(b"\x1f\x8b") {
        FileKind::Gzip
    } else if head.starts_with(b"BZh") {
        FileKind::Bzip2
    } else if head.starts_with(b"PK") {
        FileKind::Zip
    } else {
        FileKind::Plain
    }
}

fn read_magic(path: &str) -> std::io::Result<[u8; 4]> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 4];
    let _ = f.read(&mut buf);
    Ok(buf)
}

type StreamResult = Result<Vec<(String, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>>;
// ─── iter_log_streams ─────────────────────────────────────────────────────────

/// Yield `(source_name, Box<dyn Read>)` for every log stream inside `path`.
/// Handles: plain, gzip, bzip2, zip (all members), tar.gz, tar.bz2.
pub fn iter_log_streams(
    path: &str,
    _cfg: &Config,
) -> StreamResult {
    let kind = classify(path);
    match kind {
        FileKind::Gzip => iter_gzip(path),
        FileKind::Bzip2 => iter_bzip2(path),
        FileKind::Zip => iter_zip(path),
        FileKind::Plain => iter_plain(path),
    }
}

fn iter_plain(
    path: &str,
) -> StreamResult {
    let data = std::fs::read(path)?;
    Ok(vec![(path.to_string(), data)])
}

fn iter_gzip(
    path: &str,
) -> StreamResult {
    let f = std::fs::File::open(path)?;
    let mut decoder = flate2::read::GzDecoder::new(f);
    let mut data = Vec::new();
    decoder.read_to_end(&mut data)?;

    // Peek: is the decompressed content a tar?
    if looks_like_tar(&data) {
        extract_tar_members(path, &data)
    } else {
        let name = strip_gz(path);
        Ok(vec![(format!("{path}::{name}"), data)])
    }
}

fn iter_bzip2(
    path: &str,
) -> StreamResult {
    let f = std::fs::File::open(path)?;
    let mut decoder = bzip2::read::BzDecoder::new(f);
    let mut data = Vec::new();
    decoder.read_to_end(&mut data)?;

    if looks_like_tar(&data) {
        extract_tar_members(path, &data)
    } else {
        let name = strip_bz2(path);
        Ok(vec![(format!("{path}::{name}"), data)])
    }
}

fn iter_zip(
    path: &str,
) -> StreamResult {
    let f = std::fs::File::open(path)?;
    let mut zf = zip::ZipArchive::new(f)?;
    let mut results = Vec::new();
    for i in 0..zf.len() {
        let mut member = zf.by_index(i)?;
        if member.is_dir() {
            continue;
        }
        let name = member.name().to_string();
        let mut data = Vec::new();
        member.read_to_end(&mut data)?;
        // Handle nested .gz/.bz2 inside zip
        let (final_data, final_name) = decompress_nested(&data, &name)?;
        results.push((format!("{path}::{final_name}"), final_data));
    }
    Ok(results)
}

fn extract_tar_members(
    outer_path: &str,
    data: &[u8],
) -> StreamResult {
    let mut ar = tar::Archive::new(std::io::Cursor::new(data));
    let mut results = Vec::new();
    for entry in ar.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry.path()?.to_string_lossy().to_string();
        let mut member_data = Vec::new();
        entry.read_to_end(&mut member_data)?;
        let (final_data, final_name) = decompress_nested(&member_data, &name)?;
        results.push((format!("{outer_path}::{final_name}"), final_data));
    }
    Ok(results)
}

fn decompress_nested(
    data: &[u8],
    name: &str,
) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
    if name.ends_with(".gz") && data.starts_with(b"\x1f\x8b") {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok((out, strip_gz(name).to_string()))
    } else if name.ends_with(".bz2") && data.starts_with(b"BZh") {
        let mut decoder = bzip2::read::BzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok((out, strip_bz2(name).to_string()))
    } else {
        Ok((data.to_vec(), name.to_string()))
    }
}

fn looks_like_tar(data: &[u8]) -> bool {
    // tar magic at byte 257: "ustar"
    data.len() >= 512 && data[257..].starts_with(b"ustar")
}

fn strip_gz(s: &str) -> &str {
    s.strip_suffix(".gz").unwrap_or(s)
}

fn strip_bz2(s: &str) -> &str {
    s.strip_suffix(".bz2").unwrap_or(s)
}

// ─── record_matches ───────────────────────────────────────────────────────────

/// Case-insensitive filter: check orig, rcpt, any_, types against Config.
pub fn record_matches(orig: &str, rcpt: &str, rtype: &str, cfg: &Config) -> bool {
    if let Some(ps) = &cfg.orig {
        if !field_matches(&orig.to_lowercase(), &ps.lower_patterns(), cfg.match_mode) {
            return false;
        }
    }
    if let Some(ps) = &cfg.rcpt {
        if !field_matches(&rcpt.to_lowercase(), &ps.lower_patterns(), cfg.match_mode) {
            return false;
        }
    }
    if let Some(ps) = &cfg.any_ {
        let lps = ps.lower_patterns();
        if !field_matches(&orig.to_lowercase(), &lps, cfg.match_mode)
            && !field_matches(&rcpt.to_lowercase(), &lps, cfg.match_mode)
        {
            return false;
        }
    }
    if !cfg.types.is_empty() && !cfg.types.contains(rtype) {
        return false;
    }
    true
}

fn field_matches(value: &str, patterns: &[String], mode: MatchMode) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|p| match mode {
        MatchMode::Exact => value == p.as_str(),
        MatchMode::Contains => value.contains(p.as_str()),
        MatchMode::Domain => {
            // strip leading '@' from pattern for domain comparison
            let p = p.strip_prefix('@').unwrap_or(p);
            value == p || value.ends_with(&format!("@{p}")) || value.ends_with(&format!(".{p}"))
        }
    })
}

// ─── process_file ─────────────────────────────────────────────────────────────

/// Process a single input file (possibly archive with multiple members).
/// Returns matched rows as `HashMap<String, String>` with `source_file` key.
pub fn process_file(
    path: &str,
    cfg: &Config,
    cols: &[String],
) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
    let streams = iter_log_streams(path, cfg)?;
    let mut results = Vec::new();
    for (source_name, data) in streams {
        if cfg.verbose {
            eprintln!("[INFO] Processing {source_name}");
        }
        process_stream(&source_name, &data, cfg, cols, &mut results);
    }
    Ok(results)
}

fn process_stream(
    source: &str,
    data: &[u8],
    cfg: &Config,
    cols: &[String],
    out: &mut Vec<HashMap<String, String>>,
) {
    // Build fast prefilter byte patterns from all configured patterns
    let prefilter: Vec<Vec<u8>> = prefilter_patterns(cfg);

    for line in data.split(|&b| b == b'\n') {
        let line = trim_end(line);
        if line.is_empty() {
            continue;
        }
        // Fast prefilter: skip lines that can't possibly match
        if !prefilter.is_empty() {
            let lower = line.to_ascii_lowercase();
            if !prefilter.iter().any(|p| memchr::memmem::find(&lower, p).is_some()) {
                continue;
            }
        }
        if let Some(row) = parse_and_match(source, line, cfg, cols) {
            out.push(row);
        }
    }
}

fn parse_and_match(
    source: &str,
    line: &[u8],
    cfg: &Config,
    cols: &[String],
) -> Option<HashMap<String, String>> {
    let (orig, rcpt, rtype, rec): (String, String, String, HashMap<String, String>);

    if line.starts_with(b"{") {
        // JSONL
        let obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(line).ok()?;
        orig = str_val(&obj, "orig");
        rcpt = str_val(&obj, "rcpt");
        rtype = str_val(&obj, "type");
        rec = obj
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    },
                )
            })
            .collect();
    } else {
        // CSV: use col header (skip source_file at index 0)
        let text = std::str::from_utf8(line).ok()?;
        // ponytail: no csv crate here — simple split is enough for flat PMTA logs
        let values: Vec<&str> = text.split(',').collect();
        let headers = &cols[1..]; // skip source_file
        let mut map: HashMap<String, String> = HashMap::new();
        for (h, v) in headers.iter().zip(values.iter()) {
            map.insert(h.clone(), v.trim().to_string());
        }
        orig = map.get("orig").cloned().unwrap_or_default();
        rcpt = map.get("rcpt").cloned().unwrap_or_default();
        rtype = map.get("type").cloned().unwrap_or_default();
        rec = map;
    }

    if !record_matches(&orig, &rcpt, &rtype, cfg) {
        return None;
    }

    let mut row: HashMap<String, String> = HashMap::new();
    row.insert("source_file".to_string(), source.to_string());
    for col in cols.iter().skip(1) {
        row.insert(col.clone(), rec.get(col).cloned().unwrap_or_default());
    }
    Some(row)
}

fn str_val(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn trim_end(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\r' || line[end - 1] == b'\n') {
        end -= 1;
    }
    &line[..end]
}

fn prefilter_patterns(cfg: &Config) -> Vec<Vec<u8>> {
    let mut set = std::collections::HashSet::new();
    for ps in [&cfg.orig, &cfg.rcpt, &cfg.any_].into_iter().flatten() {
        for p in &ps.patterns {
            let lower = p.to_lowercase();
            if !lower.is_empty() {
                set.insert(lower.into_bytes());
            }
        }
    }
    set.into_iter().collect()
}

// ─── run_selftest ─────────────────────────────────────────────────────────────

/// Run built-in self-test with generated fixtures.
pub fn run_selftest() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;

    eprintln!("[INFO] Self-test mode");

    let dir = tempfile::tempdir()?;
    let base = dir.path();

    let csv_data = b"orig,rcpt,type,time,vmta\n\
alice@example.com,user1@hdfclife.com,d,2026-01-01T00:00:00,vmta1\n\
alice@example.com,user2@hdfclife.com,b,2026-01-01T00:00:01,vmta1\n\
bob@other.com,user1@hdfclife.com,d,2026-01-01T00:00:02,vmta2\n\
charlie@test.com,user4@other.com,d,2026-01-01T00:00:04,vmta3\n";

    // Plain CSV
    let plain = base.join("acct.csv");
    std::fs::write(&plain, csv_data)?;

    // Gzip CSV
    let gz = base.join("acct.csv.gz");
    {
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&gz)?,
            flate2::Compression::default(),
        );
        enc.write_all(csv_data)?;
    }

    // tar.gz with two members
    let tgz = base.join("logs.tar.gz");
    {
        let gz_f = flate2::write::GzEncoder::new(
            std::fs::File::create(&tgz)?,
            flate2::Compression::default(),
        );
        let mut ar = tar::Builder::new(gz_f);
        for name in &["a.csv", "b.csv"] {
            let mut header = tar::Header::new_gnu();
            header.set_size(csv_data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            ar.append_data(&mut header, name, csv_data.as_ref())?;
        }
        ar.finish()?;
    }

    let cols = vec![
        "source_file".to_string(),
        "orig".to_string(),
        "rcpt".to_string(),
        "type".to_string(),
        "time".to_string(),
        "vmta".to_string(),
    ];

    // Test 1: plain CSV, filter orig=alice
    {
        let cfg = Config {
            path: plain.to_string_lossy().to_string(),
            orig: Some(PatternSet {
                patterns: vec!["alice@example.com".to_string()],
            }),
            rcpt: None,
            any_: None,
            match_mode: MatchMode::Contains,
            types: HashSet::new(),
            fields: None,
            out: "-".to_string(),
            workers: 1,
            verbose: false,
        };
        let rows = process_file(&cfg.path, &cfg, &cols)?;
        assert_eq!(rows.len(), 2, "test1: expected 2 alice rows, got {}", rows.len());
        eprintln!("[INFO] test1 passed: plain CSV orig filter ({} rows)", rows.len());
    }

    // Test 2: gzip CSV, domain match hdfclife.com
    {
        let cfg = Config {
            path: gz.to_string_lossy().to_string(),
            orig: None,
            rcpt: Some(PatternSet {
                patterns: vec!["hdfclife.com".to_string()],
            }),
            any_: None,
            match_mode: MatchMode::Domain,
            types: HashSet::new(),
            fields: None,
            out: "-".to_string(),
            workers: 1,
            verbose: false,
        };
        let rows = process_file(&cfg.path, &cfg, &cols)?;
        assert_eq!(rows.len(), 3, "test2: expected 3 hdfclife rows, got {}", rows.len());
        eprintln!("[INFO] test2 passed: gzip domain filter ({} rows)", rows.len());
    }

    // Test 3: tar.gz, --any filter for hdfclife.com, type=d only
    {
        let mut types = HashSet::new();
        types.insert("d".to_string());
        let cfg = Config {
            path: tgz.to_string_lossy().to_string(),
            orig: None,
            rcpt: None,
            any_: Some(PatternSet {
                patterns: vec!["hdfclife.com".to_string()],
            }),
            match_mode: MatchMode::Domain,
            types,
            fields: None,
            out: "-".to_string(),
            workers: 1,
            verbose: false,
        };
        let rows = process_file(&cfg.path, &cfg, &cols)?;
        // 2 members × 2 hdfclife type=d rows each = 4
        assert_eq!(rows.len(), 4, "test3: expected 4 rows (2 members × 2), got {}", rows.len());
        eprintln!("[INFO] test3 passed: tar.gz --any + type filter ({} rows)", rows.len());
    }

    // Test 4: exact match
    {
        let cfg = Config {
            path: plain.to_string_lossy().to_string(),
            orig: Some(PatternSet {
                patterns: vec!["alice@example.com".to_string()],
            }),
            rcpt: None,
            any_: None,
            match_mode: MatchMode::Exact,
            types: HashSet::new(),
            fields: None,
            out: "-".to_string(),
            workers: 1,
            verbose: false,
        };
        let rows = process_file(&cfg.path, &cfg, &cols)?;
        assert_eq!(rows.len(), 2, "test4: expected 2 exact rows, got {}", rows.len());
        eprintln!("[INFO] test4 passed: exact match ({} rows)", rows.len());
    }

    // Test 5: load_patterns @file
    {
        let pat_file = base.join("patterns.txt");
        std::fs::write(&pat_file, "alice@example.com\nbob@other.com\n")?;
        let values = vec![format!("@{}", pat_file.display())];
        let patterns = load_patterns(&values)?;
        assert_eq!(patterns.len(), 2);
        eprintln!("[INFO] test5 passed: @file pattern loading");
    }

    eprintln!("[INFO] All self-tests passed");
    Ok(())
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_gzip() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"\x1f\x8b\x08\x00").unwrap();
        assert_eq!(classify(f.path().to_str().unwrap()), FileKind::Gzip);
    }

    #[test]
    fn classify_bzip2() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"BZh1AY").unwrap();
        assert_eq!(classify(f.path().to_str().unwrap()), FileKind::Bzip2);
    }

    #[test]
    fn classify_plain() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"orig,rcpt,type\n").unwrap();
        assert_eq!(classify(f.path().to_str().unwrap()), FileKind::Plain);
    }

    #[test]
    fn record_matches_contains() {
        let cfg = Config {
            path: "".into(),
            orig: Some(PatternSet { patterns: vec!["alice".to_string()] }),
            rcpt: None,
            any_: None,
            match_mode: MatchMode::Contains,
            types: HashSet::new(),
            fields: None,
            out: "-".into(),
            workers: 1,
            verbose: false,
        };
        assert!(record_matches("alice@example.com", "x@y.com", "d", &cfg));
        assert!(!record_matches("bob@example.com", "x@y.com", "d", &cfg));
    }

    #[test]
    fn record_matches_domain() {
        let cfg = Config {
            path: "".into(),
            orig: None,
            rcpt: Some(PatternSet { patterns: vec!["hdfclife.com".to_string()] }),
            any_: None,
            match_mode: MatchMode::Domain,
            types: HashSet::new(),
            fields: None,
            out: "-".into(),
            workers: 1,
            verbose: false,
        };
        assert!(record_matches("x@x.com", "user@hdfclife.com", "d", &cfg));
        assert!(!record_matches("x@x.com", "user@other.com", "d", &cfg));
    }

    #[test]
    fn record_matches_type_filter() {
        let mut types = HashSet::new();
        types.insert("d".to_string());
        let cfg = Config {
            path: "".into(),
            orig: None,
            rcpt: None,
            any_: None,
            match_mode: MatchMode::Contains,
            types,
            fields: None,
            out: "-".into(),
            workers: 1,
            verbose: false,
        };
        assert!(record_matches("a@b.com", "c@d.com", "d", &cfg));
        assert!(!record_matches("a@b.com", "c@d.com", "b", &cfg));
    }

    #[test]
    fn record_matches_any() {
        let cfg = Config {
            path: "".into(),
            orig: None,
            rcpt: None,
            any_: Some(PatternSet { patterns: vec!["hdfclife.com".to_string()] }),
            match_mode: MatchMode::Domain,
            types: HashSet::new(),
            fields: None,
            out: "-".into(),
            workers: 1,
            verbose: false,
        };
        assert!(record_matches("x@hdfclife.com", "y@other.com", "d", &cfg));
        assert!(record_matches("x@other.com", "y@hdfclife.com", "d", &cfg));
        assert!(!record_matches("x@other.com", "y@other.com", "d", &cfg));
    }

    #[test]
    fn load_patterns_literal() {
        let v = vec!["a@b.com".to_string(), "c@d.com".to_string()];
        let p = load_patterns(&v).unwrap();
        assert_eq!(p, v);
    }

    #[test]
    fn load_patterns_at_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "a@b.com").unwrap();
        writeln!(f, "c@d.com").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let _keep = f;
        let v = vec![format!("@{path}")];
        let p = load_patterns(&v).unwrap();
        assert_eq!(p, vec!["a@b.com", "c@d.com"]);
    }

    #[test]
    fn process_file_plain_csv() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "orig,rcpt,type").unwrap();
        writeln!(f, "alice@example.com,user@hdfclife.com,d").unwrap();
        writeln!(f, "bob@other.com,user@hdfclife.com,d").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let _keep = f;

        let cfg = Config {
            path: path.clone(),
            orig: Some(PatternSet { patterns: vec!["alice".to_string()] }),
            rcpt: None,
            any_: None,
            match_mode: MatchMode::Contains,
            types: HashSet::new(),
            fields: None,
            out: "-".into(),
            workers: 1,
            verbose: false,
        };
        let cols = vec!["source_file".to_string(), "orig".to_string(), "rcpt".to_string(), "type".to_string()];
        let rows = process_file(&path, &cfg, &cols).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("orig").unwrap(), "alice@example.com");
    }
}
