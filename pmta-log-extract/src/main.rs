use clap::Parser;
use glob::glob;
use pmta_log_extract::{load_patterns, process_file, run_selftest, Config, MatchMode, PatternSet};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufWriter, Write};

/// Stream-extract PMTA accounting log records by sender/recipient.
///
/// Supported inputs (auto-detected by magic bytes):
///   .tar.gz / .tgz, .tar.bz2 / .tbz2, .zip, .gz, .bz2, plain CSV/JSONL
#[derive(Parser)]
#[command(name = "pmta-log-extract")]
struct Cli {
    /// Input path/glob (supports * and **)
    #[arg(long)]
    path: Option<String>,

    /// Sender pattern(s) or @file (repeatable)
    #[arg(long, action = clap::ArgAction::Append, value_name = "PATTERN")]
    orig: Vec<String>,

    /// Recipient pattern(s) or @file (repeatable)
    #[arg(long, action = clap::ArgAction::Append, value_name = "PATTERN")]
    rcpt: Vec<String>,

    /// Match orig OR rcpt (repeatable)
    #[arg(long = "any", action = clap::ArgAction::Append, value_name = "PATTERN")]
    any_: Vec<String>,

    /// Match mode: exact, contains, domain
    #[arg(long = "match", default_value = "contains", value_parser = ["exact", "contains", "domain"])]
    match_mode: String,

    /// Record type filter (repeatable, e.g. d, b)
    #[arg(long = "type", action = clap::ArgAction::Append, value_name = "TYPE")]
    types: Vec<String>,

    /// Output columns (* for auto-discover, repeatable)
    #[arg(long, action = clap::ArgAction::Append, value_name = "FIELD")]
    fields: Vec<String>,

    /// Output file (- for stdout)
    #[arg(long, default_value = "-")]
    out: String,

    /// Parallel workers
    #[arg(long, default_value_t = 1)]
    workers: usize,

    /// Run self-test and exit
    #[arg(long)]
    selftest: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.selftest {
        match run_selftest() {
            Ok(()) => {
                eprintln!("[INFO] Self-test passed");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("[ERROR] Self-test failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let path = match cli.path {
        Some(p) => p,
        None => {
            eprintln!("[ERROR] --path is required (unless --selftest)");
            std::process::exit(1);
        }
    };

    let orig_ps = build_pattern_set(&cli.orig, "--orig");
    let rcpt_ps = build_pattern_set(&cli.rcpt, "--rcpt");
    let any_ps = build_pattern_set(&cli.any_, "--any");

    let match_mode = match cli.match_mode.as_str() {
        "exact" => MatchMode::Exact,
        "domain" => MatchMode::Domain,
        _ => MatchMode::Contains,
    };

    let types: HashSet<String> = cli.types.into_iter().collect();
    let fields: Option<Vec<String>> = if cli.fields.is_empty() {
        None
    } else {
        Some(cli.fields)
    };

    let cfg = Config {
        path: path.clone(),
        orig: orig_ps,
        rcpt: rcpt_ps,
        any_: any_ps,
        match_mode,
        types,
        fields: fields.clone(),
        out: cli.out.clone(),
        workers: cli.workers,
        verbose: cli.verbose,
    };

    // Expand glob (recursive=true for **)
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    match glob(&path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(p) if p.is_file() => paths.push(p),
                    Ok(_) => {}
                    Err(e) => eprintln!("[WARN] Glob entry error: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("[ERROR] Invalid glob pattern '{path}': {e}");
            std::process::exit(1);
        }
    }
    paths.sort();

    if paths.is_empty() {
        eprintln!("[ERROR] No files matched: {path}");
        std::process::exit(1);
    }
    eprintln!("[INFO] Found {} input file(s)", paths.len());

    // Discover output columns from the first matched file
    let cols = discover_columns(&paths[0].to_string_lossy(), &fields);
    if cli.verbose {
        eprintln!("[DEBUG] Columns: {cols:?}");
    }

    // Process files
    let all_rows = collect_rows(&paths, &cfg, &cols, cli.verbose);

    let total = all_rows.len();

    if let Err(e) = write_output(&cfg.out, &cols, &all_rows) {
        eprintln!("[ERROR] Write failed: {e}");
        std::process::exit(1);
    }

    eprintln!(
        "[INFO] Done. Matched {total} record(s) from {} file(s). Output: {}",
        paths.len(),
        cfg.out
    );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn build_pattern_set(values: &[String], flag: &str) -> Option<PatternSet> {
    if values.is_empty() {
        return None;
    }
    match load_patterns(values) {
        Ok(patterns) => Some(PatternSet { patterns }),
        Err(e) => {
            eprintln!("[ERROR] {flag}: {e}");
            std::process::exit(1);
        }
    }
}

/// Discover CSV/JSONL column names from the first non-empty line of a file.
/// For compressed files we fall back to just ["source_file"] — same as Python.
fn discover_columns(first_path: &str, fields: &Option<Vec<String>>) -> Vec<String> {
    // Explicit fields override auto-discovery (unless "*")
    if let Some(f) = fields {
        if f != &["*".to_string()] {
            let mut cols = vec!["source_file".to_string()];
            cols.extend(f.iter().cloned());
            return cols;
        }
        // "*" → fall through to auto-discover
    }

    let mut cols = vec!["source_file".to_string()];
    if let Ok(f) = File::open(first_path) {
        if let Some(line) = first_nonempty_line(f) {
            if line.starts_with(b"{") {
                if let Ok(obj) =
                    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&line)
                {
                    let mut keys: Vec<String> = obj
                        .keys()
                        .filter(|k| *k != "source_file")
                        .cloned()
                        .collect();
                    keys.sort();
                    cols.extend(keys);
                }
            } else {
                // CSV header row
                let s = String::from_utf8_lossy(&line);
                let headers: Vec<String> = s
                    .trim()
                    .split(',')
                    .map(|h| h.trim().to_string())
                    .filter(|h| !h.is_empty() && h != "source_file")
                    .collect();
                cols.extend(headers);
            }
        }
    }
    cols
}

fn first_nonempty_line(f: File) -> Option<Vec<u8>> {
    let mut reader = std::io::BufReader::new(f);
    for _ in 0..5 {
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                // strip \r\n
                while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
                    line.pop();
                }
                if !line.is_empty() {
                    return Some(line);
                }
            }
        }
    }
    None
}

fn collect_rows(
    paths: &[std::path::PathBuf],
    cfg: &Config,
    cols: &[String],
    verbose: bool,
) -> Vec<HashMap<String, String>> {
    if cfg.workers > 1 {
        use rayon::prelude::*;
        rayon::ThreadPoolBuilder::new()
            .num_threads(cfg.workers)
            .build_global()
            .ok();
        paths
            .par_iter()
            .flat_map(|p| {
                let s = p.to_string_lossy().to_string();
                if verbose {
                    eprintln!("[INFO] Processing {s}");
                }
                match process_file(&s, cfg, cols) {
                    Ok(rows) => rows,
                    Err(e) => {
                        eprintln!("[WARN] Failed {s}: {e}");
                        vec![]
                    }
                }
            })
            .collect()
    } else {
        let mut out = Vec::new();
        for p in paths {
            let s = p.to_string_lossy().to_string();
            if verbose {
                eprintln!("[INFO] Processing {s}");
            }
            match process_file(&s, cfg, cols) {
                Ok(rows) => out.extend(rows),
                Err(e) => eprintln!("[WARN] Failed {s}: {e}"),
            }
        }
        out
    }
}

fn write_output(
    out: &str,
    cols: &[String],
    rows: &[HashMap<String, String>],
) -> Result<(), Box<dyn std::error::Error>> {
    if out == "-" {
        let stdout = std::io::stdout();
        write_csv(BufWriter::new(stdout.lock()), cols, rows)
    } else {
        write_csv(BufWriter::new(File::create(out)?), cols, rows)
    }
}

fn write_csv(
    w: impl Write,
    cols: &[String],
    rows: &[HashMap<String, String>],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::WriterBuilder::new().from_writer(w);
    wtr.write_record(cols)?;
    for row in rows {
        let record: Vec<&str> = cols
            .iter()
            .map(|c| row.get(c).map(|s| s.as_str()).unwrap_or(""))
            .collect();
        wtr.write_record(&record)?;
    }
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_nonempty_line_skips_blanks() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "orig,rcpt,type").unwrap();
        let path = f.path().to_owned();
        let _keep = f;
        let file = File::open(&path).unwrap();
        let line = first_nonempty_line(file).unwrap();
        assert_eq!(line, b"orig,rcpt,type");
    }

    #[test]
    fn discover_columns_from_csv_header() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "orig,rcpt,type,time").unwrap();
        writeln!(f, "a@b.com,c@d.com,d,2026-01-01").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let _keep = f;
        let cols = discover_columns(&path, &None);
        assert_eq!(cols[0], "source_file");
        assert!(cols.contains(&"orig".to_string()));
        assert!(cols.contains(&"rcpt".to_string()));
        assert!(cols.contains(&"type".to_string()));
    }

    #[test]
    fn discover_columns_explicit_fields() {
        let cols = discover_columns(
            "/nonexistent",
            &Some(vec!["orig".to_string(), "rcpt".to_string()]),
        );
        assert_eq!(cols, vec!["source_file", "orig", "rcpt"]);
    }

    #[test]
    fn write_csv_roundtrip() {
        let cols = vec!["source_file".to_string(), "orig".to_string()];
        let mut row = HashMap::new();
        row.insert("source_file".to_string(), "f.csv".to_string());
        row.insert("orig".to_string(), "a@b.com".to_string());
        let mut buf = Vec::new();
        write_csv(&mut buf, &cols, &[row]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("source_file,orig"));
        assert!(s.contains("f.csv,a@b.com"));
    }
}
