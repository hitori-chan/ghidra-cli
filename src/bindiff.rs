//! BinDiff (google/bindiff) integration for `gd diff programs`.
//!
//! Pipeline: the bridge exports both programs to `.BinExport` (loading the
//! plain `BinExport.jar` at runtime), this module runs the **native**
//! `bindiff` differ on the two exports and parses the resulting `.BinDiff`
//! SQLite database. No Python, no GUI, no extra runtime dependencies — the
//! only external pieces are the BinDiff release binary and the exporter jar,
//! both configured explicitly.

use crate::config::BindiffConfig;
use crate::error::{GhidraError, Result};
use std::path::{Path, PathBuf};

/// Candidate binary names for the native differ (the python-bindiff package
/// accepts the same set; the BinDiff release ships `bindiff`).
const DIFFER_NAMES: &[&str] = &["bindiff", "differ"];

/// Locate the native BinDiff differ binary.
///
/// Search order: explicit `bindiff.differ` config (must exist — a
/// misconfigured path is an error, not a silent fallback), `$BINDIFF_PATH`
/// (a directory, python-bindiff convention), the BinDiff release install
/// layout `/opt/bindiff/bin`, then `bindiff`/`differ` on `PATH`.
pub fn find_differ(cfg: Option<&BindiffConfig>) -> Result<PathBuf> {
    if let Some(p) = cfg.and_then(|c| c.differ.as_ref()) {
        if p.is_file() {
            return Ok(p.clone());
        }
        return Err(GhidraError::ConfigError(format!(
            "configured BinDiff differ not found: {} (fix bindiff.differ in the ghidra-cli config)",
            p.display()
        )));
    }
    if let Ok(dir) = std::env::var("BINDIFF_PATH") {
        for name in DIFFER_NAMES {
            let p = Path::new(&dir).join(name);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    for name in DIFFER_NAMES {
        let p = Path::new("/opt/bindiff/bin").join(name);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(paths) = std::env::var("PATH") {
        for dir in paths.split(':') {
            if dir.is_empty() {
                continue;
            }
            for name in DIFFER_NAMES {
                let p = Path::new(dir).join(name);
                if p.is_file() {
                    return Ok(p);
                }
            }
        }
    }
    Err(GhidraError::ConfigError(
        "BinDiff differ binary not found (looked for bindiff.differ config, $BINDIFF_PATH, \
         /opt/bindiff/bin, and 'bindiff'/'differ' on PATH). Install BinDiff from \
         https://github.com/google/bindiff releases and/or set bindiff.differ."
            .to_string(),
    ))
}

/// One matched function pair from the `function` table of a `.BinDiff`
/// database. `address2`/`name2` are `None` when the primary function has no
/// counterpart (the differ records such rows with NULLs).
#[derive(Debug, Clone, PartialEq)]
pub struct MatchRow {
    pub address1: u64,
    pub name1: String,
    pub address2: Option<u64>,
    pub name2: Option<String>,
    /// 0.0..=1.0; exactly 1.0 means byte-identical structure.
    pub similarity: f64,
    pub confidence: f64,
}

/// Parsed contents of a `.BinDiff` database.
#[derive(Debug, Clone, Default)]
pub struct BinDiffData {
    /// Whole-program similarity/confidence from the `metadata` table.
    pub metadata_similarity: Option<f64>,
    pub metadata_confidence: Option<f64>,
    /// Matched function pairs, sorted by similarity ascending (the changed
    /// head first — what an analyst wants to see under a row cap).
    pub matches: Vec<MatchRow>,
}

/// Parse a `.BinDiff` database (BinDiff writes SQLite; only the `metadata`
/// and `function` tables are needed — basic blocks and instructions stay on
/// disk for `bdf.py func`-style drill-downs).
pub fn parse_bin_diff(path: &Path) -> Result<BinDiffData> {
    let conn = rusqlite::Connection::open(path).map_err(|e| {
        GhidraError::ConfigError(format!(
            "failed to open BinDiff database {}: {}",
            path.display(),
            e
        ))
    })?;

    let mut data = BinDiffData::default();

    if let Ok((sim, conf)) =
        conn.query_row("SELECT similarity, confidence FROM metadata", [], |r| {
            let s: Option<f64> = r.get(0)?;
            let c: Option<f64> = r.get(1)?;
            Ok((s, c))
        })
    {
        data.metadata_similarity = sim;
        data.metadata_confidence = conf;
    }

    let mut stmt = conn
        .prepare("SELECT address1, name1, address2, name2, similarity, confidence FROM function")
        .map_err(|e| {
            GhidraError::ConfigError(format!(
                "failed to query BinDiff function table in {}: {} \
                 (is this a .BinDiff database written by the BinDiff differ?)",
                path.display(),
                e
            ))
        })?;
    let rows = stmt
        .query_map([], |r| {
            Ok(MatchRow {
                address1: r.get::<_, i64>(0)? as u64,
                name1: r.get(1)?,
                address2: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                name2: r.get(3)?,
                similarity: r.get(4)?,
                confidence: r.get(5)?,
            })
        })
        .map_err(|e| GhidraError::ConfigError(format!("failed to read BinDiff rows: {}", e)))?;
    let mut matches: Vec<MatchRow> = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| GhidraError::ConfigError(format!("failed to read BinDiff rows: {}", e)))?;
    // Changed (lowest similarity) first.
    matches.sort_by(|a, b| {
        a.similarity
            .partial_cmp(&b.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    data.matches = matches;
    Ok(data)
}

/// Run the native differ on two `.BinExport` files and return the path of
/// the produced `.BinDiff` database inside `out_dir`. The differ's stderr is
/// captured and appended to the error on failure (its log lines are the only
/// diagnostic it produces).
pub fn run_differ(
    differ: &Path,
    primary: &Path,
    secondary: &Path,
    out_dir: &Path,
) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let output = std::process::Command::new(differ)
        .arg(format!("--primary={}", primary.display()))
        .arg(format!("--secondary={}", secondary.display()))
        .arg(format!("--output_dir={}", out_dir.display()))
        .output()
        .map_err(|e| {
            GhidraError::ConfigError(format!(
                "failed to run BinDiff differ {}: {}",
                differ.display(),
                e
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GhidraError::ConfigError(format!(
            "BinDiff differ failed ({}): {}",
            output.status,
            stderr.trim()
        )));
    }
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(out_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|e| e.to_str()) == Some("BinDiff") {
            found.push(entry.path());
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [..] if found.is_empty() => Err(GhidraError::ConfigError(
            "BinDiff differ produced no .BinDiff file".to_string(),
        )),
        _ => Err(GhidraError::ConfigError(format!(
            "BinDiff differ produced multiple .BinDiff files in {}: {:?}",
            out_dir.display(),
            found
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One function row of the test database: (address1, name1, (address2,
    /// name2) of the match or None, similarity, confidence).
    type Row = (u64, &'static str, Option<(u64, &'static str)>, f64, f64);

    /// Build a minimal .BinDiff-shaped database (the schema the BinDiff
    /// differ writes) and return its path.
    fn make_db(dir: &Path, rows: &[Row]) -> PathBuf {
        let path = dir.join("test.BinDiff");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE file (id INTEGER PRIMARY KEY, filename TEXT, exefilename TEXT, \
             hash CHARACTER(40), functions INT, libfunctions INT, calls INT, basicblocks INT, \
             libbasicblocks INT, edges INT, libedges INT, instructions INT, libinstructions INT); \
             CREATE TABLE metadata (version TEXT, file1 INTEGER, file2 INTEGER, description TEXT, \
             created DATE, modified DATE, similarity DOUBLE PRECISION, confidence DOUBLE PRECISION); \
             CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, \
             address2 BIGINT, name2 TEXT, similarity DOUBLE PRECISION, confidence DOUBLE PRECISION, \
             flags INTEGER, algorithm SMALLINT, evaluate BOOLEAN, commentsported BOOLEAN, \
             basicblocks INTEGER, edges INTEGER, instructions INTEGER, UNIQUE(address1, address2));",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO metadata (version, file1, file2, description, created, modified, similarity, confidence) \
             VALUES ('8', 1, 2, '', 'now', 'now', 0.912, 0.876)",
            [],
        )
        .unwrap();
        for (i, (a1, n1, m2, sim, conf)) in rows.iter().enumerate() {
            conn.execute(
                "INSERT INTO function (id, address1, name1, address2, name2, similarity, confidence, \
                 flags, algorithm, evaluate, commentsported, basicblocks, edges, instructions) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, 1, 1, 1, 1, 1)",
                rusqlite::params![
                    i as i64,
                    *a1 as i64,
                    *n1,
                    m2.map(|m| m.0 as i64),
                    m2.map(|m| m.1),
                    *sim,
                    *conf,
                ],
            )
            .unwrap();
        }
        path
    }

    #[test]
    fn parse_reads_metadata_and_matches_sorted_by_similarity() {
        let dir = std::env::temp_dir().join(format!("bindiff-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = make_db(
            &dir,
            &[
                (0x1000, "main", Some((0x2000, "main")), 0.5, 0.4),
                (0x1040, "ident_fn", Some((0x2040, "ident_fn")), 1.0, 1.0),
                (0x1080, "orphan", None, 0.0, 0.0),
            ],
        );
        let data = parse_bin_diff(&path).unwrap();
        assert_eq!(data.metadata_similarity, Some(0.912));
        assert_eq!(data.metadata_confidence, Some(0.876));
        assert_eq!(data.matches.len(), 3);
        // Sorted similarity-ascending: the changed function first.
        assert_eq!(data.matches[0].name1, "orphan");
        assert_eq!(data.matches[1].name1, "main");
        assert_eq!(data.matches[2].name1, "ident_fn");
        assert_eq!(data.matches[2].address2, Some(0x2040));
        assert_eq!(data.matches[0].address2, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_differ_uses_configured_path() {
        let dir = std::env::temp_dir().join(format!("bindiff-diff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("bindiff");
        std::fs::write(&fake, b"").unwrap();
        let cfg = BindiffConfig {
            differ: Some(fake.clone()),
            binexport_jar: None,
        };
        assert_eq!(find_differ(Some(&cfg)).unwrap(), fake);
        // A configured-but-missing path is an error, not a silent fallback.
        let cfg = BindiffConfig {
            differ: Some(dir.join("nope")),
            binexport_jar: None,
        };
        assert!(find_differ(Some(&cfg)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
