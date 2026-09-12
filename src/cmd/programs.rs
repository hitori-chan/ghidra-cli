//! Program/memory/diff bridge commands (extracted from execute_via_bridge, P1).

use crate::cli;
use crate::cli::Commands;
use crate::ipc::client::BridgeClient;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub fn run(
    client: &BridgeClient,
    command: &Commands,
    ctx: &super::ExecCtx,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Commands::Raw(args) => {
            let payload: serde_json::Value = serde_json::from_str(&args.json_args)
                .map_err(|e| anyhow::anyhow!("Invalid JSON args for raw command: {}", e))?;
            if !payload.is_object() {
                anyhow::bail!("raw command args must be a JSON object, got {}", payload);
            }
            // Escape hatch for arbitrary (possibly slow) bridge commands —
            // do not impose the default read timeout.
            client.send_command_with_timeout(&args.command, Some(payload), None)
        }

        Commands::Memory(cmd) => {
            use cli::MemoryCommands;
            match cmd {
                MemoryCommands::Map(_) => client.memory_map(),
                MemoryCommands::Read(args) => client.send_command(
                    "read_memory",
                    Some(json!({
                        "address": args.address,
                        "size": args.size,
                    })),
                ),
                MemoryCommands::Write(args) => client.send_command(
                    "write_memory",
                    Some(json!({
                        "address": args.address,
                        "bytes": args.bytes,
                    })),
                ),
                MemoryCommands::Search(args) => client.send_command(
                    "search_memory",
                    Some(json!({
                        "pattern": args.pattern,
                    })),
                ),
            }
        }

        Commands::Program(cmd) => {
            use cli::ProgramCommands;
            match cmd {
                ProgramCommands::List(_) => client.list_programs(),
                ProgramCommands::Open(args) => {
                    let program = args.program.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Program name required. Use --program <name>")
                    })?;
                    client.open_program(program)
                }
                ProgramCommands::Close(_) => client.program_close(),
                ProgramCommands::Delete(args) => {
                    let program = args
                        .program
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Program name required"))?;
                    client.program_delete(program)
                }
                ProgramCommands::Info(_) => client.program_info(),
                ProgramCommands::Export(args) => {
                    client.program_export(&args.format, args.output.as_deref())
                }
            }
        }

        Commands::Diff(cmd) => {
            use cli::DiffCommands;
            match cmd {
                DiffCommands::Programs(args) => run_diff_programs(client, ctx, args),
                DiffCommands::Functions(args) => client.diff_functions(&args.func1, &args.func2),
            }
        }

        _ => anyhow::bail!("Command not supported"),
    }
}

/// Ghidra-style address strings are hex without a prefix ("00101040");
/// the .BinDiff database stores raw integers. Parse both forms the bridge
/// might send (tolerate an optional 0x prefix).
fn parse_ghidra_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// binDiff's doubles carry ~16 significant digits of noise; three decimals
/// (0.984) is what an analyst can act on and keeps rows compact.
fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Parsed address -> native address string, from a bridge function list
/// (JsonArray of {address, name} or JsonNull). Lets the rows keep the
/// program's own address rendering (e.g. "00101040") instead of the DB's
/// raw integers.
fn prep_addr_map(prep: &Value, key: &str) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    if let Some(arr) = prep.get(key).and_then(|v| v.as_array()) {
        for f in arr {
            if let Some(s) = f.get("address").and_then(|v| v.as_str()) {
                if let Some(a) = parse_ghidra_addr(s) {
                    map.insert(a, s.to_string());
                }
            }
        }
    }
    map
}

/// `gd diff programs`: bridge exports both programs to .BinExport, the
/// native google/bindiff differ matches functions across layouts, the
/// .BinDiff SQLite DB is parsed here. Client-side shaping (changed/min_sim/
/// name/unmatched/limit) happens on the parsed rows — the differ itself
/// always runs to completion.
fn run_diff_programs(
    client: &BridgeClient,
    ctx: &super::ExecCtx,
    args: &cli::DiffProgramsArgs,
) -> anyhow::Result<Value> {
    use crate::bindiff;
    use std::path::Path;

    let prog2 = args
        .program2
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("program2 is required: gd diff programs [PROG1] PROG2"))?;

    let cfg = ctx.bindiff.as_ref();
    let jar = cfg
        .and_then(|c| c.binexport_jar.as_ref())
        .ok_or_else(|| {
            anyhow::anyhow!("BinDiff is not configured: set `bindiff.binexport_jar` in the ghidra-cli config to the plain (non-OSGi) BinExport.jar (the same jar used by ExportBE.java-style scripts). The native differ is located via `bindiff.differ`, $BINDIFF_PATH, /opt/bindiff/bin, or PATH.")
        })?;

    // 1. Bridge: open (if needed) + export both programs, then release them.
    let prep = client
        .diff_programs(args.program1.as_deref(), prog2, &jar.to_string_lossy())
        .map_err(|e| anyhow::anyhow!("BinDiff export failed: {}", e))?;
    if prep.get("status").and_then(|s| s.as_str()) != Some("ok") {
        let msg = prep
            .get("error")
            .or_else(|| prep.get("message"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        // A pre-BinDiff bridge answers with the old stub/stats payload:
        // hint at the one-time restart that picks up the new script.
        let hint = if prep.get("export1").is_none() {
            " If the message looks unrelated to BinExport, the bridge is running an older script — run `gd restart` and retry."
        } else {
            ""
        };
        anyhow::bail!("BinDiff export failed: {}{}", msg, hint);
    }
    let export1 = prep
        .get("export1")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("bridge response missing export1"))?;
    let export2 = prep
        .get("export2")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("bridge response missing export2"))?;

    // 2. Native differ: .BinExport pair -> .BinDiff SQLite DB.
    let differ = bindiff::find_differ(cfg).map_err(|e| anyhow::anyhow!("{}", e))?;
    let workdir = std::env::temp_dir().join(format!(
        "gd-bindiff-run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let db = bindiff::run_differ(&differ, Path::new(export1), Path::new(export2), &workdir)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let data = bindiff::parse_bin_diff(&db).map_err(|e| anyhow::anyhow!("{}", e))?;

    // 3. Unmatched functions: the bridge's function lists minus the matched
    //    pairs (the DB only stores pairs). Lists are JsonNull when a
    //    program exceeded the bridge's cap -> "not computed".
    let matched_p: HashSet<u64> = data
        .matches
        .iter()
        .filter(|m| m.address2.is_some())
        .map(|m| m.address1)
        .collect();
    let matched_s: HashSet<u64> = data.matches.iter().filter_map(|m| m.address2).collect();
    let unmatched_of = |key: &str, matched: &HashSet<u64>| -> Vec<(String, String)> {
        prep.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        let addr = f.get("address")?.as_str()?.to_string();
                        let name = f
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        match parse_ghidra_addr(&addr) {
                            Some(a) if matched.contains(&a) => None,
                            _ => Some((addr, name)),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let unmatched_p = unmatched_of("functions1", &matched_p);
    let unmatched_s = unmatched_of("functions2", &matched_s);
    let unmatched_computed = prep.get("functions1").and_then(|v| v.as_array()).is_some()
        && prep.get("functions2").and_then(|v| v.as_array()).is_some();

    // Native address formatting for the DB's integer addresses (fall back
    // to plain hex when a program's function list was not computable).
    let fmt_p = prep_addr_map(&prep, "functions1");
    let fmt_s = prep_addr_map(&prep, "functions2");
    let fmt_addr = |m: &HashMap<u64, String>, a: u64| -> String {
        m.get(&a).cloned().unwrap_or_else(|| format!("{:08x}", a))
    };

    // 4. Rows (flat: one row per matched pair or unmatched function).
    // Matched pairs come first, similarity-ascending (the changed head).
    let mut rows: Vec<Value> = data
        .matches
        .iter()
        .filter(|m| !(args.changed && m.similarity >= 1.0))
        .filter(|m| args.min_sim.is_none_or(|min| m.similarity >= min))
        .filter(|m| {
            args.name.as_deref().is_none_or(|nf| {
                format!("{} {}", m.name1, m.name2.as_deref().unwrap_or(""))
                    .to_lowercase()
                    .contains(&nf.to_lowercase())
            })
        })
        .map(|m| {
            json!({
                "name1": m.name1,
                "address1": fmt_addr(&fmt_p, m.address1),
                "name2": m.name2,
                "address2": m.address2.map(|a| fmt_addr(&fmt_s, a)),
                "similarity": round3(m.similarity),
                "confidence": round3(m.confidence),
            })
        })
        .collect();
    if args.unmatched {
        // Unmatched rows (code present in only one version) are the
        // highest-information rows — prepend them so a --limit always
        // shows them instead of truncating them behind the matches.
        let mut unmatched_rows: Vec<Value> = Vec::new();
        for (addr, name) in &unmatched_p {
            unmatched_rows.push(json!({
                "name1": name, "address1": addr,
                "name2": Value::Null, "address2": Value::Null,
                "similarity": Value::Null, "confidence": Value::Null,
                "unmatched": "primary",
            }));
        }
        for (addr, name) in &unmatched_s {
            unmatched_rows.push(json!({
                "name1": Value::Null, "address1": Value::Null,
                "name2": name, "address2": addr,
                "similarity": Value::Null, "confidence": Value::Null,
                "unmatched": "secondary",
            }));
        }
        unmatched_rows.append(&mut rows);
        rows = unmatched_rows;
    }

    // 5. Summary + cap + final envelope.
    let matched = data.matches.iter().filter(|m| m.address2.is_some()).count();
    let identical = data
        .matches
        .iter()
        .filter(|m| m.address2.is_some() && (m.similarity - 1.0).abs() < 1e-9)
        .count();
    let changed = matched - identical;
    let cap = args.limit.or(ctx.default_limit);
    let truncated = cap.filter(|&c| c != 0).is_some_and(|c| rows.len() > c);
    if let Some(c) = cap.filter(|&c| c != 0) {
        rows.truncate(c);
    }
    let result = json!({
        "status": "ok",
        "method": "bindiff",
        "program1": prep.get("program1").cloned().unwrap_or(Value::Null),
        "program2": prep.get("program2").cloned().unwrap_or(Value::Null),
        "summary": json!({
            "matched": matched,
            "identical": identical,
            "changed": changed,
            "unmatched_primary": unmatched_p.len(),
            "unmatched_secondary": unmatched_s.len(),
            "unmatched_computed": unmatched_computed,
            "overall_similarity": data.metadata_similarity.map(round3),
            "overall_confidence": data.metadata_confidence.map(round3),
        }),
        "matches": rows,
        "truncated": truncated,
    });

    // 6. Scratch cleanup (the exports live in the bridge's temp dir; the DB
    //    and differ output in ours).
    let _ = std::fs::remove_file(export1);
    let _ = std::fs::remove_file(export2);
    let _ = std::fs::remove_dir_all(&workdir);

    Ok(result)
}
