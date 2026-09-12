//! Script & batch bridge commands (extracted from execute_via_bridge, P1).

use crate::cli;
use crate::cli::Cli;
use crate::cli::Commands;
use crate::ipc::client::BridgeClient;
use clap::Parser;
use serde_json::json;

/// Parse a `--expect` spec (`PATH` or `PATH:MIN_ROWS`) into the wire form
/// `{path, min_rows?}`. The path is made absolute against the *client's* CWD so
/// the bridge validates the same file the script wrote, regardless of the CWD
/// the bridge JVM inherited. A trailing `:<digits>` is treated as MIN_ROWS;
/// anything else (e.g. a Windows drive letter) stays part of the path.
fn parse_expect_spec(spec: &str) -> serde_json::Value {
    let (path_part, min_rows) = match spec.rsplit_once(':') {
        Some((p, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            (p, n.parse::<u64>().ok())
        }
        _ => (spec, None),
    };
    let abs = std::path::absolute(path_part)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path_part.to_string());
    let mut obj = serde_json::Map::new();
    obj.insert("path".to_string(), serde_json::Value::String(abs));
    if let Some(n) = min_rows {
        obj.insert("min_rows".to_string(), serde_json::json!(n));
    }
    serde_json::Value::Object(obj)
}

/// Parse and execute one batch line, collecting its error per-line.
fn run_batch_line(
    client: &BridgeClient,
    ctx: &super::ExecCtx,
    words: &[&str],
) -> anyhow::Result<serde_json::Value> {
    let sub_cli = Cli::try_parse_from(words).map_err(|e| anyhow::anyhow!("{}", e))?;
    // Each line gets its own query plan; a malformed --filter fails that
    // line only, matching the pre-plan behavior of per-line error collection.
    let sub_ctx = super::ExecCtx::for_command(
        true,
        ctx.default_limit,
        &sub_cli.command,
        ctx.bindiff.clone(),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    super::execute(client, &sub_cli.command, &sub_ctx)
}

pub fn run(
    client: &BridgeClient,
    command: &Commands,
    ctx: &super::ExecCtx,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Commands::Script(cmd) => {
            use cli::ScriptCommands;
            match cmd {
                ScriptCommands::Run(args) => {
                    // Canonicalize client-side so the bridge receives an absolute
                    // path independent of the working directory its JVM inherited.
                    // Fall back to the raw path if the file is missing; the bridge
                    // then reports a clear "Script not found".
                    let path = std::fs::canonicalize(&args.script_path)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| args.script_path.clone());
                    let expect: Vec<serde_json::Value> =
                        args.expect.iter().map(|s| parse_expect_spec(s)).collect();
                    client.script_run(&path, &args.args, &expect, args.allow_empty)
                }
                ScriptCommands::Python(args) => client.script_python(&args.code),
                ScriptCommands::Java(args) => client.script_java(&args.code),
                ScriptCommands::List => client.script_list(),
            }
        }

        Commands::Batch(args) => {
            // Read batch file and execute each command locally
            let content = std::fs::read_to_string(&args.script_file)
                .map_err(|e| anyhow::anyhow!("Failed to read batch file: {}", e))?;
            let lines: Vec<&str> = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .collect();

            let mut results = Vec::new();
            for line in &lines {
                let words: Vec<&str> = std::iter::once("ghidra")
                    .chain(line.split_whitespace())
                    .collect();
                let sub_result = run_batch_line(client, ctx, &words);
                match sub_result {
                    Ok(val) => results.push(json!({"command": line.trim(), "result": val})),
                    Err(e) => results.push(json!({"command": line.trim(), "error": e.to_string()})),
                }
            }

            Ok(json!({
                "commands_parsed": lines.len(),
                "results": results
            }))
        }

        _ => anyhow::bail!("Command not supported"),
    }
}
