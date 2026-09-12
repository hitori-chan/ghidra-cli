//! Import & analyze bridge commands (docs/history/refactor-plan.md P1: split from
//! `run_with_bridge`/`execute_via_bridge` in main.rs).

use crate::cli::Commands;
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ghidra::project_has_program_data;
use crate::ipc::client::BridgeClient;
use serde_json::json;
use std::path::Path;

/// `gd analyze`: run full analysis as an unbounded bridge operation.
pub fn analyze(client: &BridgeClient, quiet: bool) -> anyhow::Result<serde_json::Value> {
    if !quiet {
        eprintln!("Analyzing...");
    }
    let result = client.analyze()?;
    if !quiet {
        eprintln!("Analysis complete!");
    }
    Ok(json!({
        "command": "analyze",
        "status": "success",
        "data": result
    }))
}

/// `gd import`: acquire a bridge connection for the project, import the
/// binary, and run analysis (unless `--no-analyze`).
///
/// Returns the command result envelope; the bridge client is owned here and
/// dropped when the import completes (analysis is driven over TCP, so the
/// program persists via `handleAnalyze`'s `program.save()` without relying on
/// a clean bridge shutdown).
pub fn import(
    args: &crate::cli::ImportArgs,
    project_path: &Path,
    ghidra_install_dir: &Path,
    quiet: bool,
) -> anyhow::Result<serde_json::Value> {
    let binary_path = Path::new(&args.binary);
    if !binary_path.exists() {
        anyhow::bail!("Binary not found: {}", args.binary);
    }

    // Acquire a bridge connection and the imported program's name. Three
    // hang-proof cases (see docs/plans/prescript-fix.md §3.3):
    //   1. Bridge already running    -> TCP import into the live project.
    //   2. Project exists, no bridge -> fast launch (Project mode), TCP import.
    //   3. Brand-new project         -> bootstrap via `-import -noanalysis`
    //      (only `-import` can create a project; analysis is skipped at
    //      launch and driven over TCP below).
    // The launch is bounded (the bridge binds its socket before analysis);
    // analysis afterwards runs as an unbounded TCP operation.
    let (client, program_name) = if let Some(port) = bridge::is_bridge_running(project_path) {
        // is_bridge_running() already proved the bridge process is alive
        // and its socket is accepting; a busy bridge just queues this
        // request, so there is no pre-flight ping gate to fail here.
        let client = BridgeClient::new(port);
        if !quiet {
            eprintln!("Importing into running bridge...");
        }
        let result = client.import_binary(&args.binary, args.program.as_deref())?;
        let name = args.program.clone().unwrap_or_else(|| {
            result
                .get("program")
                .and_then(|p| p.as_str())
                .unwrap_or("unknown")
                .to_string()
        });
        client.open_program(&name)?;
        (client, name)
    } else if project_has_program_data(project_path) {
        if !quiet {
            eprintln!("Starting Ghidra bridge...");
        }
        let port = bridge::ensure_bridge_running(
            project_path,
            ghidra_install_dir,
            BridgeStartMode::Project,
        )?;
        let client = BridgeClient::new(port);
        let result = client.import_binary(&args.binary, args.program.as_deref())?;
        let name = args.program.clone().unwrap_or_else(|| {
            result
                .get("program")
                .and_then(|p| p.as_str())
                .unwrap_or("unknown")
                .to_string()
        });
        client.open_program(&name)?;
        (client, name)
    } else {
        if !quiet {
            eprintln!("Initializing project (importing {})...", args.binary);
        }
        // Brand-new or stale empty project: initialize it with a clean, short-lived
        // one-shot import that durably commits the program, then start
        // the persistent bridge in Process mode against the committed
        // program. This replaces the old `-import` bridge bootstrap,
        // whose program persistence depended on HeadlessAnalyzer's
        // post-script teardown commit — a commit `stop` could kill
        // mid-write (the macOS "program file(s) not found" failures).
        let name = bridge::import_oneshot(project_path, binary_path, ghidra_install_dir)?;
        if !quiet {
            eprintln!("Starting Ghidra bridge...");
        }
        let port = bridge::ensure_bridge_running(
            project_path,
            ghidra_install_dir,
            BridgeStartMode::Process {
                program_name: name.clone(),
            },
        )?;
        let client = BridgeClient::new(port);
        client.open_program(&name)?;
        (client, name)
    };

    // Run analysis as an UNBOUNDED operation unless the user opted out.
    // handleAnalyze runs analyzeAll + program.save(), so the program
    // persists without relying on a clean bridge shutdown.
    let analyze_data = if args.no_analyze {
        if !quiet {
            eprintln!("Skipping analysis (--no-analyze).");
        }
        json!(null)
    } else {
        if !quiet {
            eprintln!("Analyzing {}...", program_name);
        }
        let d = client.analyze()?;
        if !quiet {
            eprintln!("Analysis complete!");
        }
        d
    };

    if !quiet {
        eprintln!("Successfully imported as: {}", program_name);
    }
    Ok(json!({
        "command": "import",
        "program": program_name,
        "status": "success",
        "data": { "analyze": analyze_data }
    }))
}

/// Dispatch hook for `gd analyze` (called from `cmd::execute`).
pub fn run(
    client: &BridgeClient,
    command: &Commands,
    ctx: &super::ExecCtx,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Commands::Analyze(_) => analyze(client, ctx.quiet),
        _ => anyhow::bail!("Command not supported"),
    }
}
