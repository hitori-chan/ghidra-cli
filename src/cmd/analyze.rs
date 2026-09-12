//! Import & analyze bridge commands (split from
//! `run_with_bridge`/`execute_via_bridge` in main.rs).

use anyhow::Context;
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
        //
        // The one-shot names the program after the binary's file name and has
        // no rename option, and a program file created by a previous JVM
        // session cannot be renamed from a later one (the local project store
        // holds it "in use"), so --program is honored by staging the binary
        // under the requested name BEFORE the import: hard link when possible,
        // copy otherwise. The staged file is removed after the import reads it.
        let bin_file_name = binary_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let (staged_path, staged) = match args.program.as_deref() {
            Some(p) if !p.is_empty() && p != bin_file_name => {
                let staging_dir = std::env::temp_dir()
                    .join(format!("gd-import-stage-{}", std::process::id()));
                std::fs::create_dir_all(&staging_dir)
                    .with_context(|| format!("Failed to create staging dir {}", staging_dir.display()))?;
                let staged = staging_dir.join(p);
                if staged.exists() {
                    std::fs::remove_file(&staged).ok();
                }
                if std::fs::hard_link(binary_path, &staged).is_err() {
                    std::fs::copy(binary_path, &staged)
                        .with_context(|| format!("Failed to stage binary at {}", staged.display()))?;
                }
                (staged.clone(), true)
            }
            _ => (binary_path.to_path_buf(), false),
        };
        let file_name = bridge::import_oneshot(project_path, &staged_path, ghidra_install_dir)?;
        if staged {
            // The import has read the staged file; drop it (and the dir).
            let _ = std::fs::remove_file(&staged_path);
            let _ = std::fs::remove_dir_all(staged_path.parent().unwrap_or(std::path::Path::new("")));
        }
        if !quiet {
            eprintln!("Starting Ghidra bridge...");
        }
        let port = bridge::ensure_bridge_running(
            project_path,
            ghidra_install_dir,
            BridgeStartMode::Process {
                program_name: file_name.clone(),
            },
        )?;
        let client = BridgeClient::new(port);
        client.open_program(&file_name)?;
        (client, file_name)
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
