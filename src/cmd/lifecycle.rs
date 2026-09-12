//! Bridge lifecycle management commands (start/stop/
//! status/ping/jobs/cancel handlers, moved from main.rs).

use crate::cli::Cli;
use crate::cli::Commands;
use crate::ghidra::bridge::{self, BridgeStartMode, BridgeStatus};
use crate::ipc::client::BridgeClient;
use crate::load_config;
use crate::resolve_project_path;
use std::io::IsTerminal;
use std::path::PathBuf;

/// Dispatch bridge management commands.
pub fn handle_bridge_command(cli: Cli) -> anyhow::Result<()> {
    // Global --project/--program flags serve as fallbacks for subcommand-level
    // args, with $GD_PROJECT/$GD_PROGRAM as the next tier down.
    let global_project = cli
        .project
        .clone()
        .or_else(|| std::env::var("GD_PROJECT").ok());
    let global_program = cli
        .program
        .clone()
        .or_else(|| std::env::var("GD_PROGRAM").ok());
    let projects_dir = cli.projects_dir.clone();
    let json_output = cli.json || cli.pretty || !std::io::stdout().is_terminal();
    match cli.command {
        Commands::Start(target) => handle_bridge_start(
            target.project.or(global_project),
            target.program.or(global_program),
            &projects_dir,
        ),
        Commands::Stop(target) => {
            handle_bridge_stop(target.project.or(global_project), &projects_dir)
        }
        Commands::Restart(target) => {
            let proj = target.project.or(global_project);
            let prog = target.program.or(global_program);
            handle_bridge_stop(proj.clone(), &projects_dir)?;
            std::thread::sleep(std::time::Duration::from_secs(1));
            handle_bridge_start(proj, prog, &projects_dir)
        }
        Commands::Status(target) => {
            handle_bridge_status(target.project.or(global_project), &projects_dir)
        }
        Commands::Ping(target) => {
            handle_bridge_ping(target.project.or(global_project), &projects_dir)
        }
        Commands::Jobs { job_id, target } => handle_bridge_jobs(
            target.project.or(global_project),
            &projects_dir,
            job_id,
            json_output,
            cli.pretty,
        ),
        Commands::Cancel { job_id, target } => handle_bridge_cancel(
            target.project.or(global_project),
            &projects_dir,
            job_id,
            json_output,
            cli.pretty,
        ),
        _ => unreachable!(),
    }
}

/// Start the bridge for a project.
fn handle_bridge_start(
    project: Option<String>,
    program: Option<String>,
    projects_dir: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("Ghidra installation directory not configured. Run 'gd setup' first.")
        })?;

    // Check if bridge is already running
    if bridge::is_bridge_running(&project_path).is_some() {
        println!(
            "Bridge is already running for project: {}",
            project_path.display()
        );
        return Ok(());
    }

    // Determine start mode
    let mode = if let Some(prog) = program {
        BridgeStartMode::Process { program_name: prog }
    } else if let Some(prog) = config.get_default_program() {
        BridgeStartMode::Process { program_name: prog }
    } else {
        BridgeStartMode::Project
    };

    println!("Starting bridge for project: {}", project_path.display());

    let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;

    println!("Bridge started on port {}", port);
    Ok(())
}

/// Stop the bridge for a project.
fn handle_bridge_stop(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;

    if bridge::is_bridge_running(&project_path).is_some() {
        println!("Stopping bridge...");
        bridge::stop_bridge(&project_path)?;
        println!("Bridge stopped");
    } else {
        println!("No bridge running for project: {}", project_path.display());
    }

    Ok(())
}

/// Get bridge status for a project.
fn handle_bridge_status(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;

    match bridge::bridge_status(&project_path)? {
        BridgeStatus::Running { port, pid } => {
            println!("Bridge is running:");
            println!("  PID: {}", pid);
            println!("  Port: {}", port);
            println!("  Project: {}", project_path.display());

            // Try to get extended info from the bridge
            let client = BridgeClient::new(port);
            if let Ok(info) = client.bridge_info() {
                if let Some(prog) = info.get("current_program").and_then(|v| v.as_str()) {
                    println!("  Current program: {}", prog);
                }
                if let Some(count) = info.get("program_count").and_then(|v| v.as_u64()) {
                    println!("  Programs: {}", count);
                }
                if let Some(state) = info.get("bridge_state").and_then(|v| v.as_str()) {
                    println!("  State: {}", state);
                }
                if let Some(depth) = info.get("queue_depth").and_then(|v| v.as_u64()) {
                    println!("  Queue depth: {}", depth);
                }
                if let Some(job) = info.get("active_job").filter(|v| !v.is_null()) {
                    let id = job.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let command = job
                        .get("command")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let state = job
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let elapsed = job.get("elapsed_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!(
                        "  Active job: {} {} ({}, {:.1}s)",
                        id,
                        command,
                        state,
                        elapsed as f64 / 1000.0
                    );
                }
            }
        }
        BridgeStatus::Stopped => {
            println!("No bridge running for project: {}", project_path.display());
        }
    }

    Ok(())
}

/// Ping the bridge.
fn handle_bridge_ping(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;

    if let Some(port) = bridge::is_bridge_running(&project_path) {
        let client = BridgeClient::new(port);
        if client.ping()? {
            println!("Bridge is responsive");
        } else {
            println!("Bridge is not responding");
        }
    } else {
        println!("No bridge running for project: {}", project_path.display());
    }

    Ok(())
}

fn handle_bridge_jobs(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
    job_id: Option<u64>,
    json_output: bool,
    pretty: bool,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let port = bridge::is_bridge_running(&project_path).ok_or_else(|| {
        anyhow::anyhow!("No bridge running for project: {}", project_path.display())
    })?;
    let client = BridgeClient::new(port);
    let jobs = if job_id.is_some() {
        client.job_status(job_id)?
    } else {
        client.status()?
    };
    if pretty {
        println!("{}", serde_json::to_string_pretty(&jobs)?);
    } else if json_output {
        println!("{}", serde_json::to_string(&jobs)?);
    } else if let Some(job) = jobs.get("job") {
        print_bridge_job("Job", job);
    } else if jobs.get("found").and_then(|v| v.as_bool()) == Some(false) {
        println!("Job {} was not found", job_id.unwrap_or_default());
    } else {
        let state = jobs
            .get("bridge_state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let depth = jobs
            .get("queue_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        println!("Bridge: {} ({} queued)", state, depth);

        match jobs.get("active_job").filter(|v| !v.is_null()) {
            Some(job) => print_bridge_job("Active", job),
            None => println!("Active: none"),
        }

        if let Some(queued) = jobs.get("queued_jobs").and_then(|v| v.as_array()) {
            for job in queued {
                print_bridge_job("Queued", job);
            }
        }
        if let Some(recent) = jobs.get("recent_jobs").and_then(|v| v.as_array()) {
            for job in recent {
                print_bridge_job("Recent", job);
            }
        }
    }
    Ok(())
}

fn print_bridge_job(label: &str, job: &serde_json::Value) {
    let id = job.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let command = job
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let state = job
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let elapsed = job.get("elapsed_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let mut details = format!(
        "{label}: {id} {command} ({state}, {:.1}s",
        elapsed as f64 / 1000.0
    );

    let progress = job.get("progress").and_then(|v| v.as_u64()).unwrap_or(0);
    let maximum = job.get("maximum").and_then(|v| v.as_u64()).unwrap_or(0);
    if maximum > 0 {
        details.push_str(&format!(", {progress}/{maximum}"));
    }
    details.push(')');
    if let Some(message) = job.get("progress_message").and_then(|v| v.as_str()) {
        details.push_str(": ");
        details.push_str(message);
    } else if let Some(error) = job.get("error").and_then(|v| v.as_str()) {
        details.push_str(": ");
        details.push_str(error);
    }
    println!("{details}");
}

fn handle_bridge_cancel(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
    job_id: Option<u64>,
    json_output: bool,
    pretty: bool,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let port = bridge::is_bridge_running(&project_path).ok_or_else(|| {
        anyhow::anyhow!("No bridge running for project: {}", project_path.display())
    })?;
    let result = BridgeClient::new(port).cancel_job(job_id)?;
    if pretty {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if json_output {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        let id = result
            .get("job_id")
            .and_then(|v| v.as_u64())
            .unwrap_or_default();
        let state = result
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let message = result
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Cancellation request handled");
        println!("Job {id}: {state} - {message}");
    }
    Ok(())
}
