mod bindiff;
mod cli;
mod cmd;
mod config;
mod error;
mod filter;
mod format;
mod ghidra;
mod ipc;
mod query;

use clap::Parser;
use cli::{Cli, CommandMeta, Commands};
use config::Config;
use error::GhidraError;
use format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use ghidra::bridge::{self, BridgeStartMode};
use ipc::client::BridgeClient;
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

fn main() {
    let cli = Cli::parse();

    apply_global_env_overrides(&cli);

    // --- Logging setup ---
    // File layer: always writes at debug level
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ghidra-cli");
    let _ = std::fs::create_dir_all(&log_dir);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "ghidra-cli.log");
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false)
        .with_filter(tracing_subscriber::EnvFilter::new("debug"));

    // Stdout layer: only if -v/-vv/-vvv is specified
    let stdout_layer = match cli.verbose {
        1 => Some("warn"),
        2 => Some("info"),
        3.. => Some("debug"),
        _ => None,
    }
    .map(|level| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
            )
    });

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stdout_layer)
        .init();

    let result = match &cli.command {
        Commands::Setup(_) => {
            // Setup needs async for downloading
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(cmd::maintenance::run_setup(cli))
        }
        Commands::Start(_)
        | Commands::Stop(_)
        | Commands::Restart(_)
        | Commands::Status(_)
        | Commands::Ping(_)
        | Commands::Jobs { .. }
        | Commands::Cancel { .. } => cmd::lifecycle::handle_bridge_command(cli),
        _ => run_command(cli),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Fold global CLI flags that must reach code which independently reloads
/// `Config` (e.g. the bridge launcher in `bridge.rs`) into process env vars.
///
/// Only flags that cross such a boundary belong here. `--projects-dir`, by
/// contrast, is applied in-process via [`load_config`] and deliberately does
/// not go through the environment.
fn apply_global_env_overrides(cli: &Cli) {
    // `--java-home` is read by `Config::get_java_home`, which the bridge launcher
    // calls after reloading config from disk — so the flag must propagate via env.
    if let Some(jh) = &cli.java_home {
        std::env::set_var("GHIDRA_CLI_JAVA_HOME", jh);
    }
}

/// Command-level project, then global --project, then $GD_PROJECT.
fn resolve_project_arg(cli: &Cli) -> Option<String> {
    cli.command
        .project()
        .map(str::to_string)
        .or_else(|| cli.project.clone())
        .or_else(|| std::env::var("GD_PROJECT").ok())
}

/// Command-level program, then global --program, then $GD_PROGRAM.
fn resolve_program_arg(cli: &Cli) -> Option<String> {
    cli.command
        .program()
        .map(str::to_string)
        .or_else(|| cli.program.clone())
        .or_else(|| std::env::var("GD_PROGRAM").ok())
}

/// Run a command, starting the bridge if needed.
fn run_command(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        // Non-bridge commands
        Commands::Init => cmd::maintenance::handle_init(),
        Commands::Doctor => cmd::maintenance::handle_doctor(&cli.projects_dir),
        Commands::Version => cmd::maintenance::handle_version(),
        Commands::Config(cmd) => cmd::maintenance::handle_config_command(cmd.clone()),
        Commands::SetDefault(args) => cmd::maintenance::handle_set_default(args.clone()),
        Commands::Project(args) => cmd::maintenance::handle_project_command(args.command.clone()),
        // Commands requiring bridge
        _ if cli.command.requires_bridge() => run_with_bridge(cli),
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}

/// Resolve the output format for a bridge command result.
///
/// Precedence: explicit `-o` > `--pretty`/`--json` flags > config
/// `default_output_format` > command-specific text default (C for decompile,
/// asm for disasm) > TTY auto-detection (human on TTY, JSON when piped).
fn resolve_output_format(
    explicit: Option<OutputFormat>,
    pretty: bool,
    json: bool,
    config_format: Option<OutputFormat>,
    text_default: Option<OutputFormat>,
    is_tty: bool,
) -> OutputFormat {
    let flags = if pretty {
        Some(OutputFormat::Json)
    } else if json {
        Some(OutputFormat::JsonCompact)
    } else {
        None
    };
    explicit
        .or(flags)
        .or(config_format)
        .or(text_default)
        .unwrap_or_else(|| auto_detect_format(is_tty))
}

/// The config's `default_output_format`, if set to a concrete format.
/// "auto" (the built-in default) and empty values mean "unset"; an unknown
/// value warns and falls through to the next tier rather than aborting.
fn config_output_format(config: &config::Config) -> Option<OutputFormat> {
    config
        .default_output_format
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
        .and_then(|s| match OutputFormat::from_str(s) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("warning: ignoring invalid default_output_format '{s}' in config: {e}");
                None
            }
        })
}

fn run_with_bridge(cli: Cli) -> anyhow::Result<()> {
    let config = load_config(&cli.projects_dir)?;

    // Validate an explicit `-o` up front, before any bridge work: a bad
    // format value is a user error that must fail immediately with a clear
    // message (never silently fall back to TTY/pipe detection).
    let opts = cli.command.query_options();
    let explicit_format = match opts.as_ref().and_then(|o| o.format.as_ref()) {
        Some(f) => Some(OutputFormat::from_str(f)?),
        None => None,
    };

    // Command-level --project, then global --project, then $GD_PROJECT,
    // then config default.
    let project_path = resolve_project_path(&resolve_project_arg(&cli), &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("Ghidra installation directory not configured. Run 'gd setup' first.")
        })?;

    // Build the query plan up front, before any bridge work: a malformed
    // --filter must fail now — the fetch for a filtered query pulls the full
    // dataset, so failing late wastes that transfer (docs/history/TODO.md Bug 2).
    let mut exec_ctx = cmd::ExecCtx::for_command(
        cli.quiet,
        config.default_limit,
        &cli.command,
        config.bindiff.clone(),
    )
    .map_err(describe_query_error)?;

    // Import has its own bridge lifecycle; other commands (including
    // Analyze) produce a result via cmd::execute.
    // `last_command` tracks the wire command the result came from, so
    // `unwrap_bridge_response` can look up its envelope in the typed table.
    let mut last_command: Option<String> = None;
    let result = match &cli.command {
        Commands::Import(args) => {
            // Import has its own bridge lifecycle (3 hang-proof cases in
            // cmd::analyze); it does not go through cmd::execute.
            cmd::analyze::import(args, &project_path, &ghidra_install_dir, cli.quiet)?
        }
        _ => {
            // For all bridge commands (including Analyze), ensure bridge is running
            let client = if let Some(port) = bridge::is_bridge_running(&project_path) {
                // Liveness already proven by is_bridge_running() (PID alive + socket
                // accepting). A busy bridge queues the request rather than failing a
                // pre-flight ping, so connect directly and let it wait its turn.
                BridgeClient::new(port)
            } else {
                // Auto-start bridge - use specific program if available, otherwise project mode
                let mode = if let Some(program) =
                    resolve_program_arg(&cli).or_else(|| config.get_default_program())
                {
                    BridgeStartMode::Process {
                        program_name: program,
                    }
                } else {
                    BridgeStartMode::Project
                };

                if !cli.quiet {
                    eprintln!("Starting Ghidra bridge...");
                }
                let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                if !cli.quiet {
                    eprintln!("Bridge ready.");
                }
                BridgeClient::new(port)
            };

            // Switch to requested program if it differs from the bridge's current program
            if let Some(requested_program) = resolve_program_arg(&cli) {
                if let Ok(info) = client.program_info() {
                    let current = info.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if current != requested_program {
                        client.open_program(&requested_program)?;
                    }
                } else {
                    client.open_program(&requested_program)?;
                }
            }

            let first_attempt = cmd::execute(&client, &cli.command, &exec_ctx);
            // Restart on "Unknown command" (old bridge lacks the handler) OR on a
            // stale list_functions response: an old bridge silently ignores the
            // newer tags/untagged args and returns a successful, UNFILTERED list.
            let needs_restart = match &first_attempt {
                Ok(value) => stale_tags_response(&cli.command, value),
                Err(err) => is_unknown_command_error(err),
            };
            match first_attempt {
                Ok(value) if !needs_restart => {
                    last_command = client.last_command();
                    value
                }
                Err(err) if !needs_restart => return Err(err),
                _ => {
                    if !cli.quiet {
                        eprintln!(
                            "Bridge command not supported by running instance. Restarting bridge and retrying..."
                        );
                    }

                    // Running bridge may be from an older script; force restart to load
                    // the embedded bridge matching this CLI version.
                    let _ = bridge::stop_bridge(&project_path);
                    let mode = if let Some(program) =
                        resolve_program_arg(&cli).or_else(|| config.get_default_program())
                    {
                        BridgeStartMode::Process {
                            program_name: program,
                        }
                    } else {
                        BridgeStartMode::Project
                    };
                    let port =
                        bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                    let retry_client = BridgeClient::new(port);

                    if let Some(requested_program) = resolve_program_arg(&cli) {
                        if let Ok(info) = retry_client.program_info() {
                            let current = info.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            if current != requested_program {
                                retry_client.open_program(&requested_program)?;
                            }
                        } else {
                            retry_client.open_program(&requested_program)?;
                        }
                    }

                    // One restart per invocation: the retry result is accepted
                    // (or its error propagated) without re-probing.
                    let retry_result = cmd::execute(&retry_client, &cli.command, &exec_ctx)?;
                    last_command = retry_client.last_command();
                    retry_result
                }
            }
        }
    };

    // Check for .NET decompilation and warn
    if !cli.quiet {
        check_dotnet_decompile_warning(&cli.command, &result);
    }

    // Determine output format: explicit -o flag (validated up front) >
    // --json/--pretty > config > command-specific text default > TTY.
    // Command-specific text defaults: decompile-style commands print raw C and
    // disasm-style commands print raw assembly unless the user explicitly asks
    // for a structured format (-o, --json, --pretty).
    let text_default = if matches!(
        &cli.command,
        Commands::Decompile(_)
            | Commands::DecompileMulti(_)
            | Commands::Function(cli::FunctionCommands::Decompile(_))
    ) {
        Some(OutputFormat::C)
    } else if matches!(
        &cli.command,
        Commands::Disasm(_) | Commands::Function(cli::FunctionCommands::Disasm(_))
    ) {
        Some(OutputFormat::Asm)
    } else {
        None
    };

    let format = resolve_output_format(
        explicit_format,
        cli.pretty,
        cli.json || opts.as_ref().is_some_and(|o| o.json),
        config_output_format(&config),
        text_default,
        std::io::stdout().is_terminal(),
    );

    // For `diff programs`, the human formats need comparison context the
    // row unwrap would drop (which programs, per-category counts, whether
    // the list was truncated) — compute it from the envelope first.
    let diff_header = (last_command.as_deref() == Some("diff_programs"))
        .then(|| diff_summary_line(&result))
        .flatten();

    // Unwrap bridge response envelopes before formatting
    let values = query::unwrap_bridge_response(result, last_command.as_deref());

    // Apply client-side query processing (filter, fields, sort, pagination)
    // when the plan has post-processing. The plan was validated up front, so
    // no parse errors can surface here.
    if let Some(post) = exec_ctx.plan.post.take() {
        let output = post.process(values, format)?;
        if !output.is_empty() {
            if let Some(header) = &diff_header {
                if is_human_format(format) {
                    println!("{}", header);
                }
            }
            println!("{}", output);
        }
        return Ok(());
    }

    let formatter = DefaultFormatter;
    let output = formatter.format(&values, format)?;
    if let Some(header) = &diff_header {
        if is_human_format(format) && !output.is_empty() {
            println!("{}", header);
        }
    }
    if !output.is_empty() {
        println!("{}", output);
    }
    Ok(())
}

/// Formats where a one-line summary above the rows is readable (row
/// structures like JSON/CSV would be polluted by it).
fn is_human_format(format: OutputFormat) -> bool {
    matches!(
        format,
        OutputFormat::Table | OutputFormat::Compact | OutputFormat::Full | OutputFormat::Minimal
    )
}

/// One-line comparison context for `diff programs` (the unwrap drops the
/// envelope's summary fields from the formatted rows).
fn diff_summary_line(envelope: &serde_json::Value) -> Option<String> {
    let obj = envelope.as_object()?;
    if obj.get("status")?.as_str()? != "ok" {
        return None;
    }
    let a = obj.get("program1")?.get("name")?.as_str()?;
    let b = obj.get("program2")?.get("name")?.as_str()?;
    let s = obj.get("summary")?;
    let matched = s.get("matched").and_then(|v| v.as_u64()).unwrap_or(0);
    let identical = s.get("identical").and_then(|v| v.as_u64()).unwrap_or(0);
    let changed = s.get("changed").and_then(|v| v.as_u64()).unwrap_or(0);
    let up = s
        .get("unmatched_primary")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let us = s
        .get("unmatched_secondary")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mut out = format!(
        "binDiff {} vs {}: {} matched ({} identical, {} changed), {} unmatched in {}, {} in {}",
        a, b, matched, identical, changed, up, a, us, b
    );
    if let Some(sim) = s.get("overall_similarity").and_then(|v| v.as_f64()) {
        out.push_str(&format!("; overall similarity {:.3}", sim));
    }
    if obj.get("truncated").and_then(|t| t.as_bool()) == Some(true) {
        out.push_str(" [truncated]");
    }
    Some(out)
}

fn is_unknown_command_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("Unknown command:")
}

/// Detects a stale bridge that ignored the `tags`/`untagged` args on
/// `list_functions`: an old handler returns a successful but UNFILTERED
/// response whose rows lack the `"tags"` key (the current row builder always
/// emits it). Probes the raw bridge envelope, before `unwrap_bridge_response`
/// and any client-side field projection, so nothing can strip the key first.
///
/// Empty row sets pass vacuously: an old bridge ignoring the args returns the
/// FULL function list, which is only empty when the program has no functions —
/// where filtered and unfiltered output coincide anyway. Without this rule,
/// every legitimately empty result would trigger a bridge restart.
fn stale_tags_response(command: &Commands, value: &serde_json::Value) -> bool {
    let tag_filter_requested = matches!(
        command,
        Commands::Function(cli::FunctionCommands::List(args))
            if !args.tags.is_empty() || args.untagged
    );
    if !tag_filter_requested {
        return false;
    }
    value
        .get("functions")
        .and_then(|f| f.as_array())
        .is_some_and(|rows| {
            rows.iter()
                .any(|row| row.is_object() && row.get("tags").is_none())
        })
}

/// Make filter parse failures actionable: the DSL needs a field and operator,
/// so a bare word like `PK` is invalid (use `name~PK` instead).
fn describe_query_error(err: GhidraError) -> anyhow::Error {
    match &err {
        GhidraError::FilterParseError(_) | GhidraError::InvalidFilter(_) => anyhow::anyhow!(err)
            .context(
                "invalid --filter expression: expected <field><operator><value>, \
                 e.g. --filter 'name~PK' (contains), --filter 'name=~\"^PK_\"' (regex), \
                 --filter 'size>100'; combine with AND/OR/NOT",
            ),
        _ => anyhow::anyhow!(err),
    }
}

/// Check if a decompile result looks like .NET managed code and warn the user.
fn check_dotnet_decompile_warning(command: &Commands, result: &serde_json::Value) {
    let is_decompile = matches!(
        command,
        Commands::Decompile(_) | Commands::Function(cli::FunctionCommands::Decompile(_))
    );
    if !is_decompile {
        return;
    }

    if let Some(code) = result.get("code").and_then(|c| c.as_str()) {
        if code.contains("halt_baddata()") || code.contains(".NET CLR Managed Code") {
            eprintln!(
                "Warning: This appears to be .NET managed code. Ghidra cannot decompile .NET IL bytecode.\n\
                 Consider using a .NET decompiler (e.g., ilspy-cli) for better results."
            );
        }
    }
}

/// Whether a Ghidra project already exists on disk for the given project path.
///
/// `project_path` is `<parent>/<name>`; analyzeHeadless materializes the project
/// as sibling `<parent>/<name>.gpr` (project file) and `<parent>/<name>.rep`
/// (project directory). Either marks an existing project we can `-process`.
/// Load config, applying the global `--projects-dir` override (if any) onto
/// `ghidra_project_dir`. This keeps the precedence in [`Config::get_project_dir`]
/// (env var > config field > default) while letting the CLI flag win in-process
/// without mutating global state.
fn load_config(projects_dir: &Option<PathBuf>) -> anyhow::Result<Config> {
    let mut config = Config::load()?;
    if let Some(dir) = projects_dir {
        config.ghidra_project_dir = Some(dir.clone());
    }
    Ok(config)
}

/// Resolve a project name to its full path on disk.
fn resolve_project_path(project: &Option<String>, config: &Config) -> anyhow::Result<PathBuf> {
    let project_name = project
        .clone()
        .or_else(|| config.default_project.clone())
        .ok_or_else(|| anyhow::anyhow!("No project specified and no default project configured"))?;

    let project_dir = config.get_project_dir()?;

    if PathBuf::from(&project_name).is_absolute() {
        Ok(PathBuf::from(project_name))
    } else {
        Ok(project_dir.join(project_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn resolve_output_format_precedence() {
        // -o beats everything, including --json/--pretty and config.
        assert_eq!(
            resolve_output_format(
                Some(OutputFormat::Csv),
                true,
                true,
                Some(OutputFormat::Table),
                Some(OutputFormat::C),
                true
            ),
            OutputFormat::Csv
        );
        // --pretty beats --json and config.
        assert_eq!(
            resolve_output_format(None, true, true, Some(OutputFormat::Table), None, true),
            OutputFormat::Json
        );
        // --json beats config.
        assert_eq!(
            resolve_output_format(None, false, true, Some(OutputFormat::Table), None, true),
            OutputFormat::JsonCompact
        );
        // config beats the command-specific text default (decompile/disasm).
        assert_eq!(
            resolve_output_format(
                None,
                false,
                false,
                Some(OutputFormat::Table),
                Some(OutputFormat::C),
                true
            ),
            OutputFormat::Table
        );
        // config beats TTY auto-detection.
        assert_eq!(
            resolve_output_format(None, false, false, Some(OutputFormat::Table), None, true),
            OutputFormat::Table
        );
        // nothing set: TTY auto (human on TTY, compact JSON when piped).
        assert_eq!(
            resolve_output_format(None, false, false, None, None, true),
            OutputFormat::Compact
        );
        assert_eq!(
            resolve_output_format(None, false, false, None, None, false),
            OutputFormat::JsonCompact
        );
        // text default still applies when nothing else is set (piped decompile).
        assert_eq!(
            resolve_output_format(None, false, false, None, Some(OutputFormat::C), false),
            OutputFormat::C
        );
    }

    #[test]
    fn config_output_format_handles_auto_and_invalid() {
        let mut config = Config::default();
        assert_eq!(
            config_output_format(&config),
            None,
            "built-in \"auto\" means unset"
        );

        config.default_output_format = Some("table".into());
        assert_eq!(config_output_format(&config), Some(OutputFormat::Table));

        config.default_output_format = Some("  JSON ".into());
        assert_eq!(config_output_format(&config), Some(OutputFormat::Json));

        config.default_output_format = Some("AUTO".into());
        assert_eq!(config_output_format(&config), None);

        config.default_output_format = Some("bogus".into());
        // warns on stderr, must not abort
        assert_eq!(config_output_format(&config), None);
    }

    #[test]
    fn describe_query_error_mentions_filter_usage() {
        // Regression (`docs/history/TODO.md` Bug 2): a bare word is not a valid filter and the
        // error must surface (previously swallowed, dumping the whole dataset).
        let Err(err) = filter::Filter::parse("PK") else {
            panic!("bare word must not parse");
        };
        let msg = format!("{:#}", describe_query_error(err));
        assert!(msg.contains("invalid --filter expression"), "got: {msg}");
    }

    #[test]
    fn empty_project_artifacts_are_not_program_data() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("stale");
        std::fs::write(temp.path().join("stale.gpr"), []).unwrap();
        std::fs::create_dir_all(temp.path().join("stale.rep/idata")).unwrap();
        std::fs::write(temp.path().join("stale.rep/idata/~index.dat"), []).unwrap();

        assert!(ghidra::project_exists(&project));
        assert!(!ghidra::project_has_program_data(&project));
    }

    #[test]
    fn idata_bucket_marks_project_as_populated() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("populated");
        std::fs::write(temp.path().join("populated.gpr"), []).unwrap();
        std::fs::create_dir_all(temp.path().join("populated.rep/idata/00")).unwrap();

        assert!(ghidra::project_has_program_data(&project));
    }

    #[test]
    fn unwrap_find_constant_envelope() {
        let v = serde_json::json!({"count":2, "hits":[{"address":"00118b43","block":".text"},{"address":"00118b47","block":".text"}], "size":4, "value":"0x488"});
        let rows = query::unwrap_bridge_response(v, Some("find_constant"));
        assert_eq!(rows.len(), 2, "expected 2 hit rows, got: {:?}", rows);
    }

    // --- resolve_*_arg priority: command flag > global flag > env var ---

    #[test]
    #[serial_test::serial]
    fn resolve_project_arg_command_flag_wins() {
        std::env::set_var("GD_PROJECT", "envproj");
        let cli = Cli::parse_from(["gd", "function", "list", "--project", "cmdproj"]);
        assert_eq!(resolve_project_arg(&cli), Some("cmdproj".into()));
        std::env::remove_var("GD_PROJECT");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_project_arg_env_fallback() {
        std::env::set_var("GD_PROJECT", "envproj");
        let cli = Cli::parse_from(["gd", "function", "list"]);
        assert_eq!(resolve_project_arg(&cli), Some("envproj".into()));
        std::env::remove_var("GD_PROJECT");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_project_arg_absent() {
        std::env::remove_var("GD_PROJECT");
        let cli = Cli::parse_from(["gd", "function", "list"]);
        assert_eq!(resolve_project_arg(&cli), None);
    }

    #[test]
    #[serial_test::serial]
    fn resolve_program_arg_global_flag_beats_env() {
        std::env::set_var("GD_PROGRAM", "envprog");
        let cli = Cli::parse_from(["gd", "function", "list", "--program", "globalprog"]);
        assert_eq!(resolve_program_arg(&cli), Some("globalprog".into()));
        std::env::remove_var("GD_PROGRAM");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_program_arg_env_fallback() {
        std::env::set_var("GD_PROGRAM", "envprog");
        let cli = Cli::parse_from(["gd", "function", "list"]);
        assert_eq!(resolve_program_arg(&cli), Some("envprog".into()));
        std::env::remove_var("GD_PROGRAM");
    }
}
