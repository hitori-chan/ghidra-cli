//! Maintenance commands (docs/history/refactor-plan.md P1: setup/init/doctor/version/
//! config/set-default/project handlers, moved from main.rs).

use crate::cli;
use crate::cli::Cli;
use crate::cli::Commands;
use crate::config::Config;
use crate::error::GhidraError;
use crate::ghidra;
use crate::ghidra::bridge;
use crate::ghidra::project_exists;
use crate::ghidra::GhidraClient;
use crate::load_config;
use std::path::PathBuf;

pub async fn run_setup(cli: Cli) -> anyhow::Result<()> {
    let args = match cli.command {
        Commands::Setup(args) => args,
        _ => unreachable!(),
    };

    println!("Ghidra Setup Wizard");
    println!("===================\n");

    // 1. Check Java — Ghidra needs a full JDK (not a JRE) to compile scripts.
    if !args.force {
        let explicit = Config::load().ok().and_then(|c| c.get_java_home());
        match ghidra::java::resolve_jdk(explicit.as_deref(), ghidra::java::DEFAULT_MIN_JAVA) {
            ghidra::java::JavaStatus::Ok(info) => {
                println!(
                    "✓ JDK {} found at {} (via {})",
                    info.major,
                    info.home.display(),
                    info.source
                );
            }
            other => {
                eprintln!(
                    "Java prerequisite check failed: {}",
                    ghidra::java::describe_failure(&other)
                );
                eprintln!("Use --force to continue anyway.");
                std::process::exit(1);
            }
        }
    } else {
        println!("Skipping Java check (--force specified)");
    }

    // 2. Determine Install Directory
    let install_base = if let Some(d) = args.dir {
        PathBuf::from(d)
    } else {
        dirs::data_local_dir()
            .ok_or(anyhow::anyhow!("Could not determine data directory"))?
            .join("ghidra-cli")
            .join("ghidra")
    };

    std::fs::create_dir_all(&install_base)?;

    // 3. Install Ghidra
    println!("\nInstalling to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\nSuccess! Ghidra installed at: {}", final_path.display());
    println!("Configuration updated.");

    // 5. Verify
    println!("\nVerifying installation...");
    let client = GhidraClient::new(config)?;
    if client.verify_installation().is_ok() {
        println!("Verification passed!");
        println!("\nYou can now run: ghidra import <binary> --project <name>");
    } else {
        println!("Verification failed - analyzeHeadless not found");
        println!("  The installation may be incomplete.");
    }

    Ok(())
}

pub fn handle_init() -> anyhow::Result<()> {
    println!("Ghidra CLI Initialization");
    println!("========================\n");

    let mut config = Config::default();

    if config.ghidra_install_dir.is_none() {
        println!("Ghidra installation not found automatically.");
        println!("Please set GHIDRA_INSTALL_DIR environment variable or run 'gd setup'.");
    }

    // Set default project directory. Must avoid dot-prefixed path components,
    // which Ghidra 12.1+ rejects (see Config::default_project_dir).
    let project_dir = Config::default_project_dir()?;
    config.ghidra_project_dir = Some(project_dir.clone());

    println!("\nProject directory: {}", project_dir.display());

    // Save config
    config.save()?;

    println!(
        "\nConfiguration saved to: {}",
        Config::config_path()?.display()
    );
    println!("\nRun 'ghidra doctor' to verify your installation.");

    Ok(())
}

pub fn handle_doctor(projects_dir: &Option<PathBuf>) -> anyhow::Result<()> {
    println!("Ghidra CLI Doctor");
    println!("=================\n");

    let config = load_config(projects_dir)?;

    // Check Ghidra installation
    print!("Checking Ghidra installation... ");
    match config.get_ghidra_install_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        println!("  analyzeHeadless: OK");
                    } else {
                        println!("  analyzeHeadless: NOT FOUND");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check Java
    // Check Java — must be a full JDK (Ghidra compiles scripts at runtime).
    use ghidra::java::JavaStatus;
    let install_dir = config.get_ghidra_install_dir().ok();
    let min = install_dir
        .as_deref()
        .map(ghidra::java::ghidra_min_java)
        .unwrap_or(ghidra::java::DEFAULT_MIN_JAVA);
    let explicit = config.get_java_home();

    print!("\nChecking Java (full JDK {}+)... ", min);
    match ghidra::java::resolve_jdk(explicit.as_deref(), min) {
        JavaStatus::Ok(info) => {
            println!("OK");
            println!(
                "  JDK {} at {} (selected via {})",
                info.major,
                info.home.display(),
                info.source
            );

            // Real health check: compile the embedded bridge script against the
            // installed Ghidra. Catches API incompatibilities and JRE issues.
            if let Some(install) = &install_dir {
                print!("\nChecking bridge script compiles... ");
                match ghidra::bridge::compile_check(install, &info.home) {
                    Ok(()) => println!("OK"),
                    Err(errs) => {
                        println!("FAILED");
                        for line in errs.lines() {
                            println!("  {}", line);
                        }
                    }
                }
            }
        }
        JavaStatus::JreNoCompiler { home, major } => {
            println!("FAILED");
            println!(
                "  JRE detected: Java {} at {} has no javac / jdk.compiler module.",
                major,
                home.display()
            );
            println!(
                "  Ghidra requires a full JDK {}+ to compile scripts (a JRE cannot work).",
                min
            );
            println!("  Install a JDK, or select one with --java-home / GHIDRA_CLI_JAVA_HOME / config `java_home`.");
        }
        JavaStatus::WrongVersion { home, major, min } => {
            println!("FAILED");
            println!(
                "  JDK {} at {} is below the required JDK {}+.",
                major,
                home.display(),
                min
            );
        }
        JavaStatus::NotFound => {
            println!("FAILED");
            println!(
                "  No Java found. Install a full JDK {}+ or set --java-home.",
                min
            );
        }
    }

    // Check project directory
    print!("\nChecking project directory... ");
    match config.get_project_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());
            println!(
                "  Exists: {}",
                if dir.exists() {
                    "yes"
                } else {
                    "no (will be created)"
                }
            );
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check config file
    print!("\nConfig file... ");
    match Config::config_path() {
        Ok(path) => {
            println!("OK");
            println!("  Location: {}", path.display());
            println!("  Exists: {}", if path.exists() { "yes" } else { "no" });
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    println!("\nDone!");
    Ok(())
}

pub fn handle_version() -> anyhow::Result<()> {
    println!("ghidra-cli {}", env!("CARGO_PKG_VERSION"));
    println!("Rust CLI for Ghidra reverse engineering");
    Ok(())
}

pub fn handle_config_command(cmd: cli::ConfigCommands) -> anyhow::Result<()> {
    use cli::ConfigCommands;

    match cmd {
        ConfigCommands::List => {
            let config = Config::load()?;
            println!("{}", serde_yaml::to_string(&config)?);
        }
        ConfigCommands::Get { key } => {
            let config = Config::load()?;
            let yaml = serde_yaml::to_value(&config)?;
            if let Some(value) = yaml.get(&key) {
                println!("{}", serde_yaml::to_string(value)?);
            } else {
                println!("Key not found: {}", key);
            }
        }
        ConfigCommands::Set { key, value } => {
            let mut config = Config::load()?;
            match key.as_str() {
                "default_output_format" => config.default_output_format = Some(value),
                "timeout" => anyhow::bail!(
                    "'timeout' has been removed because it no longer controlled bridge waits. \
                     Use GHIDRA_CLI_READ_TIMEOUT for normal commands, GHIDRA_CLI_OP_TIMEOUT \
                     for analyze/import, or config 'launch_timeout_secs' for bridge startup."
                ),
                "ghidra_install_dir" => config.ghidra_install_dir = Some(PathBuf::from(value)),
                "ghidra_project_dir" => config.ghidra_project_dir = Some(PathBuf::from(value)),
                "default_program" => config.default_program = Some(value),
                "default_project" => config.default_project = Some(value),
                "launch_timeout_secs" => {
                    let timeout: u64 = value.parse().map_err(|_| {
                        GhidraError::ConfigError("Invalid launch timeout value".to_string())
                    })?;
                    config.launch_timeout_secs = Some(timeout);
                }
                "default_limit" => {
                    let limit: usize = value
                        .parse()
                        .map_err(|_| GhidraError::ConfigError("Invalid limit value".to_string()))?;
                    config.default_limit = Some(limit);
                }
                _ => {
                    anyhow::bail!("Unknown config key: {}", key);
                }
            }
            config.save()?;
            println!("Configuration updated");
        }
        ConfigCommands::Reset => {
            let config = Config::default();
            config.save()?;
            println!("Configuration reset to defaults");
        }
    }

    Ok(())
}

pub fn handle_set_default(args: cli::SetDefaultArgs) -> anyhow::Result<()> {
    let mut config = Config::load()?;

    match args.kind.as_str() {
        "program" => {
            config.default_program = Some(args.value.clone());
            config.save()?;
            println!("Default program set to: {}", args.value);
        }
        "project" => {
            config.default_project = Some(args.value.clone());
            config.save()?;
            println!("Default project set to: {}", args.value);
        }
        _ => {
            anyhow::bail!(format!("Unknown default kind: {}", args.kind));
        }
    }

    Ok(())
}

pub fn handle_project_command(cmd: cli::ProjectCommands) -> anyhow::Result<()> {
    use cli::ProjectCommands;

    let config = Config::load()?;
    let client = GhidraClient::new(config)?;

    match cmd {
        ProjectCommands::Create { name } => {
            client.create_project(&name)?;
            println!("Project '{}' created", name);
        }
        ProjectCommands::List => {
            let project_dir = client.get_project_dir();
            if !project_dir.exists() {
                println!("No projects found");
                return Ok(());
            }

            println!("Projects:");
            for entry in std::fs::read_dir(project_dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        println!("  {}", name);
                    }
                }
            }
        }
        ProjectCommands::Delete { name } => {
            // analyzeHeadless materializes a project as sibling files
            // `<parent>/<basename>.gpr` (descriptor) + `<basename>.rep` (data dir),
            // NOT a `<parent>/<basename>` directory. Derive the real paths from the
            // basename so absolute project names work too. `create_project` may
            // also have left an empty `<parent>/<basename>` directory.
            let project_path = client.get_project_path(&name);
            let (basename, parent) = match (project_path.file_name(), project_path.parent()) {
                (Some(f), Some(p)) => (f.to_string_lossy().to_string(), p.to_path_buf()),
                _ => {
                    println!("Project '{}' not found", name);
                    return Ok(());
                }
            };
            let gpr = parent.join(format!("{}.gpr", basename));
            let rep = parent.join(format!("{}.rep", basename));
            let legacy_dir = project_path.clone();

            if !gpr.exists() && !rep.exists() && !legacy_dir.is_dir() {
                println!("Project '{}' not found", name);
                return Ok(());
            }

            // Stop any running bridge first so the JVM releases the project lock
            // before we delete its files. stop_bridge also clears the stale
            // port/pid/`.lock`/`.lock~` files via cleanup_stale_files.
            let _ = bridge::stop_bridge(&project_path);

            if gpr.exists() {
                std::fs::remove_file(&gpr)?;
            }
            if rep.exists() {
                std::fs::remove_dir_all(&rep)?;
            }
            if legacy_dir.is_dir() {
                std::fs::remove_dir_all(&legacy_dir)?;
            }
            println!("Project '{}' deleted", name);
        }
        ProjectCommands::Info { name } => {
            let project_name = name.unwrap_or_else(|| "default".to_string());
            let project_path = client.get_project_path(&project_name);
            println!("Project: {}", project_name);
            println!("Path: {}", project_path.display());
            // The project lives on disk as sibling `<name>.gpr`/`<name>.rep`
            // artifacts, not a `<name>` directory, so check those (see
            // `project_exists`) rather than the bare path.
            println!("Exists: {}", project_exists(&project_path));
        }
    }

    Ok(())
}
