//! Bridge command execution, split by command group (docs/history/refactor-plan.md P1).
//!
//! Each module's `run` handles one group of `Commands`; `execute` is the only
//! place group membership is decided.

pub mod analyze;
pub mod functions;
pub mod lifecycle;
pub mod lists;
pub mod maintenance;
pub mod mutation;
pub mod programs;
pub mod scripts;
pub mod search;

use crate::cli::{self, CommandMeta, Commands};
use crate::error::Result;
use crate::ipc::client::BridgeClient;
use crate::query::QueryPlan;

/// Per-invocation context for bridge command execution.
pub struct ExecCtx {
    pub quiet: bool,
    pub default_limit: Option<usize>,
    /// The query plan for this command: server-side fetch params (read by
    /// the list arms) and client-side post-processing (applied in
    /// `run_with_bridge` after the result returns).
    pub plan: QueryPlan,
    /// BinDiff integration settings (config `bindiff:` section), for
    /// `gd diff programs`.
    pub bindiff: Option<crate::config::BindiffConfig>,
}

impl ExecCtx {
    /// Build the context for `command`, resolving its query plan. Parse
    /// errors (e.g. malformed `--filter`) propagate so the caller can render
    /// a user-facing message.
    pub fn for_command(
        quiet: bool,
        default_limit: Option<usize>,
        command: &Commands,
        bindiff: Option<crate::config::BindiffConfig>,
    ) -> Result<Self> {
        let opts = command.query_options();
        let plan = QueryPlan::from(opts.as_ref(), default_limit, bridge_filter_field(command))?;
        Ok(Self {
            quiet,
            default_limit,
            plan,
            bindiff,
        })
    }
}

/// The row field the bridge's `filter` argument matches (case-insensitive
/// contains) for this command's list handler, if any (P6). `Some` enables
/// server-side filter pushdown: the bridge filters while iterating and only
/// matching rows cross the wire. The client-side filter always re-runs, so
/// this must name the *exact* field each handler filters:
/// functions/symbols/types on `name`, strings on `value`, comments on
/// `text`. Every other command returns `None` (no pushdown).
fn bridge_filter_field(command: &Commands) -> Option<&'static str> {
    match command {
        Commands::Function(cli::FunctionCommands::List(_)) => Some("name"),
        Commands::Symbol(cli::SymbolCommands::List(_)) => Some("name"),
        Commands::Type(cli::TypeCommands::List(_)) => Some("name"),
        Commands::Comment(cli::CommentCommands::List(_)) => Some("text"),
        Commands::Strings(cli::StringsCommands::List(_)) => Some("value"),
        Commands::Query(args) => match args.data_type.as_str() {
            "functions" => Some("name"),
            "strings" => Some("value"),
            _ => None,
        },
        Commands::Dump(cli::DumpCommands::Functions(_)) => Some("name"),
        Commands::Dump(cli::DumpCommands::Strings(_)) => Some("value"),
        _ => None,
    }
}

/// Execute a bridge command, dispatching to the module that owns its group.
pub fn execute(
    client: &BridgeClient,
    command: &Commands,
    ctx: &ExecCtx,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Commands::Analyze(_) => analyze::run(client, command, ctx),
        Commands::Function(_)
        | Commands::Decompile(_)
        | Commands::DecompileMulti(_)
        | Commands::Disasm(_) => functions::run(client, command, ctx),
        Commands::Query(_)
        | Commands::Strings(_)
        | Commands::Dump(_)
        | Commands::Summary(_)
        | Commands::Stats(_) => lists::run(client, command, ctx),
        Commands::XRef(_) | Commands::Graph(_) | Commands::Find(_) => {
            search::run(client, command, ctx)
        }
        Commands::Symbol(_)
        | Commands::Type(_)
        | Commands::Tag(_)
        | Commands::Comment(_)
        | Commands::Patch(_)
        | Commands::Rename(_) => mutation::run(client, command, ctx),
        Commands::Program(_) | Commands::Memory(_) | Commands::Diff(_) | Commands::Raw(_) => {
            programs::run(client, command, ctx)
        }
        Commands::Script(_) | Commands::Batch(_) => scripts::run(client, command, ctx),
        _ => anyhow::bail!("Command not supported"),
    }
}
