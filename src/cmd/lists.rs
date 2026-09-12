//! List/query bridge commands (extracted from execute_via_bridge, P1).

use crate::cli;
use crate::cli::Commands;
use crate::ipc::client::BridgeClient;

pub fn run(
    client: &BridgeClient,
    command: &Commands,
    ctx: &super::ExecCtx,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Commands::Query(args) => match args.data_type.as_str() {
            "functions" => client.list_functions(
                ctx.plan.fetch.limit,
                ctx.plan.fetch.filter.clone(),
                ctx.plan.fetch.offset,
                &[],
                false,
            ),
            "strings" => client.list_strings(
                ctx.plan.fetch.limit,
                ctx.plan.fetch.filter.clone(),
                ctx.plan.fetch.offset,
            ),
            "imports" => client.list_imports(),
            "exports" => client.list_exports(),
            "memory" => client.memory_map(),
            other => anyhow::bail!("Query type '{}' not supported", other),
        },

        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(_opts) => client.list_strings(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.clone(),
                    ctx.plan.fetch.offset,
                ),
                StringsCommands::Refs(args) => client.xrefs_to(args.string.clone()),
            }
        }

        Commands::Dump(cmd) => {
            use cli::DumpCommands;
            match cmd {
                DumpCommands::Imports(_) => client.list_imports(),
                DumpCommands::Exports(_) => client.list_exports(),
                DumpCommands::Functions(_opts) => client.list_functions(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.clone(),
                    ctx.plan.fetch.offset,
                    &[],
                    false,
                ),
                DumpCommands::Strings(_opts) => client.list_strings(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.clone(),
                    ctx.plan.fetch.offset,
                ),
            }
        }

        Commands::Summary(_) => client.program_info(),

        Commands::Stats(_) => client.stats(),

        _ => anyhow::bail!("Command not supported"),
    }
}
