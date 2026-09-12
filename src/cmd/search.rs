//! Search/xref/graph bridge commands (extracted from execute_via_bridge, P1).

use crate::cli;
use crate::cli::Commands;
use crate::ipc::client::BridgeClient;
use serde_json::json;

pub fn run(
    client: &BridgeClient,
    command: &Commands,
    ctx: &super::ExecCtx,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Commands::XRef(cmd) => {
            use cli::XRefCommands;
            match cmd {
                XRefCommands::To(args) => {
                    client.xrefs_to(args.target.resolved_target().to_string())
                }
                XRefCommands::From(args) => {
                    client.xrefs_from(args.target.resolved_target().to_string())
                }
                XRefCommands::List(args) => client.send_command(
                    "xrefs_list",
                    Some(json!({"address": args.target.resolved_target()})),
                ),
            }
        }

        Commands::Graph(cmd) => {
            use cli::GraphCommands;
            match cmd {
                GraphCommands::Calls(opts) => client.graph_calls(opts.limit.or(ctx.default_limit)),
                GraphCommands::Callers(args) => {
                    client.graph_callers(args.target.resolved_target(), args.depth)
                }
                GraphCommands::Callees(args) => {
                    client.graph_callees(args.target.resolved_target(), args.depth)
                }
                GraphCommands::Export(args) => client.graph_export(&args.format),
            }
        }

        Commands::Find(cmd) => {
            use cli::FindCommands;
            match cmd {
                FindCommands::String(args) => client.find_string(&args.pattern),
                FindCommands::Bytes(args) => client.find_bytes(&args.hex),
                FindCommands::Constant(args) => {
                    client.find_constant(&args.value, args.size, args.max, !args.no_refs)
                }
                FindCommands::Instruction(args) => client.find_instruction(
                    &args.pattern,
                    // `--limit` comes from the flattened QueryOptions; find
                    // instruction keeps its own 100-match default (0 = unlimited,
                    // matching the bridge's limit>0 convention).
                    args.options.limit.unwrap_or(100),
                    args.start.as_deref(),
                    args.end.as_deref(),
                    args.case_sensitive,
                ),
                FindCommands::Function(args) => client.find_function(&args.pattern),
                FindCommands::Calls(args) => client.find_calls(args.target.resolved_target()),
                FindCommands::Crypto(_) => client.find_crypto(),
                FindCommands::Interesting(_) => client.find_interesting(),
            }
        }

        _ => anyhow::bail!("Command not supported"),
    }
}
