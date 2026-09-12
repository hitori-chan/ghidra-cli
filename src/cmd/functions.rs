//! Function-view bridge commands (extracted from execute_via_bridge, P1).

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
        Commands::Decompile(args) => client.decompile(
            args.target.resolved_target().to_string(),
            args.with_vars,
            args.with_params,
        ),

        Commands::DecompileMulti(args) => client.decompile_multi(&args.targets),

        Commands::Function(cmd) => {
            use cli::FunctionCommands;
            match cmd {
                FunctionCommands::List(args) => client.list_functions(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.clone(),
                    ctx.plan.fetch.offset,
                    &args.tags,
                    args.untagged,
                ),
                FunctionCommands::Decompile(args) => client.decompile(
                    args.target.resolved_target().to_string(),
                    args.with_vars,
                    args.with_params,
                ),
                FunctionCommands::Get(args) => client.send_command(
                    "get_function",
                    Some(json!({"address": args.target.resolved_target()})),
                ),
                FunctionCommands::Disasm(args) => {
                    client.disasm(args.target.resolved_target(), None, None, true)
                }
                FunctionCommands::Calls(args) => client.find_calls(args.target.resolved_target()),
                FunctionCommands::XRefs(args) => {
                    client.xrefs_to(args.target.resolved_target().to_string())
                }
                FunctionCommands::Rename(args) => client.send_command(
                    "rename_function",
                    Some(json!({
                        "old_name": args.old_name,
                        "new_name": args.new_name,
                    })),
                ),
                FunctionCommands::Create(args) => client.send_command(
                    "create_function",
                    Some(json!({
                        "address": args.address,
                        "name": args.name,
                    })),
                ),
                FunctionCommands::Delete(args) => client.send_command(
                    "delete_function",
                    Some(json!({
                        "address": args.target.resolved_target(),
                    })),
                ),
                FunctionCommands::SetSignature(args) => client.send_command(
                    "function_set_signature",
                    Some(json!({
                        "target": args.target.resolved_target(),
                        "signature": args.signature,
                    })),
                ),
                FunctionCommands::SetReturnType(args) => client.send_command(
                    "function_set_return_type",
                    Some(json!({
                        "target": args.target.resolved_target(),
                        "return_type": args.return_type,
                    })),
                ),
                FunctionCommands::SetCallingConvention(args) => client.send_command(
                    "function_set_calling_convention",
                    Some(json!({
                        "target": args.target.resolved_target(),
                        "convention": args.convention,
                    })),
                ),
                FunctionCommands::SetVarType(args) => client.send_command(
                    "set_var_type",
                    Some(json!({
                        "function": args.target.resolved_target(),
                        "var_name": args.var_name,
                        "type_name": args.type_name,
                    })),
                ),
            }
        }

        Commands::Disasm(args) => client.disasm(
            args.target.resolved_target(),
            args.num_instructions,
            args.end.as_deref(),
            !args.no_resolve,
        ),

        _ => anyhow::bail!("Command not supported"),
    }
}
