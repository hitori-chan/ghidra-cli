//! Mutation bridge commands (extracted from execute_via_bridge, P1).

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
        Commands::Symbol(cmd) => {
            use cli::SymbolCommands;
            match cmd {
                SymbolCommands::List(_opts) => client.symbol_list(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.as_deref(),
                    ctx.plan.fetch.offset,
                ),
                SymbolCommands::Get(args) => client.symbol_get(&args.name),
                SymbolCommands::Create(args) => client.symbol_create(&args.address, &args.name),
                SymbolCommands::Delete(args) => client.symbol_delete(&args.name),
                SymbolCommands::Rename(args) => {
                    client.symbol_rename(&args.old_name, &args.new_name)
                }
            }
        }

        Commands::Type(cmd) => {
            use cli::TypeCommands;
            match cmd {
                TypeCommands::List(_opts) => client.type_list(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.as_deref(),
                    ctx.plan.fetch.offset,
                ),
                TypeCommands::Get(args) => client.type_get(&args.name),
                TypeCommands::Create(args) => client.type_create(&args.definition),
                TypeCommands::Apply(args) => client.type_apply(&args.address, &args.type_name),
                TypeCommands::Delete(args) => {
                    client.send_command("type_delete", Some(json!({"name": args.name})))
                }
                TypeCommands::Rename(args) => client.send_command(
                    "type_rename",
                    Some(json!({"old_name": args.old_name, "new_name": args.new_name})),
                ),
                TypeCommands::CreateEnum(args) => client.send_command(
                    "type_create_enum",
                    Some(json!({
                        "name": args.name,
                        "values": args.values,
                        "size": args.size,
                    })),
                ),
                TypeCommands::Typedef(args) => client.send_command(
                    "type_typedef",
                    Some(json!({
                        "name": args.name,
                        "base_type": args.base_type,
                    })),
                ),
                TypeCommands::AddField(args) => client.send_command(
                    "type_add_field",
                    Some(json!({
                        "type_name": args.type_name,
                        "field_name": args.name,
                        "field_type": args.field_type,
                        "offset": args.offset,
                        "size": args.size,
                    })),
                ),
                TypeCommands::DelField(args) => client.send_command(
                    "type_del_field",
                    Some(json!({
                        "type_name": args.type_name,
                        "field_name": args.name,
                    })),
                ),
            }
        }

        Commands::Tag(cmd) => {
            use cli::TagCommands;
            match cmd {
                TagCommands::List(args) => {
                    client.tag_list(ctx.plan.fetch.limit, args.function.as_deref())
                }
                TagCommands::Get(args) => client.tag_get(&args.name, ctx.plan.fetch.limit),
                TagCommands::Create(args) => client.send_command(
                    "tag_create",
                    Some(json!({"name": args.name, "comment": args.comment})),
                ),
                TagCommands::Delete(args) => {
                    client.send_command("tag_delete", Some(json!({"name": args.name})))
                }
                TagCommands::Rename(args) => client.send_command(
                    "tag_rename",
                    Some(json!({"name": args.old_name, "new_name": args.new_name})),
                ),
                TagCommands::SetComment(args) => client.send_command(
                    "tag_set_comment",
                    Some(json!({"name": args.name, "comment": args.comment})),
                ),
                TagCommands::Add(args) => client.send_command(
                    "tag_add",
                    Some(json!({
                        "function": args.target,
                        "tags": args.tags,
                        "no_create": args.no_create,
                    })),
                ),
                TagCommands::Remove(args) => client.send_command(
                    "tag_remove",
                    Some(json!({
                        "function": args.target,
                        "tags": args.tags,
                        "all": args.all,
                    })),
                ),
            }
        }

        Commands::Comment(cmd) => {
            use cli::CommentCommands;
            match cmd {
                CommentCommands::List(_opts) => client.comment_list(
                    ctx.plan.fetch.limit,
                    ctx.plan.fetch.filter.as_deref(),
                    ctx.plan.fetch.offset,
                ),
                CommentCommands::Get(args) => client.comment_get(&args.address),
                CommentCommands::Set(args) => {
                    client.comment_set(&args.address, &args.text, args.comment_type.as_deref())
                }
                CommentCommands::Delete(args) => client.comment_delete(&args.address),
            }
        }

        Commands::Patch(cmd) => {
            use cli::PatchCommands;
            match cmd {
                PatchCommands::Bytes(args) => client.patch_bytes(&args.address, &args.hex),
                PatchCommands::Nop(args) => client.patch_nop(&args.address, args.count),
                PatchCommands::Export(args) => client.patch_export(&args.output),
            }
        }

        Commands::Rename(args) => client.symbol_rename(&args.old_name, &args.new_name),

        _ => anyhow::bail!("Command not supported"),
    }
}
