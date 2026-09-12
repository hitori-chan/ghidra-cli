//! Help-output snapshots: the CLI surface is a stable contract for agents and
//! scripts. These capture the top-level command tree and the help pages of
//! the command groups whose argument surface was restructured in the
//! CommandMeta/TargetArgs refactor (docs/history/refactor-plan.md P1).
//!
//! If a snapshot fails, the help text changed: review the diff deliberately
//! and update the snapshot (`INSTA_UPDATE=always cargo test --test
//! help_snapshot`), or fix the code.

use assert_cmd::cargo::cargo_bin_cmd;

fn help(args: &[&str]) -> String {
    let out = cargo_bin_cmd!("gd")
        .args(args)
        .output()
        .expect("running --help should succeed");
    assert!(
        out.status.success(),
        "help for {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn snapshot_top_level_help() {
    insta::assert_snapshot!("gd_help", help(&["--help"]));
}

// Groups whose positional TARGET / --target surface moved to TargetArgs.
#[test]
fn snapshot_decompile_help() {
    insta::assert_snapshot!("decompile_help", help(&["decompile", "--help"]));
}

#[test]
fn snapshot_disasm_help() {
    insta::assert_snapshot!("disasm_help", help(&["disasm", "--help"]));
}

#[test]
fn snapshot_function_help() {
    insta::assert_snapshot!("function_help", help(&["function", "--help"]));
}

#[test]
fn snapshot_function_get_help() {
    insta::assert_snapshot!("function_get_help", help(&["function", "get", "--help"]));
}

#[test]
fn snapshot_function_decompile_help() {
    insta::assert_snapshot!(
        "function_decompile_help",
        help(&["function", "decompile", "--help"])
    );
}

#[test]
fn snapshot_function_set_signature_help() {
    insta::assert_snapshot!(
        "function_set_signature_help",
        help(&["function", "set-signature", "--help"])
    );
}

#[test]
fn snapshot_xref_help() {
    insta::assert_snapshot!("xref_help", help(&["x-ref", "--help"]));
}

#[test]
fn snapshot_find_help() {
    insta::assert_snapshot!("find_help", help(&["find", "--help"]));
}

#[test]
fn snapshot_graph_help() {
    insta::assert_snapshot!("graph_help", help(&["graph", "--help"]));
}

#[test]
fn snapshot_raw_help() {
    insta::assert_snapshot!("raw_help", help(&["raw", "--help"]));
}

// Core query/ingest groups: anchor the rest of the tree.
#[test]
fn snapshot_query_help() {
    insta::assert_snapshot!("query_help", help(&["query", "--help"]));
}

#[test]
fn snapshot_import_help() {
    insta::assert_snapshot!("import_help", help(&["import", "--help"]));
}

#[test]
fn snapshot_batch_help() {
    insta::assert_snapshot!("batch_help", help(&["batch", "--help"]));
}

#[test]
fn snapshot_analyze_help() {
    insta::assert_snapshot!("analyze_help", help(&["analyze", "--help"]));
}
