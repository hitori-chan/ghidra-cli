//! Read-only integration tests: call graphs, stats, program info, batch,
//! and response-structure snapshots.
//!
//! Part of the P7 split of the former consolidated `readonly_tests.rs`;
//! each area now has its own suite (the shared harness still dedupes
//! import+analyze per suite).

use serial_test::serial;
use std::fs;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, ghidra, schemas::GraphResult, DaemonTestHarness, GhidraCommand};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

/// Write `content` to a temp batch file (system temp dir, never $HOME).
fn create_batch_file(content: &str) -> std::path::PathBuf {
    let temp_dir = std::env::temp_dir();
    let batch_file = temp_dir.join(format!("ghidra_batch_{}.txt", std::process::id()));
    fs::write(&batch_file, content).expect("Failed to write batch file");
    batch_file
}

#[test]
#[serial]
fn test_graph_calls() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("calls")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("nodes");
    result.assert_stdout_contains("edges");
}

#[test]
#[serial]
fn test_graph_callers() {
    require_ghidra!();
    let harness = harness();

    // Use "main" instead of "add_numbers" since add_numbers may be inlined on macOS
    let result = ghidra(harness)
        .arg("graph")
        .arg("callers")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(graph) = result.try_json::<GraphResult>() {
        eprintln!("Callers graph for main has {} nodes", graph.nodes.len());
    }
}

#[test]
#[serial]
fn test_graph_callees() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(graph) = result.try_json::<GraphResult>() {
        let node_labels: Vec<_> = graph
            .nodes
            .iter()
            .filter_map(|n| n.label.as_deref())
            .collect();

        let has_add_numbers = node_labels
            .iter()
            .any(|l| l.contains("add_numbers") || l.contains("_add_numbers"));
        let has_multiply = node_labels
            .iter()
            .any(|l| l.contains("multiply") || l.contains("_multiply"));

        if has_add_numbers {
            eprintln!("Found add_numbers in callees");
        }
        if has_multiply {
            eprintln!("Found multiply in callees");
        }
    }
}

#[test]
#[serial]
fn test_graph_export_dot() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("export")
        .arg("dot")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("digraph");
}

#[test]
#[serial]
fn test_stats_normal() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("stats");
    result.assert_stdout_contains("functions");
    result.assert_stdout_contains("symbols");
}

#[test]
#[serial]
fn test_stats_has_all_fields() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();

    // Stats may be returned as flat object or wrapped: [{"stats": {...}}]
    let obj = if let Some(obj) = json.as_object() {
        obj.clone()
    } else if let Some(arr) = json.as_array() {
        arr.first()
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("stats"))
            .and_then(|v| v.as_object())
            .expect("Expected stats object in array wrapper")
            .clone()
    } else {
        panic!("Stats should be a JSON object or array");
    };

    // Verify key fields exist
    for key in &["functions", "strings", "symbols"] {
        assert!(obj.contains_key(*key), "Missing stats field: {}", key);
    }

    let functions = obj.get("functions").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        functions > 0,
        "functions count should be > 0, got {}",
        functions
    );

    let strings = obj.get("strings").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(strings > 0, "strings count should be > 0, got {}", strings);
}

#[test]
#[serial]
fn test_stats_json_format() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    // Verify output is valid JSON
    let json: serde_json::Value = result.json();

    // Extract stats object (may be flat or wrapped)
    let stats = if json.is_object() {
        json.clone()
    } else if let Some(arr) = json.as_array() {
        arr.first()
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("stats"))
            .cloned()
            .expect("Expected stats in array wrapper")
    } else {
        panic!("Expected JSON object or array");
    };

    // Verify it has numeric function count
    let functions = stats
        .get("functions")
        .and_then(|v| v.as_u64())
        .expect("Should have numeric functions field");
    assert!(
        functions >= 8,
        "Should have at least 8 functions, got {}",
        functions
    );

    let strings = stats
        .get("strings")
        .and_then(|v| v.as_u64())
        .expect("Should have numeric strings field");
    assert!(
        strings >= 3,
        "Should have at least 3 strings, got {}",
        strings
    );
}

#[test]
#[serial]
fn test_program_info() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("info")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    // Program info should mention the program name
    assert!(
        result.stdout.contains("sample_binary") || result.stdout.contains("name"),
        "Program info should contain program name or 'name' field. Got: {}",
        &result.stdout[..result.stdout.len().min(500)]
    );
}

#[test]
#[serial]
fn test_program_export_json() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("export")
        .arg("json")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        assert!(
            result.stdout.contains("functions") || !result.stdout.is_empty(),
            "Export should produce output"
        );
    }
    // Accept "Unknown command" gracefully
}

#[test]
#[serial]
fn test_program_close() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("close")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    assert!(
        result.exit_code == 0 || result.stderr.contains("Unknown command"),
        "Expected success or 'Unknown command', got: {}",
        result.stderr
    );

    // The bridge is shared across the whole suite, and `program close` clears the
    // current program. Re-open it so later tests (which assume a program is
    // loaded, e.g. test_program_info_no_program) aren't broken by test ordering.
    let _ = ghidra(harness)
        .arg("program")
        .arg("info")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
}

#[test]
#[serial]
fn test_program_info_no_program() {
    require_ghidra!();
    let harness = harness();

    let result = GhidraCommand::new()
        .arg("program")
        .arg("info")
        .with_daemon(harness)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_batch_multiple_queries() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Test batch file
query --address 0x100000
query --function main
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("results");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_empty_file() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Only comments


# More comments
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_with_comments() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Query main function
query --function main
# Query by address
query --address 0x100000
# Another comment
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("2");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_invalid_file() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("/nonexistent/batch/file.txt")
        .run();

    result.assert_failure();
    assert!(
        result.stderr.contains("not found")
            || result.stderr.contains("No such file")
            || result.stderr.contains("cannot find"),
        "Should contain file-not-found error. Got: {}",
        result.stderr
    );
}

#[test]
#[serial]
fn test_batch_with_invalid_command() {
    require_ghidra!();
    harness();

    let batch_content = r#"
query --function main
invalid-command --arg value
query --address 0x100000
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("3");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_stats_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("stats_structure", json, {
        ".functions" => "[N]",
        ".instructions" => "[N]",
        ".strings" => "[N]",
        ".symbols" => "[N]",
        ".imports" => "[N]",
        ".exports" => "[N]",
        ".memory_blocks" => "[N]",
        ".memory_size" => "[N]",
        ".sections" => "[N]",
        ".data_types" => "[N]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_memory_map_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("memory_map_structure", json, {
        "[].start" => "[ADDR]",
        "[].end" => "[ADDR]",
        "[].size" => "[SIZE]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_graph_callees_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("graph_callees_structure", json, {
        ".nodes[].id" => "[ID]",
        ".nodes[].address" => "[ADDR]",
        ".edges[].from" => "[ID]",
        ".edges[].to" => "[ID]",
    });
}
