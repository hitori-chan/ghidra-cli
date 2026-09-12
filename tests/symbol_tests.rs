//! Tests for symbol operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

#[test]
#[serial]
fn test_symbol_list() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(output.status.success(), "symbol list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Known functions should appear as symbols
    // On macOS, names may have underscore prefix
    assert!(
        stdout.contains("main") || stdout.contains("_main"),
        "symbol list should contain main. Output: {}",
        stdout
    );
}

#[test]
#[serial]
fn test_symbol_create_and_get() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("create")
        .arg(&addr)
        .arg("test_symbol")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("get")
        .arg("test_symbol")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test_symbol"));
}

#[test]
#[serial]
fn test_symbol_rename() {
    require_ghidra!();
    let harness = harness();

    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 2);
    let addr = &addrs[1];

    // Use unique names to avoid collisions with cached project state
    let old_name = format!("old_sym_{}", std::process::id());
    let new_name = format!("new_sym_{}", std::process::id());

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("create")
        .arg(addr)
        .arg(&old_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("rename")
        .arg(&old_name)
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify new symbol exists
    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("get")
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(&*new_name));
}

#[test]
#[serial]
fn test_symbol_get_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("symbol")
        .arg("get")
        .arg("nonexistent_symbol_12345")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

#[test]
#[serial]
fn test_symbol_list_offset_pages_server_side() {
    require_ghidra!();
    let _harness = harness();

    let cmd = |extra: &[&str]| {
        let mut c = assert_cmd::cargo::cargo_bin_cmd!("gd");
        c.arg("symbol")
            .arg("list")
            .arg("--project")
            .arg(TEST_PROJECT)
            .arg("--program")
            .arg(TEST_PROGRAM);
        for a in extra {
            c.arg(a);
        }
        c
    };

    // Ground truth: the full symbol set (bridge iteration order).
    let full = cmd(&["--limit", "0", "--json"])
        .output()
        .expect("Failed to run full symbol list");
    assert!(full.status.success(), "full list should succeed");
    let all: Vec<serde_json::Value> =
        serde_json::from_slice(&full.stdout).expect("full list should be JSON");
    assert!(
        all.len() >= 5,
        "expected at least 5 symbols, got {}",
        all.len()
    );

    // Server-side page == local slice, exactly (order, rows, fields).
    let page = cmd(&["--offset", "2", "--limit", "3", "--json"])
        .output()
        .expect("Failed to run paged symbol list");
    assert!(page.status.success(), "paged list should succeed");
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&page.stdout).expect("paged list should be JSON");
    assert_eq!(
        rows,
        all[2..5],
        "server-side page must equal the client-side slice"
    );

    // A filtered page (exact pushdown) must equal the local filtered slice.
    let ffull = cmd(&["--filter", "name~main", "--json"])
        .output()
        .expect("Failed to run filtered symbol list");
    assert!(ffull.status.success());
    let fmatches: Vec<serde_json::Value> =
        serde_json::from_slice(&ffull.stdout).expect("filtered list should be JSON");
    assert!(
        !fmatches.is_empty(),
        "sample_binary should have a 'main' symbol"
    );

    let fpage = cmd(&[
        "--filter",
        "name~main",
        "--offset",
        "1",
        "--limit",
        "5",
        "--json",
    ])
    .output()
    .expect("Failed to run filtered paged symbol list");
    assert!(fpage.status.success());
    let frows: Vec<serde_json::Value> =
        serde_json::from_slice(&fpage.stdout).expect("filtered page should be JSON");
    let want: Vec<serde_json::Value> = fmatches.iter().skip(1).take(5).cloned().collect();
    assert_eq!(
        frows, want,
        "filtered server-side page must equal the client-side slice"
    );

    // Offset past the end is an empty page, not an error.
    let beyond = cmd(&["--offset", "999999", "--limit", "3", "--json"])
        .output()
        .expect("Failed to run beyond-end page");
    assert!(
        beyond.status.success(),
        "offset past the end should succeed"
    );
    assert_eq!(
        String::from_utf8_lossy(&beyond.stdout).trim(),
        "[]",
        "offset past the end should return an empty page"
    );
}
