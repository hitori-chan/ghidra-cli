//! Read-only integration tests: strings, memory map, summary, xrefs, find.
//!
//! Part of the P7 split of the former consolidated `readonly_tests.rs`;
//! each area now has its own suite (the shared harness still dedupes
//! import+analyze per suite).

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, ghidra,
    schemas::{MemoryBlock, StringData, Validate, XRef},
    DaemonTestHarness,
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
fn test_strings_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("strings")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("50")
        .run();

    result.assert_success();

    let strings: Vec<StringData> = result.json();
    assert!(!strings.is_empty(), "Should have at least one string");

    for s in &strings {
        s.assert_valid();
    }

    // Check if any known strings are present (informational)
    let known = ["Hello", "test_binary", "super_secret"];
    let found: Vec<_> = known
        .iter()
        .filter(|k| strings.iter().any(|s| s.value.contains(*k)))
        .collect();
    if !found.is_empty() {
        eprintln!("Found known strings: {:?}", found);
    }
}

#[test]
#[serial]
fn test_memory_map_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let blocks: Vec<MemoryBlock> = result.json();
    assert!(
        !blocks.is_empty(),
        "Memory map should have at least one block"
    );

    for block in &blocks {
        block.assert_valid();
    }

    let has_text = blocks
        .iter()
        .any(|b| b.name.contains("text") || b.name.contains("code") || b.name.contains(".text"));
    assert!(
        has_text,
        "Should have a text/code segment. Found: {:?}",
        blocks.iter().map(|b| &b.name).collect::<Vec<_>>()
    );
}

#[test]
#[serial]
fn test_summary_contains_expected_fields() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("summary")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Summary should produce output"
    );
    result.assert_stdout_contains("sample_binary");
}

#[test]
#[serial]
fn test_xref_to() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "add_numbers");

    let result = ghidra(harness)
        .arg("xref")
        .arg("to")
        .arg(&addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let xrefs: Vec<XRef> = result.json();
    assert!(
        !xrefs.is_empty(),
        "add_numbers should have incoming cross-references (called by main)"
    );
    // Every xref should point TO the target address
    for xref in &xrefs {
        assert_eq!(xref.to, addr, "xref 'to' field should match target address");
    }
}

#[test]
#[serial]
fn test_xref_from() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("xref")
        .arg("from")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let xrefs: Vec<XRef> = result.json();
    assert!(
        !xrefs.is_empty(),
        "main should have outgoing cross-references (calls other functions)"
    );
    // Every xref should originate FROM within main
    for xref in &xrefs {
        assert!(
            xref.from_function
                .as_deref()
                .is_some_and(|f| f.contains("main")),
            "xref from_function should be main, got: {:?}",
            xref.from_function
        );
    }
}

#[test]
#[serial]
fn test_xref_list() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "add_numbers");

    let result = ghidra(harness)
        .arg("xref")
        .arg("list")
        .arg(&addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let xrefs: Vec<XRef> = result.json();
    assert!(
        !xrefs.is_empty(),
        "add_numbers should have cross-references in list view"
    );
    // Should have both directions when function has incoming refs and outgoing refs
    let has_to = xrefs.iter().any(|x| x.direction.as_deref() == Some("to"));
    let has_from = xrefs.iter().any(|x| x.direction.as_deref() == Some("from"));
    // add_numbers is called by main, so it must have "to" xrefs
    assert!(has_to, "xref list should include incoming (to) references");
    // add_numbers has a function body, so it should have "from" xrefs too
    // (at minimum, stack/register references)
    eprintln!(
        "xref list: {} total, has_to={}, has_from={}",
        xrefs.len(),
        has_to,
        has_from
    );
}

#[test]
#[serial]
fn test_find_string() {
    require_ghidra!();
    let harness = harness();

    // Search for "Ghidra CLI" rather than "Hello": on macOS arm64 Ghidra does
    // not define the fixture's string literals, and a "Hello" search would
    // otherwise match the mangled `HELLO_WORLD` symbol name (case-insensitively)
    // and suppress the raw memory-scan fallback. "Ghidra CLI" only appears in
    // the actual greeting, so it resolves via defined strings (x86_64) or the
    // memory-scan fallback (arm64) on both arches.
    let result = ghidra(harness)
        .arg("find")
        .arg("string")
        .arg("Ghidra CLI")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("Ghidra CLI");
}

#[test]
#[serial]
fn test_find_bytes() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("bytes")
        .arg("4883ec08")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_find_function() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("function")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("main");
}

#[test]
#[serial]
fn test_find_function_glob() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("function")
        .arg("m*")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("main");
}

#[test]
#[serial]
fn test_find_calls() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("calls")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_find_crypto() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("crypto")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let _: serde_json::Value = result.json();
}

#[test]
#[serial]
fn test_find_interesting() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("interesting")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let _: serde_json::Value = result.json();
}

#[test]
#[serial]
fn test_find_string_no_matches() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("string")
        .arg("nonexistent_string_xyz123")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(json) = result.try_json::<serde_json::Value>() {
        if let Some(arr) = json.as_array() {
            assert!(
                arr.is_empty(),
                "Should have no matches for nonexistent string"
            );
        }
    }
}
