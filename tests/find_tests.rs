//! Tests for the RE-workflow additions: `find constant`, `find instruction`,
//! `decompile-multi`, `raw`, `disasm --end`, and the GD_PROJECT/GD_PROGRAM
//! environment fallbacks.

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, DaemonTestHarness, GhidraCommand};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

/// Parse a hex address like "00118b40" or "0x118b40" into u64.
fn addr_to_u64(addr: &str) -> u64 {
    let s = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .unwrap_or(addr);
    u64::from_str_radix(s, 16).expect("address must be hex")
}

#[test]
#[serial]
fn test_find_constant_locates_known_bytes() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    // Take the raw encoding of main's first instruction and interpret its
    // first 4 bytes as a little-endian u32. Scanning for that constant must
    // hit main's entry point itself (the bytes are right there).
    let dis = common::ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("1")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    dis.assert_success();
    let instructions: Vec<serde_json::Value> = dis.json();
    let bytes = instructions[0]["bytes"].as_str().expect("bytes field");
    assert!(
        bytes.len() >= 8,
        "first instruction too short to test 4-byte scan: {bytes}"
    );
    let b = |i: usize| u8::from_str_radix(&bytes[i * 2..i * 2 + 2], 16).unwrap();
    let value = u32::from_le_bytes([b(0), b(1), b(2), b(3)]);
    let expected_at = addr_to_u64(&main_addr);

    let result = common::ghidra(harness)
        .arg("find")
        .arg("constant")
        .arg(format!("0x{value:x}"))
        .arg("--size")
        .arg("4")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    result.assert_success();

    let rows: Vec<serde_json::Value> = result.json();
    assert!(!rows.is_empty(), "expected hits for 0x{value:x}");
    let hit_addrs: Vec<u64> = rows
        .iter()
        .map(|r| addr_to_u64(r["address"].as_str().unwrap()))
        .collect();
    assert!(
        hit_addrs.contains(&expected_at),
        "hits {hit_addrs:?} must include 0x{expected_at:x} (the instruction's own bytes)"
    );
    for row in &rows {
        assert!(row.get("block").is_some(), "hits carry a block name");
    }
}

#[test]
#[serial]
fn test_find_constant_value_too_large_fails() {
    require_ghidra!();
    let harness = harness();

    let result = common::ghidra(harness)
        .arg("find")
        .arg("constant")
        .arg("0x1FFFFFFFFF")
        .arg("--size")
        .arg("4")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    assert_ne!(result.exit_code, 0, "overflowing value must fail");
    assert!(
        result.stderr.contains("does not fit"),
        "stderr: {}",
        result.stderr
    );
}

#[test]
#[serial]
fn test_find_instruction_case_insensitive_default() {
    require_ghidra!();
    let harness = harness();

    // Lowercase pattern must match uppercase x86 mnemonics by default...
    let ci = common::ghidra(harness)
        .arg("find")
        .arg("instruction")
        .arg("lea")
        .arg("--limit")
        .arg("5")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    ci.assert_success();
    let rows: Vec<serde_json::Value> = ci.json();
    assert!(!rows.is_empty(), "case-insensitive 'lea' should match LEA");
    assert!(rows.len() <= 5, "limit 5 respected, got {}", rows.len());
    for row in &rows {
        assert!(row.get("address").is_some());
        assert!(row.get("disasm").is_some());
    }

    // ...but not when --case-sensitive is set.
    let cs = common::ghidra(harness)
        .arg("find")
        .arg("instruction")
        .arg("lea")
        .arg("--case-sensitive")
        .arg("--limit")
        .arg("5")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    cs.assert_success();
    let rows: Vec<serde_json::Value> = cs.json();
    assert!(rows.is_empty(), "case-sensitive 'lea' must not match LEA");
}

#[test]
#[serial]
fn test_find_instruction_range_bound() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let start = addr_to_u64(&main_addr);
    let end = start + 0x20;

    let result = common::ghidra(harness)
        .arg("find")
        .arg("instruction")
        .arg("lea")
        .arg("--start")
        .arg(&main_addr)
        .arg("--end")
        .arg(format!("0x{end:x}"))
        .arg("--limit")
        .arg("100")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    result.assert_success();
    let rows: Vec<serde_json::Value> = result.json();
    for row in &rows {
        let a = addr_to_u64(row["address"].as_str().unwrap());
        assert!(
            (start..=end).contains(&a),
            "match 0x{a:x} outside [0x{start:x}, 0x{end:x}]"
        );
    }
}

#[test]
#[serial]
fn test_decompile_multi_returns_all_targets() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let mid = format!("0x{:x}", addr_to_u64(&main_addr) + 8);

    let result = common::ghidra(harness)
        .arg("decompile-multi")
        .arg(&main_addr)
        .arg(&mid)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .timeout(120)
        .run();
    result.assert_success();

    let rows: Vec<serde_json::Value> = result.json();
    assert_eq!(rows.len(), 2, "one result per target:\n{}", result.stdout);
    assert_eq!(rows[0]["name"], "main");
    assert!(rows[0]["code"].is_string(), "first target decompiled");
}

#[test]
#[serial]
fn test_raw_program_info() {
    require_ghidra!();
    let harness = harness();

    let result = common::ghidra(harness)
        .arg("raw")
        .arg("program_info")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    result.assert_success();
    let rows: Vec<serde_json::Value> = result.json();
    assert_eq!(rows[0]["name"], TEST_PROGRAM);
}

#[test]
#[serial]
fn test_raw_rejects_non_object_args() {
    require_ghidra!();
    let harness = harness();

    // Valid JSON, but not an object.
    let result = common::ghidra(harness)
        .arg("raw")
        .arg("program_info")
        .arg("42")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    assert_ne!(result.exit_code, 0);
    assert!(
        result.stderr.contains("must be a JSON object"),
        "stderr: {}",
        result.stderr
    );

    // Not JSON at all.
    let result = common::ghidra(harness)
        .arg("raw")
        .arg("program_info")
        .arg("not-json")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    assert_ne!(result.exit_code, 0);
    assert!(
        result.stderr.contains("Invalid JSON"),
        "stderr: {}",
        result.stderr
    );
}

#[test]
#[serial]
fn test_disasm_end_bounded() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let start = addr_to_u64(&main_addr);
    let end = start + 0x10;

    let result = common::ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--end")
        .arg(format!("0x{end:x}"))
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    result.assert_success();

    let rows: Vec<serde_json::Value> = result.json();
    assert!(!rows.is_empty());
    for row in &rows {
        let a = addr_to_u64(row["address"].as_str().unwrap());
        assert!(a <= end, "disasm exceeded --end: 0x{a:x} > 0x{end:x}");
    }
}

#[test]
#[serial]
fn test_env_project_program_fallback() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    // No --project/--program flags: GD_PROJECT/GD_PROGRAM must carry the context.
    let result = GhidraCommand::new()
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("1")
        .env("GD_PROJECT", TEST_PROJECT)
        .env("GD_PROGRAM", TEST_PROGRAM)
        .json_format()
        .timeout(120)
        .run();
    result.assert_success();
    let rows: Vec<serde_json::Value> = result.json();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        addr_to_u64(rows[0]["address"].as_str().unwrap()),
        addr_to_u64(&main_addr)
    );
}
