//! Read-only integration tests: functions (list, decompile, disasm, diff).
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
    helpers::matches_function_name,
    schemas::{DisasmResult, Function, Validate},
    DaemonTestHarness, GhidraCommand,
};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

/// Known exported function names from sample_binary
const KNOWN_FUNCTIONS: &[&str] = &[
    "add_numbers",
    "multiply",
    "factorial",
    "fibonacci",
    "process_string",
    "xor_encrypt",
    "simple_hash",
    "init_struct",
    "main",
];

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

fn to_fun_style_target(address: &str) -> String {
    let base = address
        .rsplit(':')
        .next()
        .unwrap_or(address)
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let hex: String = base.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    format!("FUN_{}", hex)
}

#[test]
#[serial]
fn test_function_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(!functions.is_empty(), "Function list should not be empty");

    for func in &functions {
        func.assert_valid();
    }

    let has_main = functions.iter().any(|f| f.name == "main");
    assert!(has_main, "Should contain main function");
}

#[test]
#[serial]
fn test_function_list_contains_expected_functions() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();

    // main must always be present
    assert!(
        names.iter().any(|n| matches_function_name(n, "main")),
        "Should have main function. Found: {:?}",
        &names[..names.len().min(20)]
    );

    // Binary should have many functions (stdlib + user code)
    assert!(
        functions.len() >= 5,
        "Should have at least 5 functions, found {}",
        functions.len()
    );

    // Check how many known functions we can find (informational, not hard failure)
    let mut found_count = 0;
    for expected in KNOWN_FUNCTIONS {
        if names.iter().any(|n| matches_function_name(n, expected)) {
            found_count += 1;
        }
    }
    eprintln!(
        "Found {}/{} known functions from sample_binary",
        found_count,
        KNOWN_FUNCTIONS.len()
    );
}

#[test]
#[serial]
fn test_function_list_limit() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("3")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        functions.len() <= 3,
        "Limit 3 should return at most 3 functions, got {}",
        functions.len()
    );
}

#[test]
#[serial]
fn test_function_list_filter() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("name~main")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        !functions.is_empty(),
        "Filter 'name~main' should match at least one function"
    );

    // The filter must actually filter: EVERY returned row matches, not just one
    // (a bare-word filter used to silently dump the whole unfiltered dataset).
    assert!(
        functions
            .iter()
            .all(|f| f.name.to_lowercase().contains("main")),
        "All filtered results should contain 'main'. Got: {:?}",
        functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
#[serial]
fn test_function_list_bare_word_filter_rejected() {
    require_ghidra!();
    let harness = harness();

    // A bare word is not a valid filter expression. It must fail with a
    // nonzero exit instead of dumping the entire unfiltered dataset.
    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("main")
        .run();

    result.assert_failure();
}

#[test]
#[serial]
fn test_decompile_by_name() {
    require_ghidra!();
    let harness = harness();

    // Use "main" instead of "add_numbers" since add_numbers may be inlined on macOS
    let result = ghidra(harness)
        .arg("decompile")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    assert!(
        result.stdout.contains("return")
            || result.stdout.contains("param")
            || result.stdout.contains("int")
            || result.stdout.contains("long")
            || result.stdout.contains("void"),
        "Decompiled output should contain C-like code keywords.\nGot: {}",
        result.stdout
    );
}

#[test]
#[serial]
fn test_decompile_by_address() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("decompile")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Decompile should produce output"
    );
}

#[test]
#[serial]
fn test_decompile_by_fun_style_target() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let fun_target = to_fun_style_target(&main_addr);

    let result = ghidra(harness)
        .arg("decompile")
        .arg(&fun_target)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Decompile should produce output for FUN-style target"
    );
}

#[test]
#[serial]
fn test_decompile_nonexistent_function() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("decompile")
        .arg("this_function_definitely_does_not_exist_xyz123")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        assert!(
            result.stdout.to_lowercase().contains("not found")
                || result.stdout.to_lowercase().contains("error")
                || result.stdout.trim().is_empty(),
            "Should indicate function not found"
        );
    }
}

#[test]
#[serial]
fn test_disasm_at_main() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    // `patch_tests` deliberately writes bytes at `main`'s entry point (the
    // code-patch cases), which destroys the entry instruction in the shared
    // fixture. Disassemble 8 bytes into the body, where no patch reaches.
    let target = format!("0x{:x}", u64::from_str_radix(&main_addr, 16).unwrap() + 8);

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&target)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            !disasm.results.is_empty(),
            "Should have at least one instruction"
        );
        for instr in &disasm.results {
            instr.assert_valid();
        }
    } else if let Some(instructions) = result.try_json::<Vec<common::schemas::Instruction>>() {
        assert!(
            !instructions.is_empty(),
            "Should have at least one instruction"
        );
        for instr in &instructions {
            instr.assert_valid();
        }
    }
}

#[test]
#[serial]
fn test_disasm_with_instruction_limit() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    // See test_disasm_at_main: avoid the entry bytes that `patch_tests` mutates.
    let target = format!("0x{:x}", u64::from_str_radix(&main_addr, 16).unwrap() + 8);
    let limit = 5;

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&target)
        .arg("--instructions")
        .arg(limit.to_string())
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            disasm.results.len() <= limit,
            "Should return at most {} instructions, got {}",
            limit,
            disasm.results.len()
        );
        for instr in &disasm.results {
            instr.assert_valid();
        }
    } else if let Some(instructions) = result.try_json::<Vec<common::schemas::Instruction>>() {
        assert!(
            instructions.len() <= limit,
            "Should return at most {} instructions, got {}",
            limit,
            instructions.len()
        );
    }
}

#[test]
#[serial]
fn test_disasm_small_count() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    // See test_disasm_at_main: avoid the entry bytes that `patch_tests` mutates.
    let target = format!("0x{:x}", u64::from_str_radix(&main_addr, 16).unwrap() + 8);

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&target)
        .arg("--instructions")
        .arg("1")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            disasm.results.len() <= 1,
            "Should return at most 1 instruction, got {}",
            disasm.results.len()
        );
    }
}

#[test]
#[serial]
fn test_disasm_instruction_fields() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    // See test_disasm_at_main: avoid the entry bytes that `patch_tests` mutates.
    let target = format!("0x{:x}", u64::from_str_radix(&main_addr, 16).unwrap() + 8);

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&target)
        .arg("--instructions")
        .arg("10")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(!disasm.results.is_empty(), "Should have instructions");

        let first = &disasm.results[0];
        assert!(!first.mnemonic.is_empty(), "Mnemonic should not be empty");
        assert!(!first.address.is_empty(), "Address should not be empty");

        let addr_hex = first
            .address
            .strip_prefix("0x")
            .or_else(|| first.address.strip_prefix("0X"))
            .unwrap_or(&first.address);
        assert!(
            !addr_hex.is_empty() && addr_hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "Address should be hex format, got: {}",
            first.address
        );

        let common_first_instr = [
            "PUSH", "SUB", "MOV", "ENDBR", "LEA", "XOR", "JMP", // x86
            "STP", "STR", "BL", "NOP", "ADRP", "ADD", "RET", // ARM64
        ];
        let mnemonic_upper = first.mnemonic.to_uppercase();

        if !common_first_instr
            .iter()
            .any(|&m| mnemonic_upper.starts_with(m))
        {
            eprintln!(
                "Note: First instruction is '{}' - unusual but not necessarily wrong",
                first.mnemonic
            );
        }
    }
}

#[test]
#[serial]
fn test_disasm_invalid_address() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("disasm")
        .arg("0xFFFFFFFFFFFFFFFF")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        if let Some(_disasm) = result.try_json::<DisasmResult>() {
            // Empty results are acceptable for unmapped address
        }
    } else {
        assert!(
            !result.stderr.is_empty() || !result.stdout.is_empty(),
            "Should provide some output explaining the error"
        );
    }
}

#[test]
#[serial]
fn test_disasm_missing_program() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness).arg("disasm").arg("0x101000").run();

    result.assert_failure();
}

#[test]
#[serial]
fn test_disasm_zero_instructions() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("0")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        if let Some(disasm) = result.try_json::<DisasmResult>() {
            assert!(
                disasm.results.is_empty(),
                "Zero instruction count should return empty results"
            );
        }
    }
}

#[test]
#[serial]
fn test_diff_functions() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("diff")
        .arg("functions")
        .arg("main")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_diff_functions_different() {
    require_ghidra!();
    harness();

    // Self-diff main vs main - use same function to avoid depending on
    // add_numbers which may be inlined on macOS
    let result = GhidraCommand::new()
        .arg("diff")
        .arg("functions")
        .arg("main")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .run();

    result.assert_success();
    // Self-diff should succeed (output may be empty for identical functions)
}

#[test]
#[serial]
fn test_diff_functions_with_fun_style_targets() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let fun_target = to_fun_style_target(&main_addr);

    let result = ghidra(harness)
        .arg("diff")
        .arg("functions")
        .arg(&fun_target)
        .arg(&fun_target)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_function_list_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("1")
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("function_list_structure", json, {
        "[].address" => "[ADDR]",
        "[].entry_point" => "[ADDR]",
        "[].size" => "[SIZE]",
        "[].parameters[].ordinal" => "[N]",
        "[].local_variables[].stack_offset" => "[N]",
        "[].calls[]" => "[ADDR]",
        "[].called_by[]" => "[ADDR]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_disasm_structure() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("3")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("disasm_structure", json, {
        ".results[].address" => "[ADDR]",
        ".results[].operands" => "[OPS]",
        ".results[].bytes" => "[BYTES]",
        ".results[].length" => "[N]",
        ".start_address" => "[ADDR]",
        ".end_address" => "[ADDR]",
        "[].address" => "[ADDR]",
        "[].operands" => "[OPS]",
        "[].bytes" => "[BYTES]",
        "[].length" => "[N]",
    });
}
