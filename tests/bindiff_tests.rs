//! binDiff integration tests for `gd diff programs` (P8).
//!
//! Ghidra is always required (per AGENTS.md). The binDiff toolchain is an
//! optional third-party dependency: the heavy test skips with a message
//! when the `bindiff:` config (BinExport.jar + native differ) is absent,
//! but the Ghidra-side behavior (self-diff guard) is always tested.

use serial_test::serial;
use std::path::PathBuf;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness, GhidraCommand};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";
/// Patched copy imported for the cross-program diff.
const TEST_PROGRAM_ALT: &str = "sample_binary_alt";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

/// Self-diff is rejected: both sides must be distinct programs (the bridge
/// resolves names first, so this holds whether or not the named program is
/// the currently loaded one).
#[test]
#[serial]
fn test_diff_programs_self_diff_rejected() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .args(["diff", "programs", TEST_PROGRAM, TEST_PROGRAM])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_failure();
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("different programs") || combined.contains("BinDiff"),
        "Self-diff should be rejected with a clear message. Got: {}",
        combined
    );
}

/// Full binDiff pipeline: bridge exports both programs, the native differ
/// matches functions, the CLI parses the .BinDiff database. Skips when the
/// binDiff toolchain is not installed/configured.
#[test]
#[serial]
fn test_diff_programs_bindiff() {
    require_ghidra!();
    harness();

    // --- binDiff availability (optional third-party dependency) ---
    let cfg = ghidra_cli::config::Config::load().unwrap_or_default();
    let bindiff_cfg = match &cfg.bindiff {
        Some(c) => c,
        None => {
            eprintln!(
                "SKIP: no `bindiff:` config section (set bindiff.binexport_jar to the plain BinExport.jar)"
            );
            return;
        }
    };
    if !bindiff_cfg
        .binexport_jar
        .as_deref()
        .map(|p| p.is_file())
        .unwrap_or(false)
    {
        eprintln!("SKIP: bindiff.binexport_jar not found on this machine");
        return;
    }
    if let Err(e) = ghidra_cli::bindiff::find_differ(Some(bindiff_cfg)) {
        eprintln!("SKIP: native differ not available: {e}");
        return;
    }

    // --- Import a byte-patched copy of the fixture (idempotent) ---
    let patched = build_patched_fixture();
    let listed = GhidraCommand::new()
        .args(["program", "list", "--project", TEST_PROJECT])
        .run();
    if !listed.stdout.contains(TEST_PROGRAM_ALT) {
        let import = GhidraCommand::new()
            .args([
                "import",
                patched.to_str().unwrap(),
                "--program",
                TEST_PROGRAM_ALT,
                "--project",
                TEST_PROJECT,
            ])
            .timeout(600)
            .run();
        import.assert_success();
    }

    // --- Diff: all rows, unmatched included ---
    let result = GhidraCommand::new()
        .args([
            "diff",
            "programs",
            TEST_PROGRAM,
            TEST_PROGRAM_ALT,
            "--unmatched",
            "--limit",
            "0",
        ])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .timeout(600)
        .run();
    result.assert_success();

    let rows: Vec<serde_json::Value> = result.try_json().unwrap_or_else(|| {
        panic!(
            "diff output was not a JSON row array.\nstdout: {}\nstderr: {}",
            result.stdout, result.stderr
        )
    });
    let unmatched: Vec<_> = rows
        .iter()
        .filter(|r| r.get("unmatched").and_then(|v| v.as_str()).is_some())
        .collect();
    let matched: Vec<_> = rows
        .iter()
        .filter(|r| r.get("similarity").and_then(|v| v.as_f64()).is_some())
        .collect();

    // Basic shape: the fixture's main must be matched, similarities bounded.
    assert!(!matched.is_empty(), "expected matched function rows");
    assert!(
        matched
            .iter()
            .any(|r| r.get("name1").and_then(|v| v.as_str()) == Some("main")),
        "expected a matched row for main. Got: {}",
        result.stdout
    );
    for r in &matched {
        let s = r
            .get("similarity")
            .and_then(|v| v.as_f64())
            .expect("similarity");
        assert!((0.0..=1.0).contains(&s), "similarity out of range: {s}");
    }

    // The patch is a structural change inside a function body (the first
    // instruction of main becomes a RET), so binDiff must attribute it to a
    // changed match or an unmatched function — a silent 0 is a bug.
    let changed = matched
        .iter()
        .filter(|r| {
            r.get("similarity")
                .and_then(|v| v.as_f64())
                .is_some_and(|s| s < 1.0)
        })
        .count();
    assert!(
        changed + unmatched.len() >= 1,
        "the byte patch must be visible in the diff (changed={changed}, unmatched={})",
        unmatched.len()
    );

    // Count invariant: every primary function is matched or unmatched
    // exactly once (the .BinDiff table stores only matched pairs; unmatched
    // rows come from the bridge's function list).
    let count_cmd = GhidraCommand::new()
        .args(["function", "list", "--count"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    let primary_count: usize = count_cmd.stdout.trim().parse().unwrap_or_else(|_| {
        panic!(
            "function list --count did not return a number: {}",
            count_cmd.stdout
        )
    });
    let unmatched_primary = unmatched
        .iter()
        .filter(|r| r["unmatched"].as_str() == Some("primary"))
        .count();
    assert_eq!(
        matched.len() + unmatched_primary,
        primary_count,
        "matched + unmatched_primary must equal the primary program's function count (matched={}, unmatched_primary={}, primary={})",
        matched.len(),
        unmatched_primary,
        primary_count
    );
}

/// Patched copy of the fixture: the first instruction of `main` becomes a
/// RET (0xC3), a guaranteed *structural* change (binDiff normalizes
/// immediate constants, so a constant flip is not a reliable test delta).
/// Returns the path of the patched binary in the system temp dir (never in
/// $HOME).
fn build_patched_fixture() -> PathBuf {
    let data =
        std::fs::read(common::fixture_binary().to_str().unwrap()).expect("read fixture binary");

    // Ghidra's import base: PIEs are imported at a fixed base (e.g.
    // 0x100000), so Ghidra addresses are link-time VAs plus the base.
    // No --format flag: piped output auto-detects to compact JSON.
    let info = GhidraCommand::new()
        .args(["program", "info"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    info.assert_success();
    let info_stdout = info.stdout.clone();
    let info: serde_json::Value = info.try_json().expect("program info JSON");
    let info = match info {
        serde_json::Value::Array(mut v) => v
            .pop()
            .unwrap_or_else(|| panic!("empty program info: {}", info_stdout)),
        other => other,
    };
    let base = hex_u64(
        info.get("image_base")
            .and_then(|v| v.as_str())
            .expect("image_base"),
    );

    // Find an instruction to patch: the first one Ghidra disassembles in main.
    let dis = GhidraCommand::new()
        .args(["disasm", "main", "--instructions", "8"])
        .json_format()
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    dis.assert_success();
    let insts: Vec<serde_json::Value> = dis.try_json().expect("disasm JSON");
    let first = insts
        .iter()
        .find(|i| {
            i.get("bytes")
                .and_then(|b| b.as_str())
                .is_some_and(|b| !b.is_empty())
        })
        .unwrap_or_else(|| panic!("no instructions disassembled in main: {}", dis.stdout));
    let ghidra_addr = hex_u64(first["address"].as_str().expect("instruction address"));

    // ELF64: map the link-time address to a file offset via PT_LOAD.
    let mut out = data.clone();
    patch_elf_text_byte(&mut out, ghidra_addr - base, 0xC3).expect("locate address in ELF .text");

    let path = std::env::temp_dir().join(format!("gd-e2e-patched-{}.elf", std::process::id()));
    std::fs::write(&path, &out).expect("write patched fixture");
    path
}

/// Parse a Ghidra hex address string (no 0x prefix, but tolerant of one).
fn hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("parse hex")
}

/// Set the byte at link-time address `va` to `byte` using the ELF program
/// headers (first PT_LOAD segment containing the address).
fn patch_elf_text_byte(data: &mut [u8], va: u64, byte: u8) -> Result<(), String> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        return Err("fixture is not an ELF64 binary".into());
    }
    let rd8 = |off: usize| -> u64 { u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) };
    let phoff = rd8(0x20) as usize;
    let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if p + 0x38 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
        if p_type != 1 {
            continue; // PT_LOAD
        }
        let p_offset = rd8(p + 8) as usize;
        let p_vaddr = rd8(p + 0x10);
        let p_filesz = rd8(p + 0x20) as usize;
        if va >= p_vaddr && (va - p_vaddr) < p_filesz as u64 {
            let off = p_offset + (va - p_vaddr) as usize;
            data[off] = byte;
            return Ok(());
        }
    }
    Err(format!("address {va:#x} not in any PT_LOAD segment"))
}
