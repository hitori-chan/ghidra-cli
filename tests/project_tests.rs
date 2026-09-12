//! Tests for project management commands.

use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;

/// Generate unique project name for test isolation.
/// UUID prevents collisions in parallel CI runs.
fn unique_project_name(prefix: &str) -> String {
    format!("test-{}-{}", prefix, uuid::Uuid::new_v4())
}

#[test]
fn test_project_create() {
    require_ghidra!();

    let project = unique_project_name("create");

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("created").or(predicate::str::contains("Created")));

    // Cleanup
    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_list() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("list")
        .assert()
        .success();
}

#[test]
fn test_project_info() {
    require_ghidra!();

    let project = unique_project_name("info");

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("info")
        .arg(&project)
        .assert()
        .success();

    // Cleanup
    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_lifecycle() {
    require_ghidra!();

    let project = unique_project_name("lifecycle");

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(&project));

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_import_binary() {
    require_ghidra!();

    let project = unique_project_name("import");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra import` spawns a JVM whose inherited pipe handles block output() forever.
    //
    // The requested program name deliberately DIFFERS from the fixture's
    // file name ("sample_binary"): on the brand-new-project path the
    // one-shot import names the program after the file name, and the CLI
    // must then rename it to --program (a matching name would pass even if
    // the rename were broken).
    let program = "imported_program";
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("gd");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            program,
        ],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    // The program list must show the requested name (not the fixture's
    // file name), and the imported (current) program must be analyzed with
    // a real function count — a 0-function "success" used to pass this
    // test.
    let asserted = assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("program")
        .arg("list")
        .arg("--project")
        .arg(&project)
        .assert()
        .success();
    let list_out = asserted.get_output();
    let list = String::from_utf8_lossy(&list_out.stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&list)
        .unwrap_or_else(|e| panic!("Program list output is not JSON: {e}: {list}"));
    // The list is a bare array (quiet/pipe mode) or wrapped in an envelope:
    // {"command":..,"data":{programs:[]}} or {"programs":[]}.
    let programs = value
        .as_array()
        .cloned()
        .or_else(|| value.get("programs").and_then(|v| v.as_array().cloned()))
        .or_else(|| value.pointer("/data/programs").and_then(|v| v.as_array().cloned()))
        .unwrap_or_else(|| panic!("Program list has no programs array: {list}"));
    let entry = programs
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(program))
        .unwrap_or_else(|| {
            panic!("Program '{program}' not found in list (import must honor --program): {list}")
        });
    assert!(
        entry.get("current").and_then(|c| c.as_bool()).unwrap_or(false),
        "Imported program should be current: {list}"
    );
    assert!(
        entry.get("analyzed").and_then(|a| a.as_bool()).unwrap_or(false),
        "Imported program must be analyzed: {list}"
    );
    let func_count = entry
        .get("function_count")
        .and_then(|f| f.as_u64())
        .unwrap_or(0);
    assert!(
        func_count >= 100,
        "Imported program must have a real function count (fixture has hundreds), got {func_count}: {list}"
    );
    assert!(
        !list.contains("\"sample_binary\""),
        "Program list must not contain the fixture file name: {list}"
    );

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

/// Importing the same binary file twice: the second import's file name
/// collides with the existing program's name. The AutoImporter suffixes the
/// new file ("sample_binary.0"); the bridge must rename the file the import
/// actually created to the requested --program name — not the pre-existing
/// program (old behavior resolved the lookup by file name, hit the old
/// program, and failed "in use" while orphaning the suffixed file). No
/// orphan "x.0" may remain.
#[test]
#[serial]
fn test_import_name_collision() {
    require_ghidra!();

    let project = unique_project_name("collision");
    let binary = common::fixture_binary();
    let binary_str = binary.to_str().unwrap();

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("gd");

    // First import: no --program, so the program keeps the file name.
    let status1 = common::run_cli_with_timeout(
        ghidra_bin,
        &["import", binary_str, "--project", &project],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run first import");
    assert!(status1.success(), "First import failed (exit: {:?})", status1.code());

    // Second import: same file, explicit --program name.
    let status2 = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary_str,
            "--project",
            &project,
            "--program",
            "renamed_prog",
        ],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run second import");
    assert!(
        status2.success(),
        "Second (colliding) import failed (exit: {:?})",
        status2.code()
    );

    // Exactly the two requested programs exist; no auto-suffixed orphan.
    let asserted = assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("program")
        .arg("list")
        .arg("--project")
        .arg(&project)
        .assert()
        .success();
    let output = asserted.get_output();
    let list = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        list.contains("\"renamed_prog\""),
        "Expected program 'renamed_prog' in list: {}",
        list
    );
    assert!(
        list.contains("\"sample_binary\""),
        "Expected original program 'sample_binary' in list: {}",
        list
    );
    assert!(
        !list.contains("sample_binary.0"),
        "Orphaned auto-suffixed program must not remain: {}",
        list
    );

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_analyze_program() {
    require_ghidra!();

    let project = unique_project_name("analyze");
    let binary = common::fixture_binary();

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("gd");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "analyze",
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run analyze");
    assert!(status.success(), "Analyze failed with status: {}", status);

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_delete_nonexistent() {
    require_ghidra!();

    let project = unique_project_name("missing");

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
#[serial]
fn test_import_existing_program() {
    require_ghidra!();

    let project = unique_project_name("import-existing");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("gd");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    // Import again - should still succeed (idempotent or with new name)
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(600),
    )
    .expect("Failed to run second import");
    assert!(
        status.success(),
        "Second import failed with status: {}",
        status
    );

    assert_cmd::cargo::cargo_bin_cmd!("gd")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}
