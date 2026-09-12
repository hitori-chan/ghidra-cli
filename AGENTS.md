# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If Ghidra is not installed, the tests MUST fail. `require_ghidra!()` panics when `ghidra doctor` fails.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output. Exception: when stdout is not a TTY (piped/scripted), the default auto-detects to `JsonCompact` for machine consumption — this is standard Unix pipe convention.

## Architecture

ghidra-cli uses a **direct bridge architecture**:
- CLI connects directly to a Java bridge running inside Ghidra's JVM via TCP
- The bridge is a GhidraScript (`GhidraCliBridge.java`) started via `analyzeHeadless -preScript`
- Bridge binds `ServerSocket(0)` on localhost, writes port/PID files for discovery
- One bridge per project, identified by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- Any command auto-starts the bridge if not running (import/analyze included)
- No separate Rust daemon process — the Java bridge IS the persistent server

## Optional third-party dependency

- `gd diff programs` requires **Google binDiff**: the native differ (`bindiff.differ` config, `$BINDIFF_PATH`, `/opt/bindiff/bin`, or `PATH`) plus the plain (non-OSGi) `BinExport.jar` (`bindiff.binexport_jar` config, loaded by the bridge at runtime in a child-first classloader). Without it the command fails with setup instructions — that is intended, not a bug to work around.
