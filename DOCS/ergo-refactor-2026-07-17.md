# STATUS: COMPLETED

All items below were implemented, tested, and pushed (branch `rev-workflow-2026-07`).
The `gd` binary now ships `find constant`, `find instruction`, `decompile-multi`,
`raw`, `disasm --end/--no-resolve`, and `GD_PROJECT`/`GD_PROGRAM`; the bridge was
extended accordingly, and `gdbc.py` is retired. This file is kept as the original
spec/historical record.

---

## Original spec (2026-07-17)

Goal: kill the `gdbc.py` sidecar and make `gd` the single tool for Ghidra-driven
incident RE. Scope is **CLI-side only — the Java bridge is unchanged** (all
needed bridge commands already exist; the installed `gd` binary is from Sep 8
and predates them, which is why `gdbc.py` exists).

## Verified facts (from code review, 2026-07-17)

### Bridge command arg shapes (GhidraCliBridge.java, current)
- `disasm`: `{address, count?, resolve? (default true), end?}`
- `find_constant`: `{value (hex str), size (2|4|8, default 4), max (default 100), refs (default true)}`
  - Response: `{value, size, hits: [{address, block, zero_block, ldr_refs?: [{address, disasm, function?}]}], count}`
  - LDR-pool ref scan window is `found - 0x804 .. found` (ARM literal pools only).
- `decompile_multi`: `{addresses: [..], timeout_secs (default 0)}`
  - Response: `{results: [{address, name?, entry?, code? | error?}]}`
- `decompile`: `{address, with_vars, with_params, timeout_secs}` (CLI already wired).

### CLI structure (src/)
- `cli.rs` (~1395 ln): clap definitions. `Commands` enum @48; `FindCommands` @968
  (variants String/Bytes/Function/Calls/Crypto/Interesting — **no Constant**);
  `DisasmArgs` @1343 (only `target`, `num_instructions`, `options`) — **no end/resolve**;
  `DecompileArgs` @1372 (single target); `QueryOptions` @1318 (project/program/filter/fields/format/limit...).
  `Cli` struct has globals: `--project --program --json --pretty -q -v --projects-dir --java-home`.
- `ipc/client.rs`: `send_command` @153 (default read timeout), `send_command_with_timeout` @166
  (`None` = block forever, used for unbounded ops), `disasm` @573 (sends only address+count),
  `decompile` @298, `find_string` @520, `find_calls` @532. **Missing: find_constant, decompile_multi, raw.**
- `main.rs` (~2338 ln) — exhaustive `Commands` matches to extend for every new variant:
  - `requires_bridge` @122
  - `extract_project_from_command` @153 (pattern: `Commands::X(args) => args.options.project.clone()`)
  - `extract_program_from_command` @279 (same pattern)
  - `extract_query_options` @398 (has `_ => None` fallback; not exhaustive-checked)
  - dispatch match @~934-1350 (`Commands::Decompile` @934, `Commands::Find` @~1300, `Commands::Disasm` @1346,
    `FunctionCommands::Disasm` @962)
  - `check_dotnet_decompile_warning` @2110 (uses `matches!`, no change needed)
- Output pipeline (main.rs @~742): `explicit -o flag > --json/--pretty > auto_detect_format(is_tty)`.
  `auto_detect_format` (format/mod.rs @460): TTY→`Compact`, non-TTY→`JsonCompact`.
  **Gap:** `OutputFormat::C` and `Asm` exist in the enum but `DefaultFormatter::format`
  (format/mod.rs @~65) falls through `_ =>` to JSON-pretty. So `gd decompile` on a TTY prints
  a Compact dump / piped prints JSON — never raw C. Same for disasm.
- Project resolution: `run_with_bridge` @~640: `extract_project_from_command(...).or_else(|| cli.project.clone())`
  then `resolve_project_path`; config default is the last fallback. Program resolution similar
  @~662/711: `extract_program_from_command(...).or_else(|| cli.program.clone())`.
- Install: `cargo install --path . --force` (bin name `gd` → `~/.cargo/bin/gd`). Release build dir exists.
- Bridge redeploy: `gd start` re-copies the script from the CLI's `ghidra/scripts/` dir; since the
  bridge Java is **unchanged**, no bridge concerns. A running bridge for `tmp-ws50` (port file in
  `~/.local/share/ghidra-cli/`) can be used for live tests without restart.

## Changes to implement

### 1. Env-var project/program context (biggest friction: repeating `--project P --program N`)
In `run_with_bridge` (and the import/analyze branches), extend the resolution chain:
command flag → global `--project/--program` → **`$GD_PROJECT` / `$GD_PROGRAM`** → config default.
Single helper: `fn env_project() -> Option<String>` / `fn env_program()`. Document in `gd --help`.
(Do NOT put these in `Cli` struct globals — keep env fallback explicit in resolution code.)

### 2. `gd raw COMMAND [JSON]` — generic bridge passthrough (replaces gdbc.py)
```rust
#[command(name = "raw")]
Raw(RawArgs),   // in Commands enum

pub struct RawArgs {
    /// Bridge command name (e.g. find_constant, decompile_multi, read_memory, ping)
    pub command: String,
    /// JSON object payload sent as args (default "{}")
    #[arg(default_value = "{}")]
    pub json: String,
    #[command(flatten)]
    pub options: QueryOptions,
}
```
Dispatch: `serde_json::from_str(&args.json)` → `client.send_command(&args.command, Some(payload))`.
Return `None` from `extract_query_options` (arbitrary payloads should print raw JSON, not table).

### 3. `gd find constant VALUE`
New `FindCommands::Constant(FindConstantArgs)` variant +
```rust
pub struct FindConstantArgs {
    pub value: String,                 // hex, e.g. 0x8031
    #[arg(long, default_value_t = 4)] pub size: usize,   // 2|4|8
    #[arg(long, default_value_t = 100)] pub max: usize,
    #[arg(long)] pub no_refs: bool,
    #[command(flatten)] pub options: QueryOptions,
}
```
New client method `find_constant(value, size, max, refs)` → `send_command("find_constant", ...)`.

### 4. `gd disasm T [--end ADDR] [--no-resolve]`
Add to `DisasmArgs`: `#[arg(long)] pub end: Option<String>`, `#[arg(long)] pub no_resolve: bool`.
Extend `client.disasm(address, count, end, resolve)` to send `end`/`resolve` when set
(`resolve` always sent; default true). Update both call sites (main.rs @962, @1346).
`FunctionCommands::Disasm` (@962) passes `None, None, true`.

### 5. `gd decompile-multi T [T...]`
```rust
#[command(name = "decompile-multi", alias = "dmulti")]
DecompileMulti(DecompileMultiArgs),
pub struct DecompileMultiArgs { pub targets: Vec<String>, #[command(flatten)] pub options: QueryOptions }
```
Client method: `send_command_with_timeout("decompile_multi", Some(json!({"addresses": targets})), None)`
(blocking — batch decompile is unbounded; mirrors `decompile`'s timeout handling).

### 6. Real `C` / `Asm` output (stop printing JSON for decompile/disasm)
In `format/mod.rs` `DefaultFormatter::format`: handle `OutputFormat::C` and `OutputFormat::Asm`
by extracting the text fields from the JSON values and joining with newlines
(`C`: each item's `code` field (and per-item `error` as stderr-ish comment `// error:`);
`Asm`: each item's `address` + `disasm`/`mnemonic` fields — confirm exact keys by running
`gd disasm 0x34db8 --project tmp-ws50 --program webService --json` first and reading the item shape).
Command-specific default in main.rs output section (@~742): when no explicit `-o/--json/--pretty`
and command is Decompile/DecompileMulti (→ `C`) or Disasm (→ `Asm`), use that format regardless of TTY.
Keep `--json`/`-o json` as explicit overrides.

### 7. Rebuild + live test
```
cd ~/tool/gd && cargo build --release && cargo install --path . --force
gd --help                                  # new subcommands visible
gd raw ping --project tmp-ws50 --program webService
gd find constant 0x8031 --project tmp-ws50 --program webService
gd disasm 0x34db8 -n 20 --project tmp-ws50 --program webService          # raw C/asm-ish, no JSON
gd disasm 0x34db8 --end 0x34e40 --project tmp-ws50 --program webService
GD_PROJECT=tmp-ws50 GD_PROGRAM=webService gd decompile-multi 0x15b78 0x15b2c
```
Verify `cargo test` still passes (format module has tests).

### 8. Docs
- Tool: append CHANGELOG.md entry; README command table + `GD_PROJECT`/`GD_PROGRAM` env + `gd raw` section.
- Incident: `incident/highlands/docs/DEEP-DIVE-NOTES.md` §7 — replace `gdbc.py tmp-ws50 ...` lines
  with `gd find constant ...` / `gd raw ...`; `incident/highlands/re/tools/README.md` — mark
  `gdbc.py` **DEPRECATED** (kept as historical fallback; `gd raw` supersedes it).

## Immediate payoff (incident task resume)
Once built, resume the live `getP2PInfo` `-2` debugging with:
- `gd find constant 0xFFFFFFFE --size 4 --project tmp-ws50 --program webService` (the -2 result constant),
- `gd find string --project tmp-ws50 --program webService "getP2PInfo"` → deref table ptr @ file 0x92a68 (VA 0x9aa68) via `gd raw read_memory` if needed,
- `gd decompile-multi <handler> <dispatcher>` in one round trip.

## Out of scope (deliberately)
- Bridge Java changes (protocol is fine; it's the reusable core).
- Auto-starting the bridge from query commands (JVM boot ~30s; keep explicit `gd start`).
- Rewriting the query/filter/format engine (works; only C/Asm gaps).
