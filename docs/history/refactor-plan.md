# ghidra-cli Refactor & Optimization Plan

> **Status: COMPLETE (2026-09-12, shipped in 0.4.0).** All phases P0–P8 and
> P7 are done and verified (unit + full E2E suites green). This file is kept
> in `docs/history/` as the design record; the per-phase "what landed" is
> also summarized in `CHANGELOG.md` (0.3.0 / 0.4.0). The only intentionally
> open follow-ups are listed under "Open follow-ups" at the end.

Final status: P0 complete (`786ad27`); P1 complete (`21d6f4d`, `9c3f41c`,
`0dd74c3`, `8866797`); P2 complete (`6a4ecfb`); P3 complete (`256b7f4`);
P4 complete (`918f155`); P5 complete (see P5 section); P6 complete (filter
pushdown `788b1e6`, offset pushdown `16f30c8`, plan-time regex validation in
`29e222f`); P7 complete (`1758f39` + earlier items); P8 complete (`29e222f`,
binDiff-based, see P8 section).
Companion to
`README.md` (current architecture) and `PLAN.md` (result-envelope design). This is a *maintenance* plan: no new
features, no protocol-breaking changes to the running bridge (except the
registry work in P5, which is additive).

## Current-state summary

| Area | State |
|------|-------|
| Build / tests | `cargo build` clean, 60 unit tests pass, clippy/fmt clean. Integration suites need Ghidra (`require_ghidra!` panics without it — keep that behavior, AGENTS.md rule 1). |
| `src/main.rs` | 2,479 lines. Four near-duplicate `match`es over `Commands` (`requires_bridge`, `extract_project_from_command`, `extract_program_from_command`, `extract_query_options`) plus a ~400-line `execute_via_bridge`. Every new command touches 5+ sites — the code comments admit this trap. |
| `src/cli.rs` | 1,475 lines. ~10 structs each re-declare `positional_target`/`target`/`resolved_target()`; ~25 structs each re-declare `program`/`project` `Option<String>`. |
| Query pipeline | Limit/filter/pagination logic split across `bridge_list_params` (main.rs), `Query::from_options`, and `Query::process_results` with documented "idempotent re-apply" safety. `DataType` enum is a dead placeholder. |
| Envelope unwrapping | `unwrap_bridge_response` (main.rs) uses an `ARRAY_KEYS` + `META_KEYS` string heuristic; new bridge commands with unlisted keys silently change output shape. |
| Output formats | 15 `OutputFormat` variants; `Tree` and `Hex` fall through to pretty-JSON silently. `tabled` dep declared but `comfy-table` is what's used. |
| Deps | Unused: `tabled`, `strsim`, `lazy_static`, `csv`, `dunce`, `chrono`, dev `proptest`. `reqwest 0.11` is old but works. |
| Config | `default_output_format` and `aliases` fields are never read (dead knobs). `GhidraClient::project_exists` (ghidra/mod.rs) has a wrong path check and is shadowed by the correct `project_exists` in main.rs. |
| Java bridge | 5,461-line single-file GhidraScript: 85 `handleXxx` methods, 74 repeated `currentProgram == null` guards, 90-case dispatch `switch`. Single file is a hard constraint (GhidraScript), so refactor is internal. |
| Docs | SKILL.md still says binary name `ghidra` (renamed to `gd`). `docs/plan-prod.md` self-declares stale; `PLAN.md`/`NEXT.md`/`PLAN-java-plugin.md`/`DOCS/` are historical. |

## Guiding constraints

1. **Never skip tests.** If Ghidra is absent, integration tests must fail (`require_ghidra!`).
2. **Default output** stays human/agent-readable on TTY, `JsonCompact` when piped; `--json`/`--pretty` override.
3. **Bridge wire protocol stays stable** in P0–P4. P5 is additive only.
4. Land phases in order; each phase ends green on: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --lib`, and the Ghidra-gated E2E suite (where available).

---

## P0 — Housekeeping (low risk, ~1 day)

1. **Remove unused dependencies** from `Cargo.toml`:
   `tabled`, `strsim`, `lazy_static`, `csv`, `dunce`, `chrono`,
   dev-dep `proptest`. (Verified: zero `crate::` usages in `src/`+`tests/`.)
   Shrinks build time; no behavior change.
2. **Dead config knobs**: remove `Config::aliases` (never read) and either
   wire `default_output_format` into the format-selection chain in
   `run_with_bridge` (explicit `-o` > `--json/--pretty` > config > TTY auto)
   or remove it with a deprecation message like the existing `timeout` key.
   Recommendation: wire it — it's already user-settable via `gd config set`.
   Add a unit test for the precedence.
3. **`GhidraClient` cleanup** (`src/ghidra/mod.rs`): delete the buggy
   `project_exists` (wrong path, unused — main.rs has the correct sibling
   `.gpr`/`.rep` check) or fix it to delegate to the main.rs helper.
   `create_project` (empty `mkdir`) is inconsistent with bridge-side project
   creation; document or route `gd project create` through the same
   `project_exists` check.
4. **Docs**: fix SKILL.md binary name (`ghidra` → `gd`) and its "explicit
   `gd start`" note (auto-start is implemented). Move `PLAN.md`, `NEXT.md`,
   `PLAN-java-plugin.md`, `docs/plan-prod.md` to `docs/history/` with a
   "superseded" header; keep `docs/` for current plans only.
5. **Optional**: bump `reqwest` 0.11 → 0.12 (rustls) and `thiserror` 1 → 2.
   Do in its own commit so build breakage is easy to attribute.

Exit criteria: build + all unit tests green, no behavior change.

## P1 — Kill the five-way command duplication (core structural win, ~2–4 days)

Today: adding one command = edit `cli.rs` + `requires_bridge` +
`extract_project_from_command` + `extract_program_from_command` +
`extract_query_options` + `execute_via_bridge`.

1. **`CommandMeta` trait** (new, in `src/cli.rs` or `src/cmd/mod.rs`):

   ```rust
   pub trait CommandMeta {
       fn project(&self) -> Option<&str>;        // no more .clone() in extraction
       fn program(&self) -> Option<&str>;
       fn query_options(&self) -> Option<&QueryOptions>;
       fn requires_bridge(&self) -> bool;        // default false = fail-closed
   }
   impl CommandMeta for Commands { /* one match, arms call into arg structs */ }
   ```

   Most arg structs already `#[command(flatten)] pub options: QueryOptions`,
   so provide a macro that implements the trait for "options-bearing" structs
   in one line (e.g. `impl_options_meta!(FunctionListArgs);`) and a second
   macro for plain `program`/`project`-field structs. The `Commands`-level
   impl becomes one `match` with short arms; `requires_bridge` becomes the
   trait's `requires_bridge()` (explicit per variant, default false — keeps
   the documented fail-closed semantics).

   The extraction functions in `main.rs` collapse to
   `meta.project().map(str::to_string)` etc. Net: −300 lines in main.rs and
   the "missing arm silently degrades" failure mode disappears (a variant
   without a trait arm fails to compile).

2. **`TargetArgs`**: one struct

   ```rust
   pub struct TargetArgs {
       #[arg(value_name = "TARGET", required_unless_present = "target")]
       pub positional_target: Option<String>,
       #[arg(long = "target", value_name = "TARGET")]
       pub target: Option<String>,
   }
   impl TargetArgs { pub fn resolved_target(&self) -> &str { ... } }
   ```

   flattened into the ~10 structs that currently duplicate
   `positional_target`/`target`/`resolved_target()`
   (`FunctionGetArgs`, `FunctionDecompileArgs`, `DecompileArgs`, `DisasmArgs`,
   `XRefArgs`, `GraphFunctionArgs`, `FindCallsArgs`, `SetSignatureArgs`,
   `SetReturnTypeArgs`, `SetCallingConventionArgs`, `SetVarTypeArgs`).
   −100 lines, zero drift. Verify help text and `gd batch` re-parsing
   (`Cli::try_parse_from`) still work (batch test covers this).

3. **Shared `BridgeTargetArgs`** for `Start/Stop/Restart/Status/Ping/Jobs/Cancel`
   (repeated inline `project`/`program` struct-variant fields).

4. **Split `execute_via_bridge`** into `src/cmd/` modules, one per command
   group, each exposing `pub fn run(client: &BridgeClient, args: …,
   ctx: &ExecCtx) -> Result<serde_json::Value>`:

   ```
   src/cmd/mod.rs          // ExecCtx { quiet, default_limit }, group dispatch
   src/cmd/analyze.rs      // Import (3-case hang-proof logic) + Analyze
   src/cmd/functions.rs    // FunctionCommands + Decompile/DecompileMulti/Disasm
   src/cmd/lists.rs        // Query/Strings/Dump/Symbol/Type/Tag/Comment/Stats/Summary
   src/cmd/search.rs       // FindCommands + XRef + Graph
   src/cmd/mutation.rs     // Patch, Type mutation, Symbol/Tag/Comment mutation, Rename
   src/cmd/scripts.rs      // Script, Batch
   src/cmd/programs.rs     // ProgramCommands, Memory, Diff
   ```

   `main.rs` then holds: `main()`, logging, `run_command` (small),
   `run_with_bridge` (bridge lifecycle + restart-on-stale-bridge + output
   formatting), bridge-management handlers, project/config/doctor handlers,
   and helpers (`unwrap_bridge_response` moves to `src/query/`). Target:
   main.rs < ~900 lines.

   Keep `stale_tags_response`, `is_unknown_command_error`, the
   restart-and-retry block, and `check_dotnet_decompile_warning` verbatim in
   `run_with_bridge` — they encode hard-won regression fixes (see tests).

Exit criteria: `gd --help` tree unchanged (add a snapshot test over the full
`--help` output with insta), all E2E suites pass, `gd batch` golden file passes.

## P2 — Unify the query pipeline (~1–2 days)

1. New `src/query/planner.rs` — single source of truth for
   "what to ask the bridge" vs "what to do client-side":

   ```rust
   pub struct QueryPlan {
       pub fetch: FetchParams,      // { limit, filter, tags, untagged } sent to bridge
       pub post: PostProc,          // { filter, fields, sort, limit, offset, count }
   }
   impl QueryPlan {
       pub fn from(opts: &QueryOptions, default_limit: Option<usize>) -> Result<Option<QueryPlan>>;
   }
   ```

   Replaces `bridge_list_params` (main.rs) + `Query::from_options` +
   `Query::process_results`'s duplicated limit semantics. The
   "filtered/sorted/counted ⇒ fetch full dataset" rule lives in exactly one
   place, and `--limit 0 = all` (TODO.md Bug 1) is asserted there once.
   Keep the existing unit tests, retargeted at `QueryPlan`.

2. **Delete the dead `DataType` enum** (placeholder in `Query`) or use it:
   recommended deletion; the `gd query functions|strings|imports|exports|memory`
   arms in `execute_via_bridge` already match on the raw string.

3. **Ownership, not clones**: `process_results` currently `item.clone()`s per
   row and `unwrap_bridge_response` `.clone()`s the whole array. Change to
   consuming passes (`Vec<Value>::retain` for filtering, `std::mem::take`
   patterns) — measurable on the 1.9M-symbol case (TODO.md Bug 3 territory).

Exit criteria: all query E2E tests (`readonly_tests`, filter tests) pass
unchanged; unit tests for `QueryPlan` cover the limit-0 / default-limit /
filter-fetch-full matrix.

## P3 — Envelope unwrapping correctness (~1 day)

**Status: implemented, verifying.** `BridgeClient` now records the last wire
command it sent (`RefCell<Option<String>>`, set in
`send_command_with_timeout` — the single chokepoint for all bridge calls).
`run_with_bridge` passes `client.last_command()` into
`unwrap_bridge_response(value, command)`, which looks up the key in the typed
`query::ENVELOPES` table (29 entries, derived from the Java handlers) instead
of the name-guessing `ARRAY_KEYS` scan. The metadata guard is kept: a
table-mapped command only unwraps when the mapped key is present *and* every
other top-level key is in `META_KEYS`, so shape drift falls back to
single-item passthrough (debug-logged) exactly like before. `decompile`
(`code` key) remains the single-item rule. Tests: per-entry unwrap for all 29
rows, real envelope shapes (disasm/find_constant/tag_get), drift fallback,
and a CI guard asserting every table command appears in the bridge dispatch
`switch` (parses `GhidraCliBridge.java`).

---
Original plan:

`unwrap_bridge_response`'s `ARRAY_KEYS`/`META_KEYS` heuristic is the riskiest
stringly-typed code in the CLI.

1. Replace with an explicit table: `const ENVELOPES: &[(&str, &str)] =
   [("list_functions", "functions"), …, ("find_constant", "hits")]` mapping
   bridge command → array key. `run_with_bridge` already knows the command
   (or the `BridgeClient` method used), so pass it through. Unknown command ⇒
   return value as single item (today's fallback), and log at debug.
2. Unit-test every entry: build the real envelope shape (copy the 5 insta
   snapshots' shapes into the test), assert unwrapping yields N rows.
   Add a CI-enforced test that the table's command set is a subset of the
   bridge's dispatch `switch` (extract the switch's case labels via a small
   build-time check or a grep test in the E2E suite).
3. Keep the `{"code": …}` decompile special case (document it as the
   single-item rule).

Exit criteria: no output diff on any E2E assertion; new unit tests green.

## P4 — Output formats: consistent and tested (~1–2 days)

**Status: implemented, verifying.** Decisions taken:
- `Tree` implemented for the two graph shapes the bridge emits: callers/
  callees rows (flat list, `depth` field → indentation) and the `graph calls`
  envelope (nodes + edges → adjacency tree with a cycle guard, `(…)` marks a
  revisit, deterministic BTree ordering, hard depth cap 128). Empty →
  `No results`; non-graph data → clear error.
- `Hex` removed (no producer); `OutputFormat::from_str` rejects it with the
  full expected-value list. An invalid `-o` value now fails up front in
  `run_with_bridge` (before project resolution or bridge work) instead of
  being silently swallowed by `.ok().flatten()`.
- Dedup: `CodeRow` / `InsnRow` row parsers (generic over a `Gettable` trait
  so they accept both `JsonValue` and the object `Map`) now back
  `format_compact`, `format_full`, `format_c`, and `format_asm`; layouts are
  unchanged.
- `-o` help text lists the actually-supported formats; SKILL.md's format
  table drops `hex` and documents `tree`.
- Golden tests: 14 insta snapshots (12 formats × shared 5-shape fixture +
  2 tree shapes) under `src/format/snapshots/`; `query_help` snapshot updated
  for the new `-o` line.

---
Original plan:

1. **`Tree`/`Hex`**: currently fall into `_ =>` pretty-JSON. Decide per
   variant: implement `Tree` for graph responses (nested callers/callees —
   there is data for it) and remove `Hex` (no producer), or implement both
   minimally. Update the `-o` help text to list actually-supported formats.
   Whatever is removed: `OutputFormat::from_str` should error clearly
   ("format not supported"), not silently JSON.
2. **Deduplicate rendering**: `format_compact` inlines decompile/disasm
   special cases that `format_c`/`format_asm` already do properly. Extract
   `render_code_item` / `render_insn_item` and share.
3. **Golden tests**: add insta snapshots per format (Compact, Table, Csv,
   Tsv, Json, JsonCompact, JsonStream, Count, C, Asm, Minimal) over a fixed
   fixture covering the shapes: function row, decompile result (with
   params/vars), disasm instruction (with `loaded`), find_constant hits,
   graph node. This locks in the P1/P3 invariants.
4. `tabled` is gone after P0; `comfy-table` stays (only real user).

Exit criteria: `output_format_integration.rs` + new snapshot suite pass.

## P5 — Java bridge: registry + guard centralization (2–4 days, highest risk, do LAST)

Gated on: P1–P4 merged, E2E suite green, `gd doctor` compile check passing.

1. **Command registry**: replace the 90-case `dispatchCommand` switch with a
   `Map<String, Handler>` built once (nested `static class CommandRegistry`),
   e.g. `registry.register("list_functions", bridge::handleListFunctions)`.
   Benefits: one-line addition for new commands, and — additively — a new
   control command `help` returning `{commands: [{name, description}]}`.
   That powers `gd raw help` and lets the CLI's `raw` command warn on
   unknown names *before* sending. Protocol stays backward compatible (old
   CLI works with new bridge; new `help` is just an extra command).
2. **`requireProgram` guard**: one wrapper
   `JsonObject requireProgram(Supplier<JsonObject> body)` replacing the 74
   copy-pasted `if (currentProgram == null) return errorResult(...)` blocks.
   Purely mechanical; verify by diffing handler behavior in E2E.
3. **Response building helpers**: several handlers hand-roll the same
   `{count, <key>: [...]}` envelope; introduce `listResponse(String key,
   JsonArray rows, Map<String,Object> meta)` so the P3 table and the bridge
   cannot drift (the table can later be *generated* from the registry).
4. Keep the file single (GhidraScript constraint) — all helpers are
   private/nested. Do NOT split into multiple scripts.
5. Validation: full E2E suite on ubuntu+macos (windows in CI), plus a
   focused test that `help` output covers every registered command.

Exit criteria: E2E green on 3 OSes; `gd raw help --json` lists ≥ the
dispatch switch's former case set.

### Implemented

- **Command registry** (step B): `dispatchCommand`'s 80-case switch is now a
  nested `static class CommandRegistry` built once in `buildRegistry()` —
  80 one-line `r.register("name", "description", (b, args) -> handleX(args))`
  entries. The registered set was diffed against the old switch: identical
  (80 program commands; the 6 control commands stay in
  `handleControlCommand`). `dispatchCommand` is now a one-line
  `registry.dispatch(this, command, args)`.
- **`help` control command** (additive, backward compatible): listed in
  `isControlCommand`, returns `{commands: [{name, description}…], count}` —
  `gd raw help` now works against a running bridge and reveals the full
  supported command set at runtime.
- **stats consistency** (step A): `countPrimaryFunctions(fm)` counts
  primary functions (the same set `list_functions` returns) and replaced
  `fm.getFunctionCount()` in 5 handlers (handleStats, handleProgramInfo,
  handleImport, handleListPrograms, handleDiffPrograms). Root cause of the
  old mismatch: `getFunctionCount()` also counts non-primary duplicates
  (import stubs). Verified on a fresh import: `stats.functions` 26→19,
  matching `function list`.
- **`requireProgram` guard** (step C): `JsonObject requireProgram(
  Supplier<JsonObject> body)` replaces the copy-pasted
  `if (currentProgram == null) return errorResult(…)` — 69 handlers now
  start with `return requireProgram(() -> { … });`. Remaining raw guards:
  3 compound (`currentProgram == null || arg == null`) and 2 inside
  handleAnalyze (arg-resolution logic, intentionally untouched).
- **`listResponse` envelope helper** (step D): `listResponse(result, key,
  rows)` appends `{key: rows, count: rows.size()}` — 24 call sites; `count`
  is now always `rows.size()`, the exact contract the CLI's ENVELOPES table
  (P3) relies on.
- **CI guard updated**: `envelopes_are_dispatched_by_the_bridge` accepts the
  command surface declared as either `case "cmd":` (legacy) or
  `register("cmd"` (registry).
- Validation: `gd doctor` compile check OK; full E2E suite 156/156 green
  (zero output diff); `gd raw help` lists all 80 commands; unknown `raw`
  command names still produce a clean `Unknown command` error.

## P6 — Performance at scale (optional, after P5)

Ranked by payoff on the known workload (1.9M-symbol `pskernel.dll`):

1. **Server-side filtering** (biggest win): bridge list handlers accept a
   `filter` expression (the existing subset: substring/prefix/regex on the
   name field, numeric compare, `tags`, `untagged`) and filter *while
   iterating*, returning only `count` + matching rows. Today
   `symbol list --filter 'name=~"^PK_"' --count` still ships ~1.9M rows over
   the socket; this makes it O(matches). Protocol: additive arg, old
   bridges ignore it (CLI already falls back to client-side filtering —
   `bridge_list_params` keeps the fetch-full rule when the bridge replies
   unfiltered, which the P3 envelope check detects).
2. **Streaming/chunked large lists**: bridge `list_*` handlers with
   `offset`/`limit` already exist; document the paging pattern and add
   `gd query … --limit N --offset M` guidance for `--limit 0` on huge
   datasets. Longer term: chunked NDJSON responses (bridge-side streaming).
3. **Single connection for `gd batch`**: `BridgeClient` opens a TCP
   connection per command; batch mode issues N commands — reuse one stream
   (`BridgeClient` gains `connect()`/`with_stream`). Small win, low risk.
4. **Regex cache is already thread-local** (evaluator); move the filter
   compile to `QueryPlan` construction so it happens exactly once per
   invocation (today it's cached per thread *during* row evaluation — fine,
   but the plan makes it explicit and testable).

### Implemented (item 1: server-side filter pushdown)

The bridge's five list handlers (`list_functions`, `list_strings`,
`list_symbols`, `type_list`, `comment_list`) already evaluate a `filter`
argument — case-insensitive substring on the command's primary string field
(`name` / `value` / `text`), *while iterating* — but the CLI never sent it
(`FetchParams.filter` was dead: any filter forced a full fetch). P6 wires
it up behind the planner, with the client-side filter kept authoritative:

- **`pushdown_filter`** (`src/query/planner.rs`) maps a parsed single-atom
  filter onto the bridge predicate, returning `(value, exact)`:
  `field~v` (case-insensitive contains — identical semantics, **exact**),
  `field^v` / `field$v` / `field=v` (contains is a strict **superset** of
  starts-with / ends-with / case-sensitive equals). Regex, `!=`, numeric
  compare, `NOT`/`AND`/`OR`, other fields, and commands with no bridge field
  never push (full fetch, client filters — unchanged).
- **Cap rule**: only an *exact* pushdown may carry `--limit` server-side
  (the bridge caps *matching* rows; an explicit `--limit` now ships at most
  `limit` rows). A superset pushdown never caps (the bridge could truncate
  the superset before the client's exact pass sees enough rows) and
  sort/count/offset still force the full match set — so `--count` becomes
  O(matches). No explicit `--limit` keeps the "filtered ⇒ all matches"
  output (fetch cap `None`, not the config default).
- **Per-command bridge field** (`bridge_filter_field` in `src/cmd/mod.rs`):
  `function`/`symbol`/`type` → `name`, `string` → `value`, `comment` →
  `text`, `query functions|strings` and `dump functions|strings` likewise;
  everything else `None`. Batch lines go through the same `for_command`
  path.
- Protocol: **no wire change** — the `filter` argument already existed on
  all five handlers; old bridges that ignore it stay correct because the
  client re-filters in every case.
- Verified on a 2,804-function / 34,084-symbol firmware binary: `symbol
  list --filter 'name~evp' --count` 0.376s → 0.139s with identical count;
  superset (`^`/`$`/`=`) results and `--limit` output match locally computed
  ground truth row-for-row; raw-bridge probe confirms filter-then-cap
  server-side. Planner unit tests: 9 (pushdown matrix, cap rule,
  bridge-field targeting). Full E2E 156/156 green (zero output diff).

Items 2–4 (streaming/chunked lists, single-connection batch, plan-time
regex compile) remain open.

## P7 — Tests & repo hygiene (continuous, ~1 day of focus) — DONE

1. **Done.** Split `tests/readonly_tests.rs` (1,570 lines) into
   `readonly_functions.rs` (21 tests), `readonly_strings_xrefs.rs` (14),
   `readonly_graphs.rs` (19) — same 49 pass / 5 ignore result as the old
   single suite. CI workflows updated to the new suite names.
2. **Done.** `test_import_binary` (and the four sibling JVM-spawning
   import/analyze timeouts) raised to 600 s; filter grammar anchored with
   `SOI`/`EOI` in `4f31a85` (trailing garbage rejected + parser test).
3. **Done** (landed with P1): `tests/help_snapshot.rs`.
4. **No change needed** (as planned).
5. **Done.** 0.3.0/0.4.0 CHANGELOG entries; version at 0.4.0.
6. **Done (docs).** SKILL.md now states the class-form requirement for
   `gd script run` (and that inline `script java`/`script python` are not
   supported by the bridge). The "detect body-only and wrap it" bridge
   improvement stays as a possible future item.

## P8 — Real program diff (Google binDiff) — DONE

Supersedes the `diff programs` stub (marked honest in `ee95466`).

**Pivot note:** this section was originally scoped to Ghidra's native
ProgramDiff engine (`DiffController`; the spike below was verified against
it). The user prefers **Google binDiff** (https://github.com/google/bindiff)
— stronger function matching (similarity/confidence, layout-independent) —
so the command now **requires** the binDiff toolchain and fails with setup
instructions when it is absent. The DiffController spike notes are kept
below for reference (they document the Ghidra 12 API pitfalls).

### Implementation (as landed)

- **Bridge (`diff_programs`)**: resolves both programs (program1 defaults
to the loaded program; self-diff rejected by name), loads the plain
  `BinExport.jar` through a child-first classloader (only
  `com.google.protobuf.*` delegated to the jar — Ghidra's protobuf version
  conflicts with the plugin's), exports both programs to `.BinExport`
  files in a temp dir, returns the export paths + both full function lists
  (needed client-side for the unmatched calculation) and releases the
  programs.
- **CLI (`src/bindiff.rs` + `cmd/programs.rs`)**: locates the native
differ (`bindiff.differ` config → `$BINDIFF_PATH` dir → `/opt/bindiff/bin`
→ `PATH`), runs it on the export pair, parses the resulting `.BinDiff`
SQLite database (`rusqlite`: `metadata` + `function` tables only —
basic blocks/instructions stay on disk), rounds similarity/confidence to
3 decimals, computes unmatched functions by subtracting matched addresses
from the bridge's function lists, and applies `--changed` / `--min-sim` /
`--name` / `--unmatched` / `--limit` client-side. Unmatched rows are
prepended so a row cap always shows them. Output renders through the normal
formatters (envelope key `matches`).
- **E2E (`tests/bindiff_tests.rs`)**: self-diff guard (always runs) + a
  full pipeline test that skips when the toolchain is absent: imports a
  byte-patched copy of the fixture (first instruction of `main` → RET,
  computed via `program info` image base + ELF PT_LOAD mapping), runs the
diff, and asserts invariants (matched+unmatched == primary function
count; the patch is visible as a changed/unmatched function; `main`
matched; similarities bounded).

### Original spike (Ghidra 12 API reference; the engine below was superseded by binDiff)

- `DiffController(Program p1, Program p2, AddressSetView limit,
  ProgramDiffFilter, ProgramMergeFilter)` needs **no Tool** — constructed
  directly in a GhidraScript; `getFilteredDifferences(TaskMonitor)` returns
  an `AddressSetView` of diff ranges.
- Loading the second program in a script (Ghidra 12 API — packages moved
  vs 11.x): `getState().getProject()` → `getProjectRootFolder().getFiles()`
  → `DomainFile.getDomainObject(this, false, false, TaskMonitor.DUMMY)`
  (first arg = non-null "consumer" owner; `null` fails with "Consumer must
  not be null"; the script itself is a valid owner).
- Category semantics (drives the UX — this is a **merge-style** diff, best
  for two versions of the same program / identical layout, weaker for
  different builds): `BYTE_DIFFS`/`CODE_UNIT_DIFFS` = code/byte changes;
  `FUNCTION_DIFFS`/`SYMBOL_DIFFS` = function/symbol *annotation* changes
  (creation/removal/metadata — a pure code-byte patch with unchanged
  annotations reports 0 here); `COMMENT_DIFFS`, `REFERENCE_DIFFS`,
  `EQUATE_DIFFS`, `BOOKMARK_DIFFS`, `FUNCTION_TAG_DIFFS`, `USER_DEFINED_DIFFS`
  also exist. Ranges map to functions via `getFunctionAt`.
- Test case: one-byte patch at `main`+4 → exactly one range
  `[101040,101046]` → `main`; diff ran in milliseconds; script round-trip
  < 0.5s incl. two program opens.
- `gd script run` requires class-form scripts (see P7 item 6); the P8
  handler was a **native bridge command** (no script indirection) — as
  landed.

### Original design (ProgramDiff; superseded — kept for the API notes)

- **Wire (additive upgrade of `diff_programs`)**: same command name, richer
  response (the CLI ships its own bridge, so there is no old-bridge matrix).
  Args: `program1` (default: loaded program), `program2` (required, by
  project name; unknown → error listing available programs), `categories`
  (default `byte,code_unit,function,symbol`), `limit` (default 100, 0 =
  all), `program` (selects the loaded program1). Response:
  `{status, method: "ghidra-program-diff", program1: {name, function_count,
  memory_size}, program2: {…}, category_counts: {…}, differences: [{address,
  end, function, symbol}…], truncated, warnings}`.
- **Bridge handler**: resolve + read-only-open program2 (keep the bridge
  script as consumer; close after), build the limit set from program1
  memory, run `DiffController` with the **job's cancellable monitor** (the
  bridge already threads one into every program job → `gd cancel` works),
  map ranges to function/symbol names on both sides, cap rows, report
  `getWarnings()`.
- **CLI**: `gd diff programs [PROG1] PROG2 [--categories …] [--limit N]`
  (PROG1 optional → loaded program); add `differences` to the ENVELOPES
  table (array key) so table/csv/json formats apply; keep `diff functions`
  as the labeled naive line diff. Update registry description + help
  snapshots.
- **Tests (E2E)**: build a patched pair in the ci-test project (import
  `sample_binary` + a 1-byte-patched copy — patch at a known function's
  mid-body byte, computed from the fixture at test-build time); assert the
  returned range is contained in that function and `category_counts` is
  nonzero where expected; unknown `program2` → clean error listing programs;
  mismatched-architecture pair → clean `ProgramConflictException` error.

### Original risks (ProgramDiff scoping; superseded)

1. **Semantics mismatch with user expectation** (binDiff-like matching was
   NOT delivered by the native engine): this is exactly why the command was
   re-scoped to binDiff and now **requires** it.
2. **Large-program memory/time**: two big programs open at once; byte scan
   is O(memory). Mitigations: read-only open, cancellable monitor, job
   progress; verify on UDTMediaServer (2.8k fns) and a 40MB+ target. (Medium.)
3. **Ghidra API drift** (`ghidra.base.*`/`framework.model.*` layout changed
   between 11→12): pin to the 12.x line the repo already targets; the
   `gd doctor` compile check catches breakage on upgrade. (Low-medium.)
4. **Concurrent GUI access to the same project** while P2 is read-only
   open: version-conflict risk; read-only + short hold, document. (Low.)

### Effort & exit criteria (as landed)

Landed in ~1 day. Exit criteria met: the E2E patched-pair test passes
(matched+unmatched == primary function count; the patched function is the
changed one); `gd diff programs` renders through the normal formatters;
self-diff and missing-toolchain paths fail with clear messages; README +
SKILL.md updated; unit + E2E suites green. Open follow-up: scale check on a
40MB+ pair (binDiff is O(functions) on the differ side; the exports and
SQLite parse are the CLI's cost).

---

## Sequencing & effort

| Phase | Depends on | Effort | Risk | Value |
|-------|-----------|--------|------|-------|
| P0 housekeeping | — | ~1 d | trivial | build time, dead-code removal |
| P1 CommandMeta + cmd/ split | P0 | 2–4 d | medium (large mechanical diff) | the #1 maintenance cost disappears |
| P2 query planner | P1 | 1–2 d | low | one source of truth for limit/filter/pagination |
| P3 envelope table | P2 | ~1 d | low | kills the stringly-typed unwrap |
| P4 formats + snapshots | P2 | 1–2 d | low | silent-wrong-format bugs caught |
| P5 bridge registry | P1–P4 | 2–4 d | **high** (core server) | +`raw help`, −74 guards, one-line commands |
| P6 scale opts | P5 | 2–5 d | medium | 1.9M-row queries stop shipping 1.9M rows |
| P7 hygiene — **done** | continuous | ~1 d | trivial | suite split, grammar hole closed, CHANGELOG, docs |
| P8 real program diff — **done** | P5 (bridge) | 1–2 d | medium (third-party toolchain, big-prog memory) | `diff programs` = real function-level diff via **Google binDiff** (requires the native differ + BinExport.jar; clear setup error if absent) |

Suggested landing: P0+P1 first (separate PRs per sub-step: trait, then
TargetArgs, then cmd/ split), then P2–P4 as one "query & output pipeline"
PR, P5 alone, P6 as feature-flagged follow-ups.

## Open follow-ups (intentionally not done)

- **Scale check on a 40MB+ binDiff pair** (P8): the small-fixture pipeline is
  verified; export time + SQLite parse on a large target is unmeasured.
- **Bridge wraps body-only Java scripts** (P7 item 6 alternative): SKILL.md
  documents the class-form requirement; auto-wrapping is a possible nicety.
- **Stale bridge port/PID files**: a `gd doctor` sweep could remove
  `~/.local/share/ghidra-cli/bridge-*.port`/`.pid` files whose processes are
  gone.
- P6.3 single-connection batching: rejected as negligible — each CLI
  invocation is one process holding one connection to the persistent bridge.

---

## Explicit non-goals

- No protocol redesign of the envelope (that's `PLAN.md` §0.1; the P3 table
  is the pragmatic step toward it).
- No multi-project scheduler / durable corpus queue (NEXT.md territory).
- No new subcommands; `help` (P5) is the only addition.
- No changes to bridge start/stop semantics, port/PID file layout, or the
  fail-closed `requires_bridge` default.

---

# Plan Document Review (2026-07-17)

Cross-checked every planning doc against the current code.

## Status verdicts

| Document | Status | Verdict |
|---|---|---|
| `PLAN.md` | Active (Slices 2–5, 4.x) | Needs a "what landed" section. 4.1 (script args + `--expect`) **implemented** (bridge `handleScriptRun` with `expect`/`allow_empty`). 4.2 artifact contract **partial** — only the `--expect` row check; no manifest (`schema`/`rows`/`sha256`), no atomic write. 4.3 module runtime, 4.4 machine-readable capabilities, Slice 2 (`project verify`, server-side filtering/streaming), Slice 3 (corpus scheduler), Slice 5 — **not implemented**. |
| `NEXT.md` | Design record | Responsive-bridge control plane it describes **is implemented** (job queue, control router, per-job monitors, drain shutdown — verified in `GhidraCliBridge.java`). Stale: line 142 still says `stop_bridge` "still has a three-second graceful period", contradicting line 44 and the code (`GHIDRA_CLI_SHUTDOWN_TIMEOUT`, default 300s). Slice checkboxes don't mark which pieces landed. |
| `PLAN-java-plugin.md` | Superseded | Migration fully done. Stale facts: says `-postScript` (code uses `-preScript`, `bridge.rs:483`); says "sequential command handling / one connection at a time" (bridge now runs acceptor + client pool + per-program job queue); references `GHIDRA_CLI_SOCKET`/`src/daemon/` (removed); 300s fixed timeout (long ops now unbounded by default). Keep as decision-history only. |
| `docs/plan-prod.md` | Superseded | Rust-daemon-era plan; self-declares stale. Archive. |
| `docs/plan-complete-stub-commands.md` | Historical | Already has a `historical` header. All 39 commands exist in the current CLI; the daemon + `*.py` handlers it describes are gone. Archive. |
| `docs/plan-e2e-tests.md` | Historical (⚠️ policy conflict) | Has a `historical` header, but prescribes `skip_if_no_ghidra!()` — **directly contradicts AGENTS.md rule 1** (never skip; `require_ghidra!()` panics). A future reader could re-introduce skipping. Needs an explicit warning note, not just an archive. |
| `DOCS/ergo-refactor-2026-07-17.md` | Completed | Fine as a log; minor stale detail (port files under `~/.local/share/gd/`; actual data dir is `ghidra-cli`). |
| `SKILL.md` | Stale | Says binary is `ghidra` (renamed `gd` in `395f60b`) and that explicit `gd start` is the only way up a bridge (auto-start on import/analyze is implemented). Fix, don't archive — it's agent-facing. |

## Confirmed capability-honesty status (PLAN.md 4.4)

`script_java` / `script_python` are already honest error stubs in the bridge
("Inline Java execution not supported in bridge mode",
`GhidraCliBridge.java:5342-5348`). 4.4's error-path requirement is met; what
remains is machine-readable `capabilities` in `bridge_info` (covered by P5.4).

## Alignment with this refactoring plan

- **P3 envelope table** is the pragmatic first step toward `PLAN.md` §0.1's
  canonical envelope — deliberately no protocol redesign.
- **P6.1 server-side filtering** *is* `NEXT.md` Slice 2's "move common
  filtering/count/pagination server-side" — do it as P6.1, don't
  duplicate-track it in the Slice plan.
- **P5.4 `capabilities`** is the lightweight version of Slice 2's
  protocol/capability negotiation.
- **P5.2 job registry** gives a stable handle a future corpus scheduler
  (Slice 3) can use for cancel/status without reworking the queue; P6.2's
  `progress` field is the incremental version of Slice 1's progress channel.
- Gap the plan docs miss: all of `PLAN.md`/`NEXT.md` is bridge/scheduler-side.
  None address the Rust CLI maintenance cost (5 near-duplicate `match`es, ~35
  redundant field declarations, 2.5k-line `main.rs`) — exactly what P1–P4
  target.

## Concrete doc actions (fold into P0) — ALL DONE

1. ~~Fix `SKILL.md` (binary name `gd`; auto-start note).~~ Done.
2. Add a warning to `docs/plan-e2e-tests.md`: "Skip-based Ghidra detection is
   forbidden — see AGENTS.md rule 1; use `require_ghidra!()` which panics."
3. Archive: move `PLAN-java-plugin.md` and `docs/plan-prod.md` to
   `docs/history/` with a `> **Status: superseded**` header (keep `PLAN.md`/
   `NEXT.md` at root — they're active).
4. Add a short "Implementation status (2026-07-17)" section to `PLAN.md` and
   `NEXT.md` per the table above; fix the stale three-second note at
   `NEXT.md:142`.
5. Move `TODO.md` to `docs/history/` after stripping the fixed-bug prose
   (keep §7 follow-ups, renumber).
