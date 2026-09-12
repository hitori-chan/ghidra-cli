---
name: ghidra-cli
description: >
    Use ghidra-cli for reverse engineering tasks: binary analysis, decompilation, function inspection, cross-reference analysis, pattern discovery, binary patching, and type system management.
    Activate when the user requests:
    - Binary analysis or reverse engineering
    - Decompilation or disassembly
    - Function listing, inspection, or renaming
    - Cross-reference or call graph analysis
    - String or byte pattern searches
    - Binary patching or modification
    - Ghidra project management
    - Type management (structs, enums, typedefs, struct fields)
    - Function signature editing (return type, calling convention, full signature)
    - Variable retyping in decompiled functions
---

# ghidra-cli Agent Reference

Rust CLI for Ghidra reverse engineering. Binary name: `gd` (installed by the `ghidra-cli` package).

## Architecture

```
CLI (Rust/clap) ──TCP──► GhidraCliBridge.java (GhidraScript in Ghidra JVM)
```

- **Direct bridge**: no daemon process. The Java bridge IS the persistent server.
- One bridge per project, keyed by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- **Any** command auto-starts the bridge if it isn't running (no manual `gd start` needed)
- Sequential command processing (Ghidra API is not thread-safe)

## Global Flags

| Flag | Effect |
|------|--------|
| `--json` | Compact JSON output (single line) |
| `--pretty` | Pretty-printed JSON |
| `--project P` / `--program PROG` | Target project/program; global, so they may precede the subcommand |
| `--projects-dir DIR` | Where Ghidra projects are stored (overrides `ghidra_project_dir`) |
| `--java-home PATH` | Full JDK for Ghidra (overrides auto-detection) |
| `-v` / `-vv` / `-vvv` | Log verbosity: warn / info / debug |
| `-q` / `--quiet` | Suppress non-essential stderr |

All flags are global, so `gd --project P --program bin function list` works the same as putting them after the subcommand.

**Format auto-detection**: TTY → compact human-readable; pipe → json-compact. Override with `--json`, `--pretty`, or `-o FORMAT`.

Ghidra 12.1+ rejects project dirs with a dot-prefixed component (e.g. `~/.cache`); on Linux the default falls back to `~/ghidra-cli-projects`. Use `--projects-dir` to override.

## Quick Start

```bash
# Fastest path: import runs auto-analysis automatically; bridge starts on demand
gd import ./binary --project myproject

# All subsequent queries reuse the running bridge
gd function list --project myproject
gd decompile main --project myproject
```

## Command Reference

### Bridge Lifecycle

```bash
gd start [--project P] [--program PROG]
gd stop [--project P]
gd restart [--project P] [--program PROG]
gd status [--project P]
gd ping [--project P]
gd jobs [JOB_ID] [--project P]      # bridge queue + recent jobs, or one job by ID
gd cancel [JOB_ID] [--project P]    # cooperatively cancel active (or given) job
```

`ping`, `status`, `jobs`, and `cancel` answer on a control plane that stays responsive while a long `analyze`/`import`/decompile occupies the serialized program lane. Queued program operations get job IDs and wait in a bounded FIFO.

`gd raw help --project P` (or `--json`) lists every command the running bridge supports — use it to check whether an old bridge predates a command before restarting.

### Project Management

```bash
gd project create NAME
gd project list
gd project info [NAME]
gd project delete NAME
```

### Import & Analysis

```bash
gd import BINARY [--project P] [--program PROG] [--no-analyze] [--detach]
gd analyze [--project P] [--program PROG] [--detach]
```

Both auto-start the bridge. `gd import` runs auto-analysis by default (and
persists the program); pass `--no-analyze` for a raw import without analysis.
`--detach` returns immediately. `--program NAME` is honored on every import
path (new project, existing project, name collision — a colliding name
renames the newly imported file and removes it if the rename fails; it never
orphan-programs or touches an existing program).

### Program Management

```bash
gd program list [--project P]          # alias: prog, programs
gd program open --program PROG [--project P]   # --program required by runtime
gd program close [--project P]
gd program delete --program PROG [--project P]
gd program info [--project P]
gd program export FORMAT [--project P] [-o OUTPUT]   # FORMAT: json, xml, c/cpp, binary/bin, gzf, ascii/asm, hex, html
```

### Function Operations

```bash
gd function list [QUERY_OPTS]           # aliases: fn, func, functions
gd function get TARGET [QUERY_OPTS]     # TARGET = name or 0xADDRESS
gd function decompile TARGET [--with-vars] [--with-params] [QUERY_OPTS]
gd function disasm TARGET [QUERY_OPTS]
gd function calls TARGET [QUERY_OPTS]   # outgoing calls
gd function xrefs TARGET [QUERY_OPTS]   # incoming references
gd function rename OLD NEW [--project P] [--program PROG]
gd function create ADDRESS [NAME] [--project P] [--program PROG]
gd function delete TARGET [QUERY_OPTS]
gd function set-signature TARGET --signature "int foo(int x, char *y)" [--project P] [--program PROG]
gd function set-return-type TARGET --type TYPE [--project P] [--program PROG]
gd function set-calling-convention TARGET --convention CC [--project P] [--program PROG]
gd function set-var-type TARGET --var VARNAME --type TYPE [--project P] [--program PROG]
```

### Top-level Shortcuts

```bash
gd decompile TARGET [--with-vars] [--with-params] [QUERY_OPTS]   # aliases: decomp, dec
gd disasm TARGET [-n COUNT] [QUERY_OPTS]   # TARGET = name or 0xADDRESS; aliases: disassemble, dis
```

`--with-vars` includes local variable details (name, type, storage) in the response.
`--with-params` includes parameter details (name, type, storage) in the response.
Both flags add structured data alongside the decompiled C code; use `--json` to see the full output.

### String Operations

```bash
gd strings list [QUERY_OPTS]            # aliases: string, str
gd strings refs STRING [QUERY_OPTS]     # xrefs to string
```

### Symbol Operations

```bash
gd symbol list [QUERY_OPTS]             # aliases: sym, symbols
gd symbol get NAME [QUERY_OPTS]
gd symbol create ADDRESS NAME [--project P] [--program PROG]
gd symbol delete NAME [QUERY_OPTS]
gd symbol rename OLD NEW [--project P] [--program PROG]
```

### Memory Operations

```bash
gd memory map [QUERY_OPTS]              # alias: mem
gd memory read ADDRESS SIZE [QUERY_OPTS]
gd memory write ADDRESS BYTES [--project P] [--program PROG]
gd memory search PATTERN [QUERY_OPTS]
```

### Cross-References

```bash
gd x-ref to ADDRESS [QUERY_OPTS]        # aliases: xref, xrefs, crossref
gd x-ref from ADDRESS [QUERY_OPTS]
gd x-ref list TARGET [QUERY_OPTS]   # refs both to and from the target
```

`x-ref list` takes a target (name, `0xADDR`, or `FUN_<hex>`) and returns references in both directions. If the target is a function, the "from" side scans the whole function body, not just its entry.

### Type Operations

```bash
gd type list [QUERY_OPTS]               # alias: types  (includes "kind" field: struct/union/enum/typedef/pointer/array/other)
gd type get NAME [QUERY_OPTS]           # shows struct fields, enum members, typedef base type, kind
gd type create DEFINITION [--project P] [--program PROG]        # create empty struct
gd type apply ADDRESS TYPE_NAME [--project P] [--program PROG]
gd type delete NAME [--project P] [--program PROG]              # alias: rm
gd type rename OLD NEW [--project P] [--program PROG]           # alias: mv
gd type create-enum NAME --values "A=0,B=1,C=2" [--size 4] [--project P] [--program PROG]
gd type typedef NAME BASE_TYPE [--project P] [--program PROG]   # create type alias
gd type add-field STRUCT_NAME --name FIELD --type TYPE [--offset N] [--size N] [--project P] [--program PROG]
gd type del-field STRUCT_NAME --name FIELD [--project P] [--program PROG]
```

### Tag Operations

Function tags organize large codebases: named, program-scoped labels with an
optional comment, attachable to any number of functions.

```bash
gd tag list [--function TARGET] [QUERY_OPTS]   # alias: tags — all tags (name, comment, use_count), or one function's tags
gd tag get NAME [QUERY_OPTS]                   # alias: show — member functions of a tag (rows: name, address)
gd tag create NAME [--comment TEXT] [--project P] [--program PROG]
gd tag delete NAME [--project P] [--program PROG]                  # alias: rm — detaches from ALL functions; reports use_count + functions_affected
gd tag rename OLD NEW [--project P] [--program PROG]               # alias: mv — global; errors if NEW exists (no implicit merge)
gd tag set-comment NAME COMMENT [--project P] [--program PROG]     # "" clears
gd tag add TARGET TAG... [--no-create] [--project P] [--program PROG]    # auto-creates missing tags; reports added/created/already_present
gd tag remove TARGET TAG... [--project P] [--program PROG]         # reports removed/not_present; idempotent
gd tag remove TARGET --all [--project P] [--program PROG]          # detach every tag
gd function list --tag NAME [--tag NAME2] [QUERY_OPTS]             # server-side filter; multiple --tag = AND
gd function list --untagged [QUERY_OPTS]                           # functions with no tags (triage complement)
```

Semantics agents should know:
- Tag names are **case-sensitive** (`Crypto` ≠ `crypto`). Unknown-tag errors
  include a `Did you mean ...?` hint and exit **nonzero** — check `gd tag
  list` first (or use `--filter`) in speculative loops. A no-match `--filter`
  exits 0 with empty output; an unknown `--tag` exits nonzero.
- `tag add`/`remove` are idempotent: already-attached / not-present tags are
  reported in the response, never errors — safe to retry.
- Function rows (`function list`/`get`) carry a sorted `tags` array (present
  even when empty), so `--fields name,address,tags` and `--filter "tags ~
  'crypto'"` work. DSL `~`/`^`/`$`/`=~`/`in` are case-insensitive on tags;
  `=`/`!=` are exact. In CSV output, tag arrays join with `;`.
- Names cannot be empty or contain `,` or `;` (rejected at creation; odd names
  created in the Ghidra GUI remain attachable/removable/deletable).
- Names with spaces work but cannot be used in `gd batch` files (whitespace
  tokenizer, no quoting).
- External functions are out of scope for tag membership operations: a tag
  applied to externals in the Ghidra GUI may show a higher `use_count` in
  `tag list` than `tag get`'s member count.

Typical agent workflow:

```bash
# Define a taxonomy (comments document meaning for future sessions)
gd tag create crypto --comment "Key schedule, cipher rounds, RNG"
gd tag create reviewed --comment "Decompiled and understood"

# Triage and tag
gd tag add FUN_00401a20 crypto
gd tag add aes_key_expand crypto reviewed

# Bulk via batch (one process, one bridge connection; bare tag names only)
printf 'tag add FUN_00402000 network\ntag add parse_packet network reviewed\n' > triage.batch
gd batch triage.batch

# Drive the next pass off the taxonomy
gd tag list                              # names, comments, use counts
gd tag get network                       # member functions (rows)
gd function list --tag network --filter "size > 200" --fields name,address,tags
gd function list --untagged --limit 20   # what's left to triage
gd tag remove parse_packet wip
```

### Comment Operations

```bash
gd comment list [QUERY_OPTS]            # alias: comments
gd comment get ADDRESS [QUERY_OPTS]
gd comment set ADDRESS TEXT [--comment-type TYPE] [--project P] [--program PROG]
gd comment delete ADDRESS [QUERY_OPTS]
```

`--comment-type` takes `EOL` (default), `PRE`, `POST`, or `PLATE`.

### Search / Find

```bash
gd find string PATTERN [QUERY_OPTS]     # alias: search
gd find bytes HEX [QUERY_OPTS]
gd find function PATTERN [QUERY_OPTS]   # glob patterns
gd find calls FUNCTION [QUERY_OPTS]
gd find crypto [QUERY_OPTS]             # detect AES/SHA/RSA constants
gd find interesting [QUERY_OPTS]        # suspicious patterns
```

### Graph / Call Graph

```bash
gd graph calls [QUERY_OPTS]             # aliases: callgraph, cg
gd graph callers FUNCTION [--depth N] [QUERY_OPTS]
gd graph callees FUNCTION [--depth N] [QUERY_OPTS]
gd graph export FORMAT [QUERY_OPTS]     # FORMAT: dot, json
```

### Diff

`diff programs` is a real cross-program diff powered by Google BinDiff
(https://github.com/google/bindiff). It **requires** two third-party pieces;
if either is missing the command fails with setup instructions:

1. **Native BinDiff differ** — located via `bindiff.differ` config, or
   `$BINDIFF_PATH` (a directory), `/opt/bindiff/bin`, or `PATH`.
2. **BinExport** — the plain (non-OSGi) `BinExport.jar`; the bridge loads it
   at runtime to export both programs. Set it once:
   `gd config set bindiff.binexport_jar /path/to/BinExport.jar`

```bash
# Function-level diff: which functions changed between two versions
# (similarity rounded to 3 decimals; 1.0 = identical)
gd diff programs OLD NEW [--project P] [--program P1] [--format F]

# Only the functions that actually changed
gd diff programs OLD NEW --changed

# Include functions present in only one program (listed first, before matches)
gd diff programs OLD NEW --unmatched

# Filter: similarity floor and/or name substring
gd diff programs OLD NEW --min-sim 0.9 --name main
```

Rows: `name1`, `name2`, `address1`, `address2`, `similarity`, `confidence`,
plus `unmatched: primary|secondary` for unmatched rows. A summary line (total
matched / changed / unmatched counts, overall similarity) is printed for
human formats. binDiff normalizes immediate constants — a constant-only edit
still reads as 1.0; structural edits (opcode, control flow, signature) drop it.

```bash
# Naive line-by-line diff of decompiled C, same program only, no alignment
gd diff functions FUNC1 FUNC2 [--project P] [--format F]
```

### Dump / Export

```bash
gd dump imports [QUERY_OPTS]            # alias: export
gd dump exports [QUERY_OPTS]
gd dump functions [QUERY_OPTS]
gd dump strings [QUERY_OPTS]
```

### Patch

```bash
gd patch bytes ADDRESS HEX [--project P] [--program PROG]
gd patch nop ADDRESS [--count N] [--project P] [--program PROG]
gd patch export -o OUTPUT [--project P] [--program PROG]
```

`--count N` NOPs N consecutive instructions from ADDRESS (default 1), walking instruction by instruction. If any address in the run has no instruction, the whole patch rolls back.

**Do not re-import** `program export binary` / `patch export` output: the re-serialized ELF is for patching/diffing only and can be degenerate for some firmwares (NULL section headers, no `.dynstr`) — re-importing such a file degrades the program (lost executable memory, 0 functions).

### Script Execution

```bash
gd script run PATH [--expect PATH[:MIN_ROWS]]... [--allow-empty] [--project P] [--program PROG] [-- ARGS...]
gd script python CODE [--project P] [--program PROG]
gd script java CODE [--project P] [--program PROG]
gd script list
```

`script run` resolves PATH to an absolute location, forwards the args after `--` to the script as real positional arguments, and captures stdout in the response (`{script, path, stdout, args}`). `--expect PATH[:MIN_ROWS]` (repeatable) fails the job if that artifact is missing, empty, or below MIN_ROWS; `--allow-empty` lets an expected artifact exist while empty. Scripts run on the cancellable job lane, so `gd cancel` works on them.

**Java scripts must be class-form**: a `public class X extends GhidraScript` whose class name matches the file name. Body-only snippets (no class declaration) fail with a misleading "class could not be found" compile error — wrap the body in the class first.

`script java`/`script python` (inline snippets) are **not supported** in the Java bridge — use `script run` with a file.

### Batch

```bash
gd batch SCRIPT_FILE [--project P] [--program PROG]
```

Batch file: one subcommand per line (without `gd` prefix), `#` comments.

### Universal Query

```bash
gd query DATA_TYPE [QUERY_OPTS]
```

DATA_TYPE: `functions`, `strings`, `imports`, `exports`, `memory`.

### Statistics & Info

```bash
gd summary [QUERY_OPTS]       # alias: info
gd stats [QUERY_OPTS]
```

### Configuration

```bash
gd init                       # create config
gd doctor                     # check installation: Ghidra, JDK (javac), bridge-script compile,
                              #   bridge state (sweeps stale port/PID files), project locks
gd doctor --clear-stale-locks # also remove stale project lock files (e.g. after a SIGKILLed bridge)
gd version
gd version
gd config list
gd config get KEY
gd config set KEY VALUE       # keys: ghidra_install_dir, ghidra_project_dir, default_program, default_project, default_output_format, default_limit, launch_timeout_secs,
                               #       bindiff.differ, bindiff.binexport_jar   (required for `gd diff programs`)
gd config reset
gd set-default KIND VALUE     # KIND: program, project
gd setup [--version V] [--dir D] [--force]
```

Bridge wait controls are environment variables: `GHIDRA_CLI_READ_TIMEOUT` for
normal commands, `GHIDRA_CLI_OP_TIMEOUT` for analyze/import, and
`GHIDRA_CLI_CONNECT_DEADLINE` for connection establishment. The legacy config
key `timeout` is ignored when loading old files and rejected by `config set`.

## Common Query Options (QUERY_OPTS)

All query commands accept these:

| Option | Description |
|--------|-------------|
| `--project P` | Project name or path |
| `--program PROG` | Program within project |
| `--filter EXPR` | Filter expression |
| `--fields LIST` | Comma-separated fields to return |
| `-o FORMAT` | Output format |
| `--limit N` | Max results |
| `--offset N` | Skip first N |
| `--sort FIELDS` | Sort: comma-separated, prefix `-` for descending |
| `--count` | Return count only |
| `--json` | Shorthand for `--format=json` |

## Output Formats

| Value | Use |
|-------|-----|
| `compact` | Default for TTY. One line per item. |
| `full` | Multi-line labeled blocks |
| `json` | Pretty JSON |
| `json-compact` | Default for pipes. Single-line JSON. |
| `json-stream` / `ndjson` | One JSON object per line |
| `csv` / `tsv` | Delimited with header |
| `table` | ASCII box-drawn table |
| `count` | Number only |
| `ids` / `minimal` | Address/name only, one per line |
| `tree` | Call tree — `graph callers`/`callees` (depth indentation) and `graph calls` (nodes + edges, cycle-safe) |
| `asm` | Assembly |
| `c` | C pseudocode |

## Filter Expressions

```bash
# Numeric
--filter "size > 100"
--filter "size >= 50"

# String
--filter "name ~ 'crypt'"

# Combined
--filter "size > 100 AND name ~ 'main'"
--filter "name != 'main'"
```

Operators: `=`, `!=`, `>`, `>=`, `<`, `<=`, `~` (contains), `^` (starts with), `$` (ends with), `=~` (regex), `AND`, `OR`, `NOT`, `IN`, `EXISTS`.

## Agent Best Practices

### 1. Count-First Pattern

Always check result volume before fetching:

```bash
gd function list --count --project P
# If manageable:
gd function list --limit 50 --fields name,address,size --project P
```

### 2. Aggressive Filtering

Pre-filter server-side, not client-side:

```bash
# GOOD
gd function list --filter "size > 1000" --project P
# BAD
gd function list --project P  # then filter in agent code
```

### 3. Field Selection

Request only needed fields:

```bash
gd function list --fields name,address --json --project P
```

### 4. Set Defaults

Avoid repeating `--project` and `--program`:

```bash
gd set-default project myproject
gd set-default program mybinary
# Now: gd function list  (no flags needed)
```

## .NET Warning

`gd decompile` prints a warning when the output looks like .NET managed code
(e.g. `halt_baddata()` or a `.NET CLR Managed Code` marker):

> "This appears to be .NET managed code. Ghidra cannot decompile .NET IL bytecode. Consider using a .NET decompiler (e.g., ilspy-cli) for better results."

Ghidra won't produce useful output for IL. Reach for a dedicated .NET
decompiler instead. `ilspy-cli` is a separate tool, not part of ghidra-cli.

## Analysis Workflow

```bash
# 1. Import and analyze
gd import ./target.exe --project analysis
gd analyze --project analysis

# 2. Recon
gd summary --project analysis
gd function list --count --project analysis
gd function list --filter "NOT name ^ 'FUN_'" --fields name,address,size --limit 30 --project analysis

# 3. Investigate
gd decompile main --project analysis
gd decompile main --with-vars --with-params --json --project analysis  # structured output
gd find crypto --project analysis
gd find string "password" --project analysis

# 4. Deep dive
gd graph callers suspicious_func --depth 3 --project analysis
gd x-ref to 0x401000 --project analysis
gd function disasm 0x401000 --project analysis

# 5. Type annotation (improves decompile output)
gd type create MyStruct --project analysis
gd type add-field MyStruct --name fd --type int --project analysis
gd type add-field MyStruct --name flags --type uint --project analysis
gd type create-enum ErrorCode --values "OK=0,ENOENT=2,EPERM=1" --project analysis
gd type typedef HANDLE void --project analysis
gd function set-return-type main --type int --project analysis
gd function set-signature parse_data --signature "int parse_data(char *buf, int len)" --project analysis
gd function set-var-type main --var local_10 --type "MyStruct *" --project analysis
gd decompile main --project analysis  # re-decompile with new types applied

# 6. Patch
gd patch nop 0x401234 --count 3 --project analysis
gd patch export -o patched.exe --project analysis
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Ghidra installation path |
| `GHIDRA_PROJECT_DIR` | Base directory for projects |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK for Ghidra (overrides auto-detection) |
| `GHIDRA_DEFAULT_PROJECT` | Default `--project` for `gd query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default `--program` for `gd query` and program auto-selection |
| `GHIDRA_CLI_CONFIG` | Override config path |
| `GHIDRA_CLI_LAUNCH_TIMEOUT` | Cap on bridge launch readiness (default 180s) |
| `GHIDRA_CLI_OP_TIMEOUT` | Cap on long `analyze`/`import` ops (default unbounded) |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Ghidra-side decompiler limit, seconds; `0` = unbounded (default unbounded) |
| `GHIDRA_CLI_READ_TIMEOUT` | Per-request socket read timeout; `0` = indefinite (default 300s) |
| `GHIDRA_CLI_CONNECT_DEADLINE` | Retry window for connecting to a (re)starting bridge (default 60s) |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Grace period to drain jobs before force-kill; `0` = indefinite (default 300s) |

## File Locations

| File | Purpose |
|------|---------|
| `~/.local/share/ghidra-cli/bridge-{md5}.port` | TCP port for running bridge |
| `~/.local/share/ghidra-cli/bridge-{md5}.pid` | Bridge process PID |
| `~/.config/ghidra-cli/config.yaml` | Configuration |
| `~/.config/ghidra-cli/scripts/GhidraCliBridge.java` | Materialized Java bridge script |
| `~/.local/share/ghidra-cli/ghidra-cli.log` | Debug log |

## Error Recovery

| Problem | Fix |
|---------|-----|
| "No project specified" | Add `--project NAME` or `gd set-default project NAME` |
| "Bridge not responding" | `gd stop --project P` then retry (auto-starts) |
| "Ghidra installation not configured" | `gd setup` or set `GHIDRA_INSTALL_DIR` |
| Function not found | Use `gd find function "*pattern*"` |
| Slow first command | Normal: bridge startup + analysis takes seconds |
| `diff programs` fails with setup instructions | binDiff toolchain missing: install the native differ + `gd config set bindiff.binexport_jar /path/to/BinExport.jar` (see Diff section) |
