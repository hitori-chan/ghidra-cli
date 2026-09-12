# Ghidra CLI

A Rust CLI for automating Ghidra reverse engineering tasks. Usable directly by hand or driven by an AI coding agent like Claude Code.

## Features

- **Direct bridge architecture** - CLI connects directly to a Java bridge running inside Ghidra's JVM
- **Auto-start bridge** - Import/analyze commands automatically start the bridge
- **Fast queries** - Sub-second response times with Ghidra kept in memory
- **Program analysis** - Functions, symbols, types, strings, cross-references
- **Type system** - Create/edit structs, enums, typedefs; add/remove struct fields
- **Function signatures** - Edit return types, calling conventions, full C signatures; retype variables
- **Binary patching** - Modify bytes, NOP instructions, export patches
- **Call graphs** - Generate caller/callee graphs, export to DOT format
- **Search capabilities** - Find strings, bytes, functions, constant values (with ARM LDR literal-pool refs), instruction text patterns (works without xrefs), crypto patterns
- **Raw C/assembly output** - `decompile` and `disasm` print raw C / raw assembly by default (override with `--json`, `--pretty`, or `-o`)
- **Raw bridge access** - `gd raw <command> [JSON]` reaches every bridge command, including memory reads and range queries
- **Session context** - `GD_PROJECT`/`GD_PROGRAM` environment variables as project/program fallbacks
- **Program diffing** - `gd diff programs` is a real function-level cross-program diff via [Google binDiff](https://github.com/google/bindiff) (per-function similarity/confidence, `--changed`, `--unmatched`) — requires the binDiff toolchain, see [Diff (BinDiff)](#diff-bindiff)
- **Script execution** - Run checked-in Java Ghidra scripts with real positional args and `--expect` artifact gates
- **Batch operations** - Execute multiple commands from a file
- **Responsive job control** - Long analyses run on a serialized program lane while `ping`, `status`, `jobs`, and `cancel` stay live on a separate control plane
- **Flexible output** - Human-readable, JSON, or pretty JSON formats
- **Filtering** - Expression-based filtering with a small DSL (e.g., `size > 100 AND name ~ 'crypt'`)

## Architecture

```
┌─────────────────┐         ┌──────────────────────────────────────┐
│   CLI Command   │──TCP──▶ │  GhidraCliBridge.java                │
│   gd ...    │         │  (GhidraScript in analyzeHeadless)   │
│   --project X   │         │  ServerSocket on localhost:dynamic   │
└─────────────────┘         └──────────────────────────────────────┘
```

The CLI connects directly to a Java bridge running inside Ghidra's JVM. Ghidra loads once and stays resident, so one process holds all state: a rename or an applied type sticks for the next command instead of resetting each invocation, and queries return in-process with no per-command JVM startup. The bridge auto-starts on demand — any command brings it up, so you never launch it by hand.

Each project gets its own bridge process and port file, so you can analyze several binaries at once. The only runtime dependencies are Ghidra and a JDK — no Python/PyGhidra.

## Installation

### From Source

```bash
git clone https://github.com/hitori-chan/ghidra-cli
cd ghidra-cli
cargo install --path .
```

The binary is named **`gd`** — a short, distinct name that never shadows the
native Ghidra commands (`ghidra`, `analyzeHeadless`, ...) on `PATH`.

### Requirements

- **Ghidra 12.x** (12.1.2 verified) - Download from [ghidra-sre.org](https://ghidra-sre.org), or run `gd setup` to fetch it
- **A full JDK** - not a JRE. Ghidra compiles the bridge script at runtime, so it needs `javac` and the `jdk.compiler` module. Ghidra 12.x wants JDK 21; older releases accept JDK 17. `gd doctor` finds a suitable JDK and compiles the bridge as a health check.
- **Rust 1.70+** - For building from source

Point the CLI at your Ghidra install (skip this if you used `gd setup`):
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Or store it in config:
gd config set ghidra_install_dir /path/to/ghidra
```

`gd` picks the JDK itself and passes it to Ghidra, so you don't have to
juggle `PATH`. Override the choice with the global `--java-home` flag, the
`java_home` config key, or `GHIDRA_CLI_JAVA_HOME`.

## Quick Start

```bash
# Check installation
gd doctor

# Import a binary. This starts the bridge and runs auto-analysis in one step.
gd import ./binary --project myproject --program mybinary

# Query functions (uses the running bridge)
gd function list

# Decompile a function
gd decompile main

# Find interesting strings
gd find string "password"

# Get cross-references
gd x-ref to 0x401000

# Generate call graph
gd graph callers main --depth 3
```

## Global Flags

These work before any subcommand, so you can set them once for a whole invocation:

```bash
gd --project P --program bin function list   # --project/--program are global
```

| Flag | Effect |
|------|--------|
| `--project <P>` | Project name or path |
| `--program <PROG>` | Program within the project |
| `--projects-dir <DIR>` | Where Ghidra projects live (default: a cache dir; overrides `ghidra_project_dir`) |
| `--java-home <PATH>` | Full JDK for Ghidra to use (must be a JDK, not a JRE) |
| `--json` | Compact JSON output |
| `--pretty` | Pretty-printed JSON |
| `-v` / `-vv` / `-vvv` | Log verbosity: warn / info / debug |
| `-q` / `--quiet` | Suppress non-essential output |

Ghidra 12.1+ rejects project directories that contain a dot-prefixed component
(such as `~/.cache`), so on Linux the default falls back to
`~/ghidra-cli-projects`. Use `--projects-dir` to put projects wherever you like.

## Commands

### Project & Program Management
```bash
gd project create <name>           # Create project
gd project list                    # List projects
gd project info [<name>]           # Show project info
gd project delete <name>           # Delete project (removes .gpr/.rep, stops its bridge)
gd import <binary> --project <p>   # Import + auto-analyze (bridge auto-starts)
gd import <binary> --no-analyze    # Import only, skip analysis (still persisted)
gd import <binary> --detach        # Return immediately; bridge keeps importing
gd import <binary> --program NAME  # Import under an explicit program name
gd analyze --project <p>           # (Re)run analysis on an imported program
gd program list                    # Programs in the project
gd program info                    # Metadata for the current program (image base, memory, counts)
gd program open --program NAME     # Switch to a program (close/delete take --program too)
gd program export FORMAT -o OUT    # Export current program (binary, c/cpp, xml, json, …)
gd rename OLD NEW                  # Rename a symbol (shortcut for symbol rename)
```

### Generic Query & Dump

```bash
gd query functions --filter "name~evp" --count     # any data type, full filter DSL
gd query strings --fields value,length --sort length --limit 20
gd dump imports|exports|functions|strings          # flat dumps with the same options
```

`query`/`dump` take the standard query options (`--filter`, `--fields`,
`--sort`, `--limit`, `--offset`, `--count`). A `--filter` on a list field is
executed in the bridge (exact match on `~`/`=`, superset on `^`/`$`), and
`--offset` pages server-side — the client always re-runs the pipeline, so
results are identical to the pre-pushdown fetch.

### Function Analysis
```bash
gd function list                   # List all functions
gd function list --filter "size > 100"  # Filter by size
gd decompile <name-or-addr>        # Decompile function (prints raw C)
gd decompile main --with-vars --with-params  # Include variable/param details
gd decompile-multi a b c           # Decompile several in one round trip
gd disasm <address> --instructions 20  # Disassemble (prints raw assembly)
gd disasm <address> --end <addr>   # Disassemble a range until <addr>
gd disasm <address> --no-resolve   # Skip literal-pool value resolution
gd function set-signature <func> --signature "int foo(int x, char *y)"
gd function set-return-type <func> --type void
gd function set-calling-convention <func> --convention __cdecl
gd function set-var-type <func> --var local_10 --type "MyStruct *"
```

Decompilation has no native time limit by default, so large valid functions are
not aborted after 30 seconds. Set `GHIDRA_CLI_DECOMPILE_TIMEOUT` to a positive
number of seconds to impose a Ghidra-side limit; `0` means unbounded. The socket
wait follows the long-operation policy controlled by `GHIDRA_CLI_OP_TIMEOUT`,
which is also unbounded by default.

### Symbols & Types
```bash
gd symbol list                     # List symbols
gd symbol create <addr> <name>     # Create symbol
gd symbol rename <old> <new>       # Rename symbol
gd type list                       # List data types (with kind: struct/enum/typedef/...)
gd type get <name>                 # Get type details (fields, enum members, typedef base)
gd type create <name>              # Create empty struct
gd type add-field <struct> --name fd --type int   # Add struct field
gd type del-field <struct> --name fd              # Remove struct field
gd type create-enum <name> --values "A=0,B=1"     # Create enum
gd type typedef <name> <base_type>                # Create typedef alias
gd type rename <old> <new>         # Rename type
gd type delete <name>              # Delete type
```

### Function Tags
```bash
gd tag list                        # All tags (name, comment, use count)
gd tag get <name>                  # Functions carrying a tag
gd tag create <name> --comment "…" # Create a tag (comment optional)
gd tag add <func> <tag>...         # Attach tags (auto-creates missing ones)
gd tag remove <func> <tag>...      # Detach tags (--all clears every tag)
gd tag rename <old> <new>          # Rename everywhere it is used
gd tag set-comment <name> "…"      # Set/clear a tag's comment
gd tag delete <name>               # Delete tag, detaching from all functions
gd function list --tag <name>      # Filter by tag (repeatable = AND)
gd function list --untagged        # Functions with no tags
```

Tag names are case-sensitive. `tag add`/`remove` are idempotent (already-present
and not-present tags are reported, not errors). Function rows include a sorted
`tags` array, so `--fields name,address,tags` and `--filter "tags ~ 'crypto'"`
work too.

### Cross-References
```bash
gd x-ref to <address>              # References TO address
gd x-ref from <address>            # References FROM address
```

### Search
```bash
gd find string "pattern"           # Find strings
gd find bytes "90 90 90"           # Find byte patterns
gd find function "*crypt*"         # Find functions by name
gd find constant 0xdeadbeef        # Find constant value (+ ARM LDR pool refs)
gd find constant 0x8031 --size 4 --max 100
gd find instruction "bl srand"     # Find instructions by disasm text (case-insensitive; --case-sensitive to disable)
gd find instruction "ldr r4, [pc" --start 0x1000 --end 0x9000 --limit 50
gd find crypto                     # Find crypto constants
gd find interesting                # Find interesting patterns
```

`find instruction` matches the instruction's disassembly text directly, so it
works even where Ghidra failed to create cross-references (under-analyzed
programs) — e.g. locating `bl srand` callers when `xref to srand` comes back
empty. `find constant` scans for little-endian byte patterns and, for ARM, the
literal-pool LDR loads into each hit.

### Raw Bridge Commands

```bash
gd raw <command> [JSON]           # Send any bridge command
gd raw ping                       # (default payload {})
gd raw read_memory '{"address":"0x34f50","size":64}'
gd raw functions_range '{"start":"0x137c8","end":"0x7be8b"}'
gd raw defined_data '{"start":"0x34f40","end":"0x34f80"}'
```

`raw` is the escape hatch: every bridge command (see the `case` list in
`src/ghidra/scripts/GhidraCliBridge.java`) is reachable even before a
dedicated subcommand exists. `--project`/`--program` work as usual.

### Call Graphs
```bash
gd graph calls                     # Full call graph
gd graph callers <func>            # Who calls this? (--depth optional)
gd graph callees <func>            # What does this call? (--depth optional)
gd graph export dot                # Export to DOT format
```

### Binary Patching
```bash
gd patch bytes <addr> "90 90"      # Patch bytes
gd patch nop <addr> --count 5      # NOP out instructions
gd patch export -o patched.bin     # Export patched binary
```

`patch nop --count N` NOPs N consecutive instructions starting at the address
(default 1), walking instruction by instruction so variable-length ISAs work. If
any address in the run has no instruction, the whole patch rolls back untouched.

### Diff (BinDiff)
```bash
gd diff programs OLD NEW            # function-level diff via Google BinDiff
gd diff programs OLD NEW --changed  # only non-identical matches
gd diff programs OLD NEW --unmatched
gd diff programs OLD NEW --min-sim 0.9 --name main
gd diff functions FUNC1 FUNC2       # naive line-by-line C diff, same program only
```

`diff programs` compares two programs in the project with the [BinDiff](https://github.com/google/bindiff)
engine: the bridge exports both programs to BinExport, the native differ
matches functions, and the CLI reads back the `.BinDiff` database. It requires
two optional third-party pieces (the command fails with setup instructions if
either is missing):

- a native **BinDiff** differ — set `bindiff.differ` in config, or install it
  under `$BINDIFF_PATH` / `/opt/bindiff/bin` / `PATH`;
- the plain (non-OSGi) **BinExport.jar** — `gd config set bindiff.binexport_jar /path/to/BinExport.jar`.

Rows carry `similarity`/`confidence` (3 decimals; 1.0 = identical) plus
addresses and names for both sides. Note that binDiff normalizes immediate
constants, so constant-only edits still read as identical — structural edits
(ops, control flow, signatures) are what drop similarity.

### Comments
```bash
gd comment get <address>           # Get comment
gd comment set <addr> "note" --comment-type EOL  # Set comment
gd comment list                    # List all comments
```

`--comment-type` accepts `EOL` (default), `PRE`, `POST`, or `PLATE`.

### Scripts
```bash
gd script list                     # List available scripts
gd script run myscript.java        # Run a script file (absolute path, no copy)
gd script run report.java -- arg1 arg2      # Pass positional args after --
gd script run dump.java --expect out.csv:10 # Fail unless out.csv has >=10 rows
```

`script run` resolves the path to an absolute location, forwards the args after
`--` to the script, and captures its stdout in the response. Use `--expect
PATH[:MIN_ROWS]` (repeatable) to make the job fail when an output artifact is
missing, empty, or short, and `--allow-empty` to permit an expected-but-empty
file. Scripts run on the cancellable job lane (`gd cancel` works).

**Java scripts must be class-form**: a `public class X extends GhidraScript`
whose class name matches the file name — body-only snippets fail with a
misleading "class could not be found" compile error. Inline `script java` /
`script python` are not supported in the bridge and return a clean error.

### Batch Operations
```bash
gd batch commands.txt              # Run commands from file
```

### Statistics
```bash
gd stats                           # Program statistics
gd summary                         # Program summary
```

## Bridge Management

The bridge keeps Ghidra loaded in memory. It starts automatically when needed, but you can also control it manually:

```bash
# Start bridge with a program loaded
gd start --project myproject --program mybinary

# Check bridge status
gd status --project myproject

# Inspect active, queued, and recent jobs (or one job by ID)
gd jobs --project myproject
gd jobs 42 --project myproject

# Cooperatively cancel the active job, or select a queued/running job by ID
gd cancel --project myproject
gd cancel 42 --project myproject

# All commands use the bridge automatically
gd function list --project myproject    # Fast!
gd decompile main --project myproject   # Fast!

# Stop bridge
gd stop --project myproject

# Restart with different program
gd restart --project myproject --program otherbinary
```

The bridge handles networking and lifecycle controls independently from Ghidra
program access. Program operations remain serialized on one Ghidra-owned thread,
but `ping`, `status`, `jobs`, `cancel`, and drain requests remain responsive while
analysis or another long operation is running. Queued program operations receive
job IDs and wait in an explicit bounded FIFO rather than an invisible socket
backlog.

### Multi-Project Support

Each project gets its own bridge process and port file, allowing concurrent analysis:

```bash
# Work on multiple projects simultaneously
gd import ./binary_a --project projA
gd analyze --project projA --program binary_a
gd import ./binary_b --project projB
gd analyze --project projB --program binary_b

# Query each independently
gd function list --project projA
gd function list --project projB
```

## Output Formats

Default output is human-readable when connected to a terminal. When piped (non-TTY), output auto-detects to compact JSON for machine consumption. Use flags to override:

- **Default (TTY)**: Compact human-readable format (designed for both humans and AI agents)
- **Default (pipe)**: Compact JSON for machine parsing
- **--json**: Compact JSON for machine parsing
- **--pretty**: Pretty-printed JSON (indented, multi-line)

Override with flags:
```bash
# Force JSON output (compact, single-line)
gd function list --json

# Force pretty JSON (indented, multi-line)
gd function list --pretty

# Select specific fields
gd function list --fields "name,address,size"
```

### Output Format Design

The bridge always emits compact JSON over the socket. The CLI decides the human-facing format at its own output boundary — human-readable when attached to a TTY, compact JSON when piped, or forced with `--json`/`--pretty`/`-o`. Doing it CLI-side keeps the wire protocol one stable shape with a single place that decides formatting.

## Filtering

Use expressions to filter results:

```bash
gd function list --filter "size > 100"
gd function list --filter "name ~ 'main'"
gd strings list --filter "length > 20"
```

## Environment Variables

Paths and defaults:

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Ghidra installation path |
| `GHIDRA_PROJECT_DIR` | Base directory for projects |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK for Ghidra (overrides auto-detection) |
| `GHIDRA_CLI_CONFIG` | Override the config file path |
| `GHIDRA_DEFAULT_PROJECT` | Default `--project` for `gd query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default `--program` for `gd query` and auto-selection |
| `GD_PROJECT` | Session-level `--project` fallback (command flag > global flag > env) |
| `GD_PROGRAM` | Session-level `--program` fallback (command flag > global flag > env) |

`GD_PROJECT`/`GD_PROGRAM` exist for agent and shell workflows that repeatedly
query one project/program — export them once instead of repeating the flags:

```bash
export GD_PROJECT=tmp-ws50 GD_PROGRAM=webService
gd decompile 0x34db8        # no flags needed
gd find instruction "bl srand"
```


Timeouts. Most default to unbounded so that a legitimately long analysis or
decompile isn't cut off. Set them when you'd rather fail fast:

| Variable | Purpose (default) |
|----------|-------------------|
| `GHIDRA_CLI_LAUNCH_TIMEOUT` | Cap on bridge launch readiness (180s) |
| `GHIDRA_CLI_OP_TIMEOUT` | Cap on long `analyze`/`import` ops (unbounded) |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Ghidra-side decompiler limit in seconds; `0` = unbounded (unbounded) |
| `GHIDRA_CLI_READ_TIMEOUT` | Per-request socket read timeout; `0` = indefinite (300s) |
| `GHIDRA_CLI_CONNECT_DEADLINE` | How long to retry connecting to a (re)starting bridge (60s) |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Grace period to drain jobs before force-kill; `0` = indefinite (300s) |

## AI Agent Integration

Output is structured JSON and the command set is broad, so an agent can script a full reverse-engineering pass end to end. A representative workflow:
1. `gd import suspicious.exe --project analysis` - Import, auto-analyze, and start the bridge in one step
2. `gd find interesting` - AI analyzes suspicious patterns
3. `gd decompile <func>` - AI examines specific functions
4. `gd x-ref to <addr>` - AI traces data flow
5. `gd patch nop <addr>` - AI patches anti-debug code
6. `gd patch export -o patched.bin` - Export patched binary

## Troubleshooting

### Common Issues

#### Missing X11 Libraries (Linux/WSL)

If you see errors like `libXtst.so.6: cannot open shared object file`, install X11 libraries:

```bash
# Arch Linux / WSL with Arch
sudo pacman -S libxtst

# Ubuntu / Debian / WSL with Ubuntu
sudo apt install libxtst6

# Fedora / RHEL
sudo dnf install libXtst
```

#### Java Version Issues

Ghidra requires JDK 17 or higher (not just JRE):

```bash
# Arch Linux
sudo pacman -S jdk21-openjdk

# Ubuntu / Debian
sudo apt install openjdk-21-jdk

# Verify installation
java -version  # Should show 17+ and include "JDK"
```

#### WSL-Specific Notes

WSL requires X11 libraries even for headless operation because Java AWT is loaded during initialization:

1. Install X11 libraries (see above)
2. If using WSL1, consider upgrading to WSL2 for better compatibility
3. Bridge port/PID files are stored in `~/.local/share/ghidra-cli/`

#### Running Doctor

Use the doctor command to verify your installation:

```bash
gd doctor
```

This checks:
- Ghidra installation directory
- analyzeHeadless availability
- Project directory configuration
- Config file status

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

GPL-3.0 License - See [LICENSE](LICENSE) for details.
