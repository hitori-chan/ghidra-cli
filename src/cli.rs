use clap::{ArgAction, Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Shared metadata for command argument structs.
///
/// `main.rs` asks any command "which project/program does this target, does
/// it take query options, does it need the bridge?" through this trait
/// instead of per-command `match`es. Subcommand enums override [`meta`](Self::meta)
/// to delegate to the active variant's arg struct; arg structs answer
/// `project`/`program`/`query_options` directly (see the impls at the bottom
/// of this file). A command variant that forgets to participate fails to
/// compile instead of silently degrading in the old extraction matches.
pub trait CommandMeta {
    /// `--project` from the command's args, if the command accepts one.
    fn project(&self) -> Option<&str>;
    /// `--program` from the command's args, if the command accepts one.
    fn program(&self) -> Option<&str>;
    /// The command's query options, if it has them.
    fn query_options(&self) -> Option<QueryOptions>;
    /// Whether the command needs a live bridge. Default `false` is
    /// fail-closed: a new command that does not opt in is rejected rather
    /// than silently running without a bridge.
    fn requires_bridge(&self) -> bool {
        false
    }
    /// Subcommand enums override this to point at the active variant's arg
    /// struct; arg structs keep the default (`self`).
    fn meta(&self) -> &dyn CommandMeta
    where
        Self: Sized,
    {
        self
    }
}

/// Argument struct for commands with no args of their own (used as the
/// `meta()` fallback for command variants that carry no arg struct).
struct NoCommandMeta;

impl CommandMeta for NoCommandMeta {
    fn project(&self) -> Option<&str> {
        None
    }
    fn program(&self) -> Option<&str> {
        None
    }
    fn query_options(&self) -> Option<QueryOptions> {
        None
    }
}

static NO_COMMAND_META: NoCommandMeta = NoCommandMeta;

/// Target selector shared by commands that take a positional TARGET or a
/// `--target` flag (function/symbol name, or 0xADDRESS). The `--target` flag
/// wins when both are given.
#[derive(Args, Clone, Default, Debug, Serialize, Deserialize)]
pub struct TargetArgs {
    /// Target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
}

impl TargetArgs {
    /// Resolve the target, preferring the explicit `--target` flag.
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

/// Shared project/program targeting for bridge lifecycle commands
/// (start/stop/restart/status/ping/jobs/cancel). Both fields are optional:
/// the global `--project`/`--program` flags and `$GD_PROJECT`/`$GD_PROGRAM`
/// fill the gaps, then the config defaults.
#[derive(Args, Clone, Default, Debug, Serialize, Deserialize)]
pub struct BridgeTargetArgs {
    /// Project path
    #[arg(long)]
    pub project: Option<String>,
    /// Program name to load
    #[arg(long)]
    pub program: Option<String>,
}

/// Implement `CommandMeta` for an arg struct that flattens `QueryOptions`
/// (`pub options: QueryOptions`): project/program/options all come from it.
macro_rules! impl_options_meta {
    ($t:ty) => {
        impl CommandMeta for $t {
            fn project(&self) -> Option<&str> {
                self.options.project.as_deref()
            }
            fn program(&self) -> Option<&str> {
                self.options.program.as_deref()
            }
            fn query_options(&self) -> Option<QueryOptions> {
                Some(self.options.clone())
            }
        }
    };
}

/// Implement `CommandMeta` for an arg struct with its own `project` and
/// `program` `Option<String>` fields (no query options).
macro_rules! impl_bridge_target_meta {
    ($t:ty) => {
        impl CommandMeta for $t {
            fn project(&self) -> Option<&str> {
                self.project.as_deref()
            }
            fn program(&self) -> Option<&str> {
                self.program.as_deref()
            }
            fn query_options(&self) -> Option<QueryOptions> {
                None
            }
        }
    };
}

/// Target/project meta for commands that carry their own `--format` field
/// instead of flattening QueryOptions. Without the synthesized options an
/// explicit `-o/--format` would be silently ignored on those commands.
macro_rules! impl_meta_with_format {
    ($t:ty, with_program) => {
        impl CommandMeta for $t {
            fn project(&self) -> Option<&str> {
                self.project.as_deref()
            }
            fn program(&self) -> Option<&str> {
                self.program.as_deref()
            }
            fn query_options(&self) -> Option<QueryOptions> {
                Some(QueryOptions {
                    program: None,
                    project: None,
                    filter: None,
                    fields: None,
                    format: self.format.clone(),
                    limit: None,
                    offset: None,
                    sort: None,
                    count: false,
                    json: false,
                })
            }
        }
    };
    ($t:ty, no_program) => {
        impl CommandMeta for $t {
            fn project(&self) -> Option<&str> {
                self.project.as_deref()
            }
            fn program(&self) -> Option<&str> {
                None
            }
            fn query_options(&self) -> Option<QueryOptions> {
                Some(QueryOptions {
                    program: None,
                    project: None,
                    filter: None,
                    fields: None,
                    format: self.format.clone(),
                    limit: None,
                    offset: None,
                    sort: None,
                    count: false,
                    json: false,
                })
            }
        }
    };
}

/// Implement `CommandMeta` for a subcommand enum: one `meta()` match maps
/// each variant to its arg struct; the accessors delegate through it and
/// `requires_bridge` is `true` because every variant of a bridge-group enum
/// needs the bridge.
macro_rules! impl_enum_meta {
    ($e:ident, $($variant:ident($field:ident)),* $(,)?) => {
        impl CommandMeta for $e {
            fn requires_bridge(&self) -> bool {
                true
            }
            fn meta(&self) -> &dyn CommandMeta {
                match self {
                    $(Self::$variant($field) => $field,)*
                }
            }
            fn project(&self) -> Option<&str> {
                self.meta().project()
            }
            fn program(&self) -> Option<&str> {
                self.meta().program()
            }
            fn query_options(&self) -> Option<QueryOptions> {
                self.meta().query_options()
            }
        }
    };
}

#[derive(Parser)]
#[command(name = "gd")]
#[command(version, about = "Rust CLI for Ghidra reverse engineering", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase log verbosity printed to stdout (-v=warn, -vv=info, -vvv=debug)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Output JSON with pretty formatting
    #[arg(long, global = true)]
    pub pretty: bool,

    /// Project name or path (can also be specified per-subcommand)
    #[arg(long, global = true)]
    pub project: Option<String>,

    /// Program name within the project (can also be specified per-subcommand)
    #[arg(long, global = true)]
    pub program: Option<String>,

    /// Directory under which Ghidra projects are stored.
    /// Overrides config `ghidra_project_dir` and the default location.
    /// Note: Ghidra 12.1+ rejects paths containing a dot-prefixed component.
    #[arg(long, global = true)]
    pub projects_dir: Option<std::path::PathBuf>,

    /// Full JDK home for Ghidra to use (must be a JDK, not a JRE).
    /// Overrides config `java_home` and auto-detection.
    #[arg(long, global = true)]
    pub java_home: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum Commands {
    /// Universal query command for any data type
    Query(QueryArgs),

    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand, alias = "prog", alias = "programs")]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand, alias = "fn", alias = "func", alias = "functions")]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand, alias = "string", alias = "str")]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand, alias = "sym", alias = "symbols")]
    Symbol(SymbolCommands),

    /// Memory operations
    #[command(subcommand, alias = "mem")]
    Memory(MemoryCommands),

    /// Cross-reference operations
    #[command(
        subcommand,
        alias = "xrefs",
        alias = "xref",
        alias = "crossref",
        alias = "crossrefs"
    )]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand, alias = "types")]
    Type(TypeCommands),

    /// Function tag operations
    #[command(subcommand, alias = "tags")]
    Tag(TagCommands),

    /// Comment operations
    #[command(subcommand, alias = "comments")]
    Comment(CommentCommands),

    /// Search operations
    #[command(subcommand, alias = "search")]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand, alias = "callgraph", alias = "cg")]
    Graph(GraphCommands),

    /// Decompile function
    #[command(alias = "decomp", alias = "dec")]
    Decompile(DecompileArgs),

    /// Disassemble code
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(DisasmArgs),

    /// Decompile several addresses in one bridge round trip
    #[command(name = "decompile-multi", alias = "dmulti")]
    DecompileMulti(DecompileMultiArgs),

    /// Send a raw bridge command with a JSON args payload (escape hatch for
    /// bridge commands that have no dedicated subcommand, e.g. find_constant,
    /// read_memory, write_memory)
    #[command(name = "raw")]
    Raw(RawArgs),

    /// Diff operations
    #[command(subcommand)]
    Diff(DiffCommands),

    /// Dump/export data
    #[command(subcommand, alias = "export")]
    Dump(DumpCommands),

    /// Patch binary
    #[command(subcommand)]
    Patch(PatchCommands),

    /// Script execution
    #[command(subcommand, alias = "scripts")]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Set default values
    SetDefault(SetDefaultArgs),

    /// Program summary
    #[command(alias = "info")]
    Summary(SummaryArgs),

    /// Program statistics
    Stats(StatsArgs),

    /// Show version information
    Version,

    /// Check Ghidra installation
    Doctor,

    /// Initialize configuration
    Init,

    /// Import a binary into a project
    Import(ImportArgs),

    /// Analyze a program
    #[command(alias = "analysis")]
    Analyze(AnalyzeArgs),

    /// Start the bridge
    Start(BridgeTargetArgs),

    /// Stop the bridge
    Stop(BridgeTargetArgs),

    /// Restart the bridge
    Restart(BridgeTargetArgs),

    /// Show bridge status
    Status(BridgeTargetArgs),

    /// Ping the bridge
    Ping(BridgeTargetArgs),

    /// List active, queued, and recently completed bridge jobs
    Jobs {
        /// Show one job by ID; omit for the bridge queue and recent jobs
        job_id: Option<u64>,
        #[command(flatten)]
        target: BridgeTargetArgs,
    },

    /// Request cooperative cancellation of a bridge job (defaults to active job)
    Cancel {
        /// Job ID; omit to cancel the currently active job
        job_id: Option<u64>,
        #[command(flatten)]
        target: BridgeTargetArgs,
    },

    /// Download and setup Ghidra automatically
    Setup(SetupArgs),

    /// Rename a symbol (shortcut for `symbol rename`)
    #[command(alias = "mv")]
    Rename(RenameArgs),
}

#[derive(Args, Clone, Default, Serialize, Deserialize, Debug)]
pub struct QueryArgs {
    /// Data type to query (functions, strings, imports, etc.)
    pub data_type: String,

    /// Target program
    #[arg(long, env = "GHIDRA_DEFAULT_PROGRAM")]
    pub program: Option<String>,

    /// Project name
    #[arg(long, env = "GHIDRA_DEFAULT_PROJECT")]
    pub project: Option<String>,

    /// Filter expression: <field><op><value>, e.g. 'name~PK' (contains),
    /// 'name=~"^PK_"' (regex), 'size>100'. Ops: = != > >= < <= ~ ^ $ =~.
    /// Combine with AND/OR/NOT. Bare words are rejected.
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format (full, compact, minimal, json, json-compact,
    /// json-stream, csv, tsv, table, ids, count, tree, asm, c)
    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results (0 = unlimited; default 1000)
    #[arg(long)]
    pub limit: Option<usize>,

    /// Skip first N results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Sort by field(s) (comma-separated, prefix with - for descending)
    #[arg(long, allow_hyphen_values = true)]
    pub sort: Option<String>,

    /// Only return count
    #[arg(long)]
    pub count: bool,

    /// Output as JSON (shorthand for --format=json)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommands,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProjectCommands {
    /// Create a new project
    Create { name: String },
    /// List all projects
    List,
    /// Delete a project
    Delete { name: String },
    /// Show project information
    Info { name: Option<String> },
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramCommands {
    /// List all programs in the project
    #[command(alias = "ls")]
    List(ProgramTargetArgs),
    /// Open/switch to a program
    Open(ProgramTargetArgs),
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(ProgramTargetArgs),
    /// Export program
    Export(ExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramTargetArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ExportArgs {
    /// Export format (xml, json, asm, c)
    pub format: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Output file
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionCommands {
    /// List all functions
    #[command(alias = "ls")]
    List(FunctionListArgs),
    /// Get function details
    #[command(alias = "show", alias = "detail")]
    Get(FunctionGetArgs),
    /// Decompile function
    #[command(alias = "decomp")]
    Decompile(FunctionDecompileArgs),
    /// Disassemble function
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(FunctionGetArgs),
    /// Get function calls
    Calls(FunctionGetArgs),
    /// Get cross-references to function
    #[command(alias = "xrefs", alias = "crossrefs", alias = "references")]
    XRefs(FunctionGetArgs),
    /// Rename function
    Rename(RenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionGetArgs),
    /// Set function signature from C-style string
    SetSignature(SetSignatureArgs),
    /// Set function return type
    SetReturnType(SetReturnTypeArgs),
    /// Set function calling convention
    SetCallingConvention(SetCallingConventionArgs),
    /// Set variable type in a function
    SetVarType(SetVarTypeArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionListArgs {
    /// Only functions carrying this tag (repeatable; multiple tags = AND)
    #[arg(long = "tag", value_name = "NAME")]
    pub tags: Vec<String>,
    /// Only functions with no tags
    #[arg(long, conflicts_with = "tags")]
    pub untagged: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionGetArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct RenameArgs {
    pub old_name: String,
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateFunctionArgs {
    pub address: String,
    pub name: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionDecompileArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetSignatureArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// C-style signature string, e.g. "int main(int argc, char** argv)"
    #[arg(long)]
    pub signature: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetReturnTypeArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Return type name
    #[arg(long = "type")]
    pub return_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetCallingConventionArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Calling convention name (e.g., "__cdecl", "__stdcall", "__fastcall")
    #[arg(long)]
    pub convention: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetVarTypeArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Variable name to retype
    #[arg(long = "var")]
    pub var_name: String,
    /// New type name (e.g., "int", "char *", "MyStruct")
    #[arg(long = "type")]
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get references to a string
    #[command(alias = "references", alias = "xrefs")]
    Refs(StringRefsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StringRefsArgs {
    pub string: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum SymbolCommands {
    /// List all symbols
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get symbol details
    Get(SymbolGetArgs),
    /// Create symbol
    Create(CreateSymbolArgs),
    /// Delete symbol
    Delete(SymbolGetArgs),
    /// Rename symbol
    Rename(RenameArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateSymbolArgs {
    pub address: String,
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// Read memory
    Read(MemReadArgs),
    /// Write memory
    Write(MemWriteArgs),
    /// Search memory
    Search(MemSearchArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemReadArgs {
    pub address: String,
    pub size: usize,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemWriteArgs {
    pub address: String,
    pub bytes: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemSearchArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum XRefCommands {
    /// Get cross-references to address
    To(XRefArgs),
    /// Get cross-references from address
    From(XRefArgs),
    /// List all cross-references
    List(XRefArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCommands {
    /// List data types
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get type definition
    Get(TypeGetArgs),
    /// Create type
    Create(CreateTypeArgs),
    /// Apply type to address
    Apply(ApplyTypeArgs),
    /// Delete a data type
    #[command(alias = "rm")]
    Delete(TypeDeleteArgs),
    /// Rename a data type
    #[command(alias = "mv")]
    Rename(TypeRenameArgs),
    /// Create an enum type
    CreateEnum(CreateEnumArgs),
    /// Create a typedef (type alias)
    Typedef(TypedefArgs),
    /// Add a field to a struct type
    AddField(TypeAddFieldArgs),
    /// Remove a field from a struct type
    DelField(TypeDelFieldArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateTypeArgs {
    pub definition: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ApplyTypeArgs {
    pub address: String,
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDeleteArgs {
    /// Name or path of the type to delete
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeRenameArgs {
    /// Current name of the type
    pub old_name: String,
    /// New name for the type
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateEnumArgs {
    /// Enum type name
    pub name: String,
    /// Comma-separated KEY=VALUE pairs, e.g. "RED=0,GREEN=1,BLUE=2"
    #[arg(long)]
    pub values: String,
    /// Size in bytes (1, 2, 4, or 8)
    #[arg(long, default_value = "4")]
    pub size: i32,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypedefArgs {
    /// Name for the new typedef
    pub name: String,
    /// Base type to alias (e.g., "int", "dword", "MyStruct")
    pub base_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeAddFieldArgs {
    /// Name of the struct type to modify
    pub type_name: String,
    /// Field name
    #[arg(long)]
    pub name: String,
    /// Field type (e.g., "int", "byte", "pointer", a custom struct name)
    #[arg(long = "type")]
    pub field_type: String,
    /// Offset within the struct (if omitted, appends at end)
    #[arg(long)]
    pub offset: Option<i32>,
    /// Field size override
    #[arg(long)]
    pub size: Option<i32>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDelFieldArgs {
    /// Name of the struct type to modify
    pub type_name: String,
    /// Field name to remove
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TagCommands {
    /// List all function tags (or one function's tags with --function)
    #[command(alias = "ls")]
    List(TagListArgs),
    /// Show the functions carrying a tag
    #[command(alias = "show")]
    Get(TagGetArgs),
    /// Create a function tag
    Create(TagCreateArgs),
    /// Delete a tag (detaches it from all functions)
    #[command(alias = "rm")]
    Delete(TagDeleteArgs),
    /// Rename a tag everywhere it is used
    #[command(alias = "mv")]
    Rename(TagRenameArgs),
    /// Set or clear a tag's comment ("" clears)
    SetComment(TagSetCommentArgs),
    /// Attach tags to a function (auto-creates missing tags)
    Add(TagAttachArgs),
    /// Detach tags from a function
    Remove(TagDetachArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagListArgs {
    /// Only tags attached to this function (name | 0xaddr | FUN_<hex>)
    #[arg(long = "function", value_name = "TARGET")]
    pub function: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagGetArgs {
    /// Tag name (case-sensitive)
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagCreateArgs {
    /// Tag name (case-sensitive; commas and semicolons not allowed)
    pub name: String,
    /// Optional comment describing the tag's meaning
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagDeleteArgs {
    /// Tag name
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagRenameArgs {
    /// Current tag name
    pub old_name: String,
    /// New tag name
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagSetCommentArgs {
    /// Tag name
    pub name: String,
    /// New comment text; empty string clears the comment
    pub comment: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagAttachArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// One or more tag names to attach
    // `required = true` is mandatory: num_args = 1.. alone does NOT make a
    // positional required — `ghidra tag add crypto` would parse with the tag
    // name consumed as TARGET and an empty tag list.
    #[arg(value_name = "TAG", required = true, num_args = 1..)]
    pub tags: Vec<String>,
    /// Error instead of auto-creating tags that don't exist yet
    #[arg(long)]
    pub no_create: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagDetachArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Tag names to detach
    #[arg(value_name = "TAG", num_args = 0.., required_unless_present = "all")]
    pub tags: Vec<String>,
    /// Detach every tag from the function
    #[arg(long, conflicts_with = "tags")]
    pub all: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CommentCommands {
    /// List all comments
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get comment at address
    Get(CommentGetArgs),
    /// Set comment
    Set(CommentSetArgs),
    /// Delete comment
    Delete(CommentGetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentGetArgs {
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentSetArgs {
    pub address: String,
    pub text: String,
    #[arg(long)]
    pub comment_type: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindInstructionArgs {
    /// Substring to match in instruction disassembly (e.g. "bl srand")
    pub pattern: String,
    /// Restrict scan to instructions at or after this address
    #[arg(long)]
    pub start: Option<String>,
    /// Restrict scan to instructions at or before this address
    #[arg(long)]
    pub end: Option<String>,
    /// Case-sensitive match (default: case-insensitive)
    #[arg(long)]
    pub case_sensitive: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindConstantArgs {
    /// Constant value to search for (hex, e.g. 0x8031)
    pub value: String,
    /// Byte width of the constant (2, 4, or 8; default 4)
    #[arg(long, default_value_t = 4)]
    pub size: usize,
    /// Maximum number of hits (default 100)
    #[arg(long, default_value_t = 100)]
    pub max: usize,
    /// Skip scanning for ARM LDR literal-pool references
    #[arg(long)]
    pub no_refs: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find strings
    #[command(alias = "str", alias = "strings")]
    String(FindStringArgs),
    /// Find byte patterns
    Bytes(FindBytesArgs),
    /// Find constant value references (byte scan + ARM LDR literal-pool refs)
    #[command(name = "constant")]
    Constant(FindConstantArgs),
    /// Find instructions matching a text pattern (works without xrefs)
    #[command(name = "instruction")]
    Instruction(FindInstructionArgs),
    /// Find functions
    #[command(alias = "func", alias = "fn", alias = "functions")]
    Function(FindFunctionArgs),
    /// Find calls to function
    Calls(FindCallsArgs),
    /// Find crypto constants
    #[command(alias = "encryption")]
    Crypto(QueryOptions),
    /// Find interesting functions
    #[command(alias = "suspicious", alias = "notable")]
    Interesting(QueryOptions),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindStringArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindBytesArgs {
    pub hex: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindFunctionArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindCallsArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    #[command(alias = "called-by", alias = "incoming")]
    Callers(GraphFunctionArgs),
    /// Get callees of function
    #[command(alias = "calls-to", alias = "outgoing")]
    Callees(GraphFunctionArgs),
    /// Export graph
    Export(GraphExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphExportArgs {
    /// Export format (e.g., dot, json)
    #[arg(id = "export_format")]
    pub format: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Number of instructions to disassemble
    #[arg(long = "instructions", short = 'n')]
    pub num_instructions: Option<usize>,
    /// Disassemble until this address (range mode; use instead of -n)
    #[arg(long)]
    pub end: Option<String>,
    /// Do not resolve literal pool loads (faster, no `loaded` fields)
    #[arg(long)]
    pub no_resolve: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileMultiArgs {
    /// One or more function targets (name | 0xaddr | FUN_<hex>)
    pub targets: Vec<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct RawArgs {
    /// Bridge command name (e.g. find_constant, decompile_multi, read_memory, ping)
    pub command: String,
    /// JSON object payload sent as the command args (default "{}")
    // NB: field name must not be `json` — that arg id collides with the
    // flattened QueryOptions `--json` flag and breaks positional parsing.
    #[arg(value_name = "JSON", default_value = "{}")]
    pub json_args: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DiffCommands {
    /// Real cross-program diff via Google binDiff (function matching + similarity).
    /// Requires the BinDiff integration: set `bindiff.binexport_jar` in the config
    /// (and optionally `bindiff.differ` for the native differ binary).
    Programs(DiffProgramsArgs),
    /// Naive line-by-line diff of decompiled C (same program only; no alignment, not BinDiff)
    Functions(DiffFunctionsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffProgramsArgs {
    /// First program (defaults to the loaded program when omitted)
    #[arg(required_unless_present = "program2")]
    pub program1: Option<String>,
    /// Second program (by project name)
    #[arg(required_unless_present = "program1")]
    pub program2: Option<String>,
    /// Only show non-identical matches (similarity < 1.0)
    #[arg(long)]
    pub changed: bool,
    /// Also list unmatched functions (present in only one of the programs);
    /// listed before the matches so a row cap always shows them
    #[arg(long)]
    pub unmatched: bool,
    /// Minimum similarity to show (0.0..=1.0; default 0.0)
    #[arg(long)]
    pub min_sim: Option<f64>,
    /// Only matches whose primary or secondary name contains this substring
    #[arg(long)]
    pub name: Option<String>,
    /// Max rows to return (0 = all; default from config)
    #[arg(long)]
    pub limit: Option<usize>,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffFunctionsArgs {
    /// First function (name or address), in the loaded program
    pub func1: String,
    /// Second function (name or address), in the loaded program
    pub func2: String,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DumpCommands {
    /// Dump imports
    Imports(QueryOptions),
    /// Dump exports
    Exports(QueryOptions),
    /// Dump functions
    Functions(QueryOptions),
    /// Dump strings
    Strings(QueryOptions),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum PatchCommands {
    /// Patch bytes
    Bytes(PatchBytesArgs),
    /// NOP instructions
    Nop(PatchNopArgs),
    /// Export patched binary
    Export(PatchExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchBytesArgs {
    pub address: String,
    pub hex: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchNopArgs {
    pub address: String,
    #[arg(long)]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchExportArgs {
    #[arg(short, long)]
    pub output: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ScriptCommands {
    /// Run a script file
    Run(ScriptRunArgs),
    /// Execute inline Python code
    Python(ScriptInlineArgs),
    /// Execute inline Java code
    Java(ScriptInlineArgs),
    /// List available scripts
    List,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptRunArgs {
    pub script_path: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Expected output artifact: PATH or PATH:MIN_ROWS (repeatable). The job
    /// fails if the artifact is missing, empty, or below MIN_ROWS.
    #[arg(long = "expect", value_name = "PATH[:MIN_ROWS]")]
    pub expect: Vec<String>,
    /// Allow an expected artifact to exist but be empty.
    #[arg(long)]
    pub allow_empty: bool,
    /// Script arguments (after --)
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptInlineArgs {
    pub code: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BatchArgs {
    pub script_file: String,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(long)]
    pub program: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ConfigCommands {
    /// List all configuration
    List,
    /// Get configuration value
    Get { key: String },
    /// Set configuration value
    Set { key: String, value: String },
    /// Reset configuration
    Reset,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetDefaultArgs {
    pub kind: String,
    pub value: String,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SummaryArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StatsArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ImportArgs {
    pub binary: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Import only — skip auto-analysis (the program is still persisted)
    #[arg(long, default_value = "false")]
    pub no_analyze: bool,
    /// Return immediately, let bridge continue import in background
    #[arg(long, default_value = "false")]
    pub detach: bool,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Return immediately, let bridge continue analysis in background
    #[arg(long, default_value = "false")]
    pub detach: bool,
}

/// Common query options used across commands
#[derive(Args, Clone, Default, Serialize, Deserialize, Debug)]
pub struct QueryOptions {
    #[arg(long)]
    pub program: Option<String>,

    #[arg(long)]
    pub project: Option<String>,

    /// Filter expression: <field><op><value>, e.g. 'name~PK' (contains),
    /// 'name=~"^PK_"' (regex), 'size>100'. Ops: = != > >= < <= ~ ^ $ =~.
    /// Combine with AND/OR/NOT. Bare words are rejected.
    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(long)]
    pub fields: Option<String>,

    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results (0 = unlimited; default 1000)
    #[arg(long)]
    pub limit: Option<usize>,

    #[arg(long)]
    pub offset: Option<usize>,

    #[arg(long, allow_hyphen_values = true)]
    pub sort: Option<String>,

    #[arg(long)]
    pub count: bool,

    #[arg(long)]
    pub json: bool,
}

/// Arguments for the setup command
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetupArgs {
    /// Specific Ghidra version to install (e.g., "11.0"). Defaults to latest.
    #[arg(long)]
    pub version: Option<String>,

    /// Installation directory. Defaults to standard data directory.
    #[arg(long, short = 'd')]
    pub dir: Option<String>,

    /// Skip Java check
    #[arg(long)]
    pub force: bool,
}

// ── CommandMeta impls ────────────────────────────────────────────────────────
// QueryOptions itself (several subcommand variants carry it directly).
impl CommandMeta for QueryOptions {
    fn project(&self) -> Option<&str> {
        self.project.as_deref()
    }
    fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }
    fn query_options(&self) -> Option<QueryOptions> {
        Some(self.clone())
    }
}

// QueryArgs carries the query fields directly (no flattened QueryOptions).
impl CommandMeta for QueryArgs {
    fn project(&self) -> Option<&str> {
        self.project.as_deref()
    }
    fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }
    fn query_options(&self) -> Option<QueryOptions> {
        Some(QueryOptions {
            program: self.program.clone(),
            project: self.project.clone(),
            filter: self.filter.clone(),
            fields: self.fields.clone(),
            format: self.format.clone(),
            limit: self.limit,
            offset: self.offset,
            sort: self.sort.clone(),
            count: self.count,
            json: self.json,
        })
    }
}

// Raw passes its JSON payload through verbatim: limit/filter live inside the
// JSON, so it has project/program but intentionally no query options.
impl CommandMeta for RawArgs {
    fn project(&self) -> Option<&str> {
        self.options.project.as_deref()
    }
    fn program(&self) -> Option<&str> {
        self.options.program.as_deref()
    }
    fn query_options(&self) -> Option<QueryOptions> {
        None
    }
}

// Option-bearing arg structs (flattened `pub options: QueryOptions`).
impl_options_meta!(FunctionListArgs);
impl_options_meta!(FunctionGetArgs);
impl_options_meta!(FunctionDecompileArgs);
impl_options_meta!(StringRefsArgs);
impl_options_meta!(SymbolGetArgs);
impl_options_meta!(MemReadArgs);
impl_options_meta!(MemSearchArgs);
impl_options_meta!(XRefArgs);
impl_options_meta!(TypeGetArgs);
impl_options_meta!(TagListArgs);
impl_options_meta!(TagGetArgs);
impl_options_meta!(CommentGetArgs);
impl_options_meta!(FindInstructionArgs);
impl_options_meta!(FindConstantArgs);
impl_options_meta!(FindStringArgs);
impl_options_meta!(FindBytesArgs);
impl_options_meta!(FindFunctionArgs);
impl_options_meta!(FindCallsArgs);
impl_options_meta!(GraphFunctionArgs);
impl_options_meta!(GraphExportArgs);
impl_options_meta!(DecompileArgs);
impl_options_meta!(DisasmArgs);
impl_options_meta!(DecompileMultiArgs);
impl_options_meta!(StatsArgs);
impl_options_meta!(SummaryArgs);

// Arg structs with their own project/program fields (no query options).
impl_bridge_target_meta!(SetSignatureArgs);
impl_bridge_target_meta!(SetReturnTypeArgs);
impl_bridge_target_meta!(SetCallingConventionArgs);
impl_bridge_target_meta!(SetVarTypeArgs);
impl_bridge_target_meta!(ImportArgs);
impl_bridge_target_meta!(AnalyzeArgs);
impl_bridge_target_meta!(RenameArgs);
impl_bridge_target_meta!(CreateFunctionArgs);
impl_bridge_target_meta!(CreateSymbolArgs);
impl_bridge_target_meta!(MemWriteArgs);
impl_bridge_target_meta!(CreateTypeArgs);
impl_bridge_target_meta!(ApplyTypeArgs);
impl_bridge_target_meta!(TypeDeleteArgs);
impl_bridge_target_meta!(TypeRenameArgs);
impl_bridge_target_meta!(CreateEnumArgs);
impl_bridge_target_meta!(TypedefArgs);
impl_bridge_target_meta!(TypeAddFieldArgs);
impl_bridge_target_meta!(TypeDelFieldArgs);
impl_bridge_target_meta!(TagCreateArgs);
impl_bridge_target_meta!(TagDeleteArgs);
impl_bridge_target_meta!(TagRenameArgs);
impl_bridge_target_meta!(TagSetCommentArgs);
impl_bridge_target_meta!(TagAttachArgs);
impl_bridge_target_meta!(TagDetachArgs);
impl_bridge_target_meta!(CommentSetArgs);
impl_bridge_target_meta!(PatchBytesArgs);
impl_bridge_target_meta!(PatchNopArgs);
impl_bridge_target_meta!(PatchExportArgs);
impl_bridge_target_meta!(ScriptRunArgs);
impl_bridge_target_meta!(ScriptInlineArgs);
impl_bridge_target_meta!(ProgramTargetArgs);
impl_bridge_target_meta!(ExportArgs);
impl_bridge_target_meta!(BatchArgs);

// Project-only arg structs.
impl_meta_with_format!(DiffProgramsArgs, with_program);
impl_meta_with_format!(DiffFunctionsArgs, no_program);

// Subcommand enums: delegate to the active variant's arg struct.
// FunctionCommands::Delete reuses FunctionGetArgs (a target + query options).
impl_enum_meta!(
    FunctionCommands,
    List(args),
    Decompile(args),
    Get(args),
    Disasm(args),
    Calls(args),
    XRefs(args),
    Rename(args),
    Create(args),
    Delete(args),
    SetSignature(args),
    SetReturnType(args),
    SetCallingConvention(args),
    SetVarType(args)
);
impl_enum_meta!(StringsCommands, List(opts), Refs(args));
impl_enum_meta!(
    MemoryCommands,
    Map(opts),
    Read(args),
    Write(args),
    Search(args)
);
impl_enum_meta!(
    DumpCommands,
    Imports(opts),
    Exports(opts),
    Functions(opts),
    Strings(opts)
);
impl_enum_meta!(XRefCommands, To(args), From(args), List(args));
impl_enum_meta!(
    FindCommands,
    String(args),
    Bytes(args),
    Constant(args),
    Instruction(args),
    Function(args),
    Calls(args),
    Crypto(opts),
    Interesting(opts)
);
impl_enum_meta!(
    GraphCommands,
    Calls(opts),
    Callers(args),
    Callees(args),
    Export(args)
);
impl_enum_meta!(
    CommentCommands,
    List(opts),
    Get(args),
    Set(args),
    Delete(args)
);
impl_enum_meta!(
    SymbolCommands,
    List(opts),
    Get(args),
    Create(args),
    Delete(args),
    Rename(args)
);
impl_enum_meta!(
    TypeCommands,
    List(opts),
    Get(args),
    Create(args),
    Apply(args),
    Delete(args),
    Rename(args),
    CreateEnum(args),
    Typedef(args),
    AddField(args),
    DelField(args)
);
impl_enum_meta!(
    TagCommands,
    List(args),
    Get(args),
    Create(args),
    Delete(args),
    Rename(args),
    SetComment(args),
    Add(args),
    Remove(args)
);
impl_enum_meta!(PatchCommands, Bytes(args), Nop(args), Export(args));
// ScriptCommands has a unit variant (List), so it is written by hand.
impl CommandMeta for ScriptCommands {
    fn requires_bridge(&self) -> bool {
        true
    }
    fn meta(&self) -> &dyn CommandMeta {
        match self {
            Self::Run(args) => args,
            Self::Python(args) => args,
            Self::Java(args) => args,
            Self::List => &NO_COMMAND_META,
        }
    }
    fn project(&self) -> Option<&str> {
        self.meta().project()
    }
    fn program(&self) -> Option<&str> {
        self.meta().program()
    }
    fn query_options(&self) -> Option<QueryOptions> {
        self.meta().query_options()
    }
}
impl_enum_meta!(
    ProgramCommands,
    List(args),
    Open(args),
    Close(args),
    Delete(args),
    Info(args),
    Export(args)
);
impl_enum_meta!(DiffCommands, Programs(args), Functions(args));

// Top-level command enum. `requires_bridge` lists the bridge groups
// explicitly (fail-closed default for anything else); `meta` delegates to
// the variant's arg struct or subcommand enum.
impl CommandMeta for Commands {
    fn requires_bridge(&self) -> bool {
        matches!(
            self,
            Commands::Import(_)
                | Commands::Analyze(_)
                | Commands::Query(_)
                | Commands::Decompile(_)
                | Commands::Function(_)
                | Commands::Strings(_)
                | Commands::Memory(_)
                | Commands::Dump(_)
                | Commands::Summary(_)
                | Commands::XRef(_)
                | Commands::Symbol(_)
                | Commands::Type(_)
                | Commands::Tag(_)
                | Commands::Comment(_)
                | Commands::Graph(_)
                | Commands::Find(_)
                | Commands::Diff(_)
                | Commands::Patch(_)
                | Commands::Script(_)
                | Commands::Disasm(_)
                | Commands::DecompileMulti(_)
                | Commands::Raw(_)
                | Commands::Batch(_)
                | Commands::Stats(_)
                | Commands::Program(_)
                | Commands::Rename(_)
        )
    }
    fn meta(&self) -> &dyn CommandMeta {
        match self {
            Commands::Query(args) => args,
            Commands::Summary(args) => args,
            Commands::Decompile(args) => args,
            Commands::Disasm(args) => args,
            Commands::DecompileMulti(args) => args,
            Commands::Stats(args) => args,
            Commands::Raw(args) => args,
            Commands::Import(args) => args,
            Commands::Analyze(args) => args,
            Commands::Batch(args) => args,
            Commands::Rename(args) => args,
            Commands::Function(cmd) => cmd,
            Commands::Strings(cmd) => cmd,
            Commands::Memory(cmd) => cmd,
            Commands::Dump(cmd) => cmd,
            Commands::XRef(cmd) => cmd,
            Commands::Symbol(cmd) => cmd,
            Commands::Type(cmd) => cmd,
            Commands::Tag(cmd) => cmd,
            Commands::Comment(cmd) => cmd,
            Commands::Find(cmd) => cmd,
            Commands::Graph(cmd) => cmd,
            Commands::Patch(cmd) => cmd,
            Commands::Script(cmd) => cmd,
            Commands::Program(cmd) => cmd,
            Commands::Diff(cmd) => cmd,
            _ => &NO_COMMAND_META,
        }
    }
    fn project(&self) -> Option<&str> {
        self.meta().project()
    }
    fn program(&self) -> Option<&str> {
        self.meta().program()
    }
    fn query_options(&self) -> Option<QueryOptions> {
        self.meta().query_options()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decompile_target_flag() {
        let cli = Cli::try_parse_from(["ghidra", "decompile", "--target", "FUN_00401000"])
            .expect("decompile --target should parse");
        match cli.command {
            Commands::Decompile(args) => {
                assert_eq!(args.target.resolved_target(), "FUN_00401000")
            }
            _ => panic!("expected decompile command"),
        }
    }

    #[test]
    fn parses_function_get_positional_target() {
        let cli = Cli::try_parse_from(["ghidra", "function", "get", "main"])
            .expect("function get positional target should parse");
        match cli.command {
            Commands::Function(FunctionCommands::Get(args)) => {
                assert_eq!(args.target.resolved_target(), "main");
            }
            _ => panic!("expected function get command"),
        }
    }

    #[test]
    fn command_meta_bridge_groups() {
        use CommandMeta as _;
        // Bridge groups report themselves as bridge commands...
        assert!(Commands::Decompile(DecompileArgs {
            target: TargetArgs::default(),
            with_vars: false,
            with_params: false,
            options: QueryOptions::default(),
        })
        .requires_bridge());
        // ...while management commands do not (fail-closed default).
        assert!(!Commands::Doctor.requires_bridge());
        assert!(!Commands::Init.requires_bridge());
        assert!(!Commands::Project(ProjectArgs {
            command: ProjectCommands::List,
        })
        .requires_bridge());

        // Project/program extraction flows through the trait.
        let cmd = Commands::Function(FunctionCommands::Get(FunctionGetArgs {
            target: TargetArgs::default(),
            options: QueryOptions {
                project: Some("proj".into()),
                program: Some("prog".into()),
                ..Default::default()
            },
        }));
        assert_eq!(cmd.project(), Some("proj"));
        assert_eq!(cmd.program(), Some("prog"));
        assert!(cmd.query_options().is_some());

        // QueryArgs builds its QueryOptions from its own fields.
        let q = Commands::Query(QueryArgs::default());
        assert!(q.project().is_none());
        assert!(q.query_options().is_some());

        // Raw has project/program but no query options.
        let raw = Commands::Raw(RawArgs {
            command: "ping".into(),
            json_args: "{}".into(),
            options: QueryOptions::default(),
        });
        assert!(raw.query_options().is_none());
    }
}
