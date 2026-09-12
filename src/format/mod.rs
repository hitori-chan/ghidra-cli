use std::collections::{BTreeMap, BTreeSet};

use crate::error::{GhidraError, Result};
use comfy_table::{presets::UTF8_FULL, Table};
use serde::Serialize;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Full,
    Compact,
    Minimal,
    Json,
    JsonCompact,
    JsonStream,
    Csv,
    Tsv,
    Table,
    Ids,
    Count,
    Tree,
    Asm,
    C,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "compact" => Ok(Self::Compact),
            "minimal" => Ok(Self::Minimal),
            "json" => Ok(Self::Json),
            "json-compact" => Ok(Self::JsonCompact),
            "json-stream" | "ndjson" => Ok(Self::JsonStream),
            "csv" => Ok(Self::Csv),
            "tsv" => Ok(Self::Tsv),
            "table" => Ok(Self::Table),
            "ids" => Ok(Self::Ids),
            "count" => Ok(Self::Count),
            "tree" => Ok(Self::Tree),
            "asm" => Ok(Self::Asm),
            "c" => Ok(Self::C),
            _ => Err(GhidraError::InvalidFormat(format!(
                "'{s}' (expected: full, compact, minimal, json, json-compact, \
                 json-stream, csv, tsv, table, ids, count, tree, asm, c)"
            ))),
        }
    }
}

pub trait Formatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String>;
}

pub struct DefaultFormatter;

impl Formatter for DefaultFormatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(data).map_err(|e| e.into()),
            OutputFormat::JsonCompact => serde_json::to_string(data).map_err(|e| e.into()),
            OutputFormat::JsonStream => {
                let mut result = String::new();
                for item in data {
                    let json = serde_json::to_string(item)?;
                    result.push_str(&json);
                    result.push('\n');
                }
                Ok(result)
            }
            OutputFormat::Count => Ok(format!("{}", data.len())),
            OutputFormat::Table => format_table(data),
            OutputFormat::Csv => format_csv(data, ','),
            OutputFormat::Tsv => format_csv(data, '\t'),
            OutputFormat::Compact => format_compact(data),
            OutputFormat::Full => format_full(data),
            OutputFormat::Minimal | OutputFormat::Ids => format_minimal(data),
            OutputFormat::C => {
                let vals = to_json_values(data)?;
                format_c(&vals)
            }
            OutputFormat::Asm => {
                let vals = to_json_values(data)?;
                format_asm(&vals)
            }
            OutputFormat::Tree => {
                let vals = to_json_values(data)?;
                format_tree(&vals)
            }
        }
    }
}

/// Read-only field access for both `JsonValue` and its inner object map
/// (so row parsers work in either context without copying).
trait Gettable {
    fn get_val(&self, key: &str) -> Option<&JsonValue>;
}

impl Gettable for JsonValue {
    fn get_val(&self, key: &str) -> Option<&JsonValue> {
        self.get(key)
    }
}

impl Gettable for serde_json::Map<String, JsonValue> {
    fn get_val(&self, key: &str) -> Option<&JsonValue> {
        self.get(key)
    }
}

/// A decompile item: the `code` field plus its optional companions
/// (`signature`, `name`/`entry`, `params`, `variables`).
struct CodeRow {
    code: String,
    signature: Option<String>,
    name: Option<String>,
    entry: Option<String>,
    /// (name, type, storage)
    params: Vec<(String, String, String)>,
    /// (name, type, storage)
    variables: Vec<(String, String, String)>,
}

impl CodeRow {
    /// Parse a decompile item; `None` when it has no string `code` field.
    fn parse<I: Gettable>(item: &I) -> Option<Self> {
        let code = item.get_val("code").and_then(|c| c.as_str())?.to_string();
        let mut row = Self {
            code,
            signature: item
                .get_val("signature")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            name: item
                .get_val("name")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            entry: item
                .get_val("entry")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            params: Vec::new(),
            variables: Vec::new(),
        };
        collect_named(item.get_val("params"), &mut row.params);
        collect_named(item.get_val("variables"), &mut row.variables);
        Some(row)
    }

    /// Code body with a trailing newline guaranteed.
    fn code_text(&self) -> String {
        let mut s = self.code.clone();
        if !s.ends_with('\n') {
            s.push('\n');
        }
        s
    }
}

fn collect_named(src: Option<&JsonValue>, out: &mut Vec<(String, String, String)>) {
    let Some(JsonValue::Array(items)) = src else {
        return;
    };
    for p in items {
        if let JsonValue::Object(obj) = p {
            out.push((
                obj.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                obj.get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                obj.get("storage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
            ));
        }
    }
}

/// A disassembly instruction row.
struct InsnRow {
    address: String,
    bytes: String,
    mnemonic: String,
    operands: Vec<String>,
    loaded: Option<String>,
}

impl InsnRow {
    /// Parse a disassembly item; `None` when it has no string `mnemonic` field.
    fn parse<I: Gettable>(item: &I) -> Option<Self> {
        let mnemonic = item.get_val("mnemonic").and_then(|v| v.as_str())?;
        Some(Self {
            address: item
                .get_val("address")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            bytes: item
                .get_val("bytes")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            mnemonic: mnemonic.to_string(),
            operands: item
                .get_val("operands")
                .and_then(|o| o.as_array())
                .map(|ops| ops.iter().map(format_json_value).collect())
                .unwrap_or_default(),
            loaded: item
                .get_val("loaded")
                .and_then(|l| l.get("value"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
    }
}

fn to_json_values<T: Serialize>(data: &[T]) -> Result<Vec<JsonValue>> {
    let collected: std::result::Result<Vec<JsonValue>, serde_json::Error> =
        data.iter().map(serde_json::to_value).collect();
    Ok(collected?)
}

/// Render decompiled C: each item's `code` field verbatim; items carrying
/// `name`/`entry` (e.g. decompile-multi results) get a `// name @ entry`
/// header; `error` items render as a comment. Items without a `code` field
/// fall back to pretty JSON.
fn format_c(data: &[JsonValue]) -> Result<String> {
    let mut out = String::new();
    for item in data {
        if let Some(err) = item.get("error").and_then(|e| e.as_str()) {
            out.push_str(&format!("// error: {}\n\n", err));
            continue;
        }
        if let Some(row) = CodeRow::parse(item) {
            if let (Some(name), Some(entry)) = (&row.name, &row.entry) {
                out.push_str(&format!("// {} @ {}\n", name, entry));
            }
            out.push_str(&row.code_text());
            out.push('\n');
        } else {
            out.push_str(&serde_json::to_string_pretty(item)?);
            out.push('\n');
        }
    }
    Ok(out)
}

/// Render disassembly: `address  bytes  mnemonic operands [; loads 0x..]` per
/// line. Items lacking a `mnemonic` field fall back to pretty JSON.
fn format_asm(data: &[JsonValue]) -> Result<String> {
    let mut out = String::new();
    for item in data {
        if let Some(row) = InsnRow::parse(item) {
            let ops = row.operands.join(", ");
            let loaded = row
                .loaded
                .as_deref()
                .map(|v| format!("  ; loads {}", v))
                .unwrap_or_default();
            out.push_str(&format!(
                "{}  {:<12} {:<8} {}{}\n",
                row.address, row.bytes, row.mnemonic, ops, loaded
            ));
        } else {
            out.push_str(&serde_json::to_string_pretty(item)?);
            out.push('\n');
        }
    }
    Ok(out)
}

fn format_table<T: Serialize>(data: &[T]) -> Result<String> {
    if data.is_empty() {
        return Ok("No results".to_string());
    }

    // Convert to JSON values to inspect structure
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let keys = union_keys(&json_data);
    if keys.is_empty() {
        return Ok(format!("{} results", data.len()));
    }

    let mut table = Table::new();
    table.load_style(UTF8_FULL);

    // Add header
    table.set_header(&keys);

    // Add rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys
                .iter()
                .map(|k| {
                    map.get(k)
                        .map(format_json_value)
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            table.add_row(row);
        }
    }

    Ok(table.to_string())
}

fn format_csv<T: Serialize>(data: &[T], delimiter: char) -> Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok(String::new());
    }

    let keys = union_keys(&json_data);
    if keys.is_empty() {
        return Ok(String::new());
    }

    let mut result = String::new();

    // Header
    result.push_str(&keys.join(&delimiter.to_string()));
    result.push('\n');

    // Rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys
                .iter()
                .map(|k| {
                    map.get(k)
                        .map(format_csv_value)
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            result.push_str(&row.join(&delimiter.to_string()));
            result.push('\n');
        }
    }

    Ok(result)
}

/// CSV cell rendering. Arrays join with `;` (never with `, `): format_csv does
/// no field quoting, so a `, `-joined array (e.g. `tags`, `operands`) would
/// inject the delimiter and shift every subsequent column.
/// Column set for tabular output: the union of keys across all rows in
/// first-seen order. Single-command row sets are homogeneous (identical to
/// first-row keys); heterogeneous rows (e.g. diff `--unmatched` rows adding
/// the `unmatched` column) must not lose columns.
fn union_keys(json_data: &[JsonValue]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for item in json_data {
        if let JsonValue::Object(map) = item {
            for k in map.keys() {
                if seen.insert(k.as_str()) {
                    keys.push(k.clone());
                }
            }
        }
    }
    keys
}

fn format_csv_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Array(arr) => arr
            .iter()
            .map(format_csv_value)
            .collect::<Vec<_>>()
            .join(";"),
        other => format_json_value(other),
    }
}

/// Compact human-readable format: one line per item with key fields.
fn format_compact<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for item in &json_data {
        match item {
            JsonValue::Object(map) => {
                // Special case: decompile response with "code" key
                if let Some(row) = CodeRow::parse(map) {
                    if let Some(sig) = &row.signature {
                        result.push_str(sig);
                        result.push('\n');
                    }
                    result.push_str(&row.code_text());
                    continue;
                }

                // Special case: disasm instruction with mnemonic
                if let Some(row) = InsnRow::parse(map) {
                    result.push_str(&format!(
                        "{:<12} {:<16} {} {}\n",
                        row.address,
                        row.bytes,
                        row.mnemonic,
                        row.operands.join(", ")
                    ));
                    continue;
                }

                // General object: render primary fields in a compact line
                let address = map.get("address").and_then(|v| v.as_str());
                let name = map.get("name").and_then(|v| v.as_str());
                let size = map.get("size").and_then(|v| v.as_u64());
                let value_str = map.get("value").and_then(|v| v.as_str());

                // Build compact line from available fields
                let mut parts: Vec<String> = Vec::new();

                if let Some(addr) = address {
                    parts.push(addr.to_string());
                }
                if let Some(n) = name {
                    parts.push(n.to_string());
                }
                if let Some(s) = size {
                    parts.push(format!("({})", s));
                }
                if let Some(v) = value_str {
                    // Truncate long strings
                    if v.len() > 80 {
                        parts.push(format!("\"{}...\"", &v[..77]));
                    } else {
                        parts.push(format!("\"{}\"", v));
                    }
                }

                // If we only have unknown fields, render as key=value pairs
                if parts.is_empty() {
                    let kv: Vec<String> = map
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                        .collect();
                    result.push_str(&kv.join("  "));
                } else {
                    result.push_str(&parts.join("  "));
                }

                // Add extra context from secondary fields
                let secondary: Vec<String> = map
                    .iter()
                    .filter(|(k, _)| {
                        !matches!(
                            k.as_str(),
                            "address"
                                | "name"
                                | "size"
                                | "value"
                                | "mnemonic"
                                | "bytes"
                                | "operands"
                                | "code"
                                | "signature"
                        )
                    })
                    .filter_map(|(k, v)| {
                        let s = format_json_value(v);
                        if s.is_empty() || s == "null" || s == "\"\"" {
                            None
                        } else {
                            Some(format!("{}={}", k, s))
                        }
                    })
                    .collect();

                if !secondary.is_empty() {
                    result.push_str("  ");
                    result.push_str(&secondary.join("  "));
                }

                result.push('\n');
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

/// Full human-readable format: multi-line labeled blocks per item.
fn format_full<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for (i, item) in json_data.iter().enumerate() {
        if i > 0 {
            result.push_str("---\n");
        }

        match item {
            JsonValue::Object(map) => {
                // Special case: decompile response
                if let Some(row) = CodeRow::parse(map) {
                    if let Some(sig) = &row.signature {
                        result.push_str(&format!("Signature: {}\n", sig));
                    }
                    if let Some(name) = &row.name {
                        result.push_str(&format!("Function:  {}\n", name));
                    }
                    result.push('\n');
                    result.push_str(&row.code_text());
                    if !row.params.is_empty() {
                        result.push_str("\nParameters:\n");
                        for (name, typ, storage) in &row.params {
                            result.push_str(&format!("  {} {} ({})\n", typ, name, storage));
                        }
                    }
                    if !row.variables.is_empty() {
                        result.push_str("\nVariables:\n");
                        for (name, typ, storage) in &row.variables {
                            result.push_str(&format!("  {} {} ({})\n", typ, name, storage));
                        }
                    }
                    continue;
                }

                // Calculate max key width for alignment
                let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);

                for (key, val) in map {
                    let formatted = format_json_value(val);
                    result.push_str(&format!(
                        "{:width$}  {}\n",
                        format!("{}:", key),
                        formatted,
                        width = max_key + 1
                    ));
                }
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

/// Render a call tree. Supports the two graph shapes the bridge emits:
///
/// * `graph callers` / `graph callees` rows — a flat list whose `depth`
///   field comes from the recursive walk, rendered as indentation;
/// * the `graph calls` envelope — `nodes` + `edges`, rendered as an
///   adjacency tree with a cycle guard (`(…)` marks a revisit).
///
/// An empty result renders as `No results` (like the other human formats);
/// non-empty non-graph data is an error: `tree` is only meaningful for graph
/// data.
fn format_tree(data: &[JsonValue]) -> Result<String> {
    if data.is_empty() {
        return Ok("No results".to_string());
    }

    // `graph calls` envelope: single item with nodes + edges.
    if let Some(first) = data.first() {
        if let (Some(nodes), Some(edges)) = (
            first.get("nodes").and_then(|v| v.as_array()),
            first.get("edges").and_then(|v| v.as_array()),
        ) {
            return render_call_graph(nodes, edges);
        }
    }

    // Callers/callees rows carry a `depth` field.
    if data.iter().any(|i| i.get("depth").is_some()) {
        let mut out = String::new();
        for item in data {
            let depth = item.get("depth").and_then(|d| d.as_u64()).unwrap_or(0) as usize;
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let addr = item.get("address").and_then(|v| v.as_str()).unwrap_or("?");
            match item.get("call_site").and_then(|v| v.as_str()) {
                Some(site) => out.push_str(&format!(
                    "{}{} @ {} ({})\n",
                    "  ".repeat(depth),
                    name,
                    site,
                    addr
                )),
                None => out.push_str(&format!("{}{} ({})\n", "  ".repeat(depth), name, addr)),
            }
        }
        return Ok(out);
    }

    Err(GhidraError::InvalidFormat(
        "format 'tree' requires graph data (use with: graph callers, graph callees, graph calls)"
            .to_string(),
    ))
}

fn render_call_graph(nodes: &[JsonValue], edges: &[JsonValue]) -> Result<String> {
    // BTree maps keep every ordering deterministic for snapshot testing.
    let mut name_by_id: BTreeMap<String, String> = BTreeMap::new();
    for n in nodes {
        if let (Some(id), Some(name)) = (
            n.get("id").and_then(|v| v.as_str()),
            n.get("name").and_then(|v| v.as_str()),
        ) {
            name_by_id.insert(id.to_string(), name.to_string());
        }
    }

    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut has_parent: BTreeSet<String> = BTreeSet::new();
    for e in edges {
        if let (Some(from), Some(to)) = (
            e.get("from").and_then(|v| v.as_str()),
            e.get("to").and_then(|v| v.as_str()),
        ) {
            children
                .entry(from.to_string())
                .or_default()
                .push(to.to_string());
            has_parent.insert(to.to_string());
        }
    }
    for v in children.values_mut() {
        v.sort();
    }

    // Roots: nodes with no incoming edge; if every node has a parent
    // (pure cycle), start from all nodes.
    let mut roots: Vec<String> = name_by_id
        .keys()
        .filter(|k| !has_parent.contains(*k))
        .cloned()
        .collect();
    if roots.is_empty() {
        roots = name_by_id.keys().cloned().collect();
    }

    let mut out = String::new();
    let mut on_path: BTreeSet<String> = BTreeSet::new();
    for root in &roots {
        if let Some(name) = name_by_id.get(root) {
            render_call_node(
                root,
                name,
                &name_by_id,
                &children,
                &mut on_path,
                &mut out,
                0,
            );
        }
    }
    Ok(out)
}

fn render_call_node(
    id: &str,
    name: &str,
    names: &BTreeMap<String, String>,
    children: &BTreeMap<String, Vec<String>>,
    on_path: &mut BTreeSet<String>,
    out: &mut String,
    depth: usize,
) {
    // Hard cap: no real call chain is this deep; guards the stack on
    // pathological input.
    if depth >= 128 {
        return;
    }
    // A node already on the current path is a cycle: mark it and stop
    // descending, otherwise strongly connected components recurse forever.
    let cyclic = on_path.contains(id);
    out.push_str(&format!(
        "{}{}{}\n",
        "  ".repeat(depth),
        name,
        if cyclic { " (…)" } else { "" }
    ));
    if cyclic {
        return;
    }
    on_path.insert(id.to_string());
    for child in children.get(id).into_iter().flatten() {
        if let Some(child_name) = names.get(child) {
            render_call_node(child, child_name, names, children, on_path, out, depth + 1);
        }
    }
    on_path.remove(id);
}

fn format_minimal<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut result = String::new();

    for item in &json_data {
        if let JsonValue::Object(map) = item {
            // Try to get address or name or first field
            let value = map
                .get("address")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("id"))
                .or_else(|| map.values().next())
                .map(format_json_value)
                .unwrap_or_else(|| "".to_string());

            result.push_str(&value);
            result.push('\n');
        } else {
            result.push_str(&format_json_value(item));
            result.push('\n');
        }
    }

    Ok(result)
}

fn format_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(arr) => {
            format!(
                "[{}]",
                arr.iter()
                    .map(format_json_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        JsonValue::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
    }
}

pub fn auto_detect_format(is_tty: bool) -> OutputFormat {
    if is_tty {
        OutputFormat::Compact
    } else {
        OutputFormat::JsonCompact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Fixed fixture covering the response shapes the bridge emits: a
    /// function row, a decompile result (params + variables), a disasm
    /// instruction (with a literal `loaded` value), a find_constant hit,
    /// and a graph (callers) node.
    fn fixture_rows() -> Vec<JsonValue> {
        vec![
            json!({"name": "main", "address": "00401000", "size": 78, "tags": ["entry", "auth"]}),
            json!({
                "name": "main",
                "entry": "00401000",
                "signature": "undefined main(void)",
                "code": "int main() {\n  return 0;\n}\n",
                "params": [{"name": "argc", "type": "int", "storage": ":RDI"}],
                "variables": [{"name": "lVar1", "type": "long", "storage": ":RAX"}]
            }),
            json!({
                "address": "00401010",
                "bytes": "55",
                "mnemonic": "PUSH",
                "operands": ["RBP"],
                "loaded": {"value": "0x1505"}
            }),
            json!({"address": "00118b43", "block": ".text", "ldr_refs": [], "zero_block": false}),
            json!({"name": "main", "address": "00401000", "call_site": "00401005", "depth": 1}),
        ]
    }

    /// Golden snapshots per output format over the shared fixture. These lock
    /// the rendering contract (including the P1/P3 invariants that row shape
    /// drives formatting) — update deliberately via `cargo insta review`.
    #[test]
    fn golden_snapshots_per_format() {
        let f = DefaultFormatter;
        let rows = fixture_rows();
        let cases: [(&str, OutputFormat); 12] = [
            ("compact", OutputFormat::Compact),
            ("full", OutputFormat::Full),
            ("table", OutputFormat::Table),
            ("csv", OutputFormat::Csv),
            ("tsv", OutputFormat::Tsv),
            ("json", OutputFormat::Json),
            ("json_compact", OutputFormat::JsonCompact),
            ("json_stream", OutputFormat::JsonStream),
            ("count", OutputFormat::Count),
            ("c", OutputFormat::C),
            ("asm", OutputFormat::Asm),
            ("minimal", OutputFormat::Minimal),
        ];
        for (name, fmt) in cases {
            insta::assert_snapshot!(name, f.format(&rows, fmt).unwrap());
        }
    }

    /// `Tree` over `graph callers`/`callees` rows (depth indentation).
    #[test]
    fn golden_snapshot_tree_callers() {
        let f = DefaultFormatter;
        let rows = vec![
            json!({"name": "main", "address": "00401000", "call_site": "00401005", "depth": 0}),
            json!({"name": "helper", "address": "00401050", "call_site": "00401060", "depth": 1}),
        ];
        insta::assert_snapshot!("tree_callers", f.format(&rows, OutputFormat::Tree).unwrap());
    }

    /// `Tree` over the `graph calls` envelope (nodes + edges, cycle guard).
    #[test]
    fn golden_snapshot_tree_graph_calls() {
        let f = DefaultFormatter;
        let rows = vec![json!({
            "nodes": [
                {"id": "00401000", "name": "main", "address": "00401000"},
                {"id": "00401050", "name": "helper", "address": "00401050"},
                {"id": "00401100", "name": "loop_fn", "address": "00401100"}
            ],
            "edges": [
                {"from": "00401000", "to": "00401050", "type": "call"},
                {"from": "00401050", "to": "00401100", "type": "call"},
                {"from": "00401100", "to": "00401050", "type": "call"}
            ],
            "node_count": 3,
            "edge_count": 3
        })];
        insta::assert_snapshot!(
            "tree_graph_calls",
            f.format(&rows, OutputFormat::Tree).unwrap()
        );
    }

    #[test]
    fn tree_empty_is_no_results() {
        let f = DefaultFormatter;
        assert_eq!(
            f.format(&[] as &[JsonValue], OutputFormat::Tree).unwrap(),
            "No results"
        );
    }

    #[test]
    fn tree_rejects_non_graph_data() {
        let f = DefaultFormatter;
        let rows = vec![fixture_rows()[0].clone()];
        let err = f.format(&rows, OutputFormat::Tree).unwrap_err();
        assert!(
            err.to_string().contains("'tree'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_str_rejects_removed_hex() {
        assert!(OutputFormat::from_str("hex").is_err());
        assert!(OutputFormat::from_str("tree").is_ok());
    }

    #[test]
    fn test_format_json() {
        let data = vec![json!({"name": "test", "value": 123})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Json).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn test_format_count() {
        let data = vec![json!({"name": "test1"}), json!({"name": "test2"})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Count).unwrap();
        assert_eq!(result, "2");
    }
}
