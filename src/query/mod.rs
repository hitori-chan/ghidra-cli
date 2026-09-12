//! Query processing: field/sort selection and bridge-response unwrapping.
//! Fetch-vs-post planning lives in [`planner`].

mod planner;

pub use planner::QueryPlan;

use serde_json::Value as JsonValue;

#[derive(Debug)]
pub struct FieldSelector {
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
}

impl FieldSelector {
    pub fn include(fields: Vec<String>) -> Self {
        Self {
            include: Some(fields),
            exclude: None,
        }
    }

    pub fn exclude(fields: Vec<String>) -> Self {
        Self {
            include: None,
            exclude: Some(fields),
        }
    }

    pub fn parse(input: &str) -> crate::error::Result<Self> {
        if input.starts_with('-') {
            // Exclude fields
            let fields: Vec<String> = input
                .trim_start_matches('-')
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            Ok(Self::exclude(fields))
        } else {
            // Include fields
            let fields = input.split(',').map(|s| s.trim().to_string()).collect();
            Ok(Self::include(fields))
        }
    }
}

#[derive(Debug)]
pub struct SortKey {
    pub field: String,
    pub descending: bool,
}

impl SortKey {
    pub fn parse(input: &str) -> Vec<Self> {
        input
            .split(',')
            .map(|s| {
                let s = s.trim();
                if s.starts_with('-') {
                    SortKey {
                        field: s.trim_start_matches('-').to_string(),
                        descending: true,
                    }
                } else {
                    SortKey {
                        field: s.to_string(),
                        descending: false,
                    }
                }
            })
            .collect()
    }
}

/// Bridge command → array key for list-shaped response envelopes.
///
/// Single source of truth for *which* bridge commands return an array —
/// derived from the handlers in `GhidraCliBridge.java` (each `handleXxx`
/// adds its rows under exactly one key). Commands not listed here (single
/// objects, mutation results, `graph_calls`' nodes/edges, …) are returned
/// as a single item. The E2E suite asserts this table stays a subset of the
/// bridge's dispatch `switch`.
pub const ENVELOPES: &[(&str, &str)] = &[
    ("list_functions", "functions"),
    ("functions_range", "functions"),
    ("tag_get", "functions"),
    ("list_strings", "strings"),
    ("list_imports", "imports"),
    ("list_exports", "exports"),
    ("memory_map", "blocks"),
    ("xrefs_to", "xrefs"),
    ("xrefs_from", "xrefs"),
    ("xrefs_list", "xrefs"),
    ("list_programs", "programs"),
    ("find_string", "results"),
    ("find_bytes", "results"),
    ("find_function", "results"),
    ("find_calls", "results"),
    ("find_crypto", "results"),
    ("find_interesting", "results"),
    ("decompile_multi", "results"),
    ("find_constant", "hits"),
    ("find_instruction", "matches"),
    ("disasm", "instructions"),
    ("symbol_list", "symbols"),
    ("symbol_get", "symbols"),
    ("type_list", "types"),
    ("tag_list", "tags"),
    ("comment_list", "comments"),
    ("comment_get", "comments"),
    ("graph_callers", "callers"),
    ("graph_callees", "callees"),
    ("diff_programs", "matches"),
];

/// Non-array envelope keys that carry no rows — their presence never
/// prevents unwrapping a table-mapped array key (e.g. `{hits, value, size,
/// count}` from `find_constant`).
const META_KEYS: &[&str] = &[
    "count",
    "target",
    "function",
    "command",
    "status",
    "current_program_name",
    "has_current_program",
    "data",
    "pattern",
    "scanned",
    "truncated",
    "value",
    "size",
    "method",
    "program1",
    "program2",
    "summary",
    "differ",
];

/// Unwrap bridge response envelopes into a flat array of objects.
///
/// Bridge returns envelopes like `{"count": N, "functions": [...]}`. This
/// extracts the inner array so formatters can render individual items.
/// `command` is the wire command that produced `value` (`BridgeClient::
/// last_command()`); it selects the array key in [`ENVELOPES`] instead of
/// guessing from key names.
///
/// Unwrapping additionally requires the mapped key to be present and every
/// *other* top-level key to be metadata, so a response whose shape drifted
/// from its table entry falls through to single-item passthrough (logged
/// at debug) instead of silently dropping fields.
///
/// Single-item rule: `decompile` responses carry a `"code"` key and are
/// rendered specially, so they are never unwrapped.
/// Consuming: the array is moved out of the envelope, not cloned.
pub fn unwrap_bridge_response(value: JsonValue, command: Option<&str>) -> Vec<JsonValue> {
    // Already an array - return as-is
    if let JsonValue::Array(arr) = value {
        return arr;
    }

    // Must be an object to unwrap
    let mut obj = match value {
        JsonValue::Object(map) => map,
        other => return vec![other],
    };

    // Single-item rule: decompile responses have a "code" key.
    if obj.contains_key("code") {
        return vec![JsonValue::Object(obj)];
    }

    let Some(key) = command
        .and_then(|c| ENVELOPES.iter().find(|(cmd, _)| *cmd == c))
        .map(|(_, k)| *k)
    else {
        tracing::debug!(
            "unwrap: command {:?} not in ENVELOPES; single item",
            command
        );
        return vec![JsonValue::Object(obj)];
    };

    if obj.contains_key(key)
        && obj
            .keys()
            .all(|k| k == key || META_KEYS.contains(&k.as_str()))
    {
        if let Some(JsonValue::Array(arr)) = obj.remove(key) {
            return arr;
        }
    }

    tracing::debug!(
        "unwrap: {:?} response does not match envelope {:?}; single item",
        command,
        key
    );
    vec![JsonValue::Object(obj)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;

    #[test]
    fn test_field_selector_parse() {
        let selector = FieldSelector::parse("name,address,size").unwrap();
        assert!(selector.include.is_some());
        assert_eq!(selector.include.unwrap().len(), 3);

        let selector = FieldSelector::parse("-metadata,internal").unwrap();
        assert!(selector.exclude.is_some());
    }

    #[test]
    fn test_sort_key_parse() {
        let keys = SortKey::parse("name,-size");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].field, "name");
        assert!(!keys[0].descending);
        assert_eq!(keys[1].field, "size");
        assert!(keys[1].descending);
    }

    #[test]
    fn unwrap_array_passthrough() -> Result<()> {
        let v = serde_json::json!([{"a": 1}, {"a": 2}]);
        let rows = unwrap_bridge_response(v, None);
        assert_eq!(rows.len(), 2);
        Ok(())
    }

    #[test]
    fn unwrap_envelope_extracts_inner_array() -> Result<()> {
        let v = serde_json::json!({"count": 2, "functions": [{"name": "a"}, {"name": "b"}]});
        let rows = unwrap_bridge_response(v, Some("list_functions"));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["name"], "a");
        Ok(())
    }

    #[test]
    fn unwrap_scalar_envelope_becomes_single_row() -> Result<()> {
        let v = serde_json::json!({"command": "analyze", "status": "success"});
        let rows = unwrap_bridge_response(v, Some("analyze"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["command"], "analyze");
        Ok(())
    }

    #[test]
    fn unwrap_decompile_code_preserved() -> Result<()> {
        let v = serde_json::json!({"function": "main", "code": "int main() {}"});
        let rows = unwrap_bridge_response(v, Some("decompile"));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].get("code").is_some());
        Ok(())
    }

    #[test]
    fn every_envelope_entry_unwraps_its_key() {
        for &(cmd, key) in ENVELOPES {
            let mut obj = serde_json::Map::new();
            obj.insert("count".to_string(), serde_json::json!(2));
            obj.insert(key.to_string(), serde_json::json!([{"n": 1}, {"n": 2}]));
            let rows = unwrap_bridge_response(JsonValue::Object(obj), Some(cmd));
            assert_eq!(rows.len(), 2, "cmd={} key={}", cmd, key);
            assert_eq!(rows[0]["n"], 1, "cmd={} key={}", cmd, key);
        }
    }

    /// Real envelope shapes from the bridge (meta keys alongside the array).
    #[test]
    fn real_envelope_shapes() {
        let cases: &[(&str, &str)] = &[
            // disasm: {instructions, count}
            (
                "disasm",
                r#"{"instructions": [{"address": "00100000"}], "count": 1}"#,
            ),
            // find_constant: {value, size, hits, count}
            (
                "find_constant",
                r#"{"value": "0x1505", "size": 4, "hits": [{"address": "00100051"}], "count": 1}"#,
            ),
            // tag_get: {target, functions, count}
            (
                "tag_get",
                r#"{"target": "hook", "functions": [{"name": "main"}], "count": 1}"#,
            ),
        ];
        for (cmd, body) in cases {
            let v: JsonValue = serde_json::from_str(body).unwrap();
            let rows = unwrap_bridge_response(v, Some(cmd));
            assert_eq!(rows.len(), 1, "cmd={}", cmd);
        }
    }

    #[test]
    fn unknown_command_keeps_envelope_whole() {
        // `graph_calls` returns {nodes, edges, …} — not in ENVELOPES.
        let v = serde_json::json!({"nodes": [{}], "edges": [{}], "count": 2});
        let rows = unwrap_bridge_response(v, Some("graph_calls"));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].get("nodes").is_some());
    }

    #[test]
    fn drifted_shape_falls_back_to_single_item() {
        // A table-mapped command whose response grew a non-meta top-level
        // key must NOT be unwrapped (fields would be silently dropped).
        let v = serde_json::json!({"instructions": [{}], "count": 1, "unexpected": true});
        let rows = unwrap_bridge_response(v, Some("disasm"));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].get("unexpected").is_some());
    }

    /// CI guard: every ENVELOPES command must exist in the bridge's dispatch
    /// `switch`, so the table can never name a command the bridge rejects.
    #[test]
    fn envelopes_are_dispatched_by_the_bridge() {
        let java = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/ghidra/scripts/GhidraCliBridge.java"
        ))
        .expect("GhidraCliBridge.java must exist in the repo");
        // The command surface is declared either as a `case "cmd":` label
        // (legacy dispatch switch) or a `r.register("cmd", ...)` entry
        // (CommandRegistry). Either form counts as dispatched.
        let dispatched = |cmd: &&str| {
            java.contains(&format!("case \"{}\":", cmd))
                || java.contains(&format!("register(\"{}\"", cmd))
        };
        let missing: Vec<&str> = ENVELOPES
            .iter()
            .filter(|(cmd, _)| !dispatched(cmd))
            .map(|(cmd, _)| *cmd)
            .collect();
        assert!(
            missing.is_empty(),
            "ENVELOPES entries missing from the bridge command registry: {:?}",
            missing
        );
    }
}
