//! Query planning: the single source of truth for what
//! to ask the bridge (`fetch`) and what to do client-side (`post`).
//!
//! The "filtered/sorted/counted/paginated ⇒ fetch the full dataset" rule and
//! the `--limit 0 = all rows` convention live here exactly once.

use crate::cli::QueryOptions;
use crate::error::Result;
use crate::filter::{CompareOp, Filter, FilterExpr, StringOp, Value};
use crate::format::{DefaultFormatter, Formatter, OutputFormat};
use serde_json::Value as JsonValue;

use super::{FieldSelector, SortKey};

/// Server-side fetch parameters for a list command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchParams {
    /// Row cap for the bridge (None = fetch the full dataset). When a
    /// filter is pushed down, the bridge caps *matching* rows, so an
    /// explicit `--limit` can travel server-side (see `pushdown_filter`).
    pub limit: Option<usize>,
    /// Server-side case-insensitive substring match on the command's
    /// primary string field (None = no server-side filtering). The
    /// client-side filter always still runs, so this is a pre-filter.
    pub filter: Option<String>,
    /// Server-side page start: skip the first N rows that pass the
    /// (pushed) filter. Only ever set when the client pipeline cannot
    /// change membership or order (no sort/count, and either no client
    /// filter or an exact pushdown) — otherwise the client offset stays
    /// authoritative in `PostProc.offset` (see `QueryPlan::from`).
    pub offset: Option<usize>,
}

/// Client-side post-processing applied to fetched rows.
#[derive(Debug)]
pub struct PostProc {
    pub filter: Option<Filter>,
    pub fields: Option<FieldSelector>,
    pub sort: Option<Vec<SortKey>>,
    /// Client-side page limit. `Some(0)` = all rows (see `QueryPlan::from`).
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub count_only: bool,
}

impl PostProc {
    /// Run the consuming pipeline: filter → fields → sort → paginate →
    /// count/format. Rows are moved, not cloned (the 1.9M-row symbol case is
    /// the target: no per-row clone on any pass).
    pub fn process(self, mut rows: Vec<JsonValue>, format: OutputFormat) -> Result<String> {
        // 1. Filter (retain by value)
        if let Some(filter) = self.filter {
            let mut kept = Vec::with_capacity(rows.len());
            for row in rows {
                if filter.evaluate(&row)? {
                    kept.push(row);
                }
            }
            rows = kept;
        }

        // 2. Field selection (entries moved out of the maps)
        if let Some(fields) = self.fields {
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(project_row(row, &fields));
            }
            rows = out;
        }

        // 3. Sort (in place, compared by reference)
        if let Some(sort) = self.sort {
            rows.sort_by(|a, b| compare_rows(a, b, &sort));
        }

        // 4. Paginate (by value)
        let offset = self.offset.unwrap_or(0);
        rows.drain(..offset.min(rows.len()));
        // `--limit 0` means "no limit", matching the bridge's convention
        // (its list handlers only cap when limit > 0).
        let limit = match self.limit {
            None | Some(0) => usize::MAX,
            Some(n) => n,
        };
        rows.truncate(limit);

        // 5. Count or format
        if self.count_only {
            return Ok(rows.len().to_string());
        }
        DefaultFormatter.format(&rows, format)
    }
}

/// Project one row onto the selected fields, moving values instead of cloning.
fn project_row(row: JsonValue, fields: &FieldSelector) -> JsonValue {
    match row {
        JsonValue::Object(mut map) => {
            let mut out = serde_json::Map::new();
            if let Some(include) = &fields.include {
                for field in include {
                    if let Some(value) = map.remove(field) {
                        out.insert(field.clone(), value);
                    }
                }
            } else if let Some(exclude) = &fields.exclude {
                for (key, value) in map {
                    if !exclude.contains(&key) {
                        out.insert(key, value);
                    }
                }
            } else {
                return JsonValue::Object(map);
            }
            JsonValue::Object(out)
        }
        other => other,
    }
}

fn compare_rows(a: &JsonValue, b: &JsonValue, keys: &[SortKey]) -> std::cmp::Ordering {
    for key in keys {
        let cmp = match (field_value(a, &key.field), field_value(b, &key.field)) {
            (Some(JsonValue::Number(x)), Some(JsonValue::Number(y))) => x
                .as_f64()
                .partial_cmp(&y.as_f64())
                .unwrap_or(std::cmp::Ordering::Equal),
            (Some(JsonValue::String(x)), Some(JsonValue::String(y))) => x.cmp(y),
            _ => std::cmp::Ordering::Equal,
        };
        let final_cmp = if key.descending { cmp.reverse() } else { cmp };
        if final_cmp != std::cmp::Ordering::Equal {
            return final_cmp;
        }
    }
    std::cmp::Ordering::Equal
}

fn field_value<'a>(row: &'a JsonValue, field: &str) -> Option<&'a JsonValue> {
    row.as_object().and_then(|map| map.get(field))
}

/// A full query plan: what the bridge should fetch and what Rust does with
/// the rows.
#[derive(Debug)]
pub struct QueryPlan {
    pub fetch: FetchParams,
    /// None = no client-side post-processing; the result passes through.
    pub post: Option<PostProc>,
}

impl QueryPlan {
    /// Build the plan from a command's query options.
    ///
    /// `bridge_field` is the row field the bridge's `filter` argument
    /// matches (case-insensitive contains); `None` for commands whose
    /// bridge handler has no filter (and no `offset` support). See
    /// `pushdown_filter` for what may be sent down.
    ///
    /// The one home for the fetch rules: sort/count need the complete
    /// dataset (no bridge cap); a filtered fetch ships only matching rows
    /// when the filter is pushable, otherwise the full dataset; an
    /// unfiltered fetch caps at the explicit `--limit` or the config
    /// default. `--offset` travels server-side when the bridge supports
    /// it and the client pipeline cannot change membership or order
    /// (no sort/count; no filter or an exact one) — then the page is cut
    /// on the server (O(offset+limit)) and the client re-applies nothing.
    /// Otherwise the offset stays client-side. The client-side pipeline in
    /// `post` is authoritative in every case.
    pub fn from(
        opts: Option<&QueryOptions>,
        default_limit: Option<usize>,
        bridge_field: Option<&str>,
    ) -> Result<QueryPlan> {
        let Some(opts) = opts else {
            // No query options: fetch under the config default cap, no post.
            return Ok(QueryPlan {
                fetch: FetchParams {
                    limit: default_limit,
                    filter: None,
                    offset: None,
                },
                post: None,
            });
        };

        let full_scan = opts.sort.is_some() || opts.count;

        // Parse once: used for the pushdown decision and (authoritatively)
        // for the client-side post filter. An invalid regex must fail HERE,
        // before any fetch — the lazy per-row compile would otherwise
        // surface it mid-pipeline after the dataset was already transferred.
        let mut filter = opts.filter.as_deref().map(Filter::parse).transpose()?;
        if let Some(f) = &mut filter {
            f.validate()?;
        }
        let (pushed, exact) = filter
            .as_ref()
            .map(|f| pushdown_filter(&f.expr, bridge_field))
            .unwrap_or((None, false));

        // Server-side paging: the bridge skips the first N rows that pass
        // its filter. Safe only when the client pipeline cannot change
        // membership or order afterwards: no sort, no count, and either no
        // client filter or an EXACT pushdown (bridge filter == client
        // filter, so "Nth matching row" means the same thing on both
        // sides). Superset pushdowns, unpushable filters, sort and count
        // keep the offset client-side, where it is re-derived after the
        // authoritative passes.
        let offset_pushed = opts.offset.filter(|&o| {
            o > 0 && !full_scan && bridge_field.is_some() && (filter.is_none() || exact)
        });

        // A client filter ALWAYS needs a post pass: pushdown only ever
        // pre-filters (exact or superset), and anything non-pushable (regex,
        // numeric compare, AND/OR/NOT, other fields) is applied HERE —
        // dropping this term made such filters silently no-ops whenever no
        // limit/sort/fields/count/offset was also given (regression from P6).
        let needs_post = filter.is_some()
            || full_scan
            || opts.fields.is_some()
            || opts.limit.is_some()
            || (offset_pushed.is_none() && opts.offset.is_some());

        let fetch = match (&pushed, exact, full_scan) {
            // Exact pushdown without sort/count/offset: the bridge caps
            // *matching* rows, so an explicit --limit is safe server-side
            // and the bridge ships at most `limit` rows. No explicit
            // limit keeps the "filtered => all matches" behavior (None,
            // not the config default, so the output is unchanged).
            (Some(_), true, false) => FetchParams {
                limit: match opts.limit {
                    Some(0) => None,
                    Some(n) => Some(n),
                    None => None,
                },
                filter: pushed,
                offset: offset_pushed,
            },
            // Superset pushdown (never cap: the bridge could truncate the
            // superset before the client's exact pass sees enough rows),
            // or nothing pushable: the client must see the whole (filtered)
            // dataset, so no bridge cap. With an exact pushdown plus
            // sort/count/offset the full match set is what those need —
            // and the bridge still only ships matches.
            _ => FetchParams {
                limit: if opts.filter.is_some() || full_scan {
                    None
                } else {
                    // The one home for `--limit 0 = all rows`
                    // --limit 0 suppresses both the
                    // explicit limit and the config default.
                    match opts.limit {
                        Some(0) => None,
                        Some(n) => Some(n),
                        None => default_limit,
                    }
                },
                filter: pushed,
                offset: offset_pushed,
            },
        };

        let post = needs_post
            .then(|| -> crate::error::Result<PostProc> {
                Ok(PostProc {
                    filter,
                    fields: opts
                        .fields
                        .as_deref()
                        .map(FieldSelector::parse)
                        .transpose()?,
                    sort: opts.sort.as_ref().map(|s| SortKey::parse(s)),
                    limit: opts.limit,
                    // The server already skipped `offset` rows; re-skipping
                    // would drop twice as many.
                    offset: if offset_pushed.is_some() {
                        None
                    } else {
                        opts.offset
                    },
                    count_only: opts.count,
                })
            })
            .transpose()?;

        Ok(QueryPlan { fetch, post })
    }
}

/// The value for the bridge's `filter` argument (case-insensitive
/// substring on `bridge_field`), if the client's predicate is guaranteed to
/// be at least as strict as the bridge's — the client-side filter always
/// re-runs, so a pushdown may over-match but never under-match.
///
/// Returns `(value, exact)`:
///
/// * `field~value` (case-insensitive contains) — identical semantics, so
///   `exact`: the bridge may apply the `--limit` cap to matching rows.
/// * `field^value` / `field$value` (case-insensitive start/ends-with) and
///   `field=value` (case-sensitive equals) — contains is a superset; the
///   caller must not cap server-side (the superset could be truncated
///   before the client's exact pass sees enough rows).
///
/// Anything else (regex, `!=`, numeric compare, `NOT`/`AND`/`OR`, other
/// fields, missing bridge field) is `None`: the client filters over a full
/// fetch, exactly as before P6.
fn pushdown_filter(expr: &FilterExpr, bridge_field: Option<&str>) -> (Option<String>, bool) {
    let Some(field) = bridge_field else {
        return (None, false);
    };
    match expr {
        FilterExpr::StringOp {
            field: f,
            op: StringOp::Contains,
            value,
        } if f == field => (Some(value.clone()), true),
        FilterExpr::StringOp {
            field: f,
            op: StringOp::StartsWith,
            value,
        } if f == field => (Some(value.clone()), false),
        FilterExpr::StringOp {
            field: f,
            op: StringOp::EndsWith,
            value,
        } if f == field => (Some(value.clone()), false),
        FilterExpr::Compare {
            field: f,
            op: CompareOp::Equal,
            value: Value::String(s),
        } if f == field => (Some(s.clone()), false),
        _ => (None, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::QueryOptions;
    use crate::error::GhidraError;

    fn opts() -> QueryOptions {
        QueryOptions::default()
    }

    fn opts_with(f: impl FnOnce(&mut QueryOptions)) -> QueryOptions {
        let mut o = opts();
        f(&mut o);
        o
    }

    #[test]
    fn no_opts_uses_default_limit_no_post() {
        let plan = QueryPlan::from(None, Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, Some(1000));
        assert_eq!(plan.fetch.filter, None);
        assert!(plan.post.is_none());
    }

    #[test]
    fn invalid_regex_fails_at_plan_time() {
        // An invalid regex must be rejected while building the plan —
        // before any fetch — not mid-evaluation after the dataset was
        // already transferred (P6.4).
        // Quoted so the grammar accepts it; the unbalanced paren must then
        // fail at regex compile time (validate), not mid-evaluation.
        let o = opts_with(|o| o.filter = Some(r#"name=~"foo(bar""#.to_string()));
        let err = QueryPlan::from(Some(&o), Some(1000), None).unwrap_err();
        assert!(
            matches!(err, GhidraError::InvalidFilter(_)),
            "expected InvalidFilter, got: {}",
            err
        );
    }

    #[test]
    fn valid_regex_plans_and_caches() {
        let o = opts_with(|o| o.filter = Some(r#"name=~"^pk_""#.to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert!(plan.post.is_some());
    }

    #[test]
    fn limit_zero_means_all_rows() {
        // Regression: --limit 0 must fetch all
        // rows, not zero, and must not fall back to the config default limit.
        let o = opts_with(|o| o.limit = Some(0));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, None);
        assert_eq!(plan.post.as_ref().unwrap().limit, Some(0));
    }

    #[test]
    fn no_limit_uses_default() {
        let o = opts_with(|o| o.fields = Some("name".to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, Some(1000));
    }

    #[test]
    fn explicit_limit_wins() {
        let o = opts_with(|o| o.limit = Some(25));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, Some(25));
        assert_eq!(plan.post.as_ref().unwrap().limit, Some(25));
    }

    #[test]
    fn unpushable_filter_fetches_full_dataset() {
        // No bridge field (e.g. tag list): nothing is pushable — the bridge
        // ships the full dataset and the client filters.
        let o = opts_with(|o| {
            o.filter = Some("name~PK".to_string());
            o.limit = Some(20);
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, None);
        assert_eq!(plan.fetch.filter, None);
        // The limit is still applied client-side after filtering.
        assert_eq!(plan.post.as_ref().unwrap().limit, Some(20));
    }

    #[test]
    fn sort_count_fetch_full_dataset() {
        let o = opts_with(|o| o.sort = Some("size".to_string()));
        assert!(QueryPlan::from(Some(&o), Some(1000), None)
            .unwrap()
            .fetch
            .limit
            .is_none());

        let o = opts_with(|o| o.count = true);
        assert!(QueryPlan::from(Some(&o), Some(1000), None)
            .unwrap()
            .fetch
            .limit
            .is_none());
    }

    #[test]
    fn offset_pages_server_side_when_unfiltered() {
        // P6.2: the bridge skips the first N rows, so a page costs
        // O(offset + limit) instead of O(rows). No explicit limit takes the
        // config default page size; the client re-applies nothing.
        let o = opts_with(|o| o.offset = Some(5));
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.offset, Some(5));
        assert_eq!(plan.fetch.limit, Some(1000));
        assert!(plan.post.is_none());

        let o = opts_with(|o| {
            o.offset = Some(5);
            o.limit = Some(2);
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.offset, Some(5));
        assert_eq!(plan.fetch.limit, Some(2));
        assert!(plan.post.as_ref().unwrap().offset.is_none());
    }

    #[test]
    fn offset_with_exact_filter_pages_server_side() {
        // "Nth matching row" means the same thing on both sides when the
        // pushdown is exact.
        let o = opts_with(|o| {
            o.filter = Some("name~PK".to_string());
            o.offset = Some(3);
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter.as_deref(), Some("PK"));
        assert_eq!(plan.fetch.offset, Some(3));
        // Paging is server-side; the client re-runs the (identical) filter,
        // which is idempotent on already-filtered rows, but must NOT skip
        // the offset again.
        let post = plan.post.as_ref().unwrap();
        assert!(post.filter.is_some());
        assert!(post.offset.is_none());
    }

    #[test]
    fn unpushable_filter_alone_still_filters_client_side() {
        // Regression (P6 dropped the filter term from `needs_post`): a
        // non-pushable filter with no other options used to fetch the full
        // UNCAPPED dataset and then skip the client pass entirely — the
        // filter was silently ignored. The post pass must exist and carry
        // the filter.
        let o = opts_with(|o| o.filter = Some("size>10".to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter, None, "size>10 is not pushable");
        assert_eq!(plan.fetch.limit, None, "filtered fetch is uncapped");
        let post = plan.post.as_ref().expect("filter must run client-side");
        assert!(post.filter.is_some());
    }

    #[test]
    fn offset_with_superset_or_sort_stays_client_side() {
        // Superset pushdown: the client's exact pass changes membership
        // after the bridge would have skipped, so the offset must be
        // re-derived client-side.
        let o = opts_with(|o| {
            o.filter = Some("name^PK_".to_string());
            o.offset = Some(3);
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.offset, None);
        assert!(plan.post.as_ref().unwrap().offset.is_some());

        // Sort reorders: the pre-sort server skip would be meaningless.
        let o = opts_with(|o| {
            o.offset = Some(3);
            o.sort = Some("size".to_string());
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.offset, None);
        assert!(plan.fetch.limit.is_none());
        assert!(plan.post.as_ref().unwrap().offset.is_some());

        // No bridge offset support: never pushed.
        let o = opts_with(|o| o.offset = Some(3));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.offset, None);
        assert!(plan.post.as_ref().unwrap().offset.is_some());
    }

    #[test]
    fn offset_zero_is_a_no_op_not_a_page() {
        let o = opts_with(|o| o.offset = Some(0));
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.offset, None);
    }

    #[test]
    fn exact_contains_pushdown_caps_bridge() {
        let o = opts_with(|o| {
            o.filter = Some("name~PK".to_string());
            o.limit = Some(20);
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        // The raw value (not the expression) goes server-side and the
        // explicit limit caps *matching* rows in the bridge.
        assert_eq!(plan.fetch.filter.as_deref(), Some("PK"));
        assert_eq!(plan.fetch.limit, Some(20));
        // The client-side filter remains authoritative.
        assert!(plan.post.as_ref().unwrap().filter.is_some());
        assert_eq!(plan.post.as_ref().unwrap().limit, Some(20));
    }

    #[test]
    fn exact_contains_without_limit_fetches_all_matches() {
        // No explicit --limit: all matches are shipped (not the config
        // default), keeping the "filtered => all matches" output.
        let o = opts_with(|o| o.filter = Some("name~PK".to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter.as_deref(), Some("PK"));
        assert_eq!(plan.fetch.limit, None);
    }

    #[test]
    fn count_with_pushable_filter_still_full_scan() {
        // --count needs the complete match set: no cap, but only matches
        // ship (the P6 win: O(matches) instead of O(rows)).
        let o = opts_with(|o| {
            o.filter = Some("name~PK".to_string());
            o.count = true;
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter.as_deref(), Some("PK"));
        assert_eq!(plan.fetch.limit, None);
        assert!(plan.post.as_ref().unwrap().count_only);
    }

    #[test]
    fn superset_ops_push_but_never_cap() {
        // Starts-with: contains is a superset, so it pushes, but an explicit
        // --limit must not cap the superset server-side (the bridge could
        // truncate it before the client's exact pass sees enough rows).
        let o = opts_with(|o| {
            o.filter = Some("name^PK_".to_string());
            o.limit = Some(10);
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter.as_deref(), Some("PK_"));
        assert_eq!(plan.fetch.limit, None);

        // With --count the superset ships (still far fewer rows than all).
        let o = opts_with(|o| {
            o.filter = Some("name^PK_".to_string());
            o.count = true;
        });
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter.as_deref(), Some("PK_"));
        assert_eq!(plan.fetch.limit, None);
    }

    #[test]
    fn unpushable_filters_fetch_full_unfiltered() {
        // Regex, !=, numeric, compound, and non-bridge fields never push.
        for f in [
            "name=~\"^PK_\"",
            "name!=PK",
            "size>100",
            "name~PK AND size>10",
            "NOT name~PK",
            "comment~x",
        ] {
            let o = opts_with(|o| o.filter = Some(f.to_string()));
            let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
            assert_eq!(plan.fetch.filter, None, "should not push {f}");
            assert_eq!(plan.fetch.limit, None);
        }
    }

    #[test]
    fn pushdown_only_targets_the_bridge_field() {
        // The functions bridge handler filters `name`; `tags~x` cannot ride
        // on it — but `value~x` on the strings command (bridge field
        // `value`) does.
        let o = opts_with(|o| o.filter = Some("tags~crypto".to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("name")).unwrap();
        assert_eq!(plan.fetch.filter, None);
        assert_eq!(plan.fetch.limit, None);

        let o = opts_with(|o| o.filter = Some("value~boot".to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), Some("value")).unwrap();
        assert_eq!(plan.fetch.filter.as_deref(), Some("boot"));
    }

    #[test]
    fn fields_alone_keeps_bridge_cap() {
        // Projection is cheap on capped rows; don't pay for a full fetch.
        let o = opts_with(|o| o.fields = Some("name,address".to_string()));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, Some(1000));
        assert!(plan.post.is_some());
    }

    #[test]
    fn plain_limit_alone_keeps_bridge_cap_and_paginates_client_side() {
        let o = opts_with(|o| o.limit = Some(7));
        let plan = QueryPlan::from(Some(&o), Some(1000), None).unwrap();
        assert_eq!(plan.fetch.limit, Some(7));
        // Re-applying the cap client-side is idempotent.
        assert_eq!(plan.post.as_ref().unwrap().limit, Some(7));
    }

    #[test]
    fn malformed_filter_is_an_error() {
        let o = opts_with(|o| o.filter = Some("bareword".to_string()));
        assert!(QueryPlan::from(Some(&o), Some(1000), None).is_err());
    }

    fn rows(n: usize) -> Vec<JsonValue> {
        (0..n)
            .map(|i| serde_json::json!({ "id": i, "name": format!("f{i}") }))
            .collect()
    }

    fn post(limit: Option<usize>, offset: Option<usize>, count: bool) -> PostProc {
        PostProc {
            filter: None,
            fields: None,
            sort: None,
            limit,
            offset,
            count_only: count,
        }
    }

    #[test]
    fn post_limit_zero_returns_all_rows() {
        assert_eq!(
            post(Some(0), None, false)
                .process(rows(5), OutputFormat::JsonCompact)
                .unwrap(),
            "[{\"id\":0,\"name\":\"f0\"},{\"id\":1,\"name\":\"f1\"},{\"id\":2,\"name\":\"f2\"},{\"id\":3,\"name\":\"f3\"},{\"id\":4,\"name\":\"f4\"}]"
        );
    }

    #[test]
    fn post_limit_none_returns_all_rows() {
        let out = post(None, None, false)
            .process(rows(5), OutputFormat::JsonCompact)
            .unwrap();
        assert_eq!(out.matches("id").count(), 5);
    }

    #[test]
    fn post_limit_applies_after_offset() {
        let out = post(Some(2), Some(1), false)
            .process(rows(5), OutputFormat::JsonCompact)
            .unwrap();
        assert!(out.contains("\"id\":1"));
        assert!(out.contains("\"id\":2"));
        assert_eq!(out.matches("id").count(), 2);
    }

    #[test]
    fn post_limit_zero_with_offset_returns_remainder() {
        let out = post(Some(0), Some(2), false)
            .process(rows(5), OutputFormat::JsonCompact)
            .unwrap();
        assert_eq!(out.matches("id").count(), 3);
    }

    #[test]
    fn post_offset_beyond_len_is_empty_not_panic() {
        let out = post(None, Some(99), false)
            .process(rows(5), OutputFormat::JsonCompact)
            .unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn post_count_only_counts_after_pagination() {
        assert_eq!(
            post(Some(3), Some(1), true)
                .process(rows(10), OutputFormat::JsonCompact)
                .unwrap(),
            "3"
        );
    }

    #[test]
    fn post_filter_sort_fields_pipeline() {
        let mut p = post(Some(2), None, false);
        p.sort = Some(SortKey::parse("name"));
        p.fields = Some(FieldSelector::include(vec!["name".to_string()]));
        let out = p.process(rows(4), OutputFormat::JsonCompact).unwrap();
        assert!(out.starts_with("[{\"name\":\"f0\"}"));
        assert_eq!(out.matches("name").count(), 2);
        assert!(!out.contains("id"));
    }
}
