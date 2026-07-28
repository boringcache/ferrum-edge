//! Bounded `$ref` expansion during API-spec import (advisory GHSA-8jc7-c52g-85xr).
//!
//! The importer must reject reference cycles the moment the chain re-enters a
//! target that is still being expanded, must charge a cumulative per-document
//! materialization budget *before* every clone, and must not re-expand a
//! high-branching acyclic DAG exponentially. Legitimate repeated acyclic
//! references and the documented depth boundary must keep working, and JSON and
//! YAML input must be accounted identically.
//!
//! Every test here asserts a specific `ExtractError` variant. The admin layer
//! maps all of them to a deterministic 4xx (`extract_error_status`); the
//! over-HTTP status contract, concurrent imports, and namespace isolation are
//! covered in `tests/integration/admin_api_specs_handler_tests.rs`.

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use serde_json::{Value, json};

fn proxy_block() -> Value {
    json!({
        "id": "ref-budget-proxy",
        "backend_host": "backend.internal",
        "backend_port": 443
    })
}

/// Wrap `components` in a document whose single operation references `entry`.
fn spec_with_components(components: Value, entry: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Ref Budget API", "version": "1.0.0"},
        "x-ferrum-validate": true,
        "x-ferrum-proxy": proxy_block(),
        "components": {"schemas": components},
        "paths": {
            "/things": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": entry}}
                        }
                    },
                    "responses": {"204": {"description": "ok"}}
                }
            }
        }
    })
}

fn extract_json(spec: &Value) -> Result<(), ExtractError> {
    extract(
        serde_json::to_vec(spec)
            .expect("fixture must serialize")
            .as_slice(),
        Some(SpecFormat::Json),
        "prod",
    )
    .map(|_| ())
}

fn extract_json_err(spec: &Value) -> ExtractError {
    extract_json(spec).expect_err("spec extraction must fail")
}

fn cycle_path(err: &ExtractError) -> &str {
    match err {
        ExtractError::SchemaReferenceCycle { path } => path.as_str(),
        other => panic!("expected SchemaReferenceCycle, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Cycles
// ---------------------------------------------------------------------------

#[test]
fn direct_self_ref_is_rejected_as_a_cycle() {
    let spec = spec_with_components(
        json!({"A": {"$ref": "#/components/schemas/A"}}),
        "#/components/schemas/A",
    );
    let err = extract_json_err(&spec);
    let path = cycle_path(&err);
    assert!(
        path.contains("#/components/schemas/A"),
        "cycle path must name the self-referencing target: {path}"
    );
}

#[test]
fn self_cycle_through_a_property_is_rejected() {
    let spec = spec_with_components(
        json!({
            "A": {
                "type": "object",
                "properties": {"child": {"$ref": "#/components/schemas/A"}}
            }
        }),
        "#/components/schemas/A",
    );
    let err = extract_json_err(&spec);
    assert!(
        cycle_path(&err).contains("#/components/schemas/A"),
        "got: {err}"
    );
}

#[test]
fn mutual_cycle_is_rejected_and_names_both_references() {
    let spec = spec_with_components(
        json!({
            "A": {
                "type": "object",
                "properties": {"b": {"$ref": "#/components/schemas/B"}}
            },
            "B": {
                "type": "object",
                "properties": {"a": {"$ref": "#/components/schemas/A"}}
            }
        }),
        "#/components/schemas/A",
    );
    let err = extract_json_err(&spec);
    let path = cycle_path(&err);
    assert!(
        path.contains("#/components/schemas/A") && path.contains("#/components/schemas/B"),
        "cycle path must name both legs of the loop: {path}"
    );
}

#[test]
fn three_node_cycle_is_rejected() {
    let spec = spec_with_components(
        json!({
            "A": {"type": "object", "properties": {"n": {"$ref": "#/components/schemas/B"}}},
            "B": {"type": "object", "properties": {"n": {"$ref": "#/components/schemas/C"}}},
            "C": {"type": "object", "properties": {"n": {"$ref": "#/components/schemas/A"}}}
        }),
        "#/components/schemas/A",
    );
    let err = extract_json_err(&spec);
    let path = cycle_path(&err);
    for name in ["A", "B", "C"] {
        assert!(
            path.contains(&format!("#/components/schemas/{name}")),
            "cycle path must name {name}: {path}"
        );
    }
}

/// The cycle must be reported before the sibling branches beside it are
/// expanded to the depth ceiling. A cyclic target carrying many wide sibling
/// branches must therefore still fail as a cycle, not as `SchemaTooLarge`.
#[test]
fn cycle_is_reported_before_sibling_branches_exhaust_the_budget() {
    let mut properties = serde_json::Map::new();
    // `zz_cycle` sorts last, so every sibling branch is visited first.
    for index in 0..64 {
        properties.insert(
            format!("wide{index:03}"),
            json!({"$ref": "#/components/schemas/Wide"}),
        );
    }
    properties.insert(
        "zz_cycle".to_string(),
        json!({"$ref": "#/components/schemas/A"}),
    );

    let mut wide = serde_json::Map::new();
    for index in 0..64 {
        wide.insert(format!("f{index:03}"), json!({"type": "string"}));
    }

    let spec = spec_with_components(
        json!({
            "A": {"type": "object", "properties": Value::Object(properties)},
            "Wide": {"type": "object", "properties": Value::Object(wide)}
        }),
        "#/components/schemas/A",
    );
    let err = extract_json_err(&spec);
    assert!(
        matches!(err, ExtractError::SchemaReferenceCycle { .. }),
        "wide cyclic schema must fail as a cycle, not as an exhausted budget: {err}"
    );
}

/// Cycle detection is by target identity, not by reference spelling: a pointer
/// fragment and a plain-name anchor that land on the same node are one target.
#[test]
fn cycle_across_mixed_reference_spellings_is_rejected() {
    let spec = spec_with_components(
        json!({
            "A": {
                "$anchor": "Alpha",
                "type": "object",
                "properties": {"loop": {"$ref": "#Alpha"}}
            }
        }),
        "#/components/schemas/A",
    );
    let err = extract_json_err(&spec);
    assert!(
        matches!(err, ExtractError::SchemaReferenceCycle { .. }),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Legitimate repeated acyclic references
// ---------------------------------------------------------------------------

#[test]
fn repeated_acyclic_references_are_still_accepted() {
    let mut level_two = serde_json::Map::new();
    for index in 0..24 {
        level_two.insert(
            format!("c{index:02}"),
            json!({"$ref": "#/components/schemas/Common"}),
        );
    }
    let mut level_one = serde_json::Map::new();
    for index in 0..12 {
        level_one.insert(
            format!("b{index:02}"),
            json!({"$ref": "#/components/schemas/Mid"}),
        );
    }

    let spec = spec_with_components(
        json!({
            "Common": {"type": "object", "properties": {"id": {"type": "string"}}},
            "Mid": {"type": "object", "properties": Value::Object(level_two)},
            "Top": {"type": "object", "properties": Value::Object(level_one)}
        }),
        "#/components/schemas/Top",
    );
    extract_json(&spec).expect("repeated acyclic references must remain importable");
}

/// The same target referenced from many operations must not exhaust the
/// document account for an ordinary document.
#[test]
fn same_target_referenced_from_many_operations_is_accepted() {
    let mut paths = serde_json::Map::new();
    for index in 0..40 {
        paths.insert(
            format!("/thing{index:03}"),
            json!({
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Shared"}
                            }
                        }
                    },
                    "responses": {"204": {"description": "ok"}}
                }
            }),
        );
    }
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Shared Ref API", "version": "1.0.0"},
        "x-ferrum-validate": true,
        "x-ferrum-proxy": proxy_block(),
        "components": {
            "schemas": {
                "Shared": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        },
        "paths": Value::Object(paths)
    });
    extract_json(&spec).expect("a shared schema across many operations must import");
}

// ---------------------------------------------------------------------------
// High-branching acyclic DAG
// ---------------------------------------------------------------------------

/// Eight levels of eight-way fan-out is acyclic and shallow enough to clear the
/// depth ceiling, but expands to roughly 16.7M values. It must be rejected by
/// the materialization budget, deterministically and quickly — never by
/// exhausting memory.
#[test]
fn high_branching_dag_is_rejected_by_the_expansion_budget() {
    const LEVELS: usize = 8;
    const FANOUT: usize = 8;

    let mut components = serde_json::Map::new();
    components.insert(
        format!("L{LEVELS}"),
        json!({"type": "object", "properties": {"leaf": {"type": "string"}}}),
    );
    for level in (0..LEVELS).rev() {
        let mut properties = serde_json::Map::new();
        for branch in 0..FANOUT {
            properties.insert(
                format!("b{branch}"),
                json!({"$ref": format!("#/components/schemas/L{}", level + 1)}),
            );
        }
        components.insert(
            format!("L{level}"),
            json!({"type": "object", "properties": Value::Object(properties)}),
        );
    }

    let spec = spec_with_components(Value::Object(components), "#/components/schemas/L0");
    let err = extract_json_err(&spec);
    assert!(
        matches!(err, ExtractError::SchemaTooLarge { .. }),
        "high-branching DAG must fail closed on the expansion budget: {err}"
    );
}

// ---------------------------------------------------------------------------
// Depth boundary (documented behavior, must be preserved)
// ---------------------------------------------------------------------------

fn linear_schema_chain(length: usize) -> Value {
    let mut components = serde_json::Map::new();
    components.insert(format!("S{length}"), json!({"type": "string"}));
    for index in (0..length).rev() {
        components.insert(
            format!("S{index}"),
            json!({"$ref": format!("#/components/schemas/S{}", index + 1)}),
        );
    }
    spec_with_components(Value::Object(components), "#/components/schemas/S0")
}

#[test]
fn short_acyclic_reference_chain_is_accepted() {
    extract_json(&linear_schema_chain(8)).expect("a short acyclic chain must import");
}

#[test]
fn over_long_acyclic_reference_chain_still_reports_depth() {
    let err = extract_json_err(&linear_schema_chain(64));
    assert!(
        matches!(err, ExtractError::SchemaTooDeep { .. }),
        "an over-long acyclic chain must remain SchemaTooDeep, not a cycle: {err}"
    );
}

// ---------------------------------------------------------------------------
// Cumulative (per-document) accounting
// ---------------------------------------------------------------------------

/// A Path Item `$ref` target is cloned wholesale. Each individual clone here is
/// far inside the per-expansion budget, and none of it is ever retained in the
/// generated operation table (the target declares no HTTP method), so only a
/// cumulative account charged before the clone can bound it.
fn spec_with_repeated_path_item_clones(repeats: usize, payload_len: usize) -> Value {
    let payload: Vec<Value> = (0..payload_len).map(|n| json!(n)).collect();
    let mut paths = serde_json::Map::new();
    for index in 0..repeats {
        paths.insert(
            format!("/clone{index:04}"),
            json!({"$ref": "#/components/pathItems/Big"}),
        );
    }
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Clone Budget API", "version": "1.0.0"},
        "x-ferrum-validate": true,
        "x-ferrum-proxy": proxy_block(),
        "components": {
            "pathItems": {
                "Big": {
                    "description": "no operations; the payload is pure clone weight",
                    "x-payload": Value::Array(payload)
                }
            }
        },
        "paths": Value::Object(paths)
    })
}

#[test]
fn few_path_item_clones_stay_within_the_document_account() {
    extract_json(&spec_with_repeated_path_item_clones(8, 20_000))
        .expect("a modest number of Path Item clones must import");
}

#[test]
fn many_path_item_clones_exhaust_the_document_account() {
    let err = extract_json_err(&spec_with_repeated_path_item_clones(200, 20_000));
    assert!(
        matches!(err, ExtractError::SchemaTooLarge { .. }),
        "repeated whole-subtree clones must be charged cumulatively: {err}"
    );
}

// ---------------------------------------------------------------------------
// JSON / YAML parity
// ---------------------------------------------------------------------------

fn extract_yaml_err(spec: &Value) -> ExtractError {
    let yaml = serde_yaml::to_string(spec).expect("fixture must serialize as YAML");
    extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod")
        .map(|_| ())
        .expect_err("spec extraction must fail")
}

#[test]
fn cycles_are_rejected_identically_for_json_and_yaml() {
    let spec = spec_with_components(
        json!({
            "A": {"type": "object", "properties": {"b": {"$ref": "#/components/schemas/B"}}},
            "B": {"type": "object", "properties": {"a": {"$ref": "#/components/schemas/A"}}}
        }),
        "#/components/schemas/A",
    );
    let json_path = cycle_path(&extract_json_err(&spec)).to_string();
    let yaml_err = extract_yaml_err(&spec);
    assert_eq!(
        cycle_path(&yaml_err),
        json_path,
        "JSON and YAML input must produce the identical cycle report"
    );
}

#[test]
fn expansion_budget_applies_identically_for_json_and_yaml() {
    let spec = spec_with_repeated_path_item_clones(200, 20_000);
    assert!(
        matches!(extract_json_err(&spec), ExtractError::SchemaTooLarge { .. }),
        "JSON input must be charged the cumulative account"
    );
    assert!(
        matches!(extract_yaml_err(&spec), ExtractError::SchemaTooLarge { .. }),
        "YAML input must be charged the same cumulative account"
    );
}

/// The parsed-source node ceiling used to apply to YAML only, leaving JSON
/// bounded solely by the request-body byte cap.
#[test]
fn oversized_json_source_tree_is_rejected_before_expansion() {
    let payload: Vec<Value> = (0..600_000).map(|n| json!(n)).collect();
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Huge Source API", "version": "1.0.0"},
        "x-ferrum-proxy": proxy_block(),
        "x-huge": Value::Array(payload),
        "paths": {}
    });
    let err = extract_json_err(&spec);
    assert!(
        matches!(err, ExtractError::InvalidJson(_)),
        "an oversized JSON source tree must be rejected at parse admission: {err}"
    );
}

// ---------------------------------------------------------------------------
// Namespace independence of the account
// ---------------------------------------------------------------------------

/// The resolution account is per-import, so one namespace's rejected import
/// cannot consume budget belonging to another namespace's subsequent import.
#[test]
fn a_rejected_import_does_not_consume_another_namespaces_budget() {
    let hostile = spec_with_repeated_path_item_clones(200, 20_000);
    for _ in 0..3 {
        assert!(matches!(
            extract(
                serde_json::to_vec(&hostile).expect("fixture").as_slice(),
                Some(SpecFormat::Json),
                "tenant-a",
            )
            .expect_err("hostile import must fail"),
            ExtractError::SchemaTooLarge { .. }
        ));
    }
    let benign = spec_with_repeated_path_item_clones(8, 20_000);
    extract(
        serde_json::to_vec(&benign).expect("fixture").as_slice(),
        Some(SpecFormat::Json),
        "tenant-b",
    )
    .expect("a later import in another namespace must start with a full account");
}
