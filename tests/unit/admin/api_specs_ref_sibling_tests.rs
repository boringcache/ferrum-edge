//! Schema Object `$ref` sibling composition for API-spec import.
//!
//! OpenAPI 3.1 Schema Objects inherit JSON Schema 2020-12, where `$ref` is an
//! applicator and adjacent keywords are independent assertions that must also
//! hold. Materializing the target and inserting each sibling by key let a
//! sibling *replace* the referenced assertion, so an imported contract could
//! enforce less than its source. These tests pin the composition contract and
//! the fail-closed rejections around it.

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use serde_json::{Value, json};

fn proxy_block() -> &'static str {
    r#"{
    "id": "ref-sibling-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  }"#
}

fn spec_with_request_schema(version: &str, component: &str, request_schema: &str) -> String {
    format!(
        r##"{{
  "openapi": "{version}",
  "info": {{"title": "Ref Sibling API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{"schemas": {{"Target": {component}}}}},
  "paths": {{
    "/items": {{
      "post": {{
        "requestBody": {{
          "content": {{"application/json": {{"schema": {request_schema}}}}}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    )
}

fn first_request_schema(spec: &str) -> Value {
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    let plugin = bundle
        .plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "openapi_validator")
        .expect("generated openapi_validator plugin must be present");
    plugin.config["operations"][0]["request_body"]["content"]["application/json"].clone()
}

fn extract_err(spec: &str) -> ExtractError {
    extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").expect_err("spec extraction must fail")
}

#[test]
fn conflicting_ref_sibling_type_becomes_a_conjunction() {
    // `{$ref: <string>, type: integer}` accepts no instance under 2020-12.
    // Overwriting the target's `type` would have accepted every integer.
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"type": "string"}"#,
        r##"{"$ref": "#/components/schemas/Target", "type": "integer"}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["allOf"][0]["type"], "string");
    assert_eq!(schema["allOf"][1]["type"], "integer");
    assert!(
        schema.get("type").is_none(),
        "the sibling must not be merged onto the materialized target: {schema}"
    );
}

#[test]
fn ref_sibling_cannot_relax_referenced_required_and_additional_properties() {
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{
          "type": "object",
          "required": ["id"],
          "additionalProperties": false,
          "properties": {"id": {"type": "string"}}
        }"#,
        r##"{"$ref": "#/components/schemas/Target", "required": [], "additionalProperties": true}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["allOf"][0]["required"], json!(["id"]));
    assert_eq!(schema["allOf"][0]["additionalProperties"], json!(false));
    assert_eq!(schema["allOf"][1]["required"], json!([]));
}

#[test]
fn annotation_only_ref_siblings_preserve_both_schema_objects() {
    // An annotation stays on the referring Schema Object. Flattening it into
    // the target would change identifier scope, overwrite target annotations,
    // and drop it entirely when the target is a boolean schema.
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"type": "string", "description": "target"}"#,
        r##"{"$ref": "#/components/schemas/Target", "description": "override", "x-owner": "team"}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["allOf"][0]["type"], "string");
    assert_eq!(schema["allOf"][0]["description"], "target");
    assert_eq!(schema["description"], "override");
    assert_eq!(schema["x-owner"], "team");
}

#[test]
fn annotation_next_to_boolean_ref_target_is_not_dropped() {
    let spec = spec_with_request_schema(
        "3.1.0",
        "true",
        r##"{"$ref": "#/components/schemas/Target", "description": "kept"}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["description"], "kept");
    assert_eq!(schema["allOf"], json!([true]));
}

#[test]
fn identifier_ref_siblings_stay_on_the_wrapper() {
    // The referring object declares its own `$id`, so the sibling `$ref` is
    // resolved against that base (2020-12 §8.2.1) — here an absolute reference
    // to a second in-document schema resource. The `$id` must stay on the
    // wrapper: relocating it into an `allOf` branch would move the base-URI
    // scope of every URI-reference keyword composed beside it.
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"$id": "https://example.com/target.json", "type": "string", "minLength": 3}"#,
        r#"{"$id": "https://example.com/wrapper.json", "$ref": "https://example.com/target.json", "maxLength": 5}"#,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["$id"], "https://example.com/wrapper.json");
    assert_eq!(schema["allOf"][0]["minLength"], 3);
    assert_eq!(schema["allOf"][1]["maxLength"], 5);
    assert!(
        schema.get("maxLength").is_none(),
        "the assertion sibling must not be merged onto the wrapper: {schema}"
    );
}

#[test]
fn identifier_ref_sibling_rebases_a_document_root_pointer() {
    // `$id` beside `$ref` starts a new schema resource, so `#/components/...`
    // no longer addresses the OpenAPI document — it addresses the wrapper.
    // That is the standard rule, and it must fail closed (with actionable
    // wording) rather than silently falling back to the document root.
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"type": "string", "minLength": 3}"#,
        r##"{"$id": "https://example.com/wrapper.json", "$ref": "#/components/schemas/Target", "maxLength": 5}"##,
    );
    let error = extract_err(&spec);
    assert!(
        matches!(error, ExtractError::SchemaReference(_)),
        "unexpected error: {error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("https://example.com/wrapper.json") && message.contains("$id"),
        "error must explain the $id rebase: {message}"
    );
}

#[test]
fn unevaluated_properties_next_to_ref_is_rejected() {
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"type": "object", "properties": {"id": {"type": "string"}}}"#,
        r##"{"$ref": "#/components/schemas/Target", "unevaluatedProperties": false}"##,
    );
    let error = extract_err(&spec);
    assert!(
        matches!(error, ExtractError::SchemaReference(_)),
        "unexpected error: {error}"
    );
    assert!(
        error.to_string().contains("unevaluatedProperties"),
        "unexpected error: {error}"
    );
}

#[test]
fn dynamic_scope_keywords_next_to_ref_are_rejected() {
    for keyword in ["$dynamicRef", "$recursiveRef"] {
        let request_schema = json!({
            "$ref": "#/components/schemas/Target",
            (keyword): "#node"
        });
        let spec = spec_with_request_schema(
            "3.1.0",
            r#"{"type": "object"}"#,
            &request_schema.to_string(),
        );
        let error = extract_err(&spec);
        assert!(
            matches!(error, ExtractError::SchemaReference(_)),
            "unexpected error for {keyword}: {error}"
        );
        assert!(
            error.to_string().contains(keyword),
            "unexpected error for {keyword}: {error}"
        );
    }
}

#[test]
fn openapi_30_assertion_ref_sibling_is_rejected() {
    // OpenAPI 3.0 Schema Object `$ref` is a JSON Reference: adjacent keywords
    // have no defined meaning, so neither merging nor 2020-12 composition is
    // correct. Fail closed instead of importing a differently-shaped contract.
    let spec = spec_with_request_schema(
        "3.0.3",
        r#"{"type": "string"}"#,
        r##"{"$ref": "#/components/schemas/Target", "nullable": true}"##,
    );
    let error = extract_err(&spec);
    assert!(
        matches!(error, ExtractError::SchemaReference(_)),
        "unexpected error: {error}"
    );
    assert!(
        error.to_string().contains("allOf"),
        "error should point at the supported construct: {error}"
    );
}

#[test]
fn openapi_30_annotation_ref_sibling_still_imports() {
    let spec = spec_with_request_schema(
        "3.0.3",
        r#"{"type": "string"}"#,
        r##"{"$ref": "#/components/schemas/Target", "description": "override"}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["description"], "override");
    assert_eq!(schema["allOf"][0]["type"], "string");
}

#[test]
fn declared_status_without_content_is_emitted() {
    // A declared status must preclude `default` fallback at runtime, which the
    // validator can only honor if the declaration survives generation.
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Status Precedence API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "get": {{
        "responses": {{
          "200": {{"description": "ok"}},
          "default": {{
            "description": "fallback",
            "content": {{"application/json": {{"schema": {{"type": "object"}}}}}}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    let plugin = bundle
        .plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "openapi_validator")
        .expect("generated openapi_validator plugin must be present");
    let responses = &plugin.config["operations"][0]["responses"];
    assert_eq!(responses["200"], json!({}));
    assert!(responses["default"]["application/json"].is_object());
}

#[test]
fn unknown_x_ferrum_validate_key_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Typo API", "version": "1.0.0"}},
  "x-ferrum-validate": {{"fail_on_missing_response_scehma": true}},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "get": {{"responses": {{"204": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let error = extract_err(&spec);
    let message = error.to_string();
    assert!(
        message.contains("fail_on_missing_response_scehma"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("fail_on_missing_response_schema"),
        "the typo should carry a spelling suggestion: {message}"
    );
}

#[test]
fn unknown_x_ferrum_validate_side_key_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Typo Side API", "version": "1.0.0"}},
  "x-ferrum-validate": {{"request": {{"enabled": true, "content_typs": ["application/json"]}}}},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "get": {{"responses": {{"204": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let error = extract_err(&spec);
    assert!(
        error.to_string().contains("content_typs"),
        "unexpected error: {error}"
    );
}

#[test]
fn unknown_x_ferrum_validate_bypass_key_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Typo Bypass API", "version": "1.0.0"}},
  "x-ferrum-validate": {{"bypass": {{"methdos": ["GET"]}}}},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "get": {{"responses": {{"204": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let error = extract_err(&spec);
    assert!(
        error.to_string().contains("methdos"),
        "unexpected error: {error}"
    );
}

#[test]
fn exponential_ref_fanout_hits_the_expansion_limit() {
    // A self-recursive Target is expanded depth-first, so one spine burns
    // MAX_SCHEMA_REF_DEPTH before the node budget can fire. Use a finite
    // layered DAG (no cycles) so width is materialised and the expansion
    // budget is what fails closed before memory exhaustion.
    let mut components = serde_json::Map::new();
    components.insert(
        "Leaf".to_string(),
        json!({"type": "string", "minLength": 1}),
    );
    let mut child = "Leaf".to_string();
    for layer in (0..7).rev() {
        let name = format!("L{layer}");
        let branches = vec![json!({ "$ref": format!("#/components/schemas/{child}") }); 8];
        components.insert(name.clone(), json!({ "anyOf": branches }));
        child = name;
    }
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Ref Fanout API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{"schemas": {schemas}}},
  "paths": {{
    "/items": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#/components/schemas/L0"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block(),
        schemas = Value::Object(components)
    );
    let error = extract_err(&spec);
    assert!(
        matches!(error, ExtractError::SchemaTooLarge { .. }),
        "fan-out must hit the expansion limit before exhausting memory: {error}"
    );
}

#[test]
fn x_ferrum_validate_operations_key_is_rejected() {
    // `operations` is always regenerated from the document; accepting and then
    // discarding it looks like a successful deployment of operator intent.
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Operations Override API", "version": "1.0.0"}},
  "x-ferrum-validate": {{"operations": []}},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "get": {{"responses": {{"204": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let error = extract_err(&spec);
    assert!(
        error.to_string().contains("operations"),
        "unexpected error: {error}"
    );
}
