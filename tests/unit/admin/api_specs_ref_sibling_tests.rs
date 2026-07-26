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
fn annotation_only_ref_siblings_stay_flat() {
    // No assertion is displaced, so the historical flat overlay is preserved
    // and no `allOf` wrapper is introduced.
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"type": "string", "description": "target"}"#,
        r##"{"$ref": "#/components/schemas/Target", "description": "override", "x-owner": "team"}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["description"], "override");
    assert_eq!(schema["x-owner"], "team");
    assert!(schema.get("allOf").is_none(), "unexpected wrapper: {schema}");
}

#[test]
fn identifier_ref_siblings_stay_on_the_wrapper() {
    let spec = spec_with_request_schema(
        "3.1.0",
        r#"{"type": "string", "minLength": 3}"#,
        r##"{"$id": "https://example.com/wrapper.json", "$ref": "#/components/schemas/Target", "maxLength": 5}"##,
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["$id"], "https://example.com/wrapper.json");
    assert_eq!(schema["allOf"][0]["minLength"], 3);
    assert_eq!(schema["allOf"][1]["maxLength"], 5);
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
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["description"], "override");
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
