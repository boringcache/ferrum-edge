//! Contract tests: importer-generated `openapi_validator` configs must validate
//! against the published Admin OpenAPI schema (`OpenapiValidatorConfig`).
//!
//! Covers issue #2337: top-level-only `schema_draft`, and JSON Schema values that
//! may be objects (Draft 7 / OAS 3.0) or boolean schemas (Draft 2020-12 / OAS 3.1).

use ferrum_edge::admin::api_specs::{SpecFormat, extract};
use serde_json::{Value, json};

fn openapi_validator_config_validator() -> jsonschema::Validator {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/OpenapiValidatorConfig",
        "components": spec["components"].clone()
    });
    jsonschema::draft202012::options()
        .build(&schema)
        .expect("OpenapiValidatorConfig schema compiles")
}

fn assert_valid_against_admin_schema(config: &Value, label: &str) {
    let validator = openapi_validator_config_validator();
    if let Err(error) = validator.validate(config) {
        panic!("{label} must validate against OpenapiValidatorConfig: {error}; config={config}");
    }
}

fn extract_validator_config(spec: &str) -> Value {
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    assert_eq!(bundle.plugins.len(), 1, "expected one generated plugin");
    assert_eq!(bundle.plugins[0].plugin_name, "openapi_validator");
    bundle.plugins[0].config.clone()
}

#[test]
fn importer_draft7_object_schemas_match_published_admin_schema() {
    let spec = r##"{
  "openapi": "3.0.3",
  "info": {"title": "Orders API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "orders-api",
    "backend_host": "orders.internal",
    "backend_port": 8080
  },
  "paths": {
    "/orders": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                  "id": {"type": "string"}
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["accepted"],
                  "properties": {
                    "accepted": {"type": "boolean"}
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    assert_eq!(config["schema_draft"], "draft7");
    assert!(
        config["operations"][0].get("schema_draft").is_none(),
        "operations must not emit a redundant schema_draft field"
    );
    assert!(config["operations"][0]["request_body"]["content"]["application/json"].is_object());
    assert!(config["operations"][0]["responses"]["200"]["application/json"].is_object());
    assert_valid_against_admin_schema(&config, "Draft 7 importer-generated config");
}

#[test]
fn importer_draft202012_boolean_schemas_match_published_admin_schema() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Boolean Schema API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "bool-api",
    "backend_host": "bool.internal",
    "backend_port": 8080
  },
  "paths": {
    "/any": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": true
            }
          }
        },
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": false
              }
            }
          },
          "default": {
            "description": "fallback",
            "content": {
              "application/json": {
                "schema": true
              }
            }
          }
        }
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    assert_eq!(config["schema_draft"], "draft2020-12");
    assert!(
        config["operations"][0].get("schema_draft").is_none(),
        "operations must not emit a redundant schema_draft field"
    );
    assert_eq!(
        config["operations"][0]["request_body"]["content"]["application/json"],
        true
    );
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"],
        false
    );
    assert_eq!(
        config["operations"][0]["responses"]["default"]["application/json"],
        true
    );
    assert_valid_against_admin_schema(&config, "Draft 2020-12 boolean-schema importer config");
}

#[test]
fn published_schema_accepts_alternate_single_schema_boolean_form() {
    // Importer emits the content-map form; the alternate content_type/schema
    // shape is operator-facing and must accept boolean schemas consistently.
    let config = json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "PUT",
            "path_template": "/items/{id}",
            "path_regex": "^/items/[^/]+$",
            "request_required": true,
            "request_body": {
                "content_type": "application/json",
                "schema": true
            },
            "responses": {
                "204": {
                    "application/json": false
                }
            }
        }]
    });
    assert_valid_against_admin_schema(&config, "alternate single-schema boolean form");
}

#[test]
fn published_schema_rejects_per_operation_schema_draft() {
    let validator = openapi_validator_config_validator();
    let config = json!({
        "schema_draft": "draft7",
        "operations": [{
            "method": "GET",
            "path_template": "/health",
            "path_regex": "^/health$",
            "schema_draft": "draft7"
        }]
    });
    assert!(
        validator.validate(&config).is_err(),
        "OpenapiValidatorOperation must reject undeclared schema_draft"
    );
}

#[test]
fn importer_preserves_form_encoding_objects_in_generated_config() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Form API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "form-api",
    "backend_host": "form.internal",
    "backend_port": 8080
  },
  "paths": {
    "/tags": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["tags"],
                "properties": {
                  "tags": {
                    "type": "array",
                    "minItems": 2,
                    "items": {"type": "string"}
                  }
                }
              },
              "encoding": {
                "tags": {"style": "form", "explode": false}
              }
            }
          }
        },
        "responses": {
          "204": {"description": "ok"}
        }
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    let media = &config["operations"][0]["request_body"]["content"]
        ["application/x-www-form-urlencoded"];
    assert_eq!(media["encoding"]["tags"]["style"], "form");
    assert_eq!(media["encoding"]["tags"]["explode"], false);
    assert!(media["schema"]["properties"]["tags"].is_object());
    assert_valid_against_admin_schema(&config, "form encoding importer config");
}

#[test]
fn importer_rejects_unsupported_encoding_style_at_admission() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Bad Form API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "bad-form-api",
    "backend_host": "form.internal",
    "backend_port": 8080
  },
  "paths": {
    "/tags": {
      "post": {
        "requestBody": {
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "properties": {
                  "tags": {"type": "array", "items": {"type": "string"}}
                }
              },
              "encoding": {
                "tags": {"style": "matrix"}
              }
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}"##;

    let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("unsupported") || message.contains("matrix"),
        "unsupported encoding must fail closed, got {message}"
    );
}

#[test]
fn published_schema_accepts_media_type_object_with_encoding() {
    let config = json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST",
            "path_template": "/tags",
            "path_regex": "^/tags$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "tags": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "encoding": {
                            "tags": {
                                "style": "form",
                                "explode": false,
                                "allowReserved": true
                            }
                        }
                    }
                }
            }
        }]
    });
    assert_valid_against_admin_schema(&config, "media type object with encoding");
}

#[test]
fn published_schema_rejects_ambiguous_media_type_objects() {
    let validator = openapi_validator_config_validator();
    for invalid_entry in [
        json!({"encoding": {}}),
        json!({"schema": true, "encoding": null}),
        json!({"schema": true, "encoding": {}, "example": "ambiguous"}),
    ] {
        let config = json!({
            "schema_draft": "draft2020-12",
            "operations": [{
                "method": "POST",
                "path_template": "/strict",
                "path_regex": "^/strict$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": invalid_entry
                    }
                }
            }]
        });
        assert!(
            validator.validate(&config).is_err(),
            "ambiguous media type object must fail the published schema: {config}"
        );
    }
}
