//! Local JSON Schema `$ref` fragment resolution for API-spec import.
//!
//! Covers issue #2338: the importer must distinguish JSON Pointer fragments from
//! Draft 2020-12 `$anchor` plain-name fragments, decode URI fragments
//! fail-closed, honor local-document `$id` resource scope without fetching, and
//! preserve OpenAPI 3.0 / Draft 7 pointer behavior.

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use serde_json::{Value, json};

fn proxy_block() -> &'static str {
    r#"{
    "id": "anchor-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  }"#
}

fn first_request_schema(spec: &str) -> Value {
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    assert_eq!(bundle.plugins.len(), 1);
    assert_eq!(bundle.plugins[0].plugin_name, "openapi_validator");
    bundle.plugins[0].config["operations"][0]["request_body"]["content"]["application/json"]
        .clone()
}

fn extract_err(spec: &str) -> ExtractError {
    extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect_err("spec extraction must fail")
}

#[test]
fn json_pointer_ref_still_resolves() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Pointer API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order": {{
        "type": "object",
        "required": ["id"],
        "properties": {{"id": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#/components/schemas/Order"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["required"], json!(["id"]));
}

#[test]
fn document_root_ref_resolves() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Root API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "type": "object",
  "required": ["root"],
  "properties": {{"root": {{"type": "boolean"}}}},
  "paths": {{
    "/root": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["required"], json!(["root"]));
    assert_eq!(schema["properties"]["root"]["type"], "boolean");
}

#[test]
fn root_anchor_ref_resolves() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Anchor API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order": {{
        "$anchor": "Order",
        "type": "object",
        "required": ["id"],
        "properties": {{"id": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Order"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["$anchor"], "Order");
    assert_eq!(schema["required"], json!(["id"]));
}

#[test]
fn nested_anchor_ref_resolves() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Nested Anchor API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Envelope": {{
        "type": "object",
        "properties": {{
          "payload": {{
            "$anchor": "Payload",
            "type": "object",
            "required": ["sku"],
            "properties": {{"sku": {{"type": "string"}}}}
          }}
        }}
      }}
    }}
  }},
  "paths": {{
    "/items": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Payload"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["$anchor"], "Payload");
    assert_eq!(schema["required"], json!(["sku"]));
}

#[test]
fn percent_encoded_pointer_and_anchor_fragments_resolve() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Encoded API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order Id": {{
        "type": "object",
        "required": ["code"],
        "properties": {{"code": {{"type": "string"}}}}
      }},
      "Tagged": {{
        "$anchor": "Order_Id",
        "type": "object",
        "required": ["tag"],
        "properties": {{"tag": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/encoded-pointer": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#/components/schemas/Order%20Id"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }},
    "/encoded-anchor": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Order%5FId"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
    let operations = bundle.plugins[0].config["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 2);
    // Operation order follows HTTP_METHODS then path map iteration; assert by path.
    let by_path: std::collections::HashMap<_, _> = operations
        .iter()
        .map(|op| (op["path_template"].as_str().unwrap().to_string(), op.clone()))
        .collect();
    assert_eq!(
        by_path["/encoded-pointer"]["request_body"]["content"]["application/json"]["required"],
        json!(["code"])
    );
    assert_eq!(
        by_path["/encoded-anchor"]["request_body"]["content"]["application/json"]["$anchor"],
        "Order_Id"
    );
}

#[test]
fn malformed_percent_encoding_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Bad Encoding API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#/components/schemas/Order%ZZ"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::MalformedExtension { which: "x-ferrum-validate", .. }),
        "got: {err}"
    );
    assert!(
        err.to_string().contains("malformed percent-encoding"),
        "got: {err}"
    );
}

#[test]
fn missing_anchor_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Missing Anchor API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Missing"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::MalformedExtension { which: "x-ferrum-validate", .. }),
        "got: {err}"
    );
    assert!(
        err.to_string().contains("unresolved internal $ref '#Missing'"),
        "got: {err}"
    );
}

#[test]
fn duplicate_anchor_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Duplicate Anchor API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "A": {{"$anchor": "Shared", "type": "string"}},
      "B": {{"$anchor": "Shared", "type": "number"}}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Shared"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::MalformedExtension { which: "x-ferrum-validate", .. }),
        "got: {err}"
    );
    assert!(
        err.to_string().contains("duplicate schema anchor 'Shared'"),
        "got: {err}"
    );
}

#[test]
fn local_id_resource_scope_resolves_without_external_fetch() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Local Id API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order": {{
        "$id": "https://example.com/schemas/order.json",
        "$anchor": "OrderBody",
        "type": "object",
        "required": ["id"],
        "properties": {{"id": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{
                "$ref": "https://example.com/schemas/order.json#OrderBody"
              }}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let schema = first_request_schema(&spec);
    assert_eq!(schema["$anchor"], "OrderBody");
    assert_eq!(schema["required"], json!(["id"]));
}

#[test]
fn unknown_absolute_ref_remains_unsupported_external() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "External API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "https://example.com/schemas/order.json#OrderBody"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::UnsupportedExternalRef { .. }),
        "got: {err}"
    );
}

#[test]
fn recursive_anchor_refs_hit_depth_limit() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Recursive API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Node": {{
        "$anchor": "Node",
        "type": "object",
        "properties": {{
          "child": {{"$ref": "#Node"}}
        }}
      }}
    }}
  }},
  "paths": {{
    "/nodes": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Node"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::SchemaTooDeep { .. }),
        "got: {err}"
    );
}

#[test]
fn openapi_30_pointer_and_draft7_id_anchor_remain_compatible() {
    let pointer_spec = format!(
        r##"{{
  "openapi": "3.0.3",
  "info": {{"title": "OAS30 Pointer", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order": {{
        "type": "object",
        "required": ["id"],
        "properties": {{"id": {{"type": "string", "nullable": true}}}}
      }}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#/components/schemas/Order"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let pointer_schema = first_request_schema(&pointer_spec);
    assert_eq!(pointer_schema["properties"]["id"]["type"], json!(["string", "null"]));

    let id_anchor_spec = format!(
        r##"{{
  "openapi": "3.0.3",
  "info": {{"title": "OAS30 Id Anchor", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order": {{
        "$id": "#Order",
        "type": "object",
        "required": ["id"],
        "properties": {{"id": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Order"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let id_schema = first_request_schema(&id_anchor_spec);
    assert_eq!(id_schema["required"], json!(["id"]));
    assert_eq!(id_schema["$id"], "#Order");
}

#[test]
fn openapi_30_ignores_dollar_anchor_keyword() {
    let spec = format!(
        r##"{{
  "openapi": "3.0.3",
  "info": {{"title": "OAS30 Dollar Anchor", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Order": {{
        "$anchor": "Order",
        "type": "object",
        "required": ["id"],
        "properties": {{"id": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/orders": {{
      "post": {{
        "requestBody": {{
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#Order"}}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        err.to_string().contains("unresolved internal $ref '#Order'"),
        "got: {err}"
    );
}
