//! External and cross-document OpenAPI `$ref` resolution (issue #3306).
//!
//! Covers opt-in policy, file/map loaders, Path Item and schema chains,
//! fragments, cycles/budgets, traversal rejection, SSRF URI gates, and
//! immutable snapshot digests. Network success paths use an in-memory map
//! loader (no live Internet). Absent policy stays fail-closed.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use ferrum_edge::admin::api_specs::external_refs::{
    ExternalDocumentLoader, contain_path, redact_reference, resource_uri_key,
};
use ferrum_edge::admin::api_specs::{
    EffectiveExternalRefPolicy, ExternalRefProcessPolicy, ExternalRefSnapshot,
    ExternalRefSpecExtension, ExtractError, MapExternalDocumentLoader, SpecFormat, extract,
    extract_with_external_refs,
};
use serde_json::{Value, json};
use url::Url;

fn proxy_block() -> &'static str {
    r#"{
    "id": "ext-ref-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  }"#
}

fn process_enabled(file_root: Option<PathBuf>) -> ExternalRefProcessPolicy {
    ExternalRefProcessPolicy {
        enabled: true,
        file_root,
        allowed_origins: vec!["https://schemas.example.com:443".to_string()],
        allow_http_origins: vec!["http://127.0.0.1:9".to_string()],
        max_documents: 8,
        max_document_bytes: 64 * 1024,
        max_aggregate_bytes: 256 * 1024,
        max_refs: 64,
        max_uri_length: 2048,
        max_redirects: 2,
        max_nesting: 8,
        connect_timeout: Duration::from_millis(100),
        request_timeout: Duration::from_millis(200),
        total_timeout: Duration::from_secs(2),
    }
}

fn extract_err(spec: &str) -> ExtractError {
    extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").expect_err("must fail")
}

fn extract_validator_ops(
    spec: &str,
    process: &ExternalRefProcessPolicy,
    loader: &dyn ExternalDocumentLoader,
) -> Value {
    let (bundle, meta) =
        extract_with_external_refs(spec.as_bytes(), Some(SpecFormat::Json), "prod", process, loader)
            .expect("extraction must succeed");
    assert!(
        meta.external_ref_snapshot.is_some(),
        "enabled external refs must produce a snapshot"
    );
    bundle
        .plugins
        .iter()
        .find(|p| p.plugin_name == "openapi_validator")
        .expect("openapi_validator")
        .config
        .clone()
}

#[test]
fn absent_policy_keeps_external_refs_unsupported() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://schemas.example.com/paths.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::UnsupportedExternalRef { .. }),
        "{err}"
    );
}

#[test]
fn process_gate_alone_is_insufficient() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://schemas.example.com/paths.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );
    let process = process_enabled(None);
    let err = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &MapExternalDocumentLoader::default(),
    )
    .expect_err("per-spec opt-in required");
    assert!(
        matches!(err, ExtractError::UnsupportedExternalRef { .. }),
        "{err}"
    );
}

#[test]
fn map_loader_resolves_external_path_item_and_schema_chain() {
    let paths_doc = br#"{
  "paths": {
    "/pets": {
      "get": {
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": { "$ref": "https://schemas.example.com/schemas/pet.json" }
              }
            }
          }
        }
      }
    }
  }
}"#;
    let schema_doc = br#"{
  "type": "object",
  "required": ["id"],
  "properties": { "id": { "type": "integer" } }
}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/paths.json".to_string(),
        paths_doc.to_vec(),
    );
    loader.docs.insert(
        "https://schemas.example.com/schemas/pet.json".to_string(),
        schema_doc.to_vec(),
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": {{
    "enabled": true,
    "allowed_origins": ["https://schemas.example.com"]
  }},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://schemas.example.com/paths.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    assert_eq!(config["operations"][0]["method"], "GET");
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["id"])
    );
}

#[test]
fn nested_relative_bases_resolve_against_containing_document() {
    let parent = br#"{
  "components": {
    "schemas": {
      "Wrapper": {
        "$id": "https://schemas.example.com/nest/wrapper.json",
        "$ref": "../leaf.json#/definitions/Leaf"
      }
    }
  }
}"#;
    let leaf = br#"{
  "definitions": {
    "Leaf": {
      "type": "object",
      "required": ["ok"],
      "properties": { "ok": { "type": "boolean" } }
    }
  }
}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/nest/parent.json".to_string(),
        parent.to_vec(),
    );
    loader.docs.insert(
        "https://schemas.example.com/leaf.json".to_string(),
        leaf.to_vec(),
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": {{ "enabled": true }},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/x": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "$ref": "https://schemas.example.com/nest/parent.json#/components/schemas/Wrapper"
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["ok"])
    );
}

#[test]
fn escaped_json_pointer_fragment_across_documents() {
    let remote = br#"{
  "components": {
    "schemas": {
      "Order Id": {
        "type": "object",
        "required": ["n"],
        "properties": { "n": { "type": "string" } }
      }
    }
  }
}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/remote.json".to_string(),
        remote.to_vec(),
    );
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/o": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "$ref": "https://schemas.example.com/remote.json#/components/schemas/Order%20Id"
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["n"])
    );
}

#[test]
fn cross_document_cycle_fails_closed() {
    let a = br#"{ "$ref": "https://schemas.example.com/b.json" }"#;
    let b = br#"{ "$ref": "https://schemas.example.com/a.json" }"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader
        .docs
        .insert("https://schemas.example.com/a.json".to_string(), a.to_vec());
    loader
        .docs
        .insert("https://schemas.example.com/b.json".to_string(), b.to_vec());
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/c": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "https://schemas.example.com/a.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process_enabled(None),
        &loader,
    )
    .expect_err("cycle");
    assert!(
        matches!(err, ExtractError::SchemaReferenceCycle { .. }),
        "{err}"
    );
}

#[test]
fn document_count_budget_fails_closed() {
    let mut loader = MapExternalDocumentLoader::default();
    for i in 0..5 {
        loader.docs.insert(
            format!("https://schemas.example.com/d{i}.json"),
            format!(r#"{{"$ref":"https://schemas.example.com/d{}.json"}}"#, i + 1)
                .into_bytes(),
        );
    }
    loader.docs.insert(
        "https://schemas.example.com/d5.json".to_string(),
        br#"{"type":"string"}"#.to_vec(),
    );
    let mut process = process_enabled(None);
    process.max_documents = 2;
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/c": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "https://schemas.example.com/d0.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .expect_err("budget");
    assert!(
        matches!(err, ExtractError::SchemaReference(_))
            || matches!(err, ExtractError::SchemaTooLarge { .. }),
        "{err}"
    );
}

#[test]
fn file_root_sibling_and_traversal_rejection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    fs::write(
        root.join("pet.json"),
        br#"{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}"#,
    )
    .unwrap();
    // Symlink escape target outside the jail.
    let outside = dir.path().parent().unwrap().join("outside-secret.json");
    fs::write(&outside, br#"{"type":"string"}"#).unwrap();
    let link = root.join("escape.json");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let process = process_enabled(Some(root.clone()));
    let mut loader = MapExternalDocumentLoader::default();
    // Use DefaultExternalDocumentLoader semantics via contain_path unit below;
    // for extract, feed file contents through map keyed by file URI.
    let pet_uri = Url::from_file_path(root.join("pet.json")).unwrap();
    loader.docs.insert(
        resource_uri_key(&pet_uri),
        fs::read(root.join("pet.json")).unwrap(),
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": {{
    "enabled": true,
    "document_base": "{base}"
  }},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "pet.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        base = Url::from_file_path(root.join("root.json")).unwrap(),
        proxy = proxy_block()
    );
    // document_base file URI requires process file_root; compose validates it.
    let config = extract_validator_ops(&spec, &process, &loader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["name"])
    );

    #[cfg(unix)]
    {
        let err = contain_path(&root, &link).expect_err("symlink must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("symbolic link") || msg.contains("escapes"),
            "{msg}"
        );
        assert!(!msg.contains("outside-secret"));
    }

    let traversal = root.join("subdir").join("..").join("..").join("etc").join("passwd");
    let err = contain_path(&root, &traversal).expect_err("traversal");
    assert!(!err.to_string().contains("/etc/passwd"));
}

#[test]
fn scheme_userinfo_and_private_https_rejected() {
    let process = process_enabled(None);
    let cases = [
        "http://schemas.example.com/a.json",
        "https://user:pass@schemas.example.com/a.json",
        "https://169.254.169.254/latest",
        "https://127.0.0.1/a.json",
        "ftp://schemas.example.com/a.json",
    ];
    for uri in cases {
        let spec = format!(
            r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{ "schema": {{ "$ref": "{uri}" }} }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
            proxy = proxy_block(),
            uri = uri
        );
        let err = extract_with_external_refs(
            spec.as_bytes(),
            Some(SpecFormat::Json),
            "prod",
            &process,
            &MapExternalDocumentLoader::default(),
        )
        .expect_err(uri);
        let rendered = err.to_string();
        assert!(
            !rendered.contains("user:pass"),
            "must not echo credentials: {rendered}"
        );
        assert!(
            matches!(
                err,
                ExtractError::UnsupportedExternalRef { .. }
                    | ExtractError::SchemaReference(_)
                    | ExtractError::MalformedExtension { .. }
            ),
            "{uri}: {err}"
        );
    }
}

#[test]
fn snapshot_is_reproducible_and_digest_stable() {
    let remote = br#"{"type":"string","minLength":1}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/s.json".to_string(),
        remote.to_vec(),
    );
    let process = process_enabled(None);
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "https://schemas.example.com/s.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let (_, meta1) = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .unwrap();
    let (_, meta2) = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .unwrap();
    let s1 = meta1.external_ref_snapshot.unwrap();
    let s2 = meta2.external_ref_snapshot.unwrap();
    assert_eq!(s1.snapshot_digest, s2.snapshot_digest);
    assert_eq!(s1.compute_digest(), s1.snapshot_digest);
    let gzip = s1.gzip_bytes().unwrap();
    let restored = ExternalRefSnapshot::from_gzip_bytes(&gzip, 1024 * 1024).unwrap();
    assert_eq!(restored.snapshot_digest, s1.snapshot_digest);
}

#[tokio::test]
async fn http_fixture_listener_resolves_under_explicit_http_allowlist() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    let origin = format!("http://127.0.0.1:{}", addr.port());
    let body = br#"{"type":"object","required":["n"],"properties":{"n":{"type":"integer"}}}"#;
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });

    let mut process = process_enabled(None);
    process.allow_http_origins = vec![format!("http://127.0.0.1:{}", addr.port())];
    // Loopback must pass egress for the fixture; production HTTPS stays public-only.
    let loader = ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader {
        egress: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        dns_cache: None,
        fixtures: Default::default(),
    };

    let uri = format!("{origin}/schema.json");
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "{uri}" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block(),
        uri = uri
    );

    let (bundle, meta) = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .expect("HTTP fixture fetch must succeed under explicit allowlist");
    assert!(meta.external_ref_snapshot.is_some());
    let config = bundle
        .plugins
        .iter()
        .find(|p| p.plugin_name == "openapi_validator")
        .unwrap()
        .config
        .clone();
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["n"])
    );
}

    let redacted = redact_reference("https://alice:s3cret@host.example/x?token=abc#/y");
    assert!(!redacted.contains("alice"));
    assert!(!redacted.contains("s3cret"));
    assert!(!redacted.contains("token"));
}

#[test]
fn policy_compose_intersects_origins() {
    let process = process_enabled(None);
    let ext = ExternalRefSpecExtension {
        enabled: true,
        document_base: None,
        allowed_origins: vec!["https://other.example.com".to_string()],
    };
    let err = EffectiveExternalRefPolicy::compose(&process, Some(&ext)).unwrap_err();
    assert!(matches!(err, ExtractError::MalformedExtension { .. }), "{err}");
}

/// Tiny tempfile shim without adding a dependency if tempfile is absent.
mod tempfile {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }

    pub fn tempdir() -> std::io::Result<TempDir> {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ferrum-extref-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    impl TempDir {
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
