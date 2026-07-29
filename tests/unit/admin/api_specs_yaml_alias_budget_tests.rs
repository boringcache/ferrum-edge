//! Bounded YAML anchor/alias expansion for API-spec ingestion (issue #3307).
//!
//! Specs may reuse shared response/schema fragments via YAML anchors and
//! aliases. Expansion must stay deterministic under node, depth, alias-
//! reference, expanded-byte, and work budgets, with cycle and undefined-alias
//! detection, and must not admit an autodetection differential versus JSON.
//!
//! YAML fixtures must preserve indentation: Rust `\` string continuations
//! elide leading whitespace after the escaped newline and flatten nested
//! mappings (which silently drops self-referential cycles and merge nests).

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use serde_json::json;

fn proxy_yaml(id: &str) -> String {
    format!("x-ferrum-proxy:\n  id: {id}\n  backend_host: backend.internal\n  backend_port: 443\n")
}

#[test]
fn shared_schema_anchor_expands_on_extract() {
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Alias Spec\n",
            "  version: '1.0.0'\n",
            "components:\n",
            "  schemas:\n",
            "    ErrorBody: &ErrorBody\n",
            "      type: object\n",
            "      properties:\n",
            "        message:\n",
            "          type: string\n",
            "paths:\n",
            "  /items:\n",
            "    get:\n",
            "      responses:\n",
            "        '500':\n",
            "          description: error\n",
            "          content:\n",
            "            application/json:\n",
            "              schema: *ErrorBody\n",
            "{}",
        ),
        proxy_yaml("alias-proxy")
    );
    let (bundle, meta) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(bundle.proxy.id, "alias-proxy");
    assert_eq!(meta.title.as_deref(), Some("Alias Spec"));
}

#[test]
fn alias_chain_expands_before_serde_conversion() {
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Chain\n",
            "  version: '1.0.0'\n",
            "base: &base\n",
            "  type: string\n",
            "mid: &mid\n",
            "  allOf:\n",
            "    - *base\n",
            "leaf: *mid\n",
            "{}",
        ),
        proxy_yaml("chain-proxy")
    );
    let (bundle, _) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(bundle.proxy.id, "chain-proxy");
}

#[test]
fn merge_key_expands_when_present() {
    let yaml = concat!(
        "openapi: '3.1.0'\n",
        "info:\n",
        "  title: Merge\n",
        "  version: '1.0.0'\n",
        "defaults: &defaults\n",
        "  backend_host: backend.internal\n",
        "  backend_port: 443\n",
        "x-ferrum-proxy:\n",
        "  <<: *defaults\n",
        "  id: merge-proxy\n",
        "  backend_port: 8443\n",
    );
    let (bundle, _) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(bundle.proxy.id, "merge-proxy");
    assert_eq!(bundle.proxy.backend_host, "backend.internal");
    assert_eq!(bundle.proxy.backend_port, 8443);
}

#[test]
fn merge_sequence_uses_earlier_mapping_precedence() {
    let yaml = concat!(
        "openapi: '3.1.0'\n",
        "info:\n",
        "  title: Merge Sequence\n",
        "  version: '1.0.0'\n",
        "first: &first\n",
        "  backend_host: first.internal\n",
        "  backend_port: 443\n",
        "second: &second\n",
        "  backend_host: second.internal\n",
        "  backend_port: 9443\n",
        "x-ferrum-proxy:\n",
        "  <<: [*first, *second]\n",
        "  id: merge-order-proxy\n",
    );
    let (bundle, _) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(bundle.proxy.backend_host, "first.internal");
    assert_eq!(bundle.proxy.backend_port, 443);
}

#[test]
fn quoted_merge_spelling_remains_an_ordinary_mapping_key() {
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Quoted Merge\n",
            "  version: '1.0.0'\n",
            "\"<<\": literal-value\n",
            "{}",
        ),
        proxy_yaml("quoted-merge-proxy")
    );
    let (bundle, _) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(bundle.proxy.id, "quoted-merge-proxy");
}

#[test]
fn duplicate_mapping_keys_fail_closed_without_echoing_the_key() {
    let yaml = concat!(
        "x-ferrum-proxy:\n",
        "  id: first\n",
        "  id: must-not-escape\n",
        "  backend_host: backend.internal\n",
        "  backend_port: 443\n",
    );
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("duplicate key")),
        "got {err:?}"
    );
    assert!(
        !format!("{err:?}").contains("must-not-escape"),
        "duplicate-key diagnostics must not echo hostile key/value material"
    );
}

#[test]
fn unsupported_collection_tags_fail_closed_without_echoing_the_tag() {
    for yaml in [
        concat!(
            "!must-not-escape\n",
            "x-ferrum-proxy:\n",
            "  id: tagged-map\n",
            "  backend_host: backend.internal\n",
            "  backend_port: 443\n",
        ),
        concat!(
            "tagged: !must-not-escape [one, two]\n",
            "x-ferrum-proxy:\n",
            "  id: tagged-sequence\n",
            "  backend_host: backend.internal\n",
            "  backend_port: 443\n",
        ),
    ] {
        let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("unsupported YAML tag")),
            "got {err:?}"
        );
        assert!(
            !format!("{err:?}").contains("must-not-escape"),
            "unsupported-tag diagnostics must not echo hostile tag text"
        );
    }
}

#[test]
fn undefined_alias_fails_closed() {
    let yaml = format!(
        concat!("openapi: '3.1.0'\n", "info: *missing\n", "{}"),
        proxy_yaml("undef-proxy")
    );
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("undefined YAML alias")),
        "got {err:?}"
    );
}

#[test]
fn duplicate_anchor_fails_closed() {
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Dup\n",
            "  version: '1.0.0'\n",
            "a: &same 1\n",
            "b: &same 2\n",
            "{}",
        ),
        proxy_yaml("dup-proxy")
    );
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("duplicate YAML anchor")),
        "got {err:?}"
    );
}

#[test]
fn alias_cycle_fails_closed() {
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Cycle\n",
            "  version: '1.0.0'\n",
            "loop: &loop\n",
            "  next: *loop\n",
            "{}",
        ),
        proxy_yaml("cycle-proxy")
    );
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("cycle")),
        "got {err:?}"
    );
}

#[test]
fn forward_mutual_alias_fails_closed() {
    // Forward references cannot resolve at compose time; fail closed as
    // undefined (never materialize a recursive graph).
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Forward\n",
            "  version: '1.0.0'\n",
            "a: &a\n",
            "  next: *b\n",
            "b: &b\n",
            "  next: *a\n",
            "{}",
        ),
        proxy_yaml("forward-mutual-proxy")
    );
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(
            &err,
            ExtractError::InvalidYaml(msg)
                if msg.contains("undefined YAML alias") || msg.contains("cycle")
        ),
        "got {err:?}"
    );
}

#[test]
fn anchored_scalar_title_survives_alias_reuse() {
    let yaml = format!(
        concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: &title Alias Scalar\n",
            "  version: '1.0.0'\n",
            "components:\n",
            "  schemas:\n",
            "    Shared:\n",
            "      type: string\n",
            "      default: *title\n",
            "{}",
        ),
        proxy_yaml("scalar-title-proxy")
    );
    let (bundle, meta) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(bundle.proxy.id, "scalar-title-proxy");
    assert_eq!(meta.title.as_deref(), Some("Alias Scalar"));
}

#[test]
fn alias_bomb_fails_closed_under_budgets() {
    let yaml = format!(
        concat!(
            "a: &a [1,2,3,4,5,6,7,8]\n",
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a]\n",
            "c: &c [*b,*b,*b,*b,*b,*b,*b,*b]\n",
            "d: &d [*c,*c,*c,*c,*c,*c,*c,*c]\n",
            "e: &e [*d,*d,*d,*d,*d,*d,*d,*d]\n",
            "f: &f [*e,*e,*e,*e,*e,*e,*e,*e]\n",
            "g: &g [*f,*f,*f,*f,*f,*f,*f,*f]\n",
            "openapi: '3.1.0'\n",
            "info: {{title: bomb, version: '1.0'}}\n",
            "{}",
        ),
        proxy_yaml("bomb-proxy")
    );
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(
            &err,
            ExtractError::InvalidYaml(msg)
                if msg.contains("limit") || msg.contains("exceeds")
        ),
        "got {err:?}"
    );
}

#[test]
fn control_character_string_escaping_cannot_bypass_byte_budget() {
    // Each U+0001 is 1 decoded byte but `\u0001` (6 bytes) in compact JSON.
    // 64 aliases × 100 KiB raw ≈ 6.25 MiB under a raw-length charge, but the
    // escaped representation exceeds the public 32 MiB expanded-byte ceiling.
    let chunk = "\\u0001".repeat(100_000);
    let aliases = std::iter::repeat_n("  - *s\n", 64).collect::<String>();
    let yaml = format!("s: &s \"{chunk}\"\nitems:\n{aliases}");
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(
            &err,
            ExtractError::InvalidYaml(msg) if msg.contains("expanded byte limit")
        ),
        "control-character string escaping must hit the expanded-byte budget, got {err:?}"
    );
    assert!(
        !format!("{err:?}").contains('\u{0001}'),
        "byte-budget diagnostics must not echo hostile scalar payloads"
    );
}

#[test]
fn escaped_mapping_key_cannot_bypass_byte_budget() {
    // Same inflation applied to mapping keys: alias reuse of an escape-heavy
    // key must charge JSON escaping, not decoded UTF-8 length alone. Unlike
    // control characters, escaped backslashes remain valid YAML mapping keys.
    let chunk = "\\\\".repeat(300_000);
    let aliases = std::iter::repeat_n("  - *e\n", 64).collect::<String>();
    let yaml = format!("e: &e\n  \"{chunk}\": 1\nitems:\n{aliases}");
    let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap_err();
    assert!(
        matches!(
            &err,
            ExtractError::InvalidYaml(msg) if msg.contains("expanded byte limit")
        ),
        "escaped key must hit the expanded-byte budget, got {err:?}"
    );
    assert!(
        format!("{err:?}").len() < 1_024,
        "byte-budget diagnostics must not echo hostile key material"
    );
}

#[test]
fn json_and_yaml_literal_parity_without_aliases() {
    let json = json!({
        "openapi": "3.1.0",
        "info": {"title": "Parity", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": "parity-proxy",
            "backend_host": "backend.internal",
            "backend_port": 443
        }
    });
    let yaml = concat!(
        "openapi: '3.1.0'\n",
        "info:\n",
        "  title: Parity\n",
        "  version: '1.0.0'\n",
        "x-ferrum-proxy:\n",
        "  id: parity-proxy\n",
        "  backend_host: backend.internal\n",
        "  backend_port: 443\n",
    );
    let (json_bundle, json_meta) = extract(
        serde_json::to_vec(&json).unwrap().as_slice(),
        Some(SpecFormat::Json),
        "prod",
    )
    .unwrap();
    let (yaml_bundle, yaml_meta) =
        extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
    assert_eq!(json_bundle.proxy.id, yaml_bundle.proxy.id);
    assert_eq!(json_meta.title, yaml_meta.title);
    assert_eq!(json_meta.version, yaml_meta.version);
}

#[test]
fn flow_style_autodetect_expands_aliases_under_same_budgets() {
    let yaml = "{openapi: '3.1.0', info: &info {title: flow, version: '1.0'}, \
                x-ferrum-proxy: {id: flow-proxy, backend_host: x.com, backend_port: 443}, \
                reused: *info}";
    let (bundle, meta) = extract(yaml.as_bytes(), None, "prod").unwrap();
    assert_eq!(bundle.proxy.id, "flow-proxy");
    assert_eq!(meta.title.as_deref(), Some("flow"));
}

#[test]
fn parser_storage_remains_stable_across_repeated_extracts() {
    for index in 0..64 {
        let yaml = format!(
            concat!(
                "openapi: '3.1.0'\n",
                "info:\n",
                "  title: Stable Parser\n",
                "  version: '1.0.0'\n",
                "{}",
            ),
            proxy_yaml(&format!("stable-parser-{index}"))
        );
        let (bundle, _) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
        assert_eq!(bundle.proxy.id, format!("stable-parser-{index}"));
    }
}

#[test]
fn malformed_documents_fail_without_reusing_parser_storage() {
    for malformed in [
        b"key: [unterminated".as_slice(),
        b"key:\n  child: value\n broken".as_slice(),
        b"'unterminated".as_slice(),
    ] {
        for _ in 0..16 {
            assert!(matches!(
                extract(malformed, Some(SpecFormat::Yaml), "prod"),
                Err(ExtractError::InvalidYaml(_))
            ));
        }
    }
}
