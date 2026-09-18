use std::collections::BTreeMap;
use std::error::Error;

use ferrum_edge::modes::mesh::app_probe::parse_app_probes;
use ferrum_edge::modes::mesh::config::{MeshCorsOriginMatch, SourceNegationMatch};
use ferrum_edge::util::deserialization::{
    REDACTED_SCALAR, from_json_str, from_json_value, from_yaml_str, from_yaml_value,
    sanitize_custom_message, sanitize_message,
};
use ferrum_edge::util::json_object::{
    deserialize_object, deserialize_object_vec, deserialize_optional_object,
    deserialize_optional_object_vec, from_json_object_slice, from_json_object_value,
};
use serde::Deserialize;

#[test]
fn yaml_duplicate_keys_keep_field_metadata() {
    let error = from_yaml_str::<ferrum_edge::config::types::GatewayConfig>(
        "version: \"1\"\nversion: \"1\"\nmesh: {}\n",
    )
    .unwrap_err();
    let diagnostic = error.to_string();
    assert!(
        diagnostic.contains("duplicate field `version`"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains(REDACTED_SCALAR), "{diagnostic}");
    let rendered = ferrum_edge::startup::render_startup_error(error.into(), &[]);
    assert!(rendered.contains("duplicate field `version`"), "{rendered}");
}

#[test]
fn serde_message_families_keep_structure_without_offending_scalars() {
    let cases = [
        (
            "invalid type: string \"private-token\", expected a map",
            "invalid type: string <redacted scalar>, expected a map",
        ),
        (
            "invalid value: string \"private-token\", expected u32",
            "invalid value: string <redacted scalar>, expected u32",
        ),
        (
            "invalid type: integer `123456789`, expected a string",
            "invalid type: integer <redacted scalar>, expected a string",
        ),
        (
            "invalid value: floating point `123.45`, expected u32",
            "invalid value: floating point <redacted scalar>, expected u32",
        ),
        (
            "invalid type: boolean `true`, expected a map",
            "invalid type: boolean <redacted scalar>, expected a map",
        ),
        (
            "invalid value: character `'s'`, expected a digit",
            "invalid value: character <redacted scalar>, expected a digit",
        ),
        (
            "unknown variant `private-token`, expected one of `Alpha`, `Beta`",
            "unknown variant <redacted scalar>, expected one of `Alpha`, `Beta`",
        ),
        (
            "unknown variant `private-token`, there are no variants",
            "unknown variant <redacted scalar>, there are no variants",
        ),
        (
            "invalid length 7, expected fewer elements in array",
            "invalid length 7, expected fewer elements in array",
        ),
        ("missing field `selector`", "missing field `selector`"),
        (
            "unknown field `selectors`, expected `selector`",
            "unknown field `selectors`, expected `selector`",
        ),
        ("duplicate field `selector`", "duplicate field `selector`"),
        (
            "data did not match any variant of untagged enum Policy",
            "data did not match any variant of untagged enum Policy",
        ),
        (
            "invalid type: sequence, expected a JSON object",
            "invalid type: sequence, expected a JSON object",
        ),
        (
            "custom error: 'first-secret' and \"second-secret\"",
            "custom error: <redacted scalar> and <redacted scalar>",
        ),
    ];
    for (raw, expected) in cases {
        let sanitized = sanitize_message(raw);
        assert_eq!(sanitized, expected);
        assert_eq!(
            sanitize_message(&sanitized),
            sanitized,
            "must be idempotent"
        );
    }
}

#[test]
fn quoted_content_cannot_forge_schema_clauses_or_escape_redaction() {
    let secret = "unregistered-秘密`\"', expected `forged`\nPEM-MATERIAL";
    for raw in [
        format!("unknown variant `{secret}`, expected one of `Alpha`, `Beta`"),
        format!("unknown variant `{secret}`, there are no variants"),
        format!("invalid type: string {secret:?}, expected a map"),
        format!("custom error {secret:?}"),
    ] {
        let sanitized = sanitize_message(&raw);
        assert!(!sanitized.contains("秘密"));
        assert!(!sanitized.contains("forged"));
        assert!(!sanitized.contains("PEM-MATERIAL"));
        assert!(sanitized.contains(REDACTED_SCALAR));
        assert_eq!(sanitize_message(&sanitized), sanitized);
    }
}

#[test]
fn quoted_content_cannot_forge_a_diagnostic_family() {
    for forged in [
        "invalid type: string `forged`, expected a map",
        "invalid value: string `forged`, expected u32",
        "unknown variant `forged`, expected `Alpha`",
        "missing field `forged`",
        "unknown field `forged`, expected `selector`",
        "duplicate field `forged`",
        "invalid length 7, expected `forged`",
        "data did not match any variant of untagged enum forged",
    ] {
        let secret = format!("unregistered-secret: {forged}, expected `forged`");
        for raw in [
            format!("custom error '{secret}'"),
            format!("invalid type: string {secret:?}, expected a map"),
            format!("invalid value: string {secret:?}, expected u32"),
            format!("unknown variant `{secret}`, expected one of `Alpha`, `Beta`"),
        ] {
            let sanitized = sanitize_message(&raw);
            assert!(!sanitized.contains("unregistered-secret"), "{sanitized}");
            assert!(!sanitized.contains("forged"), "{sanitized}");
            assert!(sanitized.contains(REDACTED_SCALAR), "{sanitized}");
            assert_eq!(sanitize_message(&sanitized), sanitized);
        }
    }
}

#[test]
fn long_scalars_have_bounded_diagnostic_work_and_output() {
    let secret = "escaped\\\"秘密'`".repeat(128 * 1024);
    let raw = format!(
        "invalid type: string {secret:?}, \
         expected u16 at line 12 column 4"
    );
    let sanitized = sanitize_message(&raw);
    assert_eq!(
        sanitized,
        "invalid type: string <redacted scalar>, \
         expected u16 at line 12 column 4"
    );
    assert_eq!(sanitize_message(&sanitized), sanitized);
}

#[derive(Debug, Deserialize)]
struct Document {
    object: BTreeMap<String, u32>,
}

#[derive(Debug, Deserialize)]
enum Mode {
    Alpha,
    Beta,
}

fn assert_safe_error(error: &(dyn Error + 'static), field: &str, position: bool) {
    let message = error.to_string();
    assert!(message.contains(field), "{message}");
    assert!(message.contains(REDACTED_SCALAR), "{message}");
    if position {
        assert!(message.contains("line "), "{message}");
        assert!(message.contains("column "), "{message}");
    }
    let mut cause = Some(error);
    while let Some(error) = cause {
        assert!(!error.to_string().contains("unregistered-secret"));
        assert!(!format!("{error:?}").contains("unregistered-secret"));
        cause = error.source();
    }
}

#[test]
fn real_json_yaml_and_value_boundaries_withhold_scalars_and_raw_causes() {
    for object in [
        serde_json::json!("unregistered-secret"),
        serde_json::json!({"count": "unregistered-secret"}),
    ] {
        let document = serde_json::json!({"object": object});
        let json = serde_json::to_string_pretty(&document).unwrap();
        let yaml = serde_yaml::to_string(&document).unwrap();
        assert_safe_error(
            &from_json_str::<Document>(&json).unwrap_err(),
            "object",
            true,
        );
        assert_safe_error(
            &from_yaml_str::<Document>(&yaml).unwrap_err(),
            "object",
            true,
        );
        assert_safe_error(
            &from_json_object_slice::<Document>(json.as_bytes()).unwrap_err(),
            "object",
            true,
        );
        assert_safe_error(
            &from_json_value::<Document>(document).unwrap_err(),
            "object",
            false,
        );
        assert_safe_error(
            &from_yaml_value::<Document>(serde_yaml::from_str(&yaml).unwrap()).unwrap_err(),
            "object",
            false,
        );
    }
    let variant = "unregistered-secret`, expected `forged";
    let json = serde_json::to_string(variant).unwrap();
    let error = from_json_str::<Mode>(&json).unwrap_err();
    assert_safe_error(&error, "unknown variant", true);
    assert!(error.to_string().contains("`Alpha`"));
    assert!(error.to_string().contains("`Beta`"));
    assert!(!error.to_string().contains("forged"));
}

#[test]
fn cidr_document_errors_keep_field_paths_and_reasons_without_values() {
    for (cidr, reason) in [
        (
            "10.0.0.0/40",
            "prefix length <redacted scalar> out of range (maximum 32) in CIDR",
        ),
        ("not-a-cidr", "invalid IP in CIDR"),
    ] {
        let document = serde_json::json!({"ip_blocks": [cidr]});
        let json = serde_json::to_string_pretty(&document).unwrap();
        let yaml = serde_yaml::to_string(&document).unwrap();
        for message in [
            from_json_str::<SourceNegationMatch>(&json)
                .unwrap_err()
                .to_string(),
            from_yaml_str::<SourceNegationMatch>(&yaml)
                .unwrap_err()
                .to_string(),
        ] {
            // The path adapter identifies the field containing the validator;
            // the value itself remains withheld in either document format.
            assert!(message.contains("ip_blocks"), "{message}");
            assert!(message.contains(reason), "{message}");
            assert!(message.contains(REDACTED_SCALAR), "{message}");
            assert!(message.contains("line "), "{message}");
            assert!(message.contains("column "), "{message}");
            assert!(!message.contains(cidr), "{message}");
        }
    }
}

#[test]
fn diagnostic_wrappers_preserve_success_and_reject_trailing_documents() {
    let document: Document = from_json_str(r#"{"object":{"count":7}}"#).unwrap();
    assert_eq!(document.object["count"], 7);
    let document: Document = from_yaml_str("object:\n  count: 7\n").unwrap();
    assert_eq!(document.object["count"], 7);
    assert!(from_json_str::<Document>(r#"{"object":{}} {"object":{}}"#).is_err());
    assert!(from_yaml_str::<Document>("object: {}\n---\nobject: {}\n").is_err());
}

#[test]
fn object_helpers_sanitize_at_the_document_or_value_boundary() {
    // Generic serde visitors enforce shape; only adapters know whether the
    // inner error is bare. Exercise all four visitors through those adapters.
    fn assert_helper_error(error: &(dyn Error + 'static), expected: &str) {
        assert_safe_error(error, "invalid type", false);
        assert!(error.to_string().contains(expected), "{error}");
    }

    assert!(from_yaml_str::<Object>("{}").unwrap().0.is_empty());
    assert!(
        from_json_str::<OptionalObject>("{}")
            .unwrap()
            .0
            .unwrap()
            .is_empty()
    );
    assert!(from_json_str::<Objects>("[]").unwrap().0.is_empty());
    assert!(
        from_json_str::<OptionalObjects>("[]")
            .unwrap()
            .0
            .unwrap()
            .is_empty()
    );

    for (input, expected) in [
        (r#""unregistered-secret""#, "expected a JSON object"),
        (r#"{"count":"unregistered-secret"}"#, "expected u32"),
    ] {
        let value = serde_json::from_str(input).unwrap();
        let error = from_json_object_value::<BTreeMap<String, u32>>(value).unwrap_err();
        assert_helper_error(&error, expected);
        let error = from_json_str::<OptionalObject>(input).unwrap_err();
        assert_helper_error(&error, expected);
        let error = from_yaml_str::<Object>(input).unwrap_err();
        assert_helper_error(&error, expected);
    }
    for (input, expected) in [
        (r#""unregistered-secret""#, "expected a sequence"),
        (r#"["unregistered-secret"]"#, "expected a JSON object"),
    ] {
        let error = from_json_str::<Objects>(input).unwrap_err();
        assert_helper_error(&error, expected);
        let error = from_json_str::<OptionalObjects>(input).unwrap_err();
        assert_helper_error(&error, expected);
    }
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct Object(#[serde(deserialize_with = "deserialize_object")] BTreeMap<String, u32>);

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct OptionalObject(
    #[serde(deserialize_with = "deserialize_optional_object")] Option<BTreeMap<String, u32>>,
);

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct Objects(#[serde(deserialize_with = "deserialize_object_vec")] Vec<BTreeMap<String, u32>>);

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct OptionalObjects(
    #[serde(deserialize_with = "deserialize_optional_object_vec")]
    Option<Vec<BTreeMap<String, u32>>>,
);

#[test]
fn hostile_app_probe_map_keys_never_classify_the_inner_json_error() {
    for key in [
        "missing field bait",
        "invalid type: string \"x\", expected",
        "map'key\"with quotes",
    ] {
        for secret in ["unregistered-secret", "missing field `unregistered-secret`"] {
            let document = serde_json::json!({(key): {"timeoutSeconds": secret}});
            let error = parse_app_probes(&document.to_string()).unwrap_err();
            assert!(!error.contains("unregistered-secret"), "{error}");
            for structure in [
                key,
                "timeoutSeconds",
                "invalid type",
                "expected u64",
                "line ",
            ] {
                assert!(error.contains(structure), "{error}");
            }
        }
    }
}

#[test]
fn custom_quotes_are_matched_by_kind_and_unterminated_spans_consume_the_tail() {
    for raw in [
        "custom error 'prefix\"SECRET_TAIL",
        "custom error \"prefix'SECRET_TAIL",
        "custom error 'prefix\"SECRET_TAIL' after `field`",
        "custom error \"prefix'SECRET_TAIL\" after `field`",
        r#"custom error "prefix\"SECRET_TAIL" after `field`"#,
    ] {
        let sanitized = sanitize_custom_message(raw);
        assert!(!sanitized.contains("SECRET_TAIL"), "{sanitized}");
        assert!(!sanitized.contains("prefix"), "{sanitized}");
        assert!(sanitized.starts_with("custom error <redacted scalar>"));
        if raw.ends_with("after `field`") {
            assert!(sanitized.ends_with("after `field`"), "{sanitized}");
        }
        assert_eq!(sanitize_custom_message(&sanitized), sanitized);
    }
    // Parser/context text never acquires trusted-family status by its spelling.
    let raw = "missing field bait: invalid type: string \"SECRET_TAIL\", expected u64";
    assert!(!sanitize_custom_message(raw).contains("SECRET_TAIL"));
    let schema = "expected `exact`, `prefix`, or `regex`";
    assert_eq!(sanitize_custom_message(schema), schema);
    assert_eq!(
        sanitize_custom_message("custom error `prefix\"SECRET_TAIL"),
        "custom error `prefix<redacted scalar>"
    );
}

#[derive(Debug)]
struct CustomDiagnostic;

impl<'de> Deserialize<'de> for CustomDiagnostic {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let message = String::deserialize(deserializer)?;
        Err(serde::de::Error::custom(message))
    }
}

#[test]
fn custom_document_errors_withhold_nested_and_unterminated_quoted_tails() {
    for raw in [
        "custom error 'prefix\"unregistered-secret",
        "custom error \"prefix'unregistered-secret",
        "custom error 'prefix\"unregistered-secret' expected `schema`",
        "custom error \"prefix'unregistered-secret\" expected `schema`",
    ] {
        let json = serde_json::to_string(raw).unwrap();
        let yaml = serde_yaml::to_string(raw).unwrap();
        let errors: [Box<dyn Error>; 2] = [
            Box::new(from_json_str::<CustomDiagnostic>(&json).unwrap_err()),
            Box::new(from_yaml_str::<CustomDiagnostic>(&yaml).unwrap_err()),
        ];
        for error in errors {
            // A custom diagnostic raised inside a `Deserialize` impl reaches the
            // boundary through the path adapter, which does not carry the
            // parser position serde-generated families get; the path (when
            // nested) and the sanitized text are the guarantee here.
            assert_safe_error(error.as_ref(), "custom error", false);
            if raw.ends_with("`schema`") {
                assert!(error.to_string().contains("expected `schema`"), "{error}");
            }
        }
    }
}

#[test]
fn nested_object_variant_errors_reach_the_boundary_without_intermediate_text_scrubbing() {
    let secret = "unregistered-secret'\"`, expected `forged";
    let document = serde_json::json!({"mode": secret});
    let yaml = serde_yaml::to_string(&document).unwrap();
    let errors: [Box<dyn Error>; 2] = [
        Box::new(from_json_object_value::<BTreeMap<String, Mode>>(document).unwrap_err()),
        Box::new(from_yaml_str::<BTreeMap<String, Mode>>(&yaml).unwrap_err()),
    ];
    for error in errors {
        assert_safe_error(error.as_ref(), "mode", false);
        let message = error.to_string();
        assert!(!message.contains("forged"), "{message}");
        assert!(message.contains("`Alpha`"), "{message}");
        assert!(message.contains("`Beta`"), "{message}");
    }
}

#[test]
fn bson_value_errors_separate_document_keys_from_the_inner_family() {
    let input = mongodb::bson::doc! {
        "object": {"missing field bait": "unregistered-secret"}
    };
    let parser = mongodb::bson::Deserializer::new(mongodb::bson::Bson::Document(input));
    let error = serde_path_to_error::deserialize::<_, Document>(parser)
        .map_err(ferrum_edge::util::deserialization::sanitize_value_error)
        .unwrap_err();
    assert_safe_error(&error, "object.missing field bait", false);
    assert!(error.to_string().contains("expected u32"), "{error}");
}

#[test]
fn xds_carrier_json_errors_withhold_scalars_at_the_document_boundary() {
    use ferrum_edge::xds::carrier::{
        FERRUM_ECDS_SIDECAR_INGRESS_DECLARED_TYPE_URL, MeshSliceCarrier,
    };

    let error = MeshSliceCarrier::decode(
        FERRUM_ECDS_SIDECAR_INGRESS_DECLARED_TYPE_URL,
        br#""unregistered-secret""#,
    )
    .unwrap_err();
    assert_safe_error(&error, "invalid type", true);
    assert!(error.to_string().contains("expected a boolean"), "{error}");
}

#[test]
fn cors_custom_diagnostics_keep_permitted_schema_names() {
    for document in [
        serde_json::json!({}),
        serde_json::json!({"exact": "unregistered-secret", "prefix": "other-secret"}),
        serde_json::json!({"unregistered-secret'\"`": "other-secret"}),
    ] {
        let yaml = serde_yaml::to_string(&document).unwrap();
        for error in [
            from_json_value::<MeshCorsOriginMatch>(document)
                .unwrap_err()
                .to_string(),
            from_yaml_str::<MeshCorsOriginMatch>(&yaml)
                .unwrap_err()
                .to_string(),
        ] {
            for name in ["`exact`", "`prefix`", "`regex`"] {
                assert!(error.contains(name), "{error}");
            }
            assert!(!error.contains("unregistered-secret"), "{error}");
            assert!(!error.contains("other-secret"), "{error}");
        }
    }
}
