use std::collections::BTreeMap;
use std::error::Error;

use ferrum_edge::util::deserialization::{
    REDACTED_SCALAR, from_json_str, from_json_value, from_yaml_str, from_yaml_value,
    sanitize_message,
};
use ferrum_edge::util::json_object::{
    deserialize_object, deserialize_object_vec, deserialize_optional_object,
    deserialize_optional_object_vec, from_json_object_slice,
};
use serde::Deserialize;

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
            "custom error: <redacted scalar>",
        ),
    ];
    for (raw, expected) in cases {
        let raw =
            format!("mesh.destination_rules[0].traffic_policy.tls: {raw} at line 9 column 14");
        let expected =
            format!("mesh.destination_rules[0].traffic_policy.tls: {expected} at line 9 column 14");
        let sanitized = sanitize_message(&raw);
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
        format!("custom error '{secret}'"),
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
fn long_scalars_have_bounded_diagnostic_work_and_output() {
    let secret = "escaped\\\"秘密'`".repeat(128 * 1024);
    let raw = format!(
        "mesh.workloads[0].ports[0].port: invalid type: string {secret:?}, \
         expected u16 at line 12 column 4"
    );
    let sanitized = sanitize_message(&raw);
    assert_eq!(
        sanitized,
        "mesh.workloads[0].ports[0].port: invalid type: string <redacted scalar>, \
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
fn diagnostic_wrappers_preserve_success_and_reject_trailing_documents() {
    let document: Document = from_json_str(r#"{"object":{"count":7}}"#).unwrap();
    assert_eq!(document.object["count"], 7);
    let document: Document = from_yaml_str("object:\n  count: 7\n").unwrap();
    assert_eq!(document.object["count"], 7);
    assert!(from_json_str::<Document>(r#"{"object":{}} {"object":{}}"#).is_err());
    assert!(from_yaml_str::<Document>("object: {}\n---\nobject: {}\n").is_err());
}

#[test]
fn object_helpers_sanitize_even_without_the_document_boundary() {
    for input in [
        r#""unregistered-secret""#,
        r#"{"count":"unregistered-secret"}"#,
    ] {
        let mut parser = serde_json::Deserializer::from_str(input);
        let error = deserialize_object::<_, BTreeMap<String, u32>>(&mut parser).unwrap_err();
        assert_safe_error(&error, "invalid type", true);
        let mut parser = serde_json::Deserializer::from_str(input);
        let error =
            deserialize_optional_object::<_, BTreeMap<String, u32>>(&mut parser).unwrap_err();
        assert_safe_error(&error, "invalid type", true);
        let parser = serde_yaml::Deserializer::from_str(input);
        let error = deserialize_object::<_, BTreeMap<String, u32>>(parser).unwrap_err();
        assert_safe_error(&error, "invalid type", true);
    }
    for input in [r#""unregistered-secret""#, r#"["unregistered-secret"]"#] {
        let mut parser = serde_json::Deserializer::from_str(input);
        let error = deserialize_object_vec::<_, BTreeMap<String, u32>>(&mut parser).unwrap_err();
        assert_safe_error(&error, "invalid type", true);
        let mut parser = serde_json::Deserializer::from_str(input);
        let error =
            deserialize_optional_object_vec::<_, BTreeMap<String, u32>>(&mut parser).unwrap_err();
        assert_safe_error(&error, "invalid type", true);
    }
}
