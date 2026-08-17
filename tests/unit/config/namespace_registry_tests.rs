//! Unit coverage for the first-class namespace registry helpers (issue #3955).

use ferrum_edge::config::namespace_registry::{
    CreateNamespaceRequest, MAX_NAMESPACE_DESCRIPTION_CHARS, NAMESPACE_REGISTRY_ADMISSION_KEY,
    UpdateNamespaceBody, normalize_description, validate_namespace_name,
};

#[test]
fn validate_namespace_name_matches_header_rules() {
    assert!(validate_namespace_name("ferrum").is_ok());
    assert!(validate_namespace_name("prod-1.staging_ns").is_ok());
    assert!(validate_namespace_name("-leading-hyphen").is_err());
    assert!(validate_namespace_name("has space").is_err());
    assert!(validate_namespace_name("").is_err());
    let too_long = "a".repeat(255);
    assert!(validate_namespace_name(&too_long).is_err());
}

#[test]
fn registry_admission_key_can_never_be_a_real_namespace() {
    // The whole cross-process serialization scheme rests on this: the global
    // registry lease must not be takeable by a tenant's own admission row.
    assert!(
        validate_namespace_name(NAMESPACE_REGISTRY_ADMISSION_KEY).is_err(),
        "the global registry admission key must be an invalid namespace name"
    );
}

#[test]
fn normalize_description_trims_and_caps_by_characters() {
    assert_eq!(normalize_description(None).unwrap(), None);
    assert_eq!(normalize_description(Some("  ".into())).unwrap(), None);
    assert_eq!(
        normalize_description(Some("  staging  ".into())).unwrap(),
        Some("staging".into())
    );

    let at_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        normalize_description(Some(at_limit.clone())).unwrap(),
        Some(at_limit)
    );
    let too_long = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    assert!(normalize_description(Some(too_long)).is_err());
}

#[test]
fn normalize_description_limit_counts_characters_not_bytes() {
    // OpenAPI `maxLength` is Unicode scalar values. A 4-byte-per-character
    // description at exactly the limit must be accepted, and one character over
    // must be rejected — a byte-length check would reject both.
    let at_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(at_limit.chars().count(), MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert!(at_limit.len() > MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        normalize_description(Some(at_limit.clone())).unwrap(),
        Some(at_limit)
    );

    let over_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    assert!(normalize_description(Some(over_limit)).is_err());

    // Combining sequences count per scalar value, consistently with the schema.
    let accented: String = "é".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert!(normalize_description(Some(accented)).is_ok());
}

fn parse_update(json: &str) -> UpdateNamespaceBody {
    serde_json::from_str(json).expect("update body deserializes")
}

#[test]
fn update_body_distinguishes_omit_from_clear() {
    let omitted = parse_update(r#"{"name":"prod"}"#).resolve().unwrap();
    assert_eq!(omitted.name.as_deref(), Some("prod"));
    assert_eq!(omitted.description, None);

    let cleared = parse_update(r#"{"description":null}"#).resolve().unwrap();
    assert_eq!(cleared.name, None);
    assert_eq!(cleared.description, Some(None));

    let empty = parse_update(r#"{"description":"  "}"#).resolve().unwrap();
    assert_eq!(empty.description, Some(None));

    let set = parse_update(r#"{"description":" live "}"#).resolve().unwrap();
    assert_eq!(set.description, Some(Some("live".into())));

    let nothing = parse_update("{}").resolve().unwrap();
    assert_eq!(nothing.name, None);
    assert_eq!(nothing.description, None);
}

#[test]
fn update_body_rejects_every_wrong_field_type() {
    // A wrong-typed `description` must NOT be interpreted as a clear: silently
    // erasing an operator's description on a malformed request is exactly the
    // fail-open behaviour this resolver exists to remove.
    for body in [
        r#"{"description":{}}"#,
        r#"{"description":[]}"#,
        r#"{"description":42}"#,
        r#"{"description":true}"#,
    ] {
        let error = parse_update(body)
            .resolve()
            .expect_err("wrong-typed description must be rejected");
        assert!(
            error.contains("description"),
            "error should name the field: {error}"
        );
    }

    // The schema permits `name` only as a string when present.
    for body in [
        r#"{"name":null}"#,
        r#"{"name":7}"#,
        r#"{"name":["a"]}"#,
        r#"{"name":{"value":"a"}}"#,
    ] {
        let error = parse_update(body)
            .resolve()
            .expect_err("wrong-typed name must be rejected");
        assert!(
            error.contains("name"),
            "error should name the field: {error}"
        );
    }
}

#[test]
fn update_body_validates_the_new_name_and_description_bounds() {
    assert!(parse_update(r#"{"name":"bad name"}"#).resolve().is_err());
    assert!(parse_update(r#"{"name":"-leading"}"#).resolve().is_err());
    assert!(parse_update(r#"{"name":""}"#).resolve().is_err());

    let over_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let body = serde_json::json!({ "description": over_limit }).to_string();
    let error = parse_update(&body)
        .resolve()
        .expect_err("over-limit description must be rejected");
    assert!(error.contains("characters"), "{error}");
}

#[test]
fn create_request_deserializes_optional_description() {
    let req: CreateNamespaceRequest = serde_json::from_str(r#"{"name":"tenant-a"}"#).unwrap();
    assert_eq!(req.name, "tenant-a");
    assert!(req.description.is_none());

    let explicit_null: CreateNamespaceRequest =
        serde_json::from_str(r#"{"name":"tenant-a","description":null}"#).unwrap();
    assert!(explicit_null.description.is_none());

    // A wrong-typed description fails deserialization, so the handler answers
    // 400 before reaching persistence.
    assert!(
        serde_json::from_str::<CreateNamespaceRequest>(r#"{"name":"tenant-a","description":5}"#)
            .is_err()
    );
}
