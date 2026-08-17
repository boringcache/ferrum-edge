//! Unit coverage for the first-class namespace registry helpers (issue #3955).

use ferrum_edge::config::namespace_registry::{
    CreateNamespaceRequest, MAX_NAMESPACE_DESCRIPTION_CHARS, NAMESPACE_OCCUPANCY_TABLES,
    NAMESPACE_REGISTRY_ADMISSION_KEY, NAMESPACE_RENAME_SIMPLE_TABLES, NamespaceRegistryCorrupt,
    UpdateNamespaceBody, mtls_dns_admission_namespaces, namespace_prefixed_id_suffix_field,
    normalize_description, parse_namespace_rfc3339, require_canonical_stored_description,
    require_namespace_identity, require_namespace_keyed_embedded_namespace,
    require_namespace_prefixed_identity, validate_namespace_name,
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

    let set = parse_update(r#"{"description":" live "}"#)
        .resolve()
        .unwrap();
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

#[test]
fn update_body_serde_preserves_present_null_versus_omission() {
    // The whole PUT contract rests on this: serde's Option<T> would map a
    // present JSON null to None, collapsing `{"description":null}` into
    // omission. The presence-aware field deserializer must keep Null.
    let omitted: UpdateNamespaceBody = serde_json::from_str("{}").unwrap();
    assert!(omitted.name.is_none());
    assert!(omitted.description.is_none());

    let name_null: UpdateNamespaceBody = serde_json::from_str(r#"{"name":null}"#).unwrap();
    assert_eq!(name_null.name, Some(serde_json::Value::Null));
    assert!(name_null.resolve().is_err());

    let desc_null: UpdateNamespaceBody = serde_json::from_str(r#"{"description":null}"#).unwrap();
    assert_eq!(desc_null.description, Some(serde_json::Value::Null));
    assert_eq!(desc_null.resolve().unwrap().description, Some(None));

    assert!(serde_json::from_str::<UpdateNamespaceBody>("").is_err());
    assert!(serde_json::from_str::<UpdateNamespaceBody>("null").is_err());
    assert!(serde_json::from_str::<UpdateNamespaceBody>("[]").is_err());
    assert!(serde_json::from_str::<UpdateNamespaceBody>("42").is_err());
}

#[test]
fn mtls_dns_admission_namespaces_are_sorted_and_deduplicated() {
    assert_eq!(
        mtls_dns_admission_namespaces("staging", "staging"),
        vec!["staging"]
    );
    assert_eq!(
        mtls_dns_admission_namespaces("zeta", "alpha"),
        vec!["alpha", "zeta"],
        "rename must lock the alphabetically first name first so SQL row locks \
         and Mongo multi-lease acquisition cannot deadlock"
    );
    assert_eq!(
        mtls_dns_admission_namespaces("alpha", "zeta"),
        vec!["alpha", "zeta"]
    );
}

#[test]
fn durable_namespace_identity_and_timestamps_fail_closed() {
    assert!(require_namespace_identity("a", "a", Some("a")).is_ok());
    assert!(require_namespace_identity("a", "b", None).is_err());
    assert!(require_namespace_identity("a", "a", Some("b")).is_err());
    assert!(require_namespace_identity("", "a", None).is_err());

    let ts = "2026-01-02T03:04:05Z";
    assert!(parse_namespace_rfc3339(ts, "created_at").is_ok());
    let err = parse_namespace_rfc3339("not-a-timestamp", "created_at").unwrap_err();
    assert!(!err.to_string().contains("not-a-timestamp"));
    assert!(err.to_string().contains(NamespaceRegistryCorrupt::MESSAGE));
    assert!(err.to_string().contains("created_at"));
}

#[test]
fn require_namespace_identity_rejects_invalid_stored_grammar() {
    assert!(require_namespace_identity("ferrum", "ferrum", None).is_ok());
    assert!(require_namespace_identity("prod-1.staging_ns", "prod-1.staging_ns", None).is_ok());
    let at_limit = "a".repeat(254);
    assert!(require_namespace_identity(&at_limit, &at_limit, None).is_ok());

    let too_long = "a".repeat(255);
    for invalid in ["has space", "-leading-hyphen", too_long.as_str()] {
        let err = require_namespace_identity(invalid, invalid, None)
            .expect_err("illegal durable names must fail closed even when _id equals name");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(text.contains("name"), "{text}");
        assert!(
            !text.contains(invalid) && !text.contains("alphanumeric"),
            "stored value and validator text must not leak: {text}"
        );
        let err = require_namespace_identity(invalid, invalid, Some(invalid))
            .expect_err("an expected-name match must not bypass grammar");
        assert!(
            !err.to_string().contains(invalid),
            "stored value must not leak: {err}"
        );
    }
}

#[test]
fn require_canonical_stored_description_rejects_noncanonical_strings() {
    assert_eq!(require_canonical_stored_description(None).unwrap(), None);
    assert_eq!(
        require_canonical_stored_description(Some("staging")).unwrap(),
        Some("staging".into())
    );

    let at_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        require_canonical_stored_description(Some(&at_limit)).unwrap(),
        Some(at_limit)
    );
    let at_limit_multibyte: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        at_limit_multibyte.chars().count(),
        MAX_NAMESPACE_DESCRIPTION_CHARS
    );
    assert!(at_limit_multibyte.len() > MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        require_canonical_stored_description(Some(&at_limit_multibyte)).unwrap(),
        Some(at_limit_multibyte)
    );

    let over_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let over_limit_multibyte = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    for noncanonical in [
        "",
        "  ",
        "\tstaging",
        "staging  ",
        "  staging  ",
        over_limit.as_str(),
        over_limit_multibyte.as_str(),
    ] {
        let err = require_canonical_stored_description(Some(noncanonical))
            .expect_err("noncanonical durable descriptions must not be served");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(text.contains("description"), "{text}");
        assert!(
            (noncanonical.is_empty() || !text.contains(noncanonical))
                && !text.contains("staging")
                && !text.contains("🧪"),
            "stored description must not leak: {text}"
        );
    }
}

#[test]
fn require_namespace_prefixed_identity_requires_suffix_field_and_embedded_namespace() {
    assert_eq!(
        namespace_prefixed_id_suffix_field("consumers").unwrap(),
        "id"
    );
    assert_eq!(
        namespace_prefixed_id_suffix_field("consumer_identity_index").unwrap(),
        "identity_value"
    );
    assert!(namespace_prefixed_id_suffix_field("gateway_trust_bundles").is_err());
    assert!(namespace_prefixed_id_suffix_field("proxies").is_err());

    assert_eq!(
        require_namespace_prefixed_identity("ns", "ns:alice", Some("ns"), "id", Some("alice"))
            .unwrap(),
        "alice"
    );
    assert_eq!(
        require_namespace_prefixed_identity(
            "ns",
            "ns:alice@ex",
            Some("ns"),
            "identity_value",
            Some("alice@ex"),
        )
        .unwrap(),
        "alice@ex"
    );

    let mismatch_id = require_namespace_prefixed_identity(
        "secret-ns",
        "secret-ns:secret-id",
        Some("secret-ns"),
        "id",
        Some("other-id"),
    )
    .unwrap_err();
    let mismatch_id_text = mismatch_id.to_string();
    assert!(
        mismatch_id_text.contains(NamespaceRegistryCorrupt::MESSAGE)
            && mismatch_id_text.contains("id")
            && !mismatch_id_text.contains("secret"),
        "{mismatch_id_text}"
    );

    let mismatch_identity = require_namespace_prefixed_identity(
        "secret-ns",
        "secret-ns:secret-id",
        Some("secret-ns"),
        "identity_value",
        Some("other"),
    )
    .unwrap_err();
    let mismatch_identity_text = mismatch_identity.to_string();
    assert!(
        mismatch_identity_text.contains("identity_value")
            && !mismatch_identity_text.contains("secret"),
        "{mismatch_identity_text}"
    );

    for (old_id, embedded, suffix) in [
        ("secret-ns:secret-id", None, Some("secret-id")),
        ("secret-ns:secret-id", Some(""), Some("secret-id")),
        ("secret-ns:secret-id", Some("other-ns"), Some("secret-id")),
        ("secret-ns:secret-id", Some("secret-ns"), None),
        ("secret-ns:secret-id", Some("secret-ns"), Some("")),
        ("secret-ns:", Some("secret-ns"), Some("secret-id")),
        ("secret-id", Some("secret-ns"), Some("secret-id")),
        ("other-ns:secret-id", Some("secret-ns"), Some("secret-id")),
    ] {
        let err = require_namespace_prefixed_identity("secret-ns", old_id, embedded, "id", suffix)
            .expect_err("corrupt composite identities must abort");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(
            !text.contains("secret") && !text.contains(old_id),
            "stored identity must not leak: {text}"
        );
    }
}

#[test]
fn require_namespace_keyed_embedded_namespace_is_strict() {
    assert!(require_namespace_keyed_embedded_namespace("ns", Some("ns")).is_ok());
    for embedded in [None, Some(""), Some("other")] {
        let err = require_namespace_keyed_embedded_namespace("secret-ns", embedded)
            .expect_err("keyed documents must not move with a mismatched namespace");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(text.contains("namespace"), "{text}");
        assert!(
            !text.contains("secret")
                && !embedded.is_some_and(|value| !value.is_empty() && text.contains(value)),
            "stored namespace must not leak: {text}"
        );
    }
}

#[test]
fn namespace_rename_simple_tables_cover_live_resources_and_exclude_audit_history() {
    // In-place SQL rename rewrites live resource rows. Historical audit
    // evidence is immutable and must keep the namespace recorded at event time.
    assert_eq!(
        NAMESPACE_RENAME_SIMPLE_TABLES,
        &["proxies", "plugin_configs", "upstreams", "api_specs"]
    );
    assert!(
        !NAMESPACE_RENAME_SIMPLE_TABLES.contains(&"audit_events"),
        "audit_events must not be rewritten on rename"
    );
    for live in ["proxies", "plugin_configs", "upstreams", "api_specs"] {
        assert!(
            NAMESPACE_RENAME_SIMPLE_TABLES.contains(&live),
            "{live} must still move with the tenant"
        );
    }
    // Occupancy still treats API specs as live tenant metadata, and still
    // excludes audit history so leftover events cannot block DELETE.
    assert!(NAMESPACE_OCCUPANCY_TABLES.contains(&"api_specs"));
    assert!(!NAMESPACE_OCCUPANCY_TABLES.contains(&"audit_events"));
}
