//! Unit coverage for the first-class namespace registry helpers (issue #3955).

use ferrum_edge::config::namespace_registry::{
    CreateNamespaceRequest, UpdateNamespaceBody, normalize_description, process_default_namespace,
    validate_namespace_name, MAX_NAMESPACE_DESCRIPTION_LENGTH,
};
use ferrum_edge::config::types::DEFAULT_NAMESPACE;

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
fn normalize_description_trims_and_caps() {
    assert_eq!(normalize_description(None).unwrap(), None);
    assert_eq!(normalize_description(Some("  ".into())).unwrap(), None);
    assert_eq!(
        normalize_description(Some("  staging  ".into())).unwrap(),
        Some("staging".into())
    );
    let too_long = "x".repeat(MAX_NAMESPACE_DESCRIPTION_LENGTH + 1);
    assert!(normalize_description(Some(too_long)).is_err());
}

#[test]
fn update_body_distinguishes_omit_from_clear() {
    let omitted: UpdateNamespaceBody = serde_json::from_str(r#"{"name":"prod"}"#).unwrap();
    assert_eq!(omitted.description_update(), None);

    let cleared: UpdateNamespaceBody = serde_json::from_str(r#"{"description":null}"#).unwrap();
    assert_eq!(cleared.description_update(), Some(None));

    let empty: UpdateNamespaceBody = serde_json::from_str(r#"{"description":"  "}"#).unwrap();
    assert_eq!(empty.description_update(), Some(None));

    let set: UpdateNamespaceBody = serde_json::from_str(r#"{"description":" live "}"#).unwrap();
    assert_eq!(set.description_update(), Some(Some("live".into())));
}

#[test]
fn create_request_deserializes_optional_description() {
    let req: CreateNamespaceRequest = serde_json::from_str(r#"{"name":"tenant-a"}"#).unwrap();
    assert_eq!(req.name, "tenant-a");
    assert!(req.description.is_none());
}

#[test]
fn process_default_namespace_falls_back_to_ferrum() {
    // Tests must not depend on a caller-set FERRUM_NAMESPACE; the helper
    // still returns a non-empty validated default when the env is unset.
    let name = process_default_namespace();
    assert!(!name.is_empty());
    if std::env::var("FERRUM_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .is_none()
    {
        assert_eq!(name, DEFAULT_NAMESPACE);
    }
}
