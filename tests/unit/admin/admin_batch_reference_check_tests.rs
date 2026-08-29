//! `POST /batch` reference-check error classification (issue #4377).
//!
//! A database `Err` during reference validation must short-circuit to 503
//! with `db_error_response`, never fold into the 400 `validation_errors`
//! payload. A genuine miss (`Ok(false)`) keeps the namespace-predicated
//! wording from issue #2122.

#[test]
fn batch_reference_check_db_errors_short_circuit_to_503() {
    let source = include_str!("../../../src/admin/mod.rs");
    let start = source
        .find("// ---- Batch Create ----")
        .expect("batch create section");
    let end = source[start..]
        .find("\n// ---- Backup & Restore ----")
        .expect("backup section follows batch")
        + start;
    let batch = &source[start..end];

    assert!(
        batch.contains("fn batch_reference_lookup"),
        "batch reference lookups must share one 503 mapper"
    );
    assert!(
        batch.contains("StatusCode::SERVICE_UNAVAILABLE"),
        "reference-check DB errors must use 503"
    );
    assert!(
        batch.contains("&db_error_response(&error)"),
        "reference-check DB errors must reuse db_error_response"
    );
    assert_eq!(
        batch.matches("match batch_reference_lookup(").count(),
        6,
        "prometheus uniqueness plus the five reference lookups must \
         short-circuit on the first DB error"
    );
    assert!(
        !batch.contains("reference check failed"),
        "DB reference-check failures must not be folded into validation_errors"
    );
    assert!(
        !batch.contains("uniqueness check failed"),
        "prometheus uniqueness DB errors must not be folded into validation_errors"
    );
}

#[test]
fn batch_missing_proxy_keeps_namespace_predicated_wording() {
    let source = include_str!("../../../src/admin/mod.rs");
    let start = source
        .find("// ---- Batch Create ----")
        .expect("batch create section");
    let end = source[start..]
        .find("\n// ---- Backup & Restore ----")
        .expect("backup section follows batch")
        + start;
    let batch = &source[start..end];

    assert!(
        batch.contains(
            "PluginConfig '{}' references proxy_id '{}' that does not exist in namespace '{}'"
        ),
        "genuine proxy misses must keep the issue #2122 wording"
    );
    assert!(
        batch.contains(
            "Proxy '{}' references upstream_id '{}' that does not exist in namespace '{}'"
        ),
        "genuine upstream misses must keep the issue #2122 wording"
    );
    assert!(
        batch.contains("Err(err) => validation_errors.push(err.to_string())"),
        "ValidationPipeline failures must remain client 400s"
    );
}
