//! Coverage for the externally-resolved-value redaction contract.
//!
//! `secrets::record_external_secret_keys()` is a one-shot `OnceLock` for the
//! process, and the derived candidate set it feeds is built once and cached, so
//! **this file owns the single recording for the `unit_tests` binary**. Every
//! assertion that depends on redaction being armed lives here, and the recorded
//! keys all use a `FERRUM_REDACTION_FIXTURE_*` prefix that no real setting uses,
//! so no other test's diagnostics are affected.

use ferrum_edge::secrets::{
    EXTERNAL_SECRET_PLACEHOLDER, is_external_secret_key, record_external_secret_keys,
    redact_external_secret_values,
};
use std::sync::Once;

/// A value echoed verbatim by a hand-written validator.
const PLAIN_KEY: &str = "FERRUM_REDACTION_FIXTURE_PLAIN";
const PLAIN_VALUE: &str = "plain-resolved-secret-sentinel";

/// A value whose meaningful content survives `trim()` — the shape
/// `FERRUM_CP_NAMESPACES` produces, where `Vec<String>` parsing trims each entry
/// before `EnvConfig::validate()` echoes the *entry*, not the variable.
const LIST_KEY: &str = "FERRUM_REDACTION_FIXTURE_LIST";
const LIST_VALUE: &str = "  first-entry-sentinel , second-entry-sentinel  ";

/// A value a validator re-renders uppercased, the shape
/// `FERRUM_TLS_EARLY_DATA_METHODS` produces.
const CASE_KEY: &str = "FERRUM_REDACTION_FIXTURE_CASE";
const CASE_VALUE: &str = "lowercase-method-sentinel";

/// A value that is escaped by the JSON fmt layer before it reaches the sink.
const QUOTED_KEY: &str = "FERRUM_REDACTION_FIXTURE_QUOTED";
const QUOTED_VALUE: &str = r#"quoted"secret\sentinel"#;

static RECORDED: Once = Once::new();

fn arm_redaction() {
    RECORDED.call_once(|| {
        for (key, value) in [
            (PLAIN_KEY, PLAIN_VALUE),
            (LIST_KEY, LIST_VALUE),
            (CASE_KEY, CASE_VALUE),
            (QUOTED_KEY, QUOTED_VALUE),
        ] {
            // SAFETY: `Once` serializes this, it runs before any thread reads
            // these names, and the names are fixture-only.
            unsafe { std::env::set_var(key, value) };
        }
        record_external_secret_keys(
            [PLAIN_KEY, LIST_KEY, CASE_KEY, QUOTED_KEY]
                .into_iter()
                .map(str::to_string),
        );
    });
}

#[test]
fn records_only_the_named_keys() {
    arm_redaction();
    assert!(is_external_secret_key(PLAIN_KEY));
    assert!(
        !is_external_secret_key("FERRUM_ADMIN_JWT_SECRET"),
        "a variable that was not externally resolved must keep normal diagnostics"
    );
}

#[test]
fn redacts_the_value_exactly_as_materialized() {
    arm_redaction();
    let redacted =
        redact_external_secret_values(&format!("Invalid {PLAIN_KEY} value '{PLAIN_VALUE}'"));
    assert!(
        !redacted.contains(PLAIN_VALUE),
        "the resolved value must not survive: {redacted}"
    );
    // The variable name stays; withholding it too would make the diagnostic
    // unactionable, and it is not secret.
    assert!(redacted.contains(PLAIN_KEY) && redacted.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// Exact-value matching alone is insufficient: `Vec<String>` parsing trims each
/// entry, so the diagnostic contains a substring of the resolved value rather
/// than the value.
#[test]
fn redacts_trimmed_list_entries_a_validator_echoes() {
    arm_redaction();
    let redacted = redact_external_secret_values(
        "Invalid FERRUM_CP_NAMESPACES entry 'first-entry-sentinel': must be a valid label",
    );
    assert!(
        !redacted.contains("first-entry-sentinel"),
        "a trimmed entry of a resolved list must not survive: {redacted}"
    );
    assert!(redacted.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// The `FERRUM_TLS_EARLY_DATA_METHODS` warning uppercases the entry before
/// interpolating it, so the emitted text shares no substring with the value.
#[test]
fn redacts_case_normalized_values() {
    arm_redaction();
    let upper = CASE_VALUE.to_ascii_uppercase();
    let redacted = redact_external_secret_values(&format!(
        "FERRUM_TLS_EARLY_DATA_METHODS includes non-GET method '{upper}'"
    ));
    assert!(
        !redacted.contains(&upper),
        "a case-normalized resolved value must not survive: {redacted}"
    );
}

/// Log records are JSON, so the sink sees the escaped form.
#[test]
fn redacts_json_escaped_values() {
    arm_redaction();
    let escaped = serde_json::to_string(QUOTED_VALUE).expect("encodable");
    let record = format!(r#"{{"level":"WARN","message":{escaped}}}"#);
    let redacted = redact_external_secret_values(&record);
    assert!(
        !redacted.contains(r#"quoted\"secret\\sentinel"#),
        "the JSON-escaped form of a resolved value must not survive: {redacted}"
    );
    assert!(redacted.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// Unrelated text must survive, or every diagnostic becomes unreadable.
#[test]
fn leaves_unrelated_diagnostics_intact() {
    arm_redaction();
    const MESSAGE: &str = "Invalid FERRUM_PROXY_HTTP_PORT value 'not-a-port'. Expected a u16";
    assert_eq!(redact_external_secret_values(MESSAGE), MESSAGE);
}

/// Substitution output is never re-scanned, so the placeholder survives intact
/// even though several of its own substrings are candidates. A `replace()` loop
/// over the running message shreds its own placeholders and amplifies the
/// message instead.
#[test]
fn substituted_placeholders_are_not_rescanned() {
    arm_redaction();
    let message = format!("first={PLAIN_VALUE} second={PLAIN_VALUE}");
    let redacted = redact_external_secret_values(&message);
    assert_eq!(
        redacted.matches(EXTERNAL_SECRET_PLACEHOLDER).count(),
        2,
        "both occurrences must be replaced with intact placeholders: {redacted}"
    );
    assert!(redacted.len() < message.len() + 4 * EXTERNAL_SECRET_PLACEHOLDER.len());
}

/// A diagnostic is filtered twice on the `validate` failure path — once as the
/// returned error, once as the serialized log record — so redaction has to be
/// idempotent. Without that, the second pass shreds the first pass's
/// placeholders on every candidate that is a substring of the placeholder
/// itself and the operator is left with noise instead of a message.
#[test]
fn redaction_is_idempotent() {
    arm_redaction();
    let once = redact_external_secret_values(&format!(
        "Invalid {PLAIN_KEY} value '{PLAIN_VALUE}'. Expected a u16"
    ));
    let twice = redact_external_secret_values(&once);
    assert_eq!(once, twice, "a second pass must be a no-op");
    assert!(once.contains(EXTERNAL_SECRET_PLACEHOLDER));
}
