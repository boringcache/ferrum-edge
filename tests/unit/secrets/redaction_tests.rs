//! Coverage for the externally-resolved-value redaction contract.
//!
//! `secrets::record_external_secret_keys()` is a one-shot `OnceLock` for the
//! process, and the derived candidate set it feeds is built once and cached, so
//! **this file owns the single recording for the `unit_tests` binary**. Every
//! assertion that depends on redaction being armed lives here, and the recorded
//! keys all use a `FERRUM_REDACTION_FIXTURE_*` prefix that no real setting uses,
//! so no other test's diagnostics are affected.

use crate::unit::env_lock::ENV_LOCK;
use ferrum_edge::secrets::{
    EXTERNAL_SECRET_PLACEHOLDER, WITHHELD_LOG_RECORD, is_external_secret_key,
    record_external_secret_keys, redact_external_secret_values,
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

/// A one-character secret. A resolved value has deliberately no minimum length,
/// so this is a legitimate secret — and it is also the JSON string delimiter,
/// which is what makes a flat text pass over a serialized record unsafe.
const QUOTE_KEY: &str = "FERRUM_REDACTION_FIXTURE_QUOTE";
const QUOTE_VALUE: &str = "\"";

/// A secret that is a JSON structural delimiter.
const DELIMITER_KEY: &str = "FERRUM_REDACTION_FIXTURE_DELIMITER";
const DELIMITER_VALUE: &str = ",";

/// A secret equal to one of the log schema's own field names. The *key* must
/// survive; occurrences in values must not.
const FIELD_NAME_KEY: &str = "FERRUM_REDACTION_FIXTURE_FIELD_NAME";
const FIELD_NAME_VALUE: &str = "level";

/// A secret that appears in a record as an unquoted JSON number — the shape a
/// resolved port or limit produces.
///
/// Deliberately not a plausible port. Recording keys arms redaction for the
/// whole `unit_tests` binary, so a realistic number like `8443` could match a
/// scalar in an unrelated test's access-log record and rewrite it.
const NUMBER_KEY: &str = "FERRUM_REDACTION_FIXTURE_NUMBER";
const NUMBER_VALUE: &str = "918273645";

/// A one-character control secret. Unlike `"` or `\n` it has no incidental
/// structural twin in a record, and its serialized body (`\t`) is two bytes —
/// shorter than the *derived* candidate minimum. If only derived forms carried
/// the escaped representation, the pre-parse screen would find neither the raw
/// tab (absent from the escaped record) nor `\t` (filtered out), the record
/// would never be parsed, and the secret would be emitted verbatim.
const TAB_KEY: &str = "FERRUM_REDACTION_FIXTURE_TAB";
const TAB_VALUE: &str = "\t";

/// Same class, second escape: backspace serializes as `\b`.
const BACKSPACE_KEY: &str = "FERRUM_REDACTION_FIXTURE_BACKSPACE";
const BACKSPACE_VALUE: &str = "\u{8}";

/// A secret whose exact value renders as the unquoted JSON scalar `null`, the
/// third rendered scalar form alongside numbers and booleans.
///
/// Safe to arm process-wide: the only other sink user in this binary
/// (`logging_tests`) serializes `TransactionSummary`, whose hand-written
/// `Serialize` skips `None` fields rather than emitting nulls. An exact `true`
/// or `false` fixture is deliberately *not* armed for the same reason the
/// number fixture avoids a plausible port — it would rewrite the boolean
/// assertions in that file.
const NULL_KEY: &str = "FERRUM_REDACTION_FIXTURE_NULL";
const NULL_VALUE: &str = "null";

const FIXTURES: [(&str, &str); 11] = [
    (PLAIN_KEY, PLAIN_VALUE),
    (LIST_KEY, LIST_VALUE),
    (CASE_KEY, CASE_VALUE),
    (QUOTED_KEY, QUOTED_VALUE),
    (QUOTE_KEY, QUOTE_VALUE),
    (DELIMITER_KEY, DELIMITER_VALUE),
    (FIELD_NAME_KEY, FIELD_NAME_VALUE),
    (NUMBER_KEY, NUMBER_VALUE),
    (TAB_KEY, TAB_VALUE),
    (BACKSPACE_KEY, BACKSPACE_VALUE),
    (NULL_KEY, NULL_VALUE),
];

static RECORDED: Once = Once::new();

/// Arm process-wide redaction exactly once for the `unit_tests` binary.
///
/// The `Once` alone is not enough. `set_var` is a data race against *any*
/// concurrent `getenv` anywhere in the process, and the `unit_tests` binary
/// runs env-reading and env-mutating tests in parallel; a file-local `Once`
/// serializes this file against itself but not against them. The shared
/// [`ENV_LOCK`] is the process-wide serialization point every other
/// env-touching unit test already acquires, so it is taken here too.
///
/// The lock is also held across the first redaction call, not just the
/// `set_var` loop. The cached candidate plan is built lazily on first use by
/// reading these variables back out of the environment, so that read is part of
/// the same critical section — otherwise the plan could be built by a later
/// test while an unrelated test is mid-`set_var`. Once the plan is cached
/// nothing reads the environment again, so the individual tests below need no
/// lock.
fn arm_redaction() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    RECORDED.call_once(|| {
        for (key, value) in FIXTURES {
            // SAFETY: `ENV_LOCK` is held, so no other test is reading or
            // writing the process environment concurrently. The names are
            // fixture-only and no real setting uses this prefix.
            unsafe { std::env::set_var(key, value) };
        }
        record_external_secret_keys(FIXTURES.iter().map(|(key, _)| key.to_string()));
        // Force the lazily built candidate plan while the lock is still held,
        // so its env read-back cannot race a concurrent mutation.
        let _ = redact_external_secret_values("");
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

// ---------------------------------------------------------------------------
// Serialization-boundary coverage, driven through the real sink.
//
// `secrets::redact_log_record` is crate-private, so these exercise it where it
// actually runs: `NonBlockingSink` -> `RecordWriter::submit`, the single point
// where a log record exists as complete bytes. That is the boundary the
// structural (rather than textual) redaction exists to protect, and driving the
// real sink also proves the substitution survives the queue/admission path.
// ---------------------------------------------------------------------------

use ferrum_edge::logging::non_blocking::EnqueueResult;
use ferrum_edge::logging::{NonBlockingOptions, NonBlockingSink, SinkName};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `write` against a live sink and return everything the writer received.
fn through_sink(write: impl FnOnce(&NonBlockingSink)) -> String {
    arm_redaction();
    let captured = CapturedWriter::default();
    let output = Arc::clone(&captured.0);
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        captured,
        NonBlockingOptions {
            record_capacity: 16,
            byte_capacity: 1 << 20,
            max_record_bytes: 64 * 1024,
            shutdown_timeout: std::time::Duration::from_secs(5),
        },
    )
    .expect("sink spawns");

    write(&sink);

    assert!(guard.shutdown(), "the sink must drain before assertions");
    let bytes = output
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    String::from_utf8(bytes).expect("sink output is UTF-8")
}

fn emit(sink: &NonBlockingSink, value: &serde_json::Value) {
    assert_eq!(
        sink.try_write_json(value).expect("fixture record serializes"),
        EnqueueResult::Queued,
        "the fixture record must be accepted, not dropped"
    );
}

fn parse_record(line: &str) -> serde_json::Value {
    serde_json::from_str(line.trim_end())
        .unwrap_or_else(|error| panic!("emitted record must stay valid JSON ({error}): {line}"))
}

/// The headline defect: a resolved value has no minimum length, so a secret can
/// be a single `"`. A flat text pass over the serialized record replaces every
/// structural quote with the placeholder and emits a line nothing can parse.
#[test]
fn one_character_quote_secret_does_not_corrupt_the_record() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "WARN",
                "message": format!("value is {QUOTE_VALUE} here"),
            }),
        );
    });

    let record = parse_record(&line);
    assert_eq!(record["level"], "WARN", "unrelated values must survive");
    let message = record["message"].as_str().expect("message stays a string");
    assert!(
        !message.contains('"'),
        "the resolved quote must not survive: {message}"
    );
    assert!(message.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// Same class, via a delimiter: the object must keep exactly its three fields
/// rather than having its separators rewritten into placeholder text.
#[test]
fn structural_delimiter_secret_does_not_rewrite_json_syntax() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "INFO",
                "message": format!("a{DELIMITER_VALUE}b"),
                "target": "ferrum_edge::config",
            }),
        );
    });

    let record = parse_record(&line);
    let object = record.as_object().expect("record is a JSON object");
    assert_eq!(
        object.len(),
        3,
        "structural delimiters must not be substituted: {line}"
    );
    assert_eq!(record["target"], "ferrum_edge::config");
    let message = record["message"].as_str().expect("string value");
    assert!(
        !message.contains(','),
        "the resolved delimiter must not survive: {message}"
    );
    assert!(message.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// A secret equal to a schema field name must not rename the field. Keys are
/// static field names, never interpolated config, so they are not a leak
/// channel — but occurrences in *values* still are.
#[test]
fn field_name_secret_keeps_the_key_and_redacts_the_value() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "WARN",
                "message": format!("the {FIELD_NAME_VALUE} was resolved externally"),
            }),
        );
    });

    let record = parse_record(&line);
    assert!(
        record.get(FIELD_NAME_VALUE).is_some(),
        "the `{FIELD_NAME_VALUE}` key must survive verbatim: {line}"
    );
    let message = record["message"].as_str().expect("string value");
    assert!(
        !message.contains(FIELD_NAME_VALUE),
        "the resolved value must not survive in a value position: {message}"
    );
    assert!(message.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// A resolved port reaches the record as an unquoted JSON number, so matching
/// only inside string literals would miss it.
#[test]
fn numeric_scalar_values_are_redacted() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "INFO",
                "port": 918273645,
                "tls": true,
            }),
        );
    });

    let record = parse_record(&line);
    assert!(
        !line.contains(NUMBER_VALUE),
        "the resolved scalar must not survive: {line}"
    );
    assert_eq!(
        record["port"],
        serde_json::Value::String(EXTERNAL_SECRET_PLACEHOLDER.to_string())
    );
    assert_eq!(
        record["tls"],
        serde_json::Value::Bool(true),
        "unrelated scalars must survive"
    );
}

/// The record is JSON-escaped by the time it reaches the sink. Matching happens
/// against the unescaped value and the reserializer re-escapes, so escaping can
/// neither smuggle a value past the scan nor break the output.
#[test]
fn escaped_string_values_are_redacted_and_reescaped() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "WARN",
                "message": format!("saw {QUOTED_VALUE} in config"),
            }),
        );
    });

    let record = parse_record(&line);
    let message = record["message"].as_str().expect("string value");
    assert!(
        !message.contains(QUOTED_VALUE),
        "the escaped resolved value must not survive: {message}"
    );
    assert!(message.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// Redaction is armed and the record is full of quotes, so it does take the
/// parse/reserialize path — and must come out byte-for-byte identical,
/// including field order. Otherwise every ordinary diagnostic in a process
/// using external secrets would be silently rewritten.
#[test]
fn a_record_with_no_resolved_value_round_trips_unchanged() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "INFO",
                "message": "listening on 0.0.0.0:8080",
                "target": "ferrum_edge::startup",
            }),
        );
    });

    assert_eq!(
        line,
        concat!(
            r#"{"level":"INFO","message":"listening on 0.0.0.0:8080","#,
            r#""target":"ferrum_edge::startup"}"#,
            "\n"
        )
    );
}

/// Fail-closed: a record that is not well-formed JSON cannot be sanitized
/// without either leaking or emitting a corrupt line, so it is replaced by a
/// fixed, valid JSON notice. Nothing derived from the record is emitted.
#[test]
fn a_non_json_record_containing_a_resolved_value_is_withheld() {
    let line = through_sink(|sink| {
        assert_eq!(
            sink.try_write_bytes(format!("not json at all: {PLAIN_VALUE}\n").as_bytes()),
            EnqueueResult::Queued
        );
    });

    assert!(
        !line.contains(PLAIN_VALUE),
        "the resolved value must not survive: {line}"
    );
    assert_eq!(line, format!("{WITHHELD_LOG_RECORD}\n"));
    parse_record(&line);
}

/// A non-JSON record that contains nothing to redact is left alone — the
/// withholding path must not swallow unrelated output.
#[test]
fn a_non_json_record_without_a_resolved_value_is_untouched() {
    let line = through_sink(|sink| {
        assert_eq!(
            sink.try_write_bytes(b"plain operator output\n"),
            EnqueueResult::Queued
        );
    });

    assert_eq!(line, "plain operator output\n");
}

/// A one-character control secret is present in the serialized record *only* in
/// its escaped form. The escaped body of an exact value therefore has to reach
/// the pre-parse screen unfiltered: with a minimum applied to it, `\t` is
/// dropped, the raw tab never appears in the escaped record, nothing triggers
/// parsing, and the record is emitted carrying the secret.
#[test]
fn one_character_escaped_control_secret_is_redacted() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "WARN",
                "message": format!("before{TAB_VALUE}after"),
            }),
        );
    });

    let record = parse_record(&line);
    assert_eq!(record["level"], "WARN", "unrelated values must survive");
    assert!(
        !line.contains("\\t"),
        "the escaped form of the resolved value must not survive: {line}"
    );
    let message = record["message"].as_str().expect("message stays a string");
    assert!(
        !message.contains(TAB_VALUE),
        "the resolved control character must not survive: {message:?}"
    );
    assert!(message.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// Same class, a second escape, so the fix is not a one-character special case
/// for tab.
#[test]
fn a_second_escaped_control_secret_is_redacted() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "INFO",
                "message": format!("before{BACKSPACE_VALUE}after"),
            }),
        );
    });

    let record = parse_record(&line);
    assert!(
        !line.contains("\\b"),
        "the escaped form of the resolved value must not survive: {line}"
    );
    let message = record["message"].as_str().expect("message stays a string");
    assert!(
        !message.contains(BACKSPACE_VALUE),
        "the resolved control character must not survive: {message:?}"
    );
    assert!(message.contains(EXTERNAL_SECRET_PLACEHOLDER));
}

/// `null` is the third unquoted scalar form, and a resolved value of `null`
/// reaches the record as that literal. Skipping it would emit the secret's own
/// representation while numbers and booleans in the same record are replaced.
#[test]
fn a_null_scalar_value_is_redacted() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &serde_json::json!({
                "level": "INFO",
                "resolved": serde_json::Value::Null,
                "tls": true,
            }),
        );
    });

    let record = parse_record(&line);
    assert_eq!(
        record["resolved"],
        serde_json::Value::String(EXTERNAL_SECRET_PLACEHOLDER.to_string()),
        "the resolved null scalar must be replaced whole: {line}"
    );
    assert_eq!(
        record["tls"],
        serde_json::Value::Bool(true),
        "unrelated scalars must survive"
    );
}
