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
    record_external_secret_keys, redact_external_secret_values, withheld_log_record,
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

/// A secret equal to one of the tracing envelope's own field names. In a record
/// the fmt layer produced the *key* must survive; occurrences in values must
/// not — and in an access record, which has no envelope, the key must go too.
const FIELD_NAME_KEY: &str = "FERRUM_REDACTION_FIXTURE_FIELD_NAME";
const FIELD_NAME_VALUE: &str = "level";

/// A second envelope name, the one the fmt layer emits *nested* under `fields`
/// rather than at the root. `log_schema` can equally put it in key position in
/// an access record at any depth.
const MESSAGE_NAME_KEY: &str = "FERRUM_REDACTION_FIXTURE_MESSAGE_NAME";
const MESSAGE_NAME_VALUE: &str = "message";

/// A third envelope name, and the one named in the review finding: `filename`
/// is structural only because the fmt layer emits it, and is otherwise an
/// entirely ordinary key for `static_fields:` or a flattened `metadata` entry.
const FILENAME_NAME_KEY: &str = "FERRUM_REDACTION_FIXTURE_FILENAME_NAME";
const FILENAME_NAME_VALUE: &str = "filename";

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

/// A TLS source URI. A successful fetch is reported back by
/// `SecretBackend::source` as `<provider>:<identifier>` — one colon, no `//` —
/// and that rewritten string, not the value as materialized, is what a
/// single-key `resolve_secret`/`resolve_external_reference` caller echoes.
///
/// TLS material itself no longer carries it: `load_secret_material` stamps the
/// provider-only `redacted_source_id()` into `MaterializedMaterial`. This
/// fixture stays because the derivation must still cover the callers that do
/// echo the rewritten reference — a textual defense that only holds while one
/// call site keeps its current shape is not a defense.
const SOURCE_URI_KEY: &str = "FERRUM_REDACTION_FIXTURE_SOURCE_URI";
const SOURCE_URI_VALUE: &str = "vault://secret/data/gw-sentinel#cert-sentinel";
const SOURCE_URI_REPORTED: &str = "vault:secret/data/gw-sentinel#cert-sentinel";

/// A `file://` TLS source, which validation reports by bare filesystem path
/// with the scheme stripped entirely.
const FILE_URI_KEY: &str = "FERRUM_REDACTION_FIXTURE_FILE_URI";
const FILE_URI_VALUE: &str = "file:///run/secrets/cert-path-sentinel.pem";
const FILE_URI_STRIPPED: &str = "/run/secrets/cert-path-sentinel.pem";

/// A database URL. MongoDB TLS-conflict diagnostics render it through
/// `db_backend::redact_url`, which scrubs the credentials but leaves the host,
/// path, and remaining query of the resolved value in the message.
const DB_URL_KEY: &str = "FERRUM_REDACTION_FIXTURE_DB_URL";
const DB_URL_VALUE: &str =
    "mongodb://user-sentinel:pass-sentinel@host-sentinel/db?authSource=admin-sentinel";

/// A value that config parsing canonicalizes before logging it: leading zeros
/// are gone by the time it is echoed as `configured=…`.
///
/// Deliberately not a plausible port or limit, for the same reason as
/// [`NUMBER_VALUE`] — the canonical form is armed process-wide.
const NUMBER_CANON_KEY: &str = "FERRUM_REDACTION_FIXTURE_NUMBER_CANON";
const NUMBER_CANON_VALUE: &str = "0918273646";
const NUMBER_CANON_RENDERED: &str = "918273646";

/// A short exact secret that collides with the withheld-record template's own
/// `target` value. The fail-closed replacement must not disclose it.
///
/// Safe to arm process-wide: no other record emitted through the sink in this
/// binary carries this target (the fixtures above use `ferrum_edge::config`).
const WITHHELD_TARGET_KEY: &str = "FERRUM_REDACTION_FIXTURE_WITHHELD_TARGET";
const WITHHELD_TARGET_VALUE: &str = "ferrum_edge::secrets";

/// A value that reaches a record in **key** position.
///
/// `TransactionSummary.metadata` / `StreamTransactionSummary.metadata`
/// serialize plugin-inserted `HashMap` keys as a JSON object, and
/// `plugins::utils::log_schema` promotes operator config straight into key
/// position (`rename:`, `static_fields:`, and `MetadataPolicy::Flatten`'s
/// prefix), so a key is not necessarily a static schema field name.
const METADATA_KEY_KEY: &str = "FERRUM_REDACTION_FIXTURE_METADATA_KEY";
const METADATA_KEY_VALUE: &str = "metadata-key-sentinel";

/// A second key-position value, so the duplicate-collapse path is exercised
/// with two *distinct* resolved values rather than one repeated.
const METADATA_KEY_TWO_KEY: &str = "FERRUM_REDACTION_FIXTURE_METADATA_KEY_TWO";
const METADATA_KEY_TWO_VALUE: &str = "second-metadata-key-sentinel";

/// A short externally sourced value whose only operator-visible rendering is a
/// *whole-value transformation* of it.
///
/// `FERRUM_MODE_FILE=DB` is the shape: `OperatingMode::resolve` lowercases
/// before echoing, so the diagnostic carries `db` and never the exact `DB`. At
/// two bytes the lowercased form sits below the derived-candidate minimum and
/// was filtered out of the plan, so the resolved value was printed verbatim.
///
/// Deliberately a digraph that appears in no diagnostic in this binary: arming
/// a two-byte candidate process-wide is only safe when it is genuinely rare.
/// This adds no new *class* of risk — the exact value already carries no
/// minimum, so `Qz` itself was armed process-wide before this fixture existed.
const SHORT_CASE_KEY: &str = "FERRUM_REDACTION_FIXTURE_SHORT_CASE";
const SHORT_CASE_VALUE: &str = "Qz";
const SHORT_CASE_LOWERED: &str = "qz";

/// The deliberate residual, pinned as a control: a *shortening* whole-value
/// rewrite that lands below the minimum stays out of the candidate set.
///
/// `trim()` of this value is one byte. Admitting it would make every diagnostic
/// containing that letter unreadable, which is precisely what the minimum
/// exists to prevent, so it is covered key-tied (`report_env_field`,
/// `invalid_env_value`) rather than textually. The exact padded value is still
/// a candidate.
const PADDED_SHORT_KEY: &str = "FERRUM_REDACTION_FIXTURE_PADDED_SHORT";
const PADDED_SHORT_VALUE: &str = "  w  ";

const FIXTURES: [(&str, &str); 22] = [
    (PLAIN_KEY, PLAIN_VALUE),
    (LIST_KEY, LIST_VALUE),
    (CASE_KEY, CASE_VALUE),
    (QUOTED_KEY, QUOTED_VALUE),
    (QUOTE_KEY, QUOTE_VALUE),
    (DELIMITER_KEY, DELIMITER_VALUE),
    (FIELD_NAME_KEY, FIELD_NAME_VALUE),
    (MESSAGE_NAME_KEY, MESSAGE_NAME_VALUE),
    (FILENAME_NAME_KEY, FILENAME_NAME_VALUE),
    (NUMBER_KEY, NUMBER_VALUE),
    (TAB_KEY, TAB_VALUE),
    (BACKSPACE_KEY, BACKSPACE_VALUE),
    (NULL_KEY, NULL_VALUE),
    (SOURCE_URI_KEY, SOURCE_URI_VALUE),
    (FILE_URI_KEY, FILE_URI_VALUE),
    (DB_URL_KEY, DB_URL_VALUE),
    (NUMBER_CANON_KEY, NUMBER_CANON_VALUE),
    (WITHHELD_TARGET_KEY, WITHHELD_TARGET_VALUE),
    (METADATA_KEY_KEY, METADATA_KEY_VALUE),
    (METADATA_KEY_TWO_KEY, METADATA_KEY_TWO_VALUE),
    (SHORT_CASE_KEY, SHORT_CASE_VALUE),
    (PADDED_SHORT_KEY, PADDED_SHORT_VALUE),
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

/// A whole-value rewrite that is *no shorter than the value itself* carries no
/// minimum length, because the exact value is already an unconditional
/// candidate at that same length — so admitting the rewrite cannot cause any
/// replacement the secret would not already cause.
///
/// Without that exemption `FERRUM_MODE_FILE=DB` leaked: the only rendering an
/// operator ever sees is the lowercased `db`, and at two bytes it was dropped.
#[test]
fn redacts_a_short_whole_value_case_transformation() {
    arm_redaction();
    let redacted = redact_external_secret_values(&format!(
        "Invalid FERRUM_MODE '{SHORT_CASE_LOWERED}'. Expected: database, file, cp, dp"
    ));
    assert!(
        !redacted.contains(SHORT_CASE_LOWERED),
        "a lowercased whole-value rendering must not survive just for being short: {redacted}"
    );
    assert!(redacted.contains(EXTERNAL_SECRET_PLACEHOLDER));
    // The actionable part of the diagnostic is untouched.
    assert!(redacted.contains("Expected: database, file, cp, dp"));
}

/// The exact value of the same fixture stays covered, as it always was.
#[test]
fn redacts_the_short_value_as_materialized() {
    arm_redaction();
    let redacted =
        redact_external_secret_values(&format!("Invalid FERRUM_MODE '{SHORT_CASE_VALUE}'"));
    assert!(
        !redacted.contains(SHORT_CASE_VALUE),
        "the exact short value must not survive: {redacted}"
    );
}

/// Control for the deliberate residual: the exemption is keyed on the derived
/// form being *no shorter than* the value, so a shortening rewrite below the
/// minimum is still excluded and unrelated diagnostics stay readable.
///
/// If this ever starts failing because `w` was admitted as a candidate, the
/// exemption has been widened into the diagnostic-shredding behavior the
/// minimum exists to prevent — and the fix is key-tied withholding at the
/// affected site, not a wider candidate set.
#[test]
fn does_not_admit_a_shortening_rewrite_below_the_minimum() {
    arm_redaction();
    let message = "Listener bound with a w flag set";
    assert_eq!(
        redact_external_secret_values(message),
        message,
        "a one-byte trimmed form must not be a candidate"
    );
    // ...while the value exactly as materialized still is.
    let exact = redact_external_secret_values(&format!("value '{PADDED_SHORT_VALUE}'"));
    assert!(
        exact.contains(EXTERNAL_SECRET_PLACEHOLDER),
        "the padded value as materialized must still redact: {exact}"
    );
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

/// Emit an **access record**: `try_write_json`, the path `stdout_logging` uses.
///
/// These carry no tracing envelope, so no key in them is structural — not even
/// at the root, which is exactly where `log_schema`'s `rename:`,
/// `static_fields:`, and `MetadataPolicy::Flatten` deposit operator-supplied
/// names.
fn emit(sink: &NonBlockingSink, value: &serde_json::Value) {
    assert_eq!(
        sink.try_write_json(value)
            .expect("fixture record serializes"),
        EnqueueResult::Queued,
        "the fixture record must be accepted, not dropped"
    );
}

/// Emit a **tracing record**: through the sink's `MakeWriter` impl, which is
/// what `tracing_subscriber`'s JSON fmt layer holds.
///
/// This is the only producer that genuinely carries the fixed envelope, so it
/// is the only one whose envelope keys are exempt from key redaction. The
/// writer auto-submits on drop, matching the fmt layer's own use.
fn emit_tracing(sink: &NonBlockingSink, value: &serde_json::Value) {
    use tracing_subscriber::fmt::MakeWriter;

    let serialized = serde_json::to_vec(value).expect("fixture serializes");
    let mut writer = sink.make_writer();
    writer.write_all(&serialized).expect("record accepted");
    writer.write_all(b"\n").expect("newline accepted");
    drop(writer);
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
        emit_tracing(
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
        emit_tracing(
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

/// A secret equal to a schema field name must not rename the field *in a
/// tracing record*. `level` is one of the envelope names, whose presence at a
/// fmt-layer record's root is structural rather than derived from configuration
/// — it appears in every such record whatever the secret holds — so it is exempt
/// from the key redaction that dynamic keys get. The same spelling in an access
/// record is not exempt; see the key-position tests at the end of this file.
/// Occurrences in *values* are still a leak channel and must go.
#[test]
fn field_name_secret_keeps_the_key_and_redacts_the_value() {
    let line = through_sink(|sink| {
        emit_tracing(
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
        emit_tracing(
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
        emit_tracing(
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
        emit_tracing(
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
    assert_eq!(line, format!("{}\n", withheld_log_record()));
    parse_record(&line);
}

/// The withheld record is fixed, but "fixed" is not the same as "safe": an
/// exact resolved value has no minimum length, and `WARN`, `secret`, `values`,
/// and `ferrum_edge::secrets` are all values the template carries in its own
/// fields. Emitting the template verbatim would disclose such a secret on the
/// one path whose entire purpose is to withhold one.
#[test]
fn the_withheld_record_does_not_disclose_a_colliding_short_secret() {
    let line = through_sink(|sink| {
        assert_eq!(
            sink.try_write_bytes(format!("not json at all: {PLAIN_VALUE}\n").as_bytes()),
            EnqueueResult::Queued
        );
    });

    let record = parse_record(&line);
    let object = record.as_object().expect("record is a JSON object");
    let discloses = object.values().any(|value| {
        value
            .as_str()
            .is_some_and(|text| text.contains(WITHHELD_TARGET_VALUE))
    });
    assert!(
        !discloses,
        "the fail-closed replacement must not carry a colliding resolved value: {line}"
    );
    // The template itself does contain it, so the assertion above is only
    // meaningful because redaction actually ran.
    assert!(
        WITHHELD_LOG_RECORD.contains(WITHHELD_TARGET_VALUE),
        "fixture no longer collides with the template; pick a colliding value"
    );
    // Schema keys are untouched, so a log pipeline still sees the same shape.
    assert!(object.contains_key("target") && object.contains_key("level"));
    assert_eq!(
        record["target"],
        serde_json::Value::String(EXTERNAL_SECRET_PLACEHOLDER.to_string()),
        "the colliding value must be replaced, not dropped: {line}"
    );
}

/// A successful fetch is reported by a *rewritten* reference: `vault://x` is
/// echoed back as `vault:x`. That transformed form is not the value as
/// materialized, so exact matching alone lets a diagnostic print the operator's
/// Vault path.
///
/// TLS material is now additionally protected at the producer — it stamps the
/// provider-only `redacted_source_id()` — but this textual coverage is kept for
/// every other caller that echoes the rewritten reference, and so that the
/// guarantee does not depend on one call site keeping its current shape.
#[test]
fn a_provider_rewritten_source_reference_is_redacted() {
    arm_redaction();
    let message = redact_external_secret_values(&format!(
        "Failed to parse PEM from {SOURCE_URI_REPORTED}: malformed"
    ));
    assert!(
        !message.contains("gw-sentinel") && !message.contains("cert-sentinel"),
        "the rewritten source reference must not survive: {message}"
    );
    assert!(
        message.contains("Failed to parse PEM from") && message.contains("malformed"),
        "the actionable diagnostic must survive: {message}"
    );
}

/// A `file://` source is reported by bare path, the scheme stripped.
#[test]
fn a_scheme_stripped_file_source_is_redacted() {
    arm_redaction();
    let message =
        redact_external_secret_values(&format!("Invalid certificate at {FILE_URI_STRIPPED}"));
    assert!(
        !message.contains("cert-path-sentinel"),
        "the scheme-stripped path must not survive: {message}"
    );
    assert!(message.contains("Invalid certificate at"));
}

/// A database URL reaches the operator credential-redacted, which leaves the
/// host, path, and query of the externally resolved value intact.
#[test]
fn a_credential_redacted_url_form_is_redacted() {
    arm_redaction();
    let rendered = ferrum_edge::config::db_backend::redact_url(DB_URL_VALUE);
    assert!(
        rendered != DB_URL_VALUE && rendered.contains("host-sentinel"),
        "fixture must actually be transformed and still carry the host: {rendered}"
    );

    let message = redact_external_secret_values(&format!(
        "MongoDB TLS options conflict for {rendered}: check tls settings"
    ));
    assert!(
        !message.contains("host-sentinel") && !message.contains("admin-sentinel"),
        "the credential-redacted URL must not survive: {message}"
    );
    assert!(message.contains("MongoDB TLS options conflict for"));
}

/// Typed parsing canonicalizes before logging: `03601` is warned about as
/// `configured=3601`, which matches no exact-value candidate.
#[test]
fn a_canonicalized_numeric_rendering_is_redacted() {
    arm_redaction();
    let message = redact_external_secret_values(&format!(
        "pool statement timeout configured={NUMBER_CANON_RENDERED}s"
    ));
    assert!(
        !message.contains(NUMBER_CANON_RENDERED),
        "the canonical numeric rendering must not survive: {message}"
    );
    assert!(message.contains("pool statement timeout configured="));
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
        emit_tracing(
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
        emit_tracing(
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
        emit_tracing(
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

// ---------------------------------------------------------------------------
// Key-position redaction.
//
// Access records are not all-static. `TransactionSummary.metadata` and
// `StreamTransactionSummary.metadata` serialize plugin-inserted `HashMap` keys
// as a nested JSON object, and `plugins::utils::log_schema` puts operator
// configuration directly in key position (`rename:`, `static_fields:`, and
// `MetadataPolicy::Flatten`'s prefix). So a resolved value can reach the sink
// as a key, where value-only redaction would emit it verbatim.
//
// Records here are built with explicit `serde_json::Map`s rather than `json!`
// so the dynamic keys are unambiguously runtime strings, and emission *order*
// is asserted against the raw line: `serde_json::Map` is a `BTreeMap` in this
// build (no `preserve_order` feature), so a parsed record would report sorted
// keys and could not distinguish preserved order from re-sorted order.
// ---------------------------------------------------------------------------

/// Build a JSON object preserving the given entry order on the wire.
fn object(entries: Vec<(&str, serde_json::Value)>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in entries {
        map.insert(key.to_string(), value);
    }
    serde_json::Value::Object(map)
}

fn string(value: &str) -> serde_json::Value {
    serde_json::Value::String(value.to_string())
}

/// Byte offset of `needle` in `haystack`, failing the test if absent.
fn offset_of(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("expected `{needle}` in: {haystack}"))
}

/// The `metadata` shape: a nested object whose key is a resolved value.
///
/// Both the key *and* the value beneath it must go. A key built from resolved
/// material routinely names material of the same provenance, and once the key
/// is gone a retained value is unattributable.
#[test]
fn a_resolved_metadata_key_and_its_value_are_both_redacted() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &object(vec![
                ("status", string("200")),
                (
                    "metadata",
                    object(vec![
                        (METADATA_KEY_VALUE, string("value-under-the-resolved-key")),
                        ("request_id", string("abc-123")),
                    ]),
                ),
            ]),
        );
    });

    assert!(
        !line.contains(METADATA_KEY_VALUE),
        "the resolved value must not survive in key position: {line}"
    );
    assert!(
        !line.contains("value-under-the-resolved-key"),
        "the value beneath a resolved key must not survive either: {line}"
    );

    let record = parse_record(&line);
    let metadata = record["metadata"]
        .as_object()
        .expect("metadata stays an object");
    assert_eq!(
        metadata.get(EXTERNAL_SECRET_PLACEHOLDER),
        Some(&string(EXTERNAL_SECRET_PLACEHOLDER)),
        "the entry must collapse to placeholder key and placeholder value: {line}"
    );
    assert_eq!(
        metadata["request_id"], "abc-123",
        "an unrelated metadata entry must survive untouched: {line}"
    );
    assert_eq!(
        record["status"], "200",
        "an unrelated access-log field must be unaffected: {line}"
    );
}

/// The `log_schema` flatten/rename shape: the resolved value is a *top-level*
/// key, not nested under `metadata`. Depth is not what makes a key dynamic.
#[test]
fn a_resolved_top_level_key_is_redacted() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &object(vec![
                ("status", string("200")),
                (METADATA_KEY_VALUE, string("flattened-value")),
            ]),
        );
    });

    assert!(
        !line.contains(METADATA_KEY_VALUE),
        "a resolved top-level key must not survive: {line}"
    );
    assert!(
        !line.contains("flattened-value"),
        "the value beneath it must not survive: {line}"
    );
    let record = parse_record(&line);
    assert_eq!(
        record["status"], "200",
        "an unrelated access-log field must be unaffected: {line}"
    );
}

/// Two distinct resolved keys in one object both collapse to the placeholder,
/// which would be a duplicate key. A JSON object with repeated keys is
/// ambiguous, so the first wins and later ones are dropped — the record must
/// stay parseable and must not retain either secret.
#[test]
fn colliding_redacted_keys_collapse_to_one_parseable_entry() {
    let line = through_sink(|sink| {
        emit(
            sink,
            &object(vec![
                ("status", string("200")),
                (
                    "metadata",
                    object(vec![
                        (METADATA_KEY_VALUE, string("first")),
                        (METADATA_KEY_TWO_VALUE, string("second")),
                        ("kept", string("yes")),
                    ]),
                ),
            ]),
        );
    });

    assert!(
        !line.contains(METADATA_KEY_VALUE),
        "first resolved key must not survive: {line}"
    );
    assert!(
        !line.contains(METADATA_KEY_TWO_VALUE),
        "second resolved key must not survive: {line}"
    );
    assert_eq!(
        line.matches(EXTERNAL_SECRET_PLACEHOLDER).count(),
        2,
        "exactly one entry survives, rendered as \
         `\"<placeholder>\":\"<placeholder>\"` — two occurrences, one for the \
         key and one for the value. Four would mean the collided second entry \
         was kept as a duplicate key: {line}"
    );

    // `parse_record` already fails the test on invalid JSON.
    let record = parse_record(&line);
    let metadata = record["metadata"]
        .as_object()
        .expect("metadata stays an object");
    assert_eq!(
        metadata.len(),
        2,
        "the collided entry is dropped, the unrelated one kept: {line}"
    );
    assert_eq!(metadata["kept"], "yes", "{line}");
}

/// The tracing envelope keys stay verbatim and in emitted order even when a
/// resolved value matches one of them, including `message` at its real position
/// nested under `fields`. Their presence is structural — `level` is in every
/// fmt-layer record whatever a secret holds — so leaving them discloses nothing,
/// while rewriting one would break every downstream consumer.
#[test]
fn fixed_schema_keys_survive_and_keep_their_order() {
    let line = through_sink(|sink| {
        emit_tracing(
            sink,
            &object(vec![
                ("timestamp", string("2026-07-18T00:00:00Z")),
                ("level", string("WARN")),
                ("filename", string("src/config/env_config.rs")),
                ("target", string("ferrum_edge::fixture")),
                ("fields", object(vec![("message", string("unrelated"))])),
            ]),
        );
    });

    for key in ["timestamp", "level", "target", "fields", "message"] {
        assert!(
            line.contains(&format!("\"{key}\":")),
            "the fixed schema key `{key}` must survive verbatim: {line}"
        );
    }
    assert!(
        line.contains("\"filename\":"),
        "the envelope `filename` key must survive verbatim: {line}"
    );
    // Order is asserted on the wire, not through the parsed map.
    let positions = [
        offset_of(&line, "\"timestamp\":"),
        offset_of(&line, "\"level\":"),
        offset_of(&line, "\"filename\":"),
        offset_of(&line, "\"target\":"),
        offset_of(&line, "\"fields\":"),
    ];
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "fixed schema keys must keep their emitted order: {line}"
    );
}

// ---------------------------------------------------------------------------
// Scoping of the envelope exemption.
//
// The exemption above is keyed on the *producer* and the key's *position*, not
// on spelling. An access record (`try_write_json`) carries no tracing envelope,
// so a key spelled `filename`, `level`, or `message` in one is operator- or
// plugin-supplied — `log_schema`'s `rename:`/`static_fields:` and
// `MetadataPolicy::Flatten` all put such names at the root, the same depth the
// genuine envelope occupies, so a depth test alone would not separate them.
// ---------------------------------------------------------------------------

/// The envelope names at the **root of an access record** are still withheld.
///
/// This is the review finding: a flattened `static_fields`/`rename:` key equal
/// to an externally resolved `filename` occupies the root, where a global
/// spelling-based exemption waved it through unredacted.
#[test]
fn envelope_names_in_access_record_root_keys_are_redacted() {
    for resolved in [FILENAME_NAME_VALUE, FIELD_NAME_VALUE, MESSAGE_NAME_VALUE] {
        let fixture = object(vec![
            ("status", string("200")),
            (resolved, string("value-under-the-resolved-key")),
        ]);
        let line = through_sink(|sink| emit(sink, &fixture));

        assert!(
            !line.contains(&format!("\"{resolved}\":")),
            "the resolved `{resolved}` must not survive as an access-record root key: {line}"
        );
        assert!(
            !line.contains("value-under-the-resolved-key"),
            "the value beneath the resolved `{resolved}` key must not survive: {line}"
        );
        let record = parse_record(&line);
        assert_eq!(
            record[EXTERNAL_SECRET_PLACEHOLDER],
            string(EXTERNAL_SECRET_PLACEHOLDER),
            "the entry must collapse to placeholder key and value: {line}"
        );
        assert_eq!(
            record["status"], "200",
            "an unrelated access-log field must be unaffected: {line}"
        );
    }
}

/// Same names, one level down: a plugin-inserted `metadata` key. Nesting is not
/// what makes them dynamic — the record's provenance is.
#[test]
fn envelope_names_nested_in_an_access_record_are_redacted() {
    for resolved in [FILENAME_NAME_VALUE, FIELD_NAME_VALUE, MESSAGE_NAME_VALUE] {
        let nested = object(vec![
            (resolved, string("nested-value")),
            ("request_id", string("abc-123")),
        ]);
        let fixture = object(vec![("status", string("200")), ("metadata", nested)]);
        let line = through_sink(|sink| emit(sink, &fixture));

        assert!(
            !line.contains(&format!("\"{resolved}\":")),
            "the resolved `{resolved}` must not survive as a metadata key: {line}"
        );
        assert!(
            !line.contains("nested-value"),
            "the value beneath the resolved `{resolved}` key must not survive: {line}"
        );
        let record = parse_record(&line);
        let metadata = record["metadata"]
            .as_object()
            .expect("metadata stays an object");
        assert_eq!(
            metadata.get(EXTERNAL_SECRET_PLACEHOLDER),
            Some(&string(EXTERNAL_SECRET_PLACEHOLDER)),
            "the entry must collapse to placeholder key and value: {line}"
        );
        assert_eq!(metadata["request_id"], "abc-123", "{line}");
    }
}

/// Inside a *tracing* record the exemption is still positional: the envelope
/// covers the root and `message` under `fields`, and nothing below that. A span
/// field or an event field named `filename` is developer/runtime data, not
/// envelope structure, so it stays screened.
#[test]
fn envelope_names_below_the_tracing_envelope_are_redacted() {
    let fields = object(vec![
        ("message", string("unrelated")),
        (FILENAME_NAME_VALUE, string("event-field-value")),
    ]);
    let span = object(vec![(FIELD_NAME_VALUE, string("span-field-value"))]);
    let fixture = object(vec![
        ("level", string("WARN")),
        ("filename", string("src/config/env_config.rs")),
        ("fields", fields),
        ("span", span),
    ]);
    let line = through_sink(|sink| emit_tracing(sink, &fixture));

    let record = parse_record(&line);
    // The genuine envelope survives, at both of its positions.
    assert_eq!(record["level"], "WARN", "{line}");
    assert_eq!(record["filename"], "src/config/env_config.rs", "{line}");
    assert_eq!(record["fields"]["message"], "unrelated", "{line}");
    // A same-named key one level deeper does not.
    assert!(
        !line.contains("event-field-value") && !line.contains("span-field-value"),
        "values beneath a resolved key below the envelope must not survive: {line}"
    );
    assert_eq!(
        record["fields"][EXTERNAL_SECRET_PLACEHOLDER],
        string(EXTERNAL_SECRET_PLACEHOLDER),
        "an event field named like an envelope key is not envelope structure: {line}"
    );
    assert_eq!(
        record["span"][EXTERNAL_SECRET_PLACEHOLDER],
        string(EXTERNAL_SECRET_PLACEHOLDER),
        "a span field named like an envelope key is not envelope structure: {line}"
    );
}

/// Scoping does not weaken the fail-closed path, and the notice it emits keeps
/// its *own* envelope.
///
/// The withheld template is a fixed literal carrying the fmt layer's root
/// `level`/`target`/`message` keys, so it is redacted as a tracing record. With
/// `message` and `level` both armed as resolved values here, classifying that
/// literal as dynamic would rewrite the notice's own schema keys and leave log
/// pipelines with an unrecognizable line on the one path that exists to keep
/// them informed.
#[test]
fn the_withheld_notice_keeps_its_own_envelope_keys() {
    let withheld = through_sink(|sink| {
        assert_eq!(
            sink.try_write_bytes(format!("{{not json: {PLAIN_VALUE}\n").as_bytes()),
            EnqueueResult::Queued
        );
    });

    assert!(
        !withheld.contains(PLAIN_VALUE),
        "the resolved value must not survive: {withheld}"
    );
    assert_eq!(withheld, format!("{}\n", withheld_log_record()));
    let record = parse_record(&withheld);
    let object = record.as_object().expect("record is a JSON object");
    for key in ["level", "target", "message"] {
        assert!(
            object.contains_key(key),
            "the withheld notice must keep its own `{key}` envelope key: {withheld}"
        );
    }
}
