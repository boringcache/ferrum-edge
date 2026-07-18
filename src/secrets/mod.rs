//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself.
//!
//! Startup secret resolution finishes before non-blocking logging and the
//! multi-threaded gateway runtime, and its temporary runtime is dropped before
//! env mutation happens.

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
pub mod env;
pub mod file;
#[cfg(feature = "secrets-gcp")]
mod gcp;
mod registry;
#[cfg(feature = "secrets-vault")]
mod vault;

#[cfg(any(feature = "secrets-aws", feature = "secrets-vault"))]
pub(crate) fn split_reference_field(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once('#') {
        Some((base, field)) => (base, Some(field)),
        None => (reference, None),
    }
}

#[allow(unused_imports)]
pub use registry::{
    EXTERNAL_SECRET_SUFFIXES, ResolvedEnvSecrets, ResolvedSecret, external_source_configured,
    resolve_all_env_secrets, resolve_external_reference, resolve_secret,
};

/// Base `FERRUM_*` variables whose current value was materialized from an
/// external secret source in this process.
///
/// Only the key names are stored *here*. The values are read back from the
/// process environment (startup writes them there with `set_var` before config
/// is parsed) the first time redaction runs, which is what makes redaction
/// key-tied rather than a guess about what looks secret.
///
/// That read-back is not copy-free, and pretending otherwise would be
/// misleading: [`REDACTION_PLAN`] retains, for the process lifetime, the exact
/// value of every externally resolved key plus the bounded set of derived forms
/// from [`derive_candidates`] (trimmed, per-segment, case-normalized, and
/// JSON-escaped). Matching a value that a validator re-rendered requires having
/// that rendering to compare against, so the copies are the cost of the
/// coverage. The tradeoff is deliberate and bounded: the plan is built once,
/// deduplicated, and never rebuilt or extended, and the *environment* remains
/// the only place the value is written or mutated.
static EXTERNAL_SECRET_KEYS: std::sync::OnceLock<std::collections::BTreeSet<String>> =
    std::sync::OnceLock::new();

/// Fast path for the log-record boundary.
///
/// `false` until at least one base variable is actually materialized from an
/// external source, which is the overwhelmingly common case (no external
/// secrets configured, and every unit/integration test). Every log record — including
/// per-transaction access-log records on the proxy hot path — passes through
/// [`redact_log_record`], so the "nothing to redact" case must cost a single
/// relaxed atomic load and nothing else.
static REDACTION_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Substituted for an externally resolved value in an operator-facing message.
pub const EXTERNAL_SECRET_PLACEHOLDER: &str = "<redacted: value from external secret source>";

/// Record which base variables were materialized from an external secret
/// source.
///
/// Called exactly once at startup, immediately after the resolved values are
/// written to the environment and before any configuration is parsed. Later
/// calls are ignored, so this cannot be re-pointed after config load.
///
/// This is what makes downstream redaction *key-tied* rather than a guess about
/// what looks secret: an externally resolved variable is known by name, so a
/// diagnostic about it can name the variable and withhold only its value.
pub fn record_external_secret_keys<I>(keys: I)
where
    I: IntoIterator<Item = String>,
{
    let keys: std::collections::BTreeSet<String> = keys.into_iter().collect();
    let any = !keys.is_empty();
    if EXTERNAL_SECRET_KEYS.set(keys).is_ok() && any {
        // Arm the log-record boundary only once there is something to redact.
        // Ordering is `Release`/`Acquire` against the plan build so a reader
        // that observes `true` also observes the recorded key set.
        REDACTION_ACTIVE.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// True when `key`'s current value came from an external secret source.
///
/// Returns `false` before [`record_external_secret_keys`] runs and in any
/// process that never resolved external secrets (including unit tests), so
/// ordinary configuration diagnostics are unaffected.
pub fn is_external_secret_key(key: &str) -> bool {
    EXTERNAL_SECRET_KEYS
        .get()
        .is_some_and(|keys| keys.contains(key))
}

/// Remove externally resolved secret values from an operator-facing message.
///
/// This is the backstop behind the structured boundary in
/// `config::env_config_macro::invalid_env_value`, which is where typed
/// `EnvConfig` parse failures already withhold the raw value by key. Config
/// validation is far wider than that one site — hand-written messages, URL and
/// namespace validators, and the file-mode spec loader all interpolate resolved
/// values — and a resolved secret is indistinguishable from ordinary
/// configuration once it is in the environment. Rather than auditing every
/// present and future message, the final rendering of a startup/validation
/// failure is filtered here against the authoritative set of externally
/// resolved keys.
///
/// Replacement is by key, never guessed at by shape: the value is read back
/// from the environment under a name known to have come from an external
/// source. The value exactly as materialized has deliberately no minimum
/// length — a short resolved secret is still a secret, and mangling an
/// unrelated substring of a diagnostic is strictly preferable to printing the
/// secret. Longest candidates are replaced first so one secret that contains
/// another cannot leave a fragment behind.
///
/// Exact-value matching alone is not sufficient, because validators and the
/// logging sink both re-render a value before it reaches an operator: list
/// parsers trim entries, `FERRUM_TLS_EARLY_DATA_METHODS` uppercases them, and
/// the tracing layer JSON-escapes the whole record. [`derive_candidates`]
/// therefore expands each value into a small, explicitly bounded set of those
/// forms. See it for the bound and the deliberate residual.
///
/// Matching runs against the *original* diagnostic only. Substituted
/// placeholders are never re-examined, so a resolved value that happens to be a
/// substring of [`EXTERNAL_SECRET_PLACEHOLDER`] (`value`, `external`, `a`)
/// cannot make one replacement's output the next replacement's input. A
/// repeated-substitution loop over the running message compounds instead:
/// n such values multiply the diagnostic by roughly the placeholder's density
/// of each, which turns a handful of externally resolved short secrets into a
/// validation-time memory/CPU exhaustion. See [`RedactionPlan::redact`] for the
/// bound.
pub fn redact_external_secret_values(message: &str) -> String {
    match redaction_plan() {
        Some(plan) => plan.redact(message).into_owned(),
        None => message.to_string(),
    }
}

/// Redact a fully serialized log record in place, at the emission boundary.
///
/// The by-key boundary in `config::env_config_macro::invalid_env_value` and the
/// final-error backstop above only cover values that reach an operator through
/// a returned `Result`. Diagnostics emitted as `warn!`/`info!` *during*
/// `EnvConfig::from_env()` or spec validation are written straight to the sink
/// and never pass through either — a `FERRUM_TLS_EARLY_DATA_METHODS_FILE`
/// holding a non-GET token is uppercased and warned about on a **successful**
/// default `validate` run, so there is no returned error to filter at all.
///
/// This is the one place every tracing record is materialized as bytes
/// (`logging::non_blocking::RecordWriter::submit`), so filtering here covers
/// present and future log sites without auditing each one.
///
/// # Why this boundary is structural, not textual
///
/// A record here is a complete JSON document: the fmt layer is configured
/// `.json()` in `main::init_logging`, `stdout_logging` access records go
/// through `NonBlockingSink::try_write_json`, and the sink's own failure notice
/// is a JSON literal. Running the flat [`RedactionPlan::redact`] pass over
/// those *serialized* bytes is not safe, because a resolved value has
/// deliberately no minimum length and no required shape. A secret of `"`
/// matches every structural quote in the record and a secret of `,`, `{`, or
/// `:` matches every delimiter, so a textual pass rewrites JSON syntax into
/// placeholder text and emits a line no log pipeline can parse; a secret equal
/// to `level`, `target`, or `message` rewrites the schema's own field names.
///
/// So the record is parsed, redacted per *value*, and reserialized:
///
/// * object **keys** are never rewritten. They are the compile-time-static
///   field names of the tracing/serde schema (plus, in access records, header
///   names), never an interpolated config value, so they are not a leak
///   channel — and rewriting one would silently change the record's schema for
///   every downstream consumer. `level` stays `level` even when `level` is
///   itself a resolved secret; its occurrences in *values* are still redacted.
/// * string **values** are matched after unescaping, so JSON escaping cannot
///   smuggle a value past the scan and the reserializer re-escapes correctly.
///   (The escaped form stays a candidate in its own right — for
///   [`redact_external_secret_values`], which does filter raw text, and for the
///   pre-parse screen, which sees the record already escaped.)
/// * numeric, boolean, and null **values** are matched against their rendered
///   form — an externally resolved port or flag is a scalar in the record, not
///   a string — and a match replaces the whole scalar with the placeholder
///   string. All three unquoted scalar forms are treated alike; leaving any of
///   them out would emit that value's own representation.
/// * field **order** is preserved (see [`LogJson`]), so a redacted record
///   differs from an unredacted one only in the values that were redacted.
///
/// Fail-closed: a record that is not well-formed JSON, or that cannot be
/// reserialized, cannot be sanitized without risking either a leak or a
/// corrupt line, so it is replaced with [`withheld_log_record`] — a fixed,
/// valid JSON line whose own field values have themselves been through this
/// same structural redaction, so a short exact secret that happens to equal
/// `WARN` or `ferrum_edge::secrets` is not disclosed by the very record that
/// exists to withhold one. The candidate is never emitted on any failure path.
/// This costs the operator one anomalous diagnostic rather than a secret.
///
/// Callers on the hot path pay one relaxed atomic load when no external secret
/// was ever resolved, and one allocation-free scan
/// ([`RedactionPlan::contains_candidate`]) when one was but this record does
/// not contain it — parsing and copying happen only for records that actually
/// carry a resolved value.
pub(crate) fn redact_log_record(record: &mut Vec<u8>) {
    if !REDACTION_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let Some(plan) = redaction_plan() else {
        return;
    };

    let trailing_newline = record.last() == Some(&b'\n');
    // Scoped so the immutable borrow of `record` ends before the assignment.
    let outcome = match std::str::from_utf8(record) {
        // Non-UTF-8 bytes cannot be scanned at all, so this record cannot be
        // shown to be free of a resolved value. Unreachable for the three
        // producers above; withhold rather than guess.
        Err(_) => Some(withheld_record(plan, trailing_newline)),
        Ok(text) if plan.contains_candidate(text) => Some(match plan.redact_json_record(text) {
            Some(mut redacted) => {
                if trailing_newline {
                    redacted.push('\n');
                }
                redacted.into_bytes()
            }
            None => withheld_record(plan, trailing_newline),
        }),
        // Nothing to redact: leave the record's bytes exactly as serialized.
        Ok(_) => None,
    };
    if let Some(outcome) = outcome {
        *record = outcome;
    }
}

/// Template for the record emitted in place of one that cannot be structurally
/// sanitized.
///
/// Deliberately a valid JSON object carrying the same stable `level`/`target`/
/// `message` keys the fmt layer emits, so a log pipeline sees a well-formed
/// line it can account for instead of a silent gap or a parse error. It is a
/// fixed literal with no interpolation, so it cannot carry a value *derived*
/// from the record it replaces.
///
/// It can still *collide* with one, though: a resolved value has deliberately
/// no minimum length, so an exact secret of `WARN`, `secret`, `values`, or
/// `ferrum_edge::secrets` is present verbatim in this literal's own field
/// values. Emitting the template unchanged would therefore disclose a short
/// exact secret on the one path that exists to prevent disclosure. So the
/// template is passed through the *same* structural redaction as every other
/// record when the plan is built, and [`withheld_log_record`] is what is
/// actually emitted. See [`RedactionPlan::build`].
pub const WITHHELD_LOG_RECORD: &str = concat!(
    r#"{"level":"WARN","target":"ferrum_edge::secrets","#,
    r#""message":"log record withheld: it is not well-formed JSON and could not be checked for externally resolved secret values"}"#
);

/// Fallback when even [`WITHHELD_LOG_RECORD`] cannot be reserialized.
///
/// A valid, minimal, candidate-free JSON object. Its two bytes are JSON syntax
/// rather than content derived from any value, exactly like the delimiters and
/// schema keys the structural redactor already leaves alone.
const MINIMAL_WITHHELD_LOG_RECORD: &str = "{}";

/// The withheld-record line for this process, with any externally resolved
/// value already removed from its field values.
///
/// Returns the bare template before redaction is armed, where there is nothing
/// to collide with.
pub fn withheld_log_record() -> &'static str {
    match redaction_plan() {
        Some(plan) => plan.withheld_record.as_str(),
        None => WITHHELD_LOG_RECORD,
    }
}

fn withheld_record(plan: &RedactionPlan, trailing_newline: bool) -> Vec<u8> {
    let mut bytes = plan.withheld_record.as_bytes().to_vec();
    if trailing_newline {
        bytes.push(b'\n');
    }
    bytes
}

/// An order-preserving JSON document, used only by [`redact_log_record`].
///
/// `serde_json::Value` stores objects in a `BTreeMap` — the `preserve_order`
/// feature is deliberately not enabled crate-wide, since it would change every
/// admin API response body — so round-tripping a record through it would
/// alphabetize the fields of every access-log line that happened to contain a
/// resolved value. Redaction must change values and nothing else, so objects
/// are held here as an ordered key/value list.
///
/// Depth is bounded by `serde_json`'s own recursion limit on the parse, which
/// also bounds the redaction walk and the reserialization.
enum LogJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<LogJson>),
    Object(Vec<(String, LogJson)>),
}

impl<'de> serde::Deserialize<'de> for LogJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LogJsonVisitor;

        impl<'de> serde::de::Visitor<'de> for LogJsonVisitor {
            type Value = LogJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<LogJson, E> {
                Ok(LogJson::Null)
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<LogJson, E> {
                Ok(LogJson::Bool(value))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<LogJson, E> {
                Ok(LogJson::Number(value.into()))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<LogJson, E> {
                Ok(LogJson::Number(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<LogJson, E> {
                serde_json::Number::from_f64(value)
                    .map(LogJson::Number)
                    .ok_or_else(|| E::custom("non-finite number"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<LogJson, E> {
                Ok(LogJson::String(value.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<LogJson, E> {
                Ok(LogJson::String(value))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<LogJson, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(LogJson::Array(items))
            }

            fn visit_map<A>(self, mut map: A) -> Result<LogJson, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, LogJson>()? {
                    entries.push(entry);
                }
                Ok(LogJson::Object(entries))
            }
        }

        deserializer.deserialize_any(LogJsonVisitor)
    }
}

impl serde::Serialize for LogJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeMap, SerializeSeq};

        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// Values are written to the environment and [`record_external_secret_keys`] is
/// called before any configuration is parsed, and neither is mutated
/// afterwards, so the candidate set is fixed for the process lifetime and is
/// built once on first use rather than per diagnostic. That matters because
/// [`redact_log_record`] runs per log record.
static REDACTION_PLAN: std::sync::OnceLock<RedactionPlan> = std::sync::OnceLock::new();

fn redaction_plan() -> Option<&'static RedactionPlan> {
    let keys = EXTERNAL_SECRET_KEYS.get()?;
    let plan = REDACTION_PLAN.get_or_init(|| {
        RedactionPlan::build(keys.iter().filter_map(|key| std::env::var(key).ok()))
    });
    (!plan.candidates.is_empty()).then_some(plan)
}

/// Derived forms of one resolved value, ordered by nothing in particular —
/// [`RedactionPlan::build`] dedups and orders them.
///
/// The expansion is deliberately small and enumerable rather than a general
/// normalization, so what is and is not covered can be audited:
///
/// 1. the value as materialized, and its `trim()`ed form (list and scalar
///    validators trim before echoing);
/// 2. each comma-separated segment, trimmed — `Vec<String>` parsing splits on
///    `,` and trims, and `EnvConfig::validate` echoes the *entry*, not the
///    whole variable (`Invalid FERRUM_CP_NAMESPACES entry '...'`);
/// 3. the ASCII upper/lowercase of each of the above, for case-normalizing
///    validators such as `FERRUM_TLS_EARLY_DATA_METHODS`;
/// 4. the reference rewrites this codebase performs on a value that names a
///    source — see [`derive_reference_forms`];
/// 5. the canonical rendering of a value that is parsed into a scalar — see
///    [`derive_scalar_forms`];
/// 6. the ASCII upper/lowercase of each of the above (again, for 4 and 5), and
/// 7. the JSON-escaped body of each of the above, because the tracing fmt
///    layer escapes the record before [`redact_log_record`] sees it.
///
/// Bounded at `(2 + MAX_LIST_SEGMENTS + MAX_REFERENCE_FORMS + MAX_SCALAR_FORMS)
/// * 3 * 2` forms per value — a fixed ceiling, not a function of message size —
/// so no configuration can turn candidate discovery into an amplification
/// vector. Each derivation below is a single deterministic rewrite of the value
/// itself, never a rewrite of another derived form, so the expansion stays
/// additive rather than combinatorial.
///
/// **Residual, deliberate:** a value with more than `MAX_LIST_SEGMENTS`
/// comma-separated segments contributes no per-segment candidates. Such a value
/// is a configuration list rather than credential material, and its whole and
/// trimmed forms are still redacted; the alternative is an unbounded candidate
/// set driven by attacker-influenced input.
fn derive_candidates(value: &str) -> Vec<String> {
    /// A value with more segments than this is a list, not a credential.
    const MAX_LIST_SEGMENTS: usize = 32;

    let mut forms: Vec<String> = vec![value.to_string(), value.trim().to_string()];

    let segments: Vec<&str> = value.split(',').collect();
    if segments.len() > 1 && segments.len() <= MAX_LIST_SEGMENTS {
        forms.extend(
            segments
                .into_iter()
                .map(|segment| segment.trim().to_string()),
        );
    }

    forms.extend(derive_reference_forms(value));
    forms.extend(derive_scalar_forms(value));

    let case_forms: Vec<String> = forms
        .iter()
        .flat_map(|form| [form.to_ascii_uppercase(), form.to_ascii_lowercase()])
        .collect();
    forms.extend(case_forms);

    let escaped_forms: Vec<String> = forms
        .iter()
        .filter_map(|form| json_escaped_body(form))
        .collect();
    forms.extend(escaped_forms);

    forms
}

/// Upper bound on the forms [`derive_reference_forms`] can return.
const MAX_REFERENCE_FORMS: usize = 5;

/// Rewrites this codebase performs on a resolved value that *names a source*,
/// before printing it back to an operator.
///
/// An externally resolved variable is not always consumed as opaque material.
/// `FERRUM_FRONTEND_TLS_CERT_PATH_FILE` can materialize a `vault://…` or
/// `file://…` URI, and `FERRUM_DB_URL_FILE` materializes a database URL; both
/// are then re-rendered by Ferrum itself before any diagnostic prints them, so
/// the value *as materialized* is not the string the operator sees:
///
/// * `tls::source::CertSourceUri::parse` splits `<scheme>://<identifier>?<query>`
///   and keeps only the identifier, and
///   `secrets::registry::SecretBackend::source` renders the completed fetch as
///   `<provider>:<identifier>` — one colon, no `//`. That is what lands in
///   `MaterializedMaterial`'s `source_id` and what a PEM-parse failure prints.
/// * a `file://` source is reported by its bare filesystem path, the scheme
///   stripped entirely (`CertSource::Path` / `load_file_material`).
/// * a database URL is echoed credential-redacted by
///   `config::db_backend::redact_url` (MongoDB TLS-conflict diagnostics, driver
///   error scrubbing), which rewrites userinfo and query values but leaves the
///   host, path, and remaining query of the resolved value intact.
///
/// Each of these is a deterministic function of the value that this code
/// already owns, so each is reproduced here rather than re-audited at every
/// print site. Non-URI values fall through and contribute nothing: the scheme
/// branch requires a literal `://` with an RFC-3986-shaped scheme, and
/// `redact_url`'s `<invalid-url>` sentinel is deliberately dropped — admitting
/// it would redact that fixed marker out of every unrelated diagnostic.
fn derive_reference_forms(value: &str) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    let trimmed = value.trim();

    if let Some((scheme, rest)) = trimmed.split_once("://")
        && !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        let identifier = rest.split('?').next().unwrap_or(rest);
        forms.push(format!("{scheme}:{identifier}"));
        forms.push(identifier.to_string());
        if identifier != rest {
            forms.push(format!("{scheme}:{rest}"));
            forms.push(rest.to_string());
        }
    }

    if trimmed.contains("://") {
        let redacted = crate::config::db_backend::redact_url(trimmed);
        if redacted != trimmed && redacted != "<invalid-url>" {
            forms.push(redacted);
        }
    }

    debug_assert!(forms.len() <= MAX_REFERENCE_FORMS);
    forms
}

/// Upper bound on the forms [`derive_scalar_forms`] can return.
const MAX_SCALAR_FORMS: usize = 2;

/// The canonical rendering of a resolved value that config parsing turns into a
/// typed scalar.
///
/// `EnvConfig` does not echo most values as written; it parses them and then
/// logs the parsed result. `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS_FILE=03601`
/// is warned about as `configured=3601`, and `FERRUM_TLS_NO_VERIFY_FILE=1` is
/// rendered `true` — neither of which is the string that was materialized, so
/// neither would match an exact-value candidate.
///
/// Only the two canonicalizations Ferrum actually performs are reproduced: the
/// boolean spellings `EnvValue for bool`/`AutoBool` accept (`true`/`1`,
/// `false`/`0`, case-insensitive after `trim()`), and integer/float
/// normalization through `Display`, which is what strips leading zeros, a `+`
/// sign, and exponent notation. Both are derived candidates and so carry the
/// 3-byte minimum, which is why a bare `1` contributes `true` but not `1`
/// itself — the exact value already covers that, without the minimum.
fn derive_scalar_forms(value: &str) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return forms;
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "true" | "1" => forms.push("true".to_string()),
        "false" | "0" => forms.push("false".to_string()),
        _ => {}
    }

    if let Ok(integer) = trimmed.parse::<i128>() {
        forms.push(integer.to_string());
    } else if let Ok(float) = trimmed.parse::<f64>()
        && float.is_finite()
    {
        forms.push(float.to_string());
    }

    debug_assert!(forms.len() <= MAX_SCALAR_FORMS);
    forms
}

/// The body of `value` as it appears inside a JSON string literal, or `None`
/// when escaping is a no-op (the overwhelmingly common case, and already
/// covered by the unescaped candidate).
fn json_escaped_body(value: &str) -> Option<String> {
    let encoded = serde_json::to_string(value).ok()?;
    let body = encoded.strip_prefix('"')?.strip_suffix('"')?;
    (body != value).then(|| body.to_string())
}

/// Pre-built, deduplicated, longest-first candidate set plus a first-byte
/// screen.
struct RedactionPlan {
    /// Non-empty strings ordered longest-first, so the scan below yields the
    /// longest match at any position.
    candidates: Vec<String>,
    /// `first_bytes[b]` is true when some candidate starts with byte `b`.
    /// Without it every position in every log record would run the full
    /// candidate list; with it the common no-match position costs one indexed
    /// bool load.
    first_bytes: [bool; 256],
    /// [`WITHHELD_LOG_RECORD`] with its own field values already redacted
    /// against `candidates`. Computed once here rather than per withheld
    /// record, which keeps the fail-closed path allocation-cheap and, more
    /// importantly, keeps it from depending on anything but the fixed template.
    withheld_record: String,
}

impl RedactionPlan {
    /// Minimum length for a *derived* candidate.
    ///
    /// The value exactly as materialized has no minimum — it is the secret, and
    /// neither does its JSON-escaped body, which is the same secret in the only
    /// other form a record can carry it in (see [`Self::build`]). A
    /// derived fragment shorter than this (a one-letter namespace entry, say)
    /// carries no meaningful secret content while matching constantly, which
    /// would shred every diagnostic the operator needs to read. Same threshold,
    /// and same reasoning, as `MIN_REDACTABLE_REFERENCE_LEN` in
    /// `secrets::registry`.
    const MIN_DERIVED_CANDIDATE_LEN: usize = 3;

    fn build<I: IntoIterator<Item = String>>(values: I) -> Self {
        let mut candidates: Vec<String> = Vec::new();
        for value in values {
            if value.is_empty() {
                continue;
            }
            candidates.push(value.clone());
            // The JSON-escaped body of the value *as materialized* is another
            // exact representation of the same secret, not a transformed
            // fragment, so it carries no minimum either. Without this, an exact
            // value whose escaped body is shorter than the derived minimum —
            // a one-character control such as tab (`\t`), carriage return
            // (`\r`), backspace (`\b`), or form feed (`\f`) — is present in a
            // serialized record only in its escaped form, which the filter
            // below drops. `contains_candidate` would then find nothing, the
            // record would never be parsed, and the secret would be emitted.
            // Unlike `"` or `\n`, those bytes need not produce an incidental
            // structural match to rescue the screen.
            if let Some(escaped) = json_escaped_body(&value) {
                candidates.push(escaped);
            }
            candidates.extend(
                derive_candidates(&value)
                    .into_iter()
                    .filter(|derived| derived.len() >= Self::MIN_DERIVED_CANDIDATE_LEN),
            );
        }
        // Distinct candidates only: two keys holding the same secret describe
        // one span, and a duplicate would otherwise be scanned (and charged
        // for) twice.
        candidates.sort_unstable();
        candidates.dedup();
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));

        let mut first_bytes = [false; 256];
        for candidate in &candidates {
            if let Some(&byte) = candidate.as_bytes().first() {
                first_bytes[byte as usize] = true;
            }
        }

        let mut plan = Self {
            candidates,
            first_bytes,
            withheld_record: String::new(),
        };
        // The fail-closed replacement is a record like any other: an exact
        // secret with no minimum length can equal one of the template's own
        // field values (`WARN`, `ferrum_edge::secrets`, `secret`, `values`), and
        // emitting the template verbatim would then disclose it on the one path
        // whose entire purpose is not to. Structural redaction rewrites those
        // values and leaves the schema keys and JSON syntax alone, exactly as
        // for a real record. Reserialization of a compile-time-constant valid
        // JSON object cannot fail, but the fallback is a minimal object rather
        // than the template so that "cannot sanitize" never means "emit
        // unsanitized".
        let withheld_record = plan
            .redact_json_record(WITHHELD_LOG_RECORD)
            .unwrap_or_else(|| MINIMAL_WITHHELD_LOG_RECORD.to_string());
        plan.withheld_record = withheld_record;
        plan
    }

    /// Allocation-free "is there anything to do here?" screen.
    ///
    /// [`redact_log_record`] runs per emitted record, and in a process that
    /// *does* use external secrets the overwhelming majority of records still
    /// contain no resolved value. This answers that question with the same
    /// first-byte screen [`Self::redact`] uses and without parsing, copying, or
    /// allocating, so only records that actually carry a value pay for the
    /// JSON round trip.
    fn contains_candidate(&self, text: &str) -> bool {
        let bytes = text.as_bytes();
        // Byte indexing is safe against UTF-8 boundaries here: every candidate
        // is valid UTF-8, so its first byte is a leading byte, and a leading
        // byte can never equal a continuation byte. A byte-prefix match
        // therefore cannot start mid-character.
        bytes.iter().enumerate().any(|(index, byte)| {
            self.first_bytes[*byte as usize]
                && self
                    .candidates
                    .iter()
                    .any(|candidate| bytes[index..].starts_with(candidate.as_bytes()))
        })
    }

    /// Parse one serialized log record, redact its values, and reserialize.
    ///
    /// `None` when the record is not well-formed JSON or cannot be
    /// reserialized; the caller withholds the record rather than emitting
    /// anything derived from it. See [`redact_log_record`] for why this is
    /// structural rather than a text pass.
    fn redact_json_record(&self, text: &str) -> Option<String> {
        let mut document: LogJson = serde_json::from_str(text).ok()?;
        self.redact_json_value(&mut document);
        serde_json::to_string(&document).ok()
    }

    /// Redact values in place, leaving object keys and JSON structure alone.
    fn redact_json_value(&self, value: &mut LogJson) {
        // A matched scalar is replaced *after* the match, so the borrow of
        // `value` taken by the pattern has ended by the time it is reassigned.
        let scalar_matches = match value {
            LogJson::String(text) => {
                let redacted = match self.redact(text) {
                    std::borrow::Cow::Owned(owned) => Some(owned),
                    std::borrow::Cow::Borrowed(_) => None,
                };
                if let Some(redacted) = redacted {
                    *text = redacted;
                }
                false
            }
            LogJson::Array(items) => {
                for item in items.iter_mut() {
                    self.redact_json_value(item);
                }
                false
            }
            // Keys are intentionally untouched: they are the schema's stable
            // field names, not interpolated configuration.
            LogJson::Object(entries) => {
                for (_key, entry) in entries.iter_mut() {
                    self.redact_json_value(entry);
                }
                false
            }
            // Scalars are unquoted in the record, so a resolved port or flag
            // is matched against its rendered form. A hit replaces the whole
            // scalar; partially rewriting a number would produce either a
            // different number or invalid JSON.
            LogJson::Bool(flag) => self.contains_candidate(if *flag { "true" } else { "false" }),
            LogJson::Number(number) => self.contains_candidate(&number.to_string()),
            // `null` is a rendered scalar exactly like `true` and `918273645`:
            // a resolved value of `null` that a validator echoes into a field
            // serialized as a JSON null is present in the record verbatim, so
            // leaving it alone would emit the secret's own representation.
            LogJson::Null => self.contains_candidate("null"),
        };
        if scalar_matches {
            *value = LogJson::String(EXTERNAL_SECRET_PLACEHOLDER.to_string());
        }
    }

    /// Single left-to-right pass over `message`, substituting the longest
    /// matching candidate at each position.
    ///
    /// The cursor only ever advances — past a matched candidate, or by one
    /// character — so every byte of the original is examined once and no
    /// generated placeholder text re-enters matching. Output is therefore
    /// bounded by `message.chars().count() * EXTERNAL_SECRET_PLACEHOLDER.len()`
    /// regardless of how many candidates exist or how short they are, and the
    /// work is `O(message.len() * candidates.len() * longest_candidate.len())`
    /// worst case, `O(message.len())` when nothing matches.
    ///
    /// Borrowed output on no match, so an unaffected log record is not copied.
    fn redact<'a>(&self, message: &'a str) -> std::borrow::Cow<'a, str> {
        let mut out: Option<String> = None;
        // Start of the not-yet-copied literal run, and the scan position.
        let mut copied = 0usize;
        let mut cursor = 0usize;

        while cursor < message.len() {
            let rest = &message[cursor..];

            // A span some earlier pass already redacted. `validate` filters the
            // returned error and then the log sink filters the whole record, so
            // without this the second pass would shred the first pass's
            // placeholders on every candidate that is a substring of the
            // placeholder itself (`value`, `external`, `source`, `a`) — bounded,
            // but it turns a readable diagnostic into noise. Skipping keeps
            // redaction idempotent.
            //
            // Overridden by a candidate at least as long as the placeholder, so
            // a resolved value that happens to *contain* the placeholder text
            // cannot use it as a shield.
            if rest.starts_with(EXTERNAL_SECRET_PLACEHOLDER)
                && !self.candidates.iter().any(|candidate| {
                    candidate.len() >= EXTERNAL_SECRET_PLACEHOLDER.len()
                        && rest.starts_with(candidate.as_str())
                })
            {
                // Left in the not-yet-copied literal run, so it is emitted
                // verbatim.
                cursor += EXTERNAL_SECRET_PLACEHOLDER.len();
                continue;
            }

            let first = rest.as_bytes()[0];
            if self.first_bytes[first as usize]
                && let Some(matched) = self
                    .candidates
                    .iter()
                    .find(|candidate| rest.starts_with(candidate.as_str()))
            {
                let out = out.get_or_insert_with(|| String::with_capacity(message.len()));
                out.push_str(&message[copied..cursor]);
                out.push_str(EXTERNAL_SECRET_PLACEHOLDER);
                cursor += matched.len();
                copied = cursor;
                continue;
            }
            // Advance a whole character, so `cursor` only ever sits on a
            // character boundary and the slicing above cannot panic on
            // multi-byte input.
            match rest.chars().next() {
                Some(next) => cursor += next.len_utf8(),
                None => break,
            }
        }

        match out {
            Some(mut out) => {
                out.push_str(&message[copied..]);
                std::borrow::Cow::Owned(out)
            }
            None => std::borrow::Cow::Borrowed(message),
        }
    }
}

// Azure Key Vault credential injection + reference parsing are exposed so the
// data-plane fetch path can be exercised against a local fake Key Vault with a
// pre-acquired bearer token (no Entra ID round trip). `AzureCredentials`
// carries `from_static_token()` for that injection.
#[cfg(feature = "secrets-azure")]
pub use azure::{AzureCredentials, parse_keyvault_reference as azure_parse_keyvault_reference};

/// Candidate derivation is deliberately private — the whole point of
/// [`RedactionPlan`] is that no caller can hand it a different candidate set —
/// and arming the process-wide plan is a one-shot `OnceLock`, so the external
/// suite can only exercise a single fixture set per test binary. These assert
/// the *individual* derivations directly, which keeps them from having to arm
/// candidates like `true` process-wide (that would rewrite unrelated boolean
/// assertions in every other test in the binary). End-to-end coverage that the
/// derived forms actually reach a diagnostic lives in
/// `tests/unit/secrets/redaction_tests.rs`.
#[cfg(test)]
mod derivation_tests {
    use super::{derive_reference_forms, derive_scalar_forms};

    #[test]
    fn provider_source_rendering_of_a_uri_is_derived() {
        // `SecretBackend::source` renders the completed fetch with one colon
        // and no `//`; that string becomes `MaterializedMaterial`'s source id
        // and is what a PEM parse failure prints.
        let forms = derive_reference_forms("vault://secret/data/gw#cert");
        assert!(forms.contains(&"vault:secret/data/gw#cert".to_string()));
        assert!(forms.contains(&"secret/data/gw#cert".to_string()));
    }

    #[test]
    fn a_uri_query_is_dropped_the_way_cert_source_uri_drops_it() {
        let forms = derive_reference_forms("vault://secret/data/gw?version=3");
        // The identifier `CertSourceUri::parse` keeps...
        assert!(forms.contains(&"vault:secret/data/gw".to_string()));
        // ...and the value as written, which some sites echo whole.
        assert!(forms.contains(&"vault:secret/data/gw?version=3".to_string()));
    }

    #[test]
    fn file_uri_contributes_its_scheme_stripped_path() {
        let forms = derive_reference_forms("file:///run/secrets/cert.pem");
        assert!(
            forms.contains(&"/run/secrets/cert.pem".to_string()),
            "TLS validation reports a file source by bare path: {forms:?}"
        );
    }

    #[test]
    fn credential_redacted_url_form_is_derived() {
        let forms = derive_reference_forms("mongodb://user:pass@secret-host/db?tls=true");
        assert!(
            forms
                .iter()
                .any(|form| form.contains("secret-host") && !form.contains("pass")),
            "the credential-redacted rendering still exposes host/path: {forms:?}"
        );
    }

    #[test]
    fn non_uri_values_derive_no_reference_forms() {
        for value in ["plain-secret", "/run/secrets/token", "not a url at all"] {
            assert!(
                derive_reference_forms(value).is_empty(),
                "{value} produced spurious reference candidates"
            );
        }
    }

    #[test]
    fn invalid_url_sentinel_is_never_admitted_as_a_candidate() {
        // Redacting `<invalid-url>` out of unrelated diagnostics would be a
        // pure loss: it is a fixed marker, not derived from the value.
        for value in ["://", "http://[", "scheme://"] {
            assert!(
                !derive_reference_forms(value).contains(&"<invalid-url>".to_string()),
                "{value} admitted the invalid-url sentinel"
            );
        }
    }

    #[test]
    fn canonical_number_and_boolean_renderings_are_derived() {
        // `configured=3601` after typed parsing, not the `03601` materialized.
        assert!(derive_scalar_forms("03601").contains(&"3601".to_string()));
        assert!(derive_scalar_forms(" 42 ").contains(&"42".to_string()));
        // `FERRUM_TLS_NO_VERIFY=1` renders as `true`.
        assert!(derive_scalar_forms("1").contains(&"true".to_string()));
        assert!(derive_scalar_forms("0").contains(&"false".to_string()));
        assert!(derive_scalar_forms("TRUE").contains(&"true".to_string()));
    }

    #[test]
    fn non_scalar_and_non_finite_values_derive_nothing() {
        for value in ["", "   ", "not-a-number", "inf", "NaN"] {
            assert!(
                derive_scalar_forms(value).is_empty(),
                "{value} produced spurious scalar candidates"
            );
        }
    }

    #[test]
    fn derivation_stays_within_its_declared_bounds() {
        // The `debug_assert!`s inside each function are the live bound; this
        // pins the worst case that exercises every branch at once.
        let both = "https://user:pass@host/path?query=1";
        assert!(derive_reference_forms(both).len() <= super::MAX_REFERENCE_FORMS);
        assert!(derive_scalar_forms("1").len() <= super::MAX_SCALAR_FORMS);
    }
}

#[cfg(all(test, any(feature = "secrets-aws", feature = "secrets-vault")))]
mod tests {
    use super::split_reference_field;

    #[test]
    fn split_reference_field_handles_optional_suffix() {
        assert_eq!(
            split_reference_field("secret/data/app#password"),
            ("secret/data/app", Some("password"))
        );
        assert_eq!(
            split_reference_field("secret/data/app"),
            ("secret/data/app", None)
        );
    }
}
