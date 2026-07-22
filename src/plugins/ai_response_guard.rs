//! AI Response Guard Plugin
//!
//! Validates and filters HTTP LLM response content before it reaches the client.
//! Complements `ai_prompt_shield` (which guards inputs) by providing output-side
//! guardrails including PII detection in responses, keyword/phrase blocklists,
//! and response format validation.
//!
//! Built-in PII patterns: SSN, credit card, email, US phone, API keys, AWS keys,
//! IPv4 addresses, and IBAN (shared with ai_prompt_shield).
//!
//! Actions: reject (return error to client), redact (replace matches with placeholders),
//! or warn (add metadata/headers but pass through). Native gRPC protobuf
//! messages are intentionally outside this JSON/SSE/text plugin's scope.

use async_trait::async_trait;
use regex::{NoExpand, Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

use super::utils::body_transform::is_json_content_type;
use super::utils::json_escape::escape_json_string;
use super::utils::sse::{
    SseReassembler, SseTextKind, is_text_event_stream_media_type,
    original_response_is_event_stream, parse_sse_data_frames, parse_sse_data_frames_checked,
};
use super::{Plugin, PluginResult, RequestContext};

static NEXT_RESPONSE_GUARD_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// JSON object keys that are structural metadata (IDs, timestamps, model
/// names, roles, etc.) and must never be redacted, even in `ScanMode::All`.
/// This protects timestamps and IDs that may incidentally match PII regexes.
const STRUCTURAL_KEY_COUNT: usize = 17;
const STRUCTURAL_KEYS: [&str; STRUCTURAL_KEY_COUNT] = [
    "id",
    "object",
    "created",
    "model",
    "role",
    "type",
    "index",
    "finish_reason",
    "stop_reason",
    "logprobs",
    "system_fingerprint",
    "usage",
    "input_tokens",
    "output_tokens",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
];

const CONFIG_KEYS: &[&str] = &[
    "action",
    "pii_patterns",
    "custom_pii_patterns",
    "blocked_phrases",
    "blocked_patterns",
    "scan_fields",
    "redaction_placeholder",
    "max_scan_bytes",
    "require_json",
    "required_fields",
    "max_completion_length",
];

const RESPONSE_VALIDATORS: &[&str] = &[
    "etag",
    "last-modified",
    "content-digest",
    "repr-digest",
    "digest",
    "content-md5",
];

/// Action to take when guarded content is detected in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GuardAction {
    Reject,
    Redact,
    Warn,
}

/// A named regex pattern for content detection.
#[derive(Debug)]
struct ContentPattern {
    name: String,
    regex: Regex,
    /// Pre-rendered redaction placeholder for this pattern, with `{type}`
    /// already substituted with `name`. Built once at config-load time so
    /// `redact_text` does not re-render the template per pattern per call.
    placeholder: String,
}

/// How to scan the response body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanMode {
    /// Only scan supported client-visible completion and tool-call fields.
    Content,
    /// Scan the entire response body as text.
    All,
}

pub struct AiResponseGuard {
    instance_id: u64,
    action: GuardAction,
    pii_patterns: Vec<ContentPattern>,
    blocked_phrases: Vec<ContentPattern>,
    /// All patterns (PII + blocked phrases) compiled into a single DFA for
    /// O(text_len) detection regardless of pattern count. Indices align with
    /// `pii_patterns ++ blocked_phrases`.
    detection_set: RegexSet,
    /// Total count of detection patterns (pii_patterns.len() + blocked_phrases.len()).
    /// Cached so we can short-circuit when no detection patterns are configured.
    detection_pattern_count: usize,
    scan_mode: ScanMode,
    max_scan_bytes: usize,
    /// True when action is Redact — enables transform_response_body.
    needs_body_transform: bool,
    /// True when the plugin has any active validation rule (patterns, phrases,
    /// `require_json`, `required_fields`, or `max_completion_length`). Drives
    /// response-body buffering — when no rule applies, the plugin is a no-op.
    has_validation_rules: bool,
    /// Optional: require response to be valid JSON.
    require_json: bool,
    /// Optional: required top-level JSON fields.
    required_fields: Vec<String>,
    /// Maximum allowed completion length in characters (0 = unlimited).
    max_completion_length: usize,
}

/// Built-in PII pattern definitions (shared with ai_prompt_shield and
/// ai_transcript_audit via [`crate::plugins::utils::ai_pii`]).
fn builtin_pii_pattern(name: &str) -> Option<&'static str> {
    crate::plugins::utils::ai_pii::builtin_pii_pattern(name)
}

impl AiResponseGuard {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_response_guard: config must be an object".to_string());
        }
        reject_unknown_keys(config, CONFIG_KEYS, "config")?;

        let action = match optional_string(config, "action")?.unwrap_or("reject") {
            "reject" => GuardAction::Reject,
            "redact" => GuardAction::Redact,
            "warn" => GuardAction::Warn,
            other => {
                return Err(format!(
                    "ai_response_guard: 'action' must be one of 'reject', 'redact', or 'warn', got {other:?}"
                ));
            }
        };

        let scan_mode = match optional_string(config, "scan_fields")?.unwrap_or("content") {
            "content" => ScanMode::Content,
            "all" => ScanMode::All,
            other => {
                return Err(format!(
                    "ai_response_guard: 'scan_fields' must be one of 'content' or 'all', got {other:?}"
                ));
            }
        };

        let redaction_template = optional_string(config, "redaction_placeholder")?
            .unwrap_or("[REDACTED:{type}]")
            .to_string();

        let max_scan_bytes =
            optional_positive_usize(config, "max_scan_bytes")?.unwrap_or(1_048_576);

        // Build PII pattern list
        let pii_pattern_names: Vec<String> =
            optional_string_vec(config, "pii_patterns")?.unwrap_or_default();

        let mut pii_patterns: Vec<ContentPattern> = Vec::new();

        for name in &pii_pattern_names {
            if let Some(regex_str) = builtin_pii_pattern(name) {
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let full_name = format!("pii:{}", name);
                        let placeholder = redaction_template.replace("{type}", &full_name);
                        pii_patterns.push(ContentPattern {
                            name: full_name,
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        // Built-in pattern failures are fatal so the operator
                        // is alerted instead of silently losing detection
                        // coverage. Symmetric with custom-pattern handling.
                        return Err(format!(
                            "ai_response_guard: failed to compile built-in PII pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            } else {
                return Err(format!(
                    "ai_response_guard: unknown built-in PII pattern '{}'",
                    name,
                ));
            }
        }

        // Add custom PII patterns
        if let Some(custom) = optional_array(config, "custom_pii_patterns")? {
            for (idx, entry) in custom.iter().enumerate() {
                if !entry.is_object() {
                    return Err(format!(
                        "ai_response_guard: 'custom_pii_patterns[{idx}]' must be an object"
                    ));
                }
                reject_unknown_keys(
                    entry,
                    &["name", "regex"],
                    &format!("custom_pii_patterns[{idx}]"),
                )?;
                let name = required_non_empty_string(entry, "custom_pii_patterns", idx, "name")?;
                let regex_str =
                    required_non_empty_string(entry, "custom_pii_patterns", idx, "regex")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let full_name = format!("pii:{}", name);
                        let placeholder = redaction_template.replace("{type}", &full_name);
                        pii_patterns.push(ContentPattern {
                            name: full_name,
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile custom PII pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        // Build blocked phrases list
        let mut blocked_phrases: Vec<ContentPattern> = Vec::new();
        if let Some(phrases) = optional_string_vec(config, "blocked_phrases")? {
            for (i, phrase) in phrases.iter().enumerate() {
                let phrase_str = phrase.as_str();
                if phrase_str.is_empty() {
                    return Err(format!(
                        "ai_response_guard: 'blocked_phrases[{i}]' must not be empty"
                    ));
                }
                // Treat as case-insensitive literal match
                let escaped = regex::escape(phrase_str);
                match Regex::new(&format!("(?i){}", escaped)) {
                    Ok(regex) => {
                        // Never derive a public identifier from the literal: the
                        // identifier appears in placeholders, metadata, logs,
                        // and reject bodies. Position is stable within a config
                        // and reveals no configured secret phrase.
                        let name = format!("blocked_phrase:{i}");
                        let placeholder = redaction_template.replace("{type}", &name);
                        blocked_phrases.push(ContentPattern {
                            name,
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile blocked phrase {}: {}",
                            i, e,
                        ));
                    }
                }
            }
        }

        // Build blocked regex patterns
        if let Some(patterns) = optional_array(config, "blocked_patterns")? {
            for (idx, entry) in patterns.iter().enumerate() {
                if !entry.is_object() {
                    return Err(format!(
                        "ai_response_guard: 'blocked_patterns[{idx}]' must be an object"
                    ));
                }
                reject_unknown_keys(
                    entry,
                    &["name", "regex"],
                    &format!("blocked_patterns[{idx}]"),
                )?;
                let name = required_non_empty_string(entry, "blocked_patterns", idx, "name")?;
                let regex_str = required_non_empty_string(entry, "blocked_patterns", idx, "regex")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let placeholder = redaction_template.replace("{type}", name);
                        blocked_phrases.push(ContentPattern {
                            name: name.to_string(),
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile blocked pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        let require_json = optional_bool(config, "require_json")?.unwrap_or(false);

        let required_fields: Vec<String> =
            optional_string_vec(config, "required_fields")?.unwrap_or_default();
        for (idx, field) in required_fields.iter().enumerate() {
            if field.is_empty() {
                return Err(format!(
                    "ai_response_guard: 'required_fields[{idx}]' must not be empty"
                ));
            }
        }

        let max_completion_length = optional_usize(config, "max_completion_length")?.unwrap_or(0);

        let has_validation_rules = !pii_patterns.is_empty()
            || !blocked_phrases.is_empty()
            || require_json
            || !required_fields.is_empty()
            || max_completion_length > 0;

        if !has_validation_rules {
            return Err(
                "ai_response_guard: no patterns, phrases, or validation rules configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let needs_body_transform = action == GuardAction::Redact
            && (!pii_patterns.is_empty() || !blocked_phrases.is_empty());

        // Build a single combined RegexSet for O(text_len) detection.
        // Patterns are already validated above (each compiled successfully
        // as an individual Regex), so RegexSet construction cannot fail
        // for syntax — but we still propagate any error defensively.
        let detection_pattern_count = pii_patterns.len() + blocked_phrases.len();
        let detection_set = RegexSet::new(
            pii_patterns
                .iter()
                .chain(blocked_phrases.iter())
                .map(|p| p.regex.as_str()),
        )
        .map_err(|e| {
            format!(
                "ai_response_guard: failed to build detection RegexSet: {}",
                e
            )
        })?;

        Ok(Self {
            instance_id: NEXT_RESPONSE_GUARD_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            action,
            pii_patterns,
            blocked_phrases,
            detection_set,
            detection_pattern_count,
            scan_mode,
            max_scan_bytes,
            needs_body_transform,
            has_validation_rules,
            require_json,
            required_fields,
            max_completion_length,
        })
    }

    /// Look up the pattern name at the given combined-index position
    /// (`pii_patterns ++ blocked_phrases`).
    fn pattern_name(&self, idx: usize) -> Option<&str> {
        let pii_len = self.pii_patterns.len();
        if idx < pii_len {
            self.pii_patterns.get(idx).map(|p| p.name.as_str())
        } else {
            self.blocked_phrases
                .get(idx - pii_len)
                .map(|p| p.name.as_str())
        }
    }

    /// Extract client-visible or executable completion text from supported AI
    /// response families.
    ///
    /// Adjacent text-bearing parts of one content array (and adjacent
    /// Anthropic text blocks / Gemini parts) are joined into one fragment, so
    /// detection and length enforcement see the logical completion the client
    /// renders rather than each part in isolation. Tool/function `arguments`
    /// contribute both the raw string and its decoded JSON tokens.
    fn extract_completion_texts<'a>(&self, json: &'a Value) -> Vec<Cow<'a, str>> {
        let mut texts = Vec::new();

        // OpenAI chat/completions, including multimodal content parts, refusal
        // strings, and tool calls. Buffered delta-shaped payloads use the same
        // selectors.
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                collect_string_value(choice.get("text"), &mut texts);
                for container in [choice.get("message"), choice.get("delta")]
                    .into_iter()
                    .flatten()
                {
                    collect_content_value(container.get("content"), &mut texts);
                    collect_string_value(container.get("refusal"), &mut texts);
                    collect_function_value(container.get("function_call"), &mut texts);
                    if let Some(tool_calls) = container.get("tool_calls").and_then(Value::as_array)
                    {
                        for tool_call in tool_calls {
                            collect_function_value(tool_call.get("function"), &mut texts);
                        }
                    }
                }
            }
        }

        // OpenAI Responses API buffered output.
        collect_string_value(json.get("output_text"), &mut texts);
        if let Some(output) = json.get("output").and_then(Value::as_array) {
            for item in output {
                collect_string_value(item.get("name"), &mut texts);
                collect_argument_value(item.get("arguments"), &mut texts);
                collect_content_value(item.get("content"), &mut texts);
            }
        }

        // Anthropic: content[].text, joining adjacent text blocks.
        if let Some(content) = json.get("content").and_then(|c| c.as_array()) {
            push_joined_adjacent_texts(
                content.iter().map(|block| {
                    if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                        block.get("text").and_then(|t| t.as_str())
                    } else {
                        None
                    }
                }),
                &mut texts,
            );
        }

        // Google Gemini: candidates[].content.parts[].text, joined per candidate.
        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get("content")
                    .and_then(|c| c.get("parts"))
                    .and_then(|p| p.as_array())
                {
                    push_joined_adjacent_texts(
                        parts
                            .iter()
                            .map(|part| part.get("text").and_then(|t| t.as_str())),
                        &mut texts,
                    );
                }
            }
        }

        texts
    }

    /// Detect content matches against all patterns. Returns names of detected matches.
    /// Uses a single `RegexSet` DFA pass per text fragment, O(text_len)
    /// regardless of pattern count.
    ///
    /// Generic over `AsRef<str>` so callers can pass borrowed `&str` slices
    /// (`ScanMode::Content`) or `Cow<str>` text (`ScanMode::All`, which must
    /// collect stringified JSON numbers that have no backing `&str`).
    fn detect_matches<S: AsRef<str>>(&self, texts: &[S]) -> Vec<String> {
        if self.detection_pattern_count == 0 {
            return Vec::new();
        }
        let mut hit = vec![false; self.detection_pattern_count];
        for text in texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        let mut detected = Vec::new();
        for (idx, &h) in hit.iter().enumerate() {
            if h && let Some(name) = self.pattern_name(idx) {
                detected.push(name.to_string());
            }
        }
        detected
    }

    /// `ScanMode::All` JSON detection: the union of two passes over the body.
    ///
    /// 1. Decoded walker (`collect_decoded_json_strings`): scans each JSON token
    ///    after serde has resolved `\uXXXX` and other escapes, so escaped PII in
    ///    string values, object keys, and numeric scalars is caught exactly as
    ///    the client will see it (issue #1720).
    /// 2. Raw-body pass: runs the `RegexSet` over the serialized response bytes.
    ///    The original all-mode scan was raw-only, and three coverage cases
    ///    depend on it: operator custom `blocked_patterns` that span JSON context
    ///    (e.g. `"role"\s*:\s*"tool"`), which testing key and value as separate
    ///    tokens never reconstructs; numeric/scalar shapes serialized only in the
    ///    raw bytes; and duplicate object members, whose overwritten value is
    ///    dropped from the parsed `Value` but is still delivered to the client.
    ///
    /// Unioning the two only ever *adds* detections, so this strictly hardens
    /// all-mode coverage. `raw` may be `None` when the serialized bytes are not
    /// valid UTF-8 (the body still parsed via `from_slice`), in which case only
    /// the decoded pass runs.
    ///
    /// Accepted trade-off: because pass 1 evaluates each decoded value in
    /// isolation, an *anchored* custom `blocked_pattern` (e.g. `^done$`) that an
    /// operator authored against the whole serialized body will additionally fire
    /// on a lone scalar value (`{"finish_reason":"done"}`). This is intentional
    /// and load-bearing for `ScanMode::All`: the decoded per-value pass is exactly
    /// what closes the escaped-PII gap (#1720) — a value encoded as `done`
    /// must be caught after decoding — so restricting custom patterns to
    /// whole-body-only would reopen that bypass for them. Operators who need
    /// strictly whole-body matching can keep the anchor and rely on raw-pass
    /// semantics in `ScanMode::Content`, or write the pattern to include the JSON
    /// context (`"finish_reason"\s*:\s*"done"`) so the lone token does not match.
    fn detect_matches_in_decoded_json(&self, json: &Value, raw: Option<&str>) -> Vec<String> {
        if self.detection_pattern_count == 0 {
            return Vec::new();
        }
        let mut hit = vec![false; self.detection_pattern_count];
        // Pass 1: decoded tokens, plus decoded tool/function-argument tokens
        // so scan-all keeps parity with content mode on nested JSON escapes.
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(json, &mut texts);
        collect_decoded_argument_tokens(json, &mut texts);
        for text in &texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        // Pass 2: raw serialized body (cross-token / contextual / duplicate-key).
        if let Some(raw) = raw {
            for idx in self.detection_set.matches(raw).into_iter() {
                hit[idx] = true;
            }
        }
        let mut detected = Vec::new();
        for (idx, &h) in hit.iter().enumerate() {
            if h && let Some(name) = self.pattern_name(idx) {
                detected.push(name.to_string());
            }
        }
        detected
    }

    /// `ScanMode::All` SSE detection: the union of decoded parsed frames and a
    /// raw-body pass.
    ///
    /// `parse_sse_data_frames` silently drops `data:` payloads that are not JSON
    /// (a plain `data: user@example.com` frame, or malformed JSON), so scanning
    /// only the parsed frames would let blocked content in unparseable SSE data
    /// bypass scan-all policies. Running the `RegexSet` over the raw body too
    /// restores the original whole-body coverage for those payloads, while the
    /// decoded-frame pass adds `\uXXXX`-escaped detection (issue #1720).
    /// `raw` is `None` only when the body is not valid UTF-8.
    fn detect_matches_in_decoded_sse_frames(
        &self,
        frames: &[Value],
        raw: Option<&str>,
    ) -> Vec<String> {
        if self.detection_pattern_count == 0 {
            return Vec::new();
        }
        let mut hit = vec![false; self.detection_pattern_count];
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        for frame in frames {
            collect_decoded_json_strings(frame, &mut texts);
            collect_decoded_argument_tokens(frame, &mut texts);
        }
        for text in &texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        // Scan the coherent client-visible/executable stream as well as each
        // decoded frame. In particular, Responses API argument deltas are a
        // serialized JSON document that may span events; only reassembly can
        // expose JSON escapes such as `\u0040` to the detector.
        let accumulated = self.extract_sse_completion_texts(frames);
        for text in &accumulated {
            for idx in self.detection_set.matches(text).into_iter() {
                hit[idx] = true;
            }
        }
        if let Some(raw) = raw {
            for idx in self.detection_set.matches(raw).into_iter() {
                hit[idx] = true;
            }
        }
        let mut detected = Vec::new();
        for (idx, &h) in hit.iter().enumerate() {
            if h && let Some(name) = self.pattern_name(idx) {
                detected.push(name.to_string());
            }
        }
        detected
    }

    /// Replace all pattern matches with the redaction placeholder.
    /// Placeholders are pre-rendered at construction time so each call is one
    /// `replace_all` per pattern, with no template formatting on the hot path.
    ///
    /// The placeholder is wrapped in `regex::NoExpand` so `$`-sequences in it
    /// (e.g. an operator pattern name like `cost $5`, or a malicious `$1` in
    /// `redaction_placeholder`) are emitted literally rather than being
    /// interpreted as capture-group references by the regex `Replacer`.
    fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            result = pattern
                .regex
                .replace_all(&result, NoExpand(pattern.placeholder.as_str()))
                .to_string();
        }
        result
    }

    /// Remove every rendered redaction placeholder from `text`.
    ///
    /// The residual re-scan (`redact_leaves_residual`) runs the detection
    /// `RegexSet` over the body *after* redaction. Placeholders embed the
    /// pattern identity — e.g. the default template makes a blocked phrase
    /// render as `[REDACTED:blocked_phrase:0]`, and PII/custom names render as
    /// `[REDACTED:pii:ssn]` / `[REDACTED:<custom name>]`. Those
    /// marker strings can themselves match a configured expression (for
    /// example, a custom name can coincide with its own regex), making a
    /// fully-redactable body look like it still carries residual content and
    /// forcing a false 502.
    /// Stripping the placeholders before the residual scan looks only at the
    /// bytes that will actually be delivered, not at text the redactor itself
    /// wrote. Placeholders are fixed strings rendered at construction, so this
    /// is a plain substring removal with no regex on the hot path.
    fn strip_known_placeholders(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            if result.contains(pattern.placeholder.as_str()) {
                result = result.replace(pattern.placeholder.as_str(), "");
            }
        }
        result
    }

    /// `ScanMode::All` redact mode: after applying the same redaction the
    /// response transform performs, decide whether any *unredactable* PII still
    /// remains, so the caller can fail closed (reject) instead of forwarding the
    /// body while reporting it `redacted`.
    ///
    /// The all-mode redactor rewrites JSON string values (with serialized
    /// argument documents handled structurally), but cannot rewrite PII carried
    /// in an object key, a numeric scalar, a cross-token/contextual custom
    /// pattern, or a duplicate-key value dropped from the parsed tree. Because
    /// all-mode detection now unions a raw-body pass, those are detected — so
    /// without this re-scan the plugin would emit false "redacted" telemetry
    /// while still delivering the PII.
    ///
    /// This mirrors `redact_json_strings`' structural carve-out: top-level
    /// structural scalar values (`model`, `id`, token counts, …) are deliberately
    /// preserved even when they incidentally match a PII regex, so they are NOT
    /// residual leaks. To run the same union detection without those preserved
    /// scalars re-triggering, the re-scan is done on a copy whose top-level
    /// structural scalars are blanked to an empty string. Blanking only the
    /// scalar values keeps the surrounding JSON structure intact, so a contextual
    /// pattern such as `"role"\s*:` still matches while a preserved
    /// `"created": 1700000000` no longer does.
    ///
    /// The residual scan also strips the redactor's own placeholder markers
    /// (`strip_known_placeholders`) before matching: a successfully redacted
    /// custom pattern can render an identifier that matches its own regex. The
    /// marker would otherwise report a false residual leak (turning a fully
    /// redacted body into a spurious 502).
    fn redact_leaves_residual(&self, original: &Value) -> bool {
        if self.detection_pattern_count == 0 {
            return false;
        }
        let mut redacted = original.clone();
        self.redact_all_strings_with_argument_shield(&mut redacted);
        blank_top_level_structural_scalars(&mut redacted);

        // Union the same two passes as `detect_matches_in_decoded_json`, but run
        // each over text with the redactor's placeholder markers removed so the
        // markers cannot re-trigger their own pattern.
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(&redacted, &mut texts);
        collect_decoded_argument_tokens(&redacted, &mut texts);
        for text in &texts {
            let cleaned = self.strip_known_placeholders(text.as_ref());
            if self.detection_set.is_match(&cleaned) {
                return true;
            }
        }
        let serialized = self.strip_known_placeholders(&redacted.to_string());
        self.detection_set.is_match(&serialized)
    }

    /// `ScanMode::Content` redact mode: decide whether the structured redactor
    /// would leave detectable content in the extracted completion texts, so
    /// the caller can fail closed (reject) instead of forwarding the body
    /// while reporting it `redacted`. Two shapes are detectable but not
    /// rewritable: a match that exists only across adjacent content-array
    /// parts (each part alone is clean, so per-part redaction rewrites
    /// nothing), and tool-argument content the argument redactor cannot
    /// rewrite (a decoded object key or numeric scalar).
    fn content_redact_leaves_residual(&self, original: &Value) -> bool {
        if self.detection_pattern_count == 0 {
            return false;
        }
        let mut redacted = original.clone();
        self.redact_response_json(&mut redacted);
        let texts = self.extract_completion_texts(&redacted);
        texts.iter().any(|text| {
            self.detection_set
                .is_match(&self.strip_known_placeholders(text.as_ref()))
        })
    }

    /// `ScanMode::All` redact mode, SSE bodies: decide whether redaction would
    /// leave residual detectable content, so the caller can fail closed instead
    /// of forwarding the original bytes while reporting them `redacted`.
    ///
    /// The SSE transform (`redact_sse_body`) only rewrites `data:` payloads that
    /// parse as JSON. A plaintext or malformed `data:` frame (e.g.
    /// `data: contact user@example.com`) is matched by the raw-body union in
    /// detection but cannot be rewritten. This mirrors the JSON
    /// `redact_leaves_residual` fail-closed: run the same redaction the transform
    /// performs, then re-scan the client-visible candidate (with the redactor's
    /// own placeholder markers and preserved structural scalars excluded). If
    /// unrewritable content still matches, the caller must reject.
    fn redact_sse_leaves_residual(&self, body: &[u8]) -> bool {
        if self.detection_pattern_count == 0 {
            return false;
        }
        // Scan the exact bytes the client would receive: transformed output
        // when redaction changed an event, otherwise the original framing.
        // The residual pass masks only preserved top-level structural scalar
        // spans, so duplicate keys and formatting remain visible and matches in
        // cross-event, key, numeric, or non-data content still fail closed.
        let redacted = self.redact_sse_body(body);
        self.sse_body_has_residual(redacted.as_deref().unwrap_or(body))
    }

    /// Re-scan an SSE body produced by [`Self::redact_sse_body`]. Scan-all
    /// redaction deliberately preserves top-level structural scalar values in
    /// each JSON event, matching the buffered JSON path. Blank those values in
    /// both decoded and raw/contextual passes so an IP-shaped `id` does not
    /// cause a false residual, while keys, numbers outside the carve-out,
    /// non-`data:` fields, and cross-token patterns remain fail-closed.
    fn sse_body_has_residual(&self, redacted: &[u8]) -> bool {
        let Ok(redacted_str) = std::str::from_utf8(redacted) else {
            // Redacted output is not valid UTF-8 — cannot re-scan safely, so
            // fail closed rather than risk forwarding undetectable residual.
            return true;
        };
        let parsed = parse_sse_data_frames_checked(redacted);
        if !parsed.fully_parsed {
            return true;
        }
        let mut frames = parsed.frames;
        if self.scan_mode == ScanMode::Content {
            let accumulated = self.extract_sse_completion_texts(&frames);
            return accumulated.iter().any(|text| {
                self.detection_set
                    .is_match(&self.strip_known_placeholders(text))
            });
        }

        // Reassemble while event routing metadata (`type`, indexes) is still
        // present. Structural masking is only for the decoded-token and raw
        // residual passes; doing it first would hide Responses delta kinds and
        // let a match split across their argument events escape this re-scan.
        let accumulated = self.extract_sse_completion_texts(&frames);

        for frame in &mut frames {
            blank_top_level_structural_scalars(frame);
        }
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        for frame in &frames {
            collect_decoded_json_strings(frame, &mut texts);
            collect_decoded_argument_tokens(frame, &mut texts);
        }
        for text in &texts {
            let cleaned = self.strip_known_placeholders(text.as_ref());
            if self.detection_set.is_match(&cleaned) {
                return true;
            }
        }

        for text in &accumulated {
            let cleaned = self.strip_known_placeholders(text);
            if self.detection_set.is_match(&cleaned) {
                return true;
            }
        }

        // Keep the raw/contextual pass without letting preserved structural
        // scalar values re-trigger it. Mask only their exact raw byte spans:
        // canonicalizing parsed frames here would drop duplicate members or
        // whitespace that the client still receives when no transform occurs.
        let Some(sanitized) = mask_sse_top_level_structural_scalars(redacted_str) else {
            return true;
        };
        let cleaned_raw = self.strip_known_placeholders(&sanitized);
        self.detection_set.is_match(&cleaned_raw)
    }

    fn redact_string_value(&self, value: &mut Value) {
        let Some(text) = value.as_str() else {
            return;
        };
        let redacted = self.redact_text(text);
        if redacted != text {
            *value = Value::String(redacted);
        }
    }

    fn redact_content_value(&self, value: &mut Value) {
        if value.is_string() {
            self.redact_string_value(value);
            return;
        }
        if let Some(parts) = value.as_array_mut() {
            for part in parts {
                if let Some(text) = part.get_mut("text") {
                    self.redact_string_value(text);
                }
                if let Some(refusal) = part.get_mut("refusal") {
                    self.redact_string_value(refusal);
                }
            }
        }
    }

    fn redact_function_value(&self, value: &mut Value) {
        if let Some(name) = value.get_mut("name") {
            self.redact_string_value(name);
        }
        if let Some(arguments) = value.get_mut("arguments") {
            self.redact_arguments_value(arguments);
        }
    }

    /// Redact a tool/function `arguments` string.
    ///
    /// When the string parses as JSON, only its decoded string values are
    /// redacted and the document re-serialized,
    /// so JSON escapes such as `\u0040` cannot carry content past redaction.
    /// Re-serialization is semantically transparent to the tool client, which
    /// parses the arguments as JSON. Matches carried in structurally
    /// unrewritable positions — decoded object keys and numeric scalars — are
    /// deliberately left in place for the residual re-scan to fail closed on;
    /// raw string replacement over the serialized document would instead
    /// rename keys or turn a numeric document into non-JSON placeholder text
    /// and erase the evidence that re-scan needs. A non-JSON arguments string
    /// is plain text and is redacted directly.
    fn redact_arguments_value(&self, value: &mut Value) {
        let Some(text) = value.as_str() else {
            return;
        };
        let Ok(mut decoded) = serde_json::from_str::<Value>(text) else {
            self.redact_string_value(value);
            return;
        };
        let original = decoded.clone();
        redact_json_strings(
            &mut decoded,
            &self.pii_patterns,
            &self.blocked_phrases,
            false,
        );
        if decoded != original
            && let Ok(rewritten) = serde_json::to_string(&decoded)
        {
            *value = Value::String(rewritten);
        }
    }

    /// `ScanMode::All` raw string redaction with tool/function argument
    /// documents handled structurally.
    ///
    /// To the generic raw pass (`redact_json_strings`) a serialized argument
    /// document is just another string value, so it would rewrite a match in
    /// a decoded object key or numeric scalar into a renamed key or non-JSON
    /// placeholder text — and erase the evidence the residual re-scan needs
    /// to fail closed on. Argument strings therefore first get the decoded
    /// value-safe redaction (`redact_arguments_value`) and are then shielded
    /// from the raw pass; argument positions holding non-string values keep
    /// today's raw pass behavior. Both visits see the same positions in the
    /// same order because shielding substitutes `Value::Null` without changing
    /// the surrounding structure.
    fn redact_all_strings_with_argument_shield(&self, json: &mut Value) {
        let mut shielded: Vec<Option<Value>> = Vec::new();
        for_each_argument_value(json, &mut |value| {
            self.redact_arguments_value(value);
            let arguments = if value.is_string() {
                Some(value.take())
            } else {
                None
            };
            shielded.push(arguments);
        });
        redact_json_strings(json, &self.pii_patterns, &self.blocked_phrases, true);
        let mut restored = shielded.into_iter();
        for_each_argument_value(json, &mut |value| {
            if let Some(Some(arguments)) = restored.next() {
                *value = arguments;
            }
        });
    }

    fn redact_message_like(&self, value: &mut Value) {
        if let Some(content) = value.get_mut("content") {
            self.redact_content_value(content);
        }
        if let Some(refusal) = value.get_mut("refusal") {
            self.redact_string_value(refusal);
        }
        if let Some(function_call) = value.get_mut("function_call") {
            self.redact_function_value(function_call);
        }
        if let Some(tool_calls) = value.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for tool_call in tool_calls {
                if let Some(function) = tool_call.get_mut("function") {
                    self.redact_function_value(function);
                }
            }
        }
    }

    /// Redact content in supported AI response JSON shapes.
    fn redact_response_json(&self, json: &mut Value) {
        if let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                if let Some(text) = choice.get_mut("text") {
                    self.redact_string_value(text);
                }
                if let Some(message) = choice.get_mut("message") {
                    self.redact_message_like(message);
                }
                if let Some(delta) = choice.get_mut("delta") {
                    self.redact_message_like(delta);
                }
            }
        }

        if let Some(output_text) = json.get_mut("output_text") {
            self.redact_string_value(output_text);
        }
        if let Some(output) = json.get_mut("output").and_then(Value::as_array_mut) {
            for item in output {
                if let Some(name) = item.get_mut("name") {
                    self.redact_string_value(name);
                }
                if let Some(arguments) = item.get_mut("arguments") {
                    self.redact_arguments_value(arguments);
                }
                if let Some(content) = item.get_mut("content") {
                    self.redact_content_value(content);
                }
            }
        }

        // Anthropic: content[].text
        if let Some(content) = json.get_mut("content").and_then(|c| c.as_array_mut()) {
            for block in content.iter_mut() {
                if block.get("type").and_then(|t| t.as_str()) == Some("text")
                    && let Some(text) = block.get("text").and_then(|t| t.as_str())
                {
                    let redacted = self.redact_text(text);
                    if redacted != text {
                        block["text"] = Value::String(redacted);
                    }
                }
            }
        }

        // Google Gemini: candidates[].content.parts[].text
        if let Some(candidates) = json.get_mut("candidates").and_then(Value::as_array_mut) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get_mut("content")
                    .and_then(|c| c.get_mut("parts"))
                    .and_then(|p| p.as_array_mut())
                {
                    for part in parts {
                        if let Some(text) = part.get_mut("text") {
                            self.redact_string_value(text);
                        }
                    }
                }
            }
        }
    }

    /// Shared action handler for detected PII/blocked content.
    fn mark_rejected(ctx: &mut RequestContext, reason: impl Into<String>) {
        ctx.metadata
            .insert("ai_response_guard_rejected".to_string(), reason.into());
    }

    fn respond_to_detection(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        detected: &[String],
    ) -> PluginResult {
        match self.action {
            GuardAction::Reject => {
                debug!(
                    "ai_response_guard: content detected (types: {:?}), rejecting response",
                    detected
                );
                Self::mark_rejected(ctx, detected.join(","));
                let types_json: Vec<String> = detected
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json_string(t)))
                    .collect();
                PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that was blocked before delivery."}}"#,
                        types_json.join(","),
                    ),
                    headers: HashMap::new(),
                }
            }
            GuardAction::Warn => {
                warn!(
                    "ai_response_guard: content detected (types: {:?}), passing through (warn mode)",
                    detected
                );
                ctx.metadata
                    .insert("ai_response_guard_detected".to_string(), detected.join(","));
                PluginResult::Continue
            }
            GuardAction::Redact => {
                if !super::response_body_rewrite_allowed(response_status) {
                    debug!(
                        response_status,
                        "ai_response_guard: governed range/delta response cannot be safely redacted; rejecting"
                    );
                    Self::mark_rejected(ctx, detected.join(","));
                    let types_json: Vec<String> = detected
                        .iter()
                        .map(|t| format!("\"{}\"", escape_json_string(t)))
                        .collect();
                    return PluginResult::Reject {
                        status_code: 502,
                        body: format!(
                            r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                            types_json.join(","),
                        ),
                        headers: HashMap::new(),
                    };
                }
                ctx.metadata
                    .insert("ai_response_guard_redacted".to_string(), detected.join(","));
                if ctx.deduplication_replay_response_finalized {
                    ctx.ai_response_guard_replay_redactions
                        .insert(self.instance_id);
                }
                PluginResult::Continue
            }
        }
    }

    fn respond_to_uninspectable(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
        message: &'static str,
    ) -> PluginResult {
        let must_reject = self.require_json
            || !self.required_fields.is_empty()
            || self.action != GuardAction::Warn;
        if must_reject {
            Self::mark_rejected(ctx, reason);
            PluginResult::Reject {
                status_code: 502,
                body: format!(
                    r#"{{"error":"AI response guard could not safely inspect the response","reason":"{}"}}"#,
                    escape_json_string(message)
                ),
                headers: HashMap::new(),
            }
        } else {
            ctx.metadata
                .insert("ai_response_guard_warning".to_string(), reason.to_string());
            PluginResult::Continue
        }
    }

    /// Check max completion length constraint.
    ///
    /// `max_completion_length` is documented and configured in **characters**
    /// (Unicode scalar values), so the measurement uses `chars().count()`
    /// rather than `str::len()` (UTF-8 bytes). Counting bytes would trip the
    /// guard early for multibyte completions (CJK, emoji, accented Latin),
    /// rejecting or warning before the operator-configured character limit.
    fn check_completion_length<S: AsRef<str>>(&self, texts: &[S]) -> Option<String> {
        if self.max_completion_length == 0 {
            return None;
        }
        for text in texts {
            let char_len = text.as_ref().chars().count();
            if char_len > self.max_completion_length {
                return Some(format!(
                    "Completion length {} exceeds maximum {}",
                    char_len, self.max_completion_length
                ));
            }
        }
        None
    }

    /// Extract and concatenate completion texts from parsed SSE frames.
    ///
    /// Handles the streaming formats:
    /// - OpenAI: `choices[].delta.content` keyed by choice `index`, plus
    ///   legacy `function_call` name/argument deltas and `delta.refusal`
    /// - OpenAI Responses: reassembler deltas plus `response.refusal.delta`
    /// - Anthropic: `content_block_delta` events with `delta.text` keyed by block `index`
    /// - Gemini: `candidates[].content.parts[].text` keyed by candidate position
    ///
    /// Returns one accumulated `String` per choice/block index, ordered by
    /// index (BTreeMap keeps output deterministic across runs). Accumulated
    /// tool/function argument strings additionally contribute their decoded
    /// JSON tokens so escapes cannot hide content from detection.
    fn extract_sse_completion_texts(&self, frames: &[Value]) -> Vec<String> {
        let mut reassembler = SseReassembler::default();
        let mut provider_texts: std::collections::BTreeMap<(u8, usize), String> =
            std::collections::BTreeMap::new();

        for frame in frames {
            // Shared OpenAI chat/completions + Responses API reassembly covers
            // prose, tool/function names and arguments, and Responses deltas.
            reassembler.push_frame(frame);

            // Legacy Chat Completions streamed `function_call` before the
            // indexed `tool_calls` shape. Keep name and arguments in separate
            // accumulators so neither field can hide a cross-frame match.
            // Chat refusal deltas (`delta.refusal`) are client-visible text
            // and accumulate the same way.
            if let Some(choices) = frame.get("choices").and_then(Value::as_array) {
                for (position, choice) in choices.iter().enumerate() {
                    let index = choice
                        .get("index")
                        .and_then(Value::as_u64)
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or(position);
                    if let Some(function_call) = choice
                        .get("delta")
                        .and_then(|delta| delta.get("function_call"))
                    {
                        if let Some(name) = function_call.get("name").and_then(Value::as_str) {
                            provider_texts.entry((2, index)).or_default().push_str(name);
                        }
                        if let Some(arguments) =
                            function_call.get("arguments").and_then(Value::as_str)
                        {
                            provider_texts
                                .entry((3, index))
                                .or_default()
                                .push_str(arguments);
                        }
                    }
                    if let Some(refusal) = choice
                        .get("delta")
                        .and_then(|delta| delta.get("refusal"))
                        .and_then(Value::as_str)
                    {
                        provider_texts
                            .entry((4, index))
                            .or_default()
                            .push_str(refusal);
                    }
                }
            }

            // Responses API refusal deltas (`response.refusal.delta`) carry a
            // client-visible refusal string outside the reassembler's coverage.
            if frame
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|event_type| event_type.ends_with("refusal.delta"))
                && let Some(delta) = frame.get("delta").and_then(Value::as_str)
            {
                let index = frame
                    .get("output_index")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(0);
                provider_texts
                    .entry((5, index))
                    .or_default()
                    .push_str(delta);
            }

            // Anthropic streaming: type=content_block_delta, delta.text
            if frame.get("type").and_then(|t| t.as_str()) == Some("content_block_delta") {
                let index = frame.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                if let Some(text) = frame
                    .get("delta")
                    .and_then(|d| d.get("text"))
                    .and_then(|t| t.as_str())
                {
                    provider_texts.entry((0, index)).or_default().push_str(text);
                }
            }

            // Gemini: candidates[].content.parts[].text
            if let Some(candidates) = frame.get("candidates").and_then(|c| c.as_array()) {
                for (idx, candidate) in candidates.iter().enumerate() {
                    if let Some(parts) = candidate
                        .get("content")
                        .and_then(|c| c.get("parts"))
                        .and_then(|p| p.as_array())
                    {
                        for part in parts {
                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                provider_texts.entry((1, idx)).or_default().push_str(text);
                            }
                        }
                    }
                }
            }
        }

        let mut texts: Vec<String> = Vec::new();
        for sse_text in reassembler.into_texts() {
            if matches!(
                sse_text.kind,
                SseTextKind::ChatToolArguments | SseTextKind::ResponsesArguments
            ) {
                append_decoded_argument_texts(&sse_text.text, &mut texts);
            }
            texts.push(sse_text.text);
        }
        for ((kind, _), text) in provider_texts {
            // Kind 3 accumulates legacy `function_call.arguments`, which is
            // nested JSON like the reassembler's tool-call arguments.
            if kind == 3 {
                append_decoded_argument_texts(&text, &mut texts);
            }
            texts.push(text);
        }
        texts
    }

    /// Redact content fields in a single parsed SSE frame.
    fn redact_sse_frame(&self, frame: &mut Value) {
        if let Some(choices) = frame.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                if let Some(text) = choice.get_mut("text") {
                    self.redact_string_value(text);
                }
                if let Some(delta) = choice.get_mut("delta") {
                    self.redact_message_like(delta);
                }
            }
        }

        let (is_responses_delta, is_responses_arguments_delta) = frame
            .get("type")
            .and_then(Value::as_str)
            .map(|event_type| {
                (
                    event_type.ends_with("output_text.delta")
                        || event_type.ends_with("function_call_arguments.delta")
                        || event_type.ends_with("refusal.delta"),
                    event_type.ends_with("function_call_arguments.delta"),
                )
            })
            .unwrap_or((false, false));
        if is_responses_delta && let Some(delta) = frame.get_mut("delta") {
            if is_responses_arguments_delta {
                self.redact_arguments_value(delta);
            } else {
                self.redact_string_value(delta);
            }
        }

        // Anthropic streaming: content_block_delta
        if frame.get("type").and_then(|t| t.as_str()) == Some("content_block_delta")
            && let Some(text) = frame
                .get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
        {
            let redacted = self.redact_text(text);
            if redacted != text {
                frame["delta"]["text"] = Value::String(redacted);
            }
        }

        // Gemini: candidates[].content.parts[].text
        if let Some(candidates) = frame.get_mut("candidates").and_then(Value::as_array_mut) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get_mut("content")
                    .and_then(|c| c.get_mut("parts"))
                    .and_then(|p| p.as_array_mut())
                {
                    for part in parts {
                        if let Some(text) = part.get_mut("text") {
                            self.redact_string_value(text);
                        }
                    }
                }
            }
        }
    }

    fn redact_sse_event(&self, lines: &[&str]) -> Option<String> {
        rewrite_sse_json_event(lines, |json| {
            if self.scan_mode == ScanMode::All {
                self.redact_all_strings_with_argument_shield(json);
            } else {
                self.redact_sse_frame(json);
            }
        })
    }

    /// Redact an SSE response body, modifying complete SSE events while
    /// preserving the overall SSE framing. Returns `None` when no frame was
    /// modified (zero-copy happy path).
    ///
    /// Rewritten `data:` lines preserve their original CR/LF terminator so
    /// CRLF-encoded streams round-trip without mixing line endings. Frame JSON
    /// is reserialized compactly by `serde_json::to_string`, which may alter
    /// whitespace within a frame — clients consuming SSE byte-for-byte should
    /// not depend on inner-frame formatting.
    fn redact_sse_body(&self, body: &[u8]) -> Option<Vec<u8>> {
        let body_str = std::str::from_utf8(body).ok()?;

        // Fast-skip the common "redact mode but no PII in the stream" case.
        // Scan-all mode unions decoded frame strings (so JSON escapes cannot hide
        // content) with a raw-body pass (so cross-token/contextual patterns and
        // unparseable `data:` payloads are not skipped here while the
        // reject/warn detection path would have flagged them).
        let has_match = if self.scan_mode == ScanMode::All {
            let frames = parse_sse_data_frames(body);
            !self
                .detect_matches_in_decoded_sse_frames(&frames, Some(body_str))
                .is_empty()
        } else {
            let frames = parse_sse_data_frames(body);
            let accumulated = self.extract_sse_completion_texts(&frames);
            let refs: Vec<&str> = accumulated.iter().map(String::as_str).collect();
            !self.detect_matches(&refs).is_empty()
        };
        if !has_match {
            return None;
        }

        let (output, modified) = rewrite_sse_events(body_str, |lines| self.redact_sse_event(lines));

        if modified {
            Some(output.into_bytes())
        } else {
            None
        }
    }
}

#[async_trait]
impl Plugin for AiResponseGuard {
    fn name(&self) -> &str {
        "ai_response_guard"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_RESPONSE_GUARD
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // Native gRPC bodies are length-prefixed protobuf frames and cannot be
        // inspected by this JSON/SSE/text guard. Do not advertise inert gRPC
        // enforcement or force gRPC responses through full-body buffering.
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.has_validation_rules
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        // Client-controlled streaming intent is not response evidence. Buffer
        // conservatively until the pristine backend Content-Type is known.
        self.has_validation_rules
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_text_event_stream_media_type)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
        {
            // This plugin's buffered SSE parser cannot safely decide an
            // unbounded stream before any bytes are committed. Reject for every
            // enforcing/redacting policy; warn-only configurations retain their
            // documented pass-through posture and record the explicit skip.
            return self.respond_to_uninspectable(
                ctx,
                "streaming_response_requires_bounded_inspection",
                "event-stream responses cannot be fully inspected before delivery",
            );
        }
        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Enforce the aggregate scan/work bound before the successful-response
        // content gate. Buffered non-2xx error bodies still reach the transform
        // phase, so returning before this check would let a large raw body evade
        // the configured fail-closed/warn disposition and reach a redaction
        // regex pass outside the bound.
        if body.len() > self.max_scan_bytes {
            debug!(
                body_size = body.len(),
                max_scan_bytes = self.max_scan_bytes,
                "ai_response_guard: rejecting or warning on oversized governed response"
            );
            return self.respond_to_uninspectable(
                ctx,
                "body_exceeds_max_scan_bytes",
                "response body exceeds max_scan_bytes",
            );
        }

        // Content governance remains scoped to successful responses. The size
        // policy above is representation-independent and applies to every
        // buffered status.
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }

        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        let is_sse = is_text_event_stream_media_type(content_type);
        let is_json = is_json_content_type(content_type);

        if body.is_empty() {
            if self.require_json || !self.required_fields.is_empty() {
                return self.respond_to_uninspectable(
                    ctx,
                    "empty_response_body",
                    "response body is empty",
                );
            }
            return PluginResult::Continue;
        }

        // --- SSE path: parse frames, extract accumulated texts, detect ---
        if is_sse {
            if self.require_json || !self.required_fields.is_empty() {
                return self.respond_to_uninspectable(
                    ctx,
                    "sse_cannot_satisfy_json_structure",
                    "SSE is not a single JSON response",
                );
            }
            let parsed = parse_sse_data_frames_checked(body);
            if !parsed.fully_parsed {
                return self.respond_to_uninspectable(
                    ctx,
                    "uninspectable_sse",
                    "SSE contains malformed, non-JSON, or non-UTF-8 data",
                );
            }
            let frames = parsed.frames;
            if frames.is_empty() && self.scan_mode != ScanMode::All {
                return PluginResult::Continue;
            }

            let accumulated = self.extract_sse_completion_texts(&frames);

            // Check max completion length on accumulated text
            if self.max_completion_length > 0 {
                let refs: Vec<&str> = accumulated.iter().map(|s| s.as_str()).collect();
                if let Some(reason) = self.check_completion_length(&refs) {
                    match self.action {
                        GuardAction::Reject | GuardAction::Redact => {
                            Self::mark_rejected(ctx, reason.clone());
                            return PluginResult::Reject {
                                status_code: 502,
                                body: format!(
                                    r#"{{"error":"AI response guard: {}"}}"#,
                                    escape_json_string(&reason)
                                ),
                                headers: HashMap::new(),
                            };
                        }
                        GuardAction::Warn => {
                            ctx.metadata
                                .insert("ai_response_guard_warning".to_string(), reason);
                        }
                    }
                }
            }

            let detected = if self.scan_mode == ScanMode::All {
                self.detect_matches_in_decoded_sse_frames(&frames, std::str::from_utf8(body).ok())
            } else {
                let refs: Vec<&str> = accumulated.iter().map(|s| s.as_str()).collect();
                self.detect_matches(&refs)
            };

            if detected.is_empty() {
                return PluginResult::Continue;
            }

            if self.action == GuardAction::Redact && self.redact_sse_leaves_residual(body) {
                debug!(
                    "ai_response_guard: redact leaves residual SSE content (types: {:?}), rejecting response",
                    detected
                );
                let types_json: Vec<String> = detected
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json_string(t)))
                    .collect();
                Self::mark_rejected(ctx, detected.join(","));
                return PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                        types_json.join(","),
                    ),
                    headers: HashMap::new(),
                };
            }

            return self.respond_to_detection(ctx, response_status, &detected);
        }

        // Scan-all can safely inspect arbitrary UTF-8 representations as raw
        // text. Structured content mode has no completion mapping for them, so
        // enforcing actions fail closed instead of silently passing through.
        if !is_json && !self.require_json && self.required_fields.is_empty() {
            if self.scan_mode == ScanMode::All {
                let Ok(text) = std::str::from_utf8(body) else {
                    return self.respond_to_uninspectable(
                        ctx,
                        "non_utf8_response",
                        "response body is not valid UTF-8",
                    );
                };
                if let Some(reason) = self.check_completion_length(&[text]) {
                    match self.action {
                        GuardAction::Reject | GuardAction::Redact => {
                            Self::mark_rejected(ctx, reason.clone());
                            return PluginResult::Reject {
                                status_code: 502,
                                body: format!(
                                    r#"{{"error":"AI response guard: {}"}}"#,
                                    escape_json_string(&reason)
                                ),
                                headers: HashMap::new(),
                            };
                        }
                        GuardAction::Warn => {
                            ctx.metadata
                                .insert("ai_response_guard_warning".to_string(), reason);
                        }
                    }
                }
                let detected = self.detect_matches(&[text]);
                return if detected.is_empty() {
                    PluginResult::Continue
                } else {
                    self.respond_to_detection(ctx, response_status, &detected)
                };
            }
            return self.respond_to_uninspectable(
                ctx,
                "unsupported_response_content_type",
                "response content type is not inspectable in content mode",
            );
        }

        // --- JSON path ---

        // Parse JSON
        let json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                return self.respond_to_uninspectable(
                    ctx,
                    "invalid_json",
                    "response body is not valid JSON",
                );
            }
        };

        // Check required fields
        for field in &self.required_fields {
            if json.get(field.as_str()).is_none() {
                Self::mark_rejected(ctx, format!("missing_required_field:{field}"));
                return PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response missing required field: \"{}\""}}"#,
                        escape_json_string(field)
                    ),
                    headers: HashMap::new(),
                };
            }
        }

        // Pattern detection in scan-all is handled separately below, but the
        // completion-length rule is independent of scan mode and must still
        // inspect supported completion/tool fields.
        let texts = if self.scan_mode == ScanMode::Content || self.max_completion_length > 0 {
            self.extract_completion_texts(&json)
        } else {
            Vec::new()
        };

        // Check max completion length
        if !texts.is_empty()
            && let Some(reason) = self.check_completion_length(&texts)
        {
            match self.action {
                GuardAction::Reject | GuardAction::Redact => {
                    Self::mark_rejected(ctx, reason.clone());
                    return PluginResult::Reject {
                        status_code: 502,
                        body: format!(
                            r#"{{"error":"AI response guard: {}"}}"#,
                            escape_json_string(&reason)
                        ),
                        headers: HashMap::new(),
                    };
                }
                GuardAction::Warn => {
                    ctx.metadata
                        .insert("ai_response_guard_warning".to_string(), reason);
                }
            }
        }

        // Detect PII and blocked content
        let detected = if self.scan_mode == ScanMode::All {
            self.detect_matches_in_decoded_json(&json, std::str::from_utf8(body).ok())
        } else {
            self.detect_matches(&texts)
        };

        if detected.is_empty() {
            return PluginResult::Continue;
        }

        // Redact mode can detect PII the redactor cannot rewrite — in scan-all,
        // object keys, numeric scalars, cross-token custom patterns, and
        // duplicate-key values; in content mode, matches that exist only across
        // adjacent content-array parts and decoded tool-argument keys/numbers.
        // Forwarding such a body while reporting it `redacted` would leak PII,
        // so fail closed (reject) when redaction would leave residual
        // detections rather than emit false "redacted" telemetry. Bodies whose
        // PII is fully rewritable fall through to the normal redact path below.
        let leaves_residual = self.action == GuardAction::Redact
            && if self.scan_mode == ScanMode::All {
                self.redact_leaves_residual(&json)
            } else {
                self.content_redact_leaves_residual(&json)
            };
        if leaves_residual {
            debug!(
                "ai_response_guard: redact leaves residual content (types: {:?}), rejecting response",
                detected
            );
            let types_json: Vec<String> = detected
                .iter()
                .map(|t| format!("\"{}\"", escape_json_string(t)))
                .collect();
            Self::mark_rejected(ctx, detected.join(","));
            return PluginResult::Reject {
                status_code: 502,
                body: format!(
                    r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                    types_json.join(","),
                ),
                headers: HashMap::new(),
            };
        }

        self.respond_to_detection(ctx, response_status, &detected)
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.needs_body_transform {
            return None;
        }

        // This check intentionally precedes content-type dispatch and UTF-8
        // conversion. Raw non-JSON bodies (including non-2xx error text skipped
        // by content inspection) must never enter regex redaction above the
        // configured aggregate scan/work limit.
        if body.len() > self.max_scan_bytes {
            return None;
        }

        if let Some(ct) = content_type {
            if is_text_event_stream_media_type(ct) {
                let redacted = self.redact_sse_body(body)?;
                return (!self.sse_body_has_residual(&redacted)).then_some(redacted);
            }
            if !is_json_content_type(ct) {
                if self.scan_mode != ScanMode::All {
                    return None;
                }
                let text = std::str::from_utf8(body).ok()?;
                let redacted = self.redact_text(text);
                return (redacted != text).then(|| redacted.into_bytes());
            }
        }

        let mut json: Value = match serde_json::from_slice(body) {
            Ok(json) => json,
            Err(_) if self.scan_mode == ScanMode::All => {
                let text = std::str::from_utf8(body).ok()?;
                let redacted = self.redact_text(text);
                return (redacted != text).then(|| redacted.into_bytes());
            }
            Err(_) => return None,
        };

        if self.scan_mode == ScanMode::All {
            if self
                .detect_matches_in_decoded_json(&json, std::str::from_utf8(body).ok())
                .is_empty()
            {
                return None;
            }
            // `on_response_body` rejects this case in the normal pipeline.
            // Keep the transform independently representation-safe as well:
            // never mutate decoded keys, numbers, duplicate members, or other
            // matches the value-only redactor cannot rewrite.
            if self.redact_leaves_residual(&json) {
                return None;
            }
            self.redact_all_strings_with_argument_shield(&mut json);
        } else {
            let texts = self.extract_completion_texts(&json);
            let has_match = !self.detect_matches(&texts).is_empty();
            if !has_match {
                return None;
            }
            if self.content_redact_leaves_residual(&json) {
                return None;
            }
            self.redact_response_json(&mut json);
        }

        serde_json::to_vec(&json).ok()
    }

    fn requires_replay_response_body_transform(&self, ctx: &RequestContext) -> bool {
        ctx.ai_response_guard_replay_redactions
            .contains(&self.instance_id)
    }

    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        // These values describe the upstream representation and become stale
        // whenever redaction changes the client-visible bytes. The proxy calls
        // this hook only after a transform returns `Some`, so clean bodies keep
        // their validators.
        response_headers.retain(|key, _| {
            !RESPONSE_VALIDATORS
                .iter()
                .any(|header| key.eq_ignore_ascii_case(header))
        });
    }
}

/// Blank scalar values under the root response/event keys whose values are
/// protocol metadata rather than model-authored content. The same carve-out is
/// used by buffered JSON and buffered SSE residual scans.
fn blank_top_level_structural_scalars(value: &mut Value) {
    if let Value::Object(map) = value {
        for (key, value) in map.iter_mut() {
            if STRUCTURAL_KEYS.contains(&key.as_str()) && (value.is_string() || value.is_number()) {
                *value = Value::String(String::new());
            }
        }
    }
}

/// Parse and rewrite one complete SSE event's joined JSON `data:` payload,
/// preserving non-data fields and the first data line's terminator.
fn rewrite_sse_json_event(lines: &[&str], mutate: impl FnOnce(&mut Value)) -> Option<String> {
    let mut data_lines = Vec::new();
    let mut payloads = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        if let Some(data) = content
            .strip_prefix("data: ")
            .or_else(|| content.strip_prefix("data:"))
        {
            data_lines.push(idx);
            payloads.push(data);
        }
    }
    if payloads.is_empty() {
        return None;
    }

    let joined = payloads.join("\n");
    let trimmed = joined.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return None;
    }
    let mut json = serde_json::from_str::<Value>(trimmed).ok()?;
    let original = json.clone();
    mutate(&mut json);
    if json == original {
        return None;
    }

    let rewritten = serde_json::to_string(&json).ok()?;
    let first_data_line = data_lines[0];
    let mut output = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx == first_data_line {
            let ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            output.push_str("data: ");
            output.push_str(&rewritten);
            output.push_str(ending);
        } else if data_lines.binary_search(&idx).is_err() {
            output.push_str(line);
        }
    }
    Some(output)
}

/// Apply an event-level rewrite across a buffered SSE body while preserving
/// event order, non-data fields, separators, and LF/CRLF framing.
fn rewrite_sse_events<'a>(
    body: &'a str,
    mut rewrite_event: impl FnMut(&[&'a str]) -> Option<String>,
) -> (String, bool) {
    let mut output = String::with_capacity(body.len());
    let mut event_lines: Vec<&'a str> = Vec::new();
    for line in body.split_inclusive('\n') {
        event_lines.push(line);
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        if content.is_empty() {
            if let Some(rewritten) = rewrite_event(&event_lines) {
                output.push_str(&rewritten);
            } else {
                for original in &event_lines {
                    output.push_str(original);
                }
            }
            event_lines.clear();
        }
    }
    if !event_lines.is_empty() {
        if let Some(rewritten) = rewrite_event(&event_lines) {
            output.push_str(&rewritten);
        } else {
            for original in &event_lines {
                output.push_str(original);
            }
        }
    }

    let modified = output != body;
    (output, modified)
}

/// Return the byte offset immediately after a JSON string beginning at
/// `start`. The containing payload has already passed `serde_json` parsing;
/// `None` still fails the residual check closed rather than guessing at spans.
fn json_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut index = start + 1;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'\\' => index = index.checked_add(2)?,
            b'"' => return index.checked_add(1),
            _ => index += 1,
        }
    }
    None
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        index += 1;
    }
    index
}

/// Return the byte offset immediately after one JSON value. The caller only
/// asks for values in a payload already parsed by `serde_json`.
fn json_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start)? {
        b'"' => json_string_end(bytes, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = start;
            while let Some(byte) = bytes.get(index) {
                match byte {
                    b'"' => index = json_string_end(bytes, index)?,
                    b'{' | b'[' => {
                        depth = depth.checked_add(1)?;
                        index += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while bytes.get(index).is_some_and(|byte| {
                !matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | b',' | b'}' | b']')
            }) {
                index += 1;
            }
            (index > start).then_some(index)
        }
    }
}

/// Locate exact byte spans of string/number values held by structural keys in
/// the root JSON object. Scanning the original serialization preserves
/// contextual whitespace for the residual raw pass. For duplicate object
/// members, a scalar is maskable only when it is the last occurrence of its
/// structural key, matching the `serde_json::Value` that redaction actually
/// inspected. A later non-scalar leaves no maskable span for that key, so no
/// overwritten duplicate value is hidden from residual detection.
fn top_level_structural_scalar_spans(
    raw: &str,
    json: &Value,
) -> Option<[Option<std::ops::Range<usize>>; STRUCTURAL_KEY_COUNT]> {
    if !json.is_object() {
        return Some(std::array::from_fn(|_| None));
    }

    let bytes = raw.as_bytes();
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return None;
    }
    index += 1;
    // One slot per known structural key records the scalar span from its last
    // root-object occurrence. A later non-scalar explicitly clears the slot:
    // serde retains that later value, so no earlier scalar was inspected by
    // the structural redactor and none may be hidden from the raw pass. The
    // fixed array avoids per-key strings and heap growth on the response path.
    let mut last_scalar_spans: [Option<std::ops::Range<usize>>; STRUCTURAL_KEY_COUNT] =
        std::array::from_fn(|_| None);

    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            break;
        }

        let key_start = index;
        let key_end = json_string_end(bytes, key_start)?;
        let raw_key = raw.get(key_start..key_end)?;
        let key: Cow<'_, str> = if raw_key.as_bytes().contains(&b'\\') {
            Cow::Owned(serde_json::from_str::<String>(raw_key).ok()?)
        } else {
            Cow::Borrowed(raw_key.get(1..raw_key.len().checked_sub(1)?)?)
        };

        index = skip_json_whitespace(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return None;
        }
        index = skip_json_whitespace(bytes, index + 1);
        let value_start = index;
        let value_end = json_value_end(bytes, value_start)?;

        if let Some(key_index) = STRUCTURAL_KEYS
            .iter()
            .position(|structural| *structural == key.as_ref())
        {
            last_scalar_spans[key_index] = match bytes.get(value_start) {
                Some(b'"' | b'-' | b'0'..=b'9') => Some(value_start..value_end),
                _ => None,
            };
        }

        index = skip_json_whitespace(bytes, value_end);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => break,
            _ => return None,
        }
    }

    Some(last_scalar_spans)
}

/// Mask top-level structural scalar bytes in one SSE event without otherwise
/// changing its data fields, duplicate JSON members, whitespace, or framing.
fn mask_sse_event_structural_scalars(lines: &[&str]) -> Result<Option<String>, ()> {
    let mut fragments = vec![None; lines.len()];
    let mut payloads = Vec::new();
    let mut joined_len = 0usize;

    for (line_index, line) in lines.iter().enumerate() {
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        let payload_start = if content.starts_with("data: ") {
            6
        } else if content.starts_with("data:") {
            5
        } else {
            continue;
        };
        let payload = content.get(payload_start..).ok_or(())?;
        if !payloads.is_empty() {
            joined_len = joined_len.checked_add(1).ok_or(())?;
        }
        fragments[line_index] = Some((payload_start, joined_len, payload.len()));
        joined_len = joined_len.checked_add(payload.len()).ok_or(())?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Ok(None);
    }
    let joined = payloads.join("\n");
    let trimmed = joined.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return Ok(None);
    }
    let json = serde_json::from_str::<Value>(trimmed).map_err(|_| ())?;
    let spans = top_level_structural_scalar_spans(&joined, &json).ok_or(())?;
    if spans.iter().all(Option::is_none) {
        return Ok(None);
    }

    // One byte per joined payload byte, bounded by the already-enforced
    // `max_scan_bytes`. Keeping a flat mask makes this O(body + spans), even
    // for attacker-controlled events with many data lines or root members.
    let mut mask = vec![false; joined.len()];
    for span in spans.into_iter().flatten() {
        let bytes = joined.as_bytes();
        let (start, end) = if span.end > span.start + 1
            && bytes.get(span.start) == Some(&b'"')
            && bytes.get(span.end - 1) == Some(&b'"')
        {
            (span.start + 1, span.end - 1)
        } else {
            (span.start, span.end)
        };
        mask.get_mut(start..end).ok_or(())?.fill(true);
    }

    let mut output = String::with_capacity(lines.iter().map(|line| line.len()).sum());
    for (line_index, line) in lines.iter().enumerate() {
        let Some((payload_start, joined_start, payload_len)) = fragments[line_index] else {
            output.push_str(line);
            continue;
        };
        let mut bytes = line.as_bytes().to_vec();
        for offset in 0..payload_len {
            if mask.get(joined_start + offset).copied().ok_or(())? {
                *bytes.get_mut(payload_start + offset).ok_or(())? = b' ';
            }
        }
        output.push_str(std::str::from_utf8(&bytes).map_err(|_| ())?);
    }
    Ok(Some(output))
}

/// Mask structural scalar spans across a complete buffered SSE body. Any
/// unexpected parse or offset failure returns `None` so enforcement fails
/// closed instead of scanning an incomplete sanitized representation.
fn mask_sse_top_level_structural_scalars(body: &str) -> Option<String> {
    let mut failed = false;
    let (output, _) = rewrite_sse_events(body, |lines| {
        match mask_sse_event_structural_scalars(lines) {
            Ok(rewritten) => rewritten,
            Err(()) => {
                failed = true;
                None
            }
        }
    });
    (!failed).then_some(output)
}

/// Collect every decoded JSON token for `ScanMode::All` detection so the
/// decoded walker matches the coverage of the original raw-body scan.
///
/// Serde has already resolved `\uXXXX` and other JSON string escapes here, so
/// detection sees the same text the client will receive after parsing — the
/// coverage gap issue #1720 closed.
///
/// Collected, mirroring the raw-body scan this supplements:
/// - String values (borrowed `&str`).
/// - Object keys (borrowed `&str`) — e.g. `{"a@b.com":"ok"}`, whose key the raw
///   scan caught but a values-only walk would drop.
/// - Numeric scalars, stringified to owned `String` — e.g. a numeric SSN
///   `{"ssn":123456789}` or credit-card number, which a `&str`-only walk cannot
///   see. Numbers are the load-bearing scalar case for PII.
///
/// Booleans and null are intentionally skipped: their canonical forms
/// (`true`/`false`/`null`) carry no PII, so collecting them would only add
/// noise. The walker yields `Cow<str>` (`Borrowed` for strings/keys, `Owned`
/// for stringified numbers) so number text is included without allocating for
/// the common string case.
fn collect_decoded_json_strings<'a>(value: &'a Value, texts: &mut Vec<Cow<'a, str>>) {
    match value {
        Value::String(text) => texts.push(Cow::Borrowed(text.as_str())),
        Value::Number(n) => texts.push(Cow::Owned(n.to_string())),
        Value::Array(items) => {
            for item in items {
                collect_decoded_json_strings(item, texts);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                // Scan object KEYS too, not just values: in `ScanMode::All` the
                // previous raw-body scan covered the whole serialized body
                // (including field names), so a blocked phrase / PII pattern in a
                // key like `{"user@example.com": "ok"}` must still be detected.
                texts.push(Cow::Borrowed(key.as_str()));
                collect_decoded_json_strings(value, texts);
            }
        }
        // Bool / Null carry no PII; deliberately dropped.
        _ => {}
    }
}

fn collect_string_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    if let Some(text) = value.and_then(Value::as_str) {
        texts.push(Cow::Borrowed(text));
    }
}

/// Client-visible text carried by one content-array part: ordinary `text`
/// parts and OpenAI Responses refusal parts shaped
/// `{"type":"refusal","refusal":"..."}`. Parts carrying neither are not
/// text-bearing.
fn content_part_text(part: &Value) -> Option<&str> {
    part.get("text")
        .and_then(Value::as_str)
        .or_else(|| part.get("refusal").and_then(Value::as_str))
}

/// Push each run of adjacent text-bearing parts as one joined fragment so
/// detection and length limits see the logical completion a client renders —
/// a match or length overflow split across adjacent parts cannot hide at part
/// boundaries. A non-text part (e.g. an image) breaks adjacency. Single-part
/// runs stay borrowed; only multi-part runs allocate.
fn push_joined_adjacent_texts<'a>(
    parts: impl Iterator<Item = Option<&'a str>>,
    texts: &mut Vec<Cow<'a, str>>,
) {
    let mut run: Vec<&'a str> = Vec::new();
    for part in parts {
        match part {
            Some(text) => run.push(text),
            None => flush_joined_text_run(&mut run, texts),
        }
    }
    flush_joined_text_run(&mut run, texts);
}

fn flush_joined_text_run<'a>(run: &mut Vec<&'a str>, texts: &mut Vec<Cow<'a, str>>) {
    if run.len() == 1 {
        texts.push(Cow::Borrowed(run[0]));
    } else if !run.is_empty() {
        texts.push(Cow::Owned(run.concat()));
    }
    run.clear();
}

fn collect_content_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    let Some(value) = value else {
        return;
    };
    if let Some(text) = value.as_str() {
        texts.push(Cow::Borrowed(text));
        return;
    }
    if let Some(parts) = value.as_array() {
        push_joined_adjacent_texts(parts.iter().map(content_part_text), texts);
    }
}

/// Tool/function `arguments` are a JSON document serialized into a string, so
/// scanning only the raw string lets JSON escapes (e.g. `\u0040` for `@`) hide
/// content the tool client will decode. Push the raw string and, when it
/// parses, every decoded token of the nested document — one bounded parse
/// under serde's recursion limit; deeper nested strings are not re-descended.
fn collect_argument_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    let Some(text) = value.and_then(Value::as_str) else {
        return;
    };
    texts.push(Cow::Borrowed(text));
    if let Ok(decoded) = serde_json::from_str::<Value>(text) {
        let mut decoded_texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(&decoded, &mut decoded_texts);
        texts.extend(
            decoded_texts
                .into_iter()
                .map(|token| Cow::Owned(token.into_owned())),
        );
    }
}

/// String-accumulator variant of [`collect_argument_value`] for the SSE path,
/// which reassembles arguments across frames into owned `String`s first.
fn append_decoded_argument_texts(arguments: &str, texts: &mut Vec<String>) {
    if let Ok(decoded) = serde_json::from_str::<Value>(arguments) {
        let mut decoded_texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(&decoded, &mut decoded_texts);
        texts.extend(decoded_texts.into_iter().map(Cow::into_owned));
    }
}

/// Collect decoded tool/function-argument tokens for the supported response
/// shapes, so `ScanMode::All` detection keeps parity with content mode: the
/// decoded-token and raw-body passes only ever see the serialized argument
/// string, in which JSON escapes still hide content until the nested document
/// is parsed.
fn collect_decoded_argument_tokens<'a>(json: &'a Value, texts: &mut Vec<Cow<'a, str>>) {
    if let Some(choices) = json.get("choices").and_then(Value::as_array) {
        for choice in choices {
            for container in [choice.get("message"), choice.get("delta")]
                .into_iter()
                .flatten()
            {
                if let Some(function_call) = container.get("function_call") {
                    collect_argument_value(function_call.get("arguments"), texts);
                }
                if let Some(tool_calls) = container.get("tool_calls").and_then(Value::as_array) {
                    for tool_call in tool_calls {
                        if let Some(function) = tool_call.get("function") {
                            collect_argument_value(function.get("arguments"), texts);
                        }
                    }
                }
            }
        }
    }
    if let Some(output) = json.get("output").and_then(Value::as_array) {
        for item in output {
            collect_argument_value(item.get("arguments"), texts);
        }
    }
    if json
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| event_type.ends_with("function_call_arguments.delta"))
    {
        collect_argument_value(json.get("delta"), texts);
    }
}

/// Visit every tool/function argument value in the supported buffered and SSE
/// response shapes. The traversal is deliberately shared by scan-all
/// redaction's shield/restore passes so both passes observe identical positions
/// without changing the surrounding arrays or objects.
fn for_each_argument_value(json: &mut Value, visitor: &mut impl FnMut(&mut Value)) {
    if let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) {
        for choice in choices {
            for container_key in ["message", "delta"] {
                let Some(container) = choice.get_mut(container_key) else {
                    continue;
                };
                if let Some(arguments) = container
                    .get_mut("function_call")
                    .and_then(|function| function.get_mut("arguments"))
                {
                    visitor(arguments);
                }
                if let Some(tool_calls) = container
                    .get_mut("tool_calls")
                    .and_then(Value::as_array_mut)
                {
                    for tool_call in tool_calls {
                        if let Some(arguments) = tool_call
                            .get_mut("function")
                            .and_then(|function| function.get_mut("arguments"))
                        {
                            visitor(arguments);
                        }
                    }
                }
            }
        }
    }

    if let Some(output) = json.get_mut("output").and_then(Value::as_array_mut) {
        for item in output {
            if let Some(arguments) = item.get_mut("arguments") {
                visitor(arguments);
            }
        }
    }

    if json
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| event_type.ends_with("function_call_arguments.delta"))
        && let Some(delta) = json.get_mut("delta")
    {
        visitor(delta);
    }
}

fn collect_function_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    let Some(value) = value else {
        return;
    };
    collect_string_value(value.get("name"), texts);
    collect_argument_value(value.get("arguments"), texts);
}

fn reject_unknown_keys(value: &Value, allowed: &[&str], path: &str) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("ai_response_guard: unknown field '{path}.{key}'"));
    }
    Ok(())
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_response_guard: '{field}' must be a string"))
}

fn optional_array<'a>(
    config: &'a Value,
    field: &'static str,
) -> Result<Option<&'a Vec<Value>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_array()
        .map(Some)
        .ok_or_else(|| format!("ai_response_guard: '{field}' must be an array"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(values) = optional_array(config, field)? else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_response_guard: '{field}[{idx}]' must be a string"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_response_guard: '{field}' must be a boolean"))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_response_guard: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ai_response_guard: '{field}' must be greater than zero"
        ));
    }
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_response_guard: '{field}' is too large for this platform"))
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_response_guard: '{field}' must be an unsigned integer"
        ));
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_response_guard: '{field}' is too large for this platform"))
}

fn required_non_empty_string<'a>(
    value: &'a Value,
    list_field: &'static str,
    idx: usize,
    field: &'static str,
) -> Result<&'a str, String> {
    let Some(value) = value.get(field) else {
        return Err(format!(
            "ai_response_guard: '{list_field}[{idx}].{field}' is required"
        ));
    };
    let Some(value) = value.as_str() else {
        return Err(format!(
            "ai_response_guard: '{list_field}[{idx}].{field}' must be a string"
        ));
    };
    if value.is_empty() {
        return Err(format!(
            "ai_response_guard: '{list_field}[{idx}].{field}' must not be empty"
        ));
    }
    Ok(value)
}

/// Recursively redact matches in all string values within a JSON Value.
///
/// `STRUCTURAL_KEYS` (IDs, timestamps, model names, roles, token counts, etc.)
/// exists to protect *top-level* response fields whose scalar values may
/// incidentally match a PII regex (e.g. a `model` name or a dotted-quad-looking
/// `id`) from being corrupted. That protection is applied ONLY to a scalar
/// string held directly by a structural key at the top level of the body.
/// Below the top level, those same key names are author-controllable hiding
/// spots, so PII nested under them — e.g. `{"choices":[{"message":{"type":
/// "<PII>"}}]}` or `{"id":{"note":"<PII>"}}` — is still redacted. The walker
/// also always recurses into nested objects and arrays even under a top-level
/// structural key, so PII cannot be hidden by wrapping it in a container.
/// Without this, redaction was fail-open on the response side: PII was reported
/// as detected (`ai_response_guard_redacted` set) but forwarded to the client
/// unredacted purely because of attacker/model-controlled JSON structure.
///
/// Placeholders are wrapped in `regex::NoExpand` so `$`-sequences in them are
/// emitted literally rather than interpreted as capture-group references.
///
/// `top_level` is true only for the root object's direct fields.
fn redact_json_strings(
    value: &mut Value,
    pii_patterns: &[ContentPattern],
    blocked_phrases: &[ContentPattern],
    top_level: bool,
) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for pattern in pii_patterns.iter().chain(blocked_phrases.iter()) {
                result = pattern
                    .regex
                    .replace_all(&result, NoExpand(pattern.placeholder.as_str()))
                    .to_string();
            }
            if result != *s {
                *s = result;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item, pii_patterns, blocked_phrases, false);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                // Preserve only top-level structural scalar strings (model
                // name, IDs, roles, token counts). Always recurse into nested
                // objects/arrays, and never skip nested occurrences of these
                // key names, so PII cannot hide under a structural key.
                if top_level && STRUCTURAL_KEYS.contains(&k.as_str()) && val.is_string() {
                    continue;
                }
                redact_json_strings(val, pii_patterns, blocked_phrases, false);
            }
        }
        _ => {}
    }
}
