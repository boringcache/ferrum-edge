//! Configuration deserialization diagnostics, before an error becomes a retained cause.
//!
//! Serde's unexpected values are document content, even for fields that do not
//! normally hold credentials. Keep type/path/position and schema names, but never
//! keep an offending scalar in Display, Debug, or a nested source error. Paths
//! can contain document map keys; they must NEVER participate in classification.

use serde::de::{DeserializeOwned, Error as _};

pub const REDACTED_SCALAR: &str = "<redacted scalar>";

/// Sanitize a BARE serde diagnostic, never a path or context-prefixed rendering.
/// Callers must separate the path with `serde_path_to_error::Error::into_inner`.
/// Parser-level errors and arbitrary context use `sanitize_custom_message`.
pub fn sanitize_message(message: &str) -> String {
    for prefix in ["invalid type: ", "invalid value: ", "unknown variant "] {
        if let Some(tail) = message.strip_prefix(prefix) {
            // Unknown variants use UNESCAPED backticks: the value can itself
            // contain quotes and diagnostic text. The LAST expected clause is
            // schema-authored, after the complete offending value.
            let end = tail
                .rfind(", expected ")
                .max(tail.rfind(", there are no variants"));
            if let Some(end) = end {
                let unexpected = &tail[..end];
                let mut result = prefix.to_owned();
                if matches!(
                    unexpected,
                    "sequence" | "map" | "unit value" | "null" | "Option value"
                ) {
                    result.push_str(unexpected);
                } else {
                    if prefix != "unknown variant " {
                        for kind in [
                            "string ",
                            "character ",
                            "integer ",
                            "floating point ",
                            "boolean ",
                        ] {
                            if unexpected.starts_with(kind) {
                                result.push_str(kind);
                                break;
                            }
                        }
                    }
                    result.push_str(REDACTED_SCALAR);
                }
                result.push_str(&tail[end..]);
                return result;
            }
        }
    }

    // Field names and expected schema variants are not document scalar values.
    // Serde's invalid-length diagnostic carries a cardinality, not a value.
    if ["missing field ", "unknown field ", "duplicate field "]
        .iter()
        .any(|prefix| message.starts_with(prefix))
        || message.starts_with("data did not match any variant of untagged enum ")
        || message.strip_prefix("invalid length ").is_some_and(|tail| {
            tail.split_once(',').is_some_and(|(length, _)| {
                !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
    {
        return message.to_owned();
    }

    sanitize_custom_message(message)
}

/// Custom validators use backticks for schema names and double quotes (Debug
/// escaping) for document values. Single quotes are also withheld. An unmatched
/// opening quote consumes the remainder, including nested quotes of the other
/// kind; escaped delimiters never close a span. This is one linear pass.
pub fn sanitize_custom_message(message: &str) -> String {
    let mut result = String::with_capacity(message.len());
    let mut quote = None;
    let mut escaped = false;
    for ch in message.chars() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
        } else if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            result.push_str(REDACTED_SCALAR);
        } else {
            result.push(ch);
        }
    }
    result
}

/// Replace a path adapter's error from a position-free value deserializer
/// (JSON/YAML Value or BSON Deserializer). Never pass native YAML errors here:
/// those embed a second path inside their inner Display.
pub fn sanitize_value_error<E: serde::de::Error>(error: serde_path_to_error::Error<E>) -> E {
    let path = error.path().to_string();
    let inner = error.into_inner();
    E::custom(with_path(&path, &sanitize_message(&inner.to_string())))
}

/// JSON document admission with field paths and the parser's line/column.
pub fn from_json_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let path = error.path().to_string();
        let inner = error.into_inner();
        let detail = json_error_detail(&inner);
        serde_json::Error::custom(with_path(&path, &detail))
    })?;
    // The path adapter only deserializes one value. Retain from_slice's rejection
    // of trailing input; accepting a valid prefix would change admission.
    deserializer
        .end()
        .map_err(|error| serde_json::Error::custom(json_error_detail(&error)))?;
    Ok(value)
}

fn json_error_detail(error: &serde_json::Error) -> String {
    // Position is parser metadata, not part of an unterminated custom quote.
    // Separate it before sanitizing, then restore it after withholding values.
    let rendered = error.to_string();
    let position = format!(" at line {} column {}", error.line(), error.column());
    let message = if error.line() > 0 {
        rendered.strip_suffix(&position).unwrap_or(&rendered)
    } else {
        &rendered
    };
    let mut detail = if error.is_data() {
        sanitize_message(message)
    } else {
        sanitize_custom_message(message)
    };
    if error.line() > 0 {
        detail.push_str(&position);
    }
    detail
}

pub fn from_json_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    from_json_slice(input.as_bytes())
}

pub fn from_json_value<T: DeserializeOwned>(
    input: serde_json::Value,
) -> Result<T, serde_json::Error> {
    serde_path_to_error::deserialize(input).map_err(sanitize_value_error)
}

/// YAML's native error Display embeds its own path. Classify only the separate,
/// position-free error from Value deserialization; never classify that Display.
/// The native pass preserves admission semantics (including duplicate fields)
/// and supplies the original position. Only failed documents need a replay.
pub fn from_yaml_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_yaml::Error> {
    let error = match serde_yaml::from_str(input) {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let location = error.location();
    let detail = match serde_yaml::from_str::<serde_yaml::Value>(input) {
        Ok(value) => match from_yaml_value::<T>(value) {
            Err(error) => error.to_string(),
            // Value can normalize a shape that the native parser rejects.
            // Do not admit it or retain its original, path-bearing diagnostic.
            Ok(_) => "invalid YAML document".to_string(),
        },
        // Parser errors have no trusted serde family, even when their text or
        // a document-controlled key happens to start with one.
        Err(error) => sanitize_custom_message(&error.to_string()),
    };
    let detail = if let Some(location) = location {
        let position = format!(" at line {} column {}", location.line(), location.column());
        let detail = detail.strip_suffix(&position).unwrap_or(&detail);
        format!("{detail}{position}")
    } else {
        detail
    };
    Err(serde_yaml::Error::custom(detail))
}

pub fn from_yaml_value<T: DeserializeOwned>(
    input: serde_yaml::Value,
) -> Result<T, serde_yaml::Error> {
    serde_path_to_error::deserialize(input).map_err(sanitize_value_error)
}

fn with_path(path: &str, detail: &str) -> String {
    if path == "." {
        detail.to_owned()
    } else {
        // Includes document map keys, verbatim, as diagnostic context only.
        format!("{path}: {detail}")
    }
}
