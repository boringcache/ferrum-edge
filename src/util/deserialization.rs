//! Configuration deserialization diagnostics, before an error becomes a retained cause.
//!
//! Serde's unexpected values are document content, even for fields that do not
//! normally hold credentials. Keep type/path/position and schema names, but never
//! keep an offending scalar in Display, Debug, or a nested source error.

use serde::de::{DeserializeOwned, Error as _};

pub const REDACTED_SCALAR: &str = "<redacted scalar>";

/// Sanitize serde diagnostics in linear time and space, with a fixed number of
/// scans and no regex backtracking or rescanning replacements.
pub fn sanitize_message(message: &str) -> String {
    // Paths and human context (including chains of plugin/operation prefixes)
    // can precede a serde diagnostic. Select the FIRST family, so a later
    // family embedded in the offending scalar cannot override its redaction.
    // A family first appearing inside quoted custom content is not schema.
    let quotes = ['"', '\'', '`'];
    let detail_start = [
        "invalid type: ",
        "invalid value: ",
        "unknown variant ",
        "missing field ",
        "unknown field ",
        "duplicate field ",
        "invalid length ",
        "data did not match any variant of untagged enum ",
    ]
    .into_iter()
    .filter_map(|prefix| message.find(prefix))
    .min()
    .filter(|start| message[..*start].find(quotes).is_none())
    .unwrap_or(0);
    let detail = &message[detail_start..];
    for prefix in ["invalid type: ", "invalid value: ", "unknown variant "] {
        if let Some(tail) = detail.strip_prefix(prefix) {
            // Unknown variants use UNESCAPED backticks: the value can itself
            // contain quotes and diagnostic text. The LAST expected clause is
            // schema-authored, after the complete offending value.
            let end = tail
                .rfind(", expected ")
                .max(tail.rfind(", there are no variants"));
            if let Some(end) = end {
                let unexpected = &tail[..end];
                let mut result = message[..detail_start + prefix.len()].to_owned();
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
        .any(|prefix| detail.starts_with(prefix))
        || detail.starts_with("data did not match any variant of untagged enum ")
        || detail.strip_prefix("invalid length ").is_some_and(|tail| {
            tail.split_once(',').is_some_and(|(length, _)| {
                !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
    {
        return message.to_owned();
    }

    // Custom serde diagnostics have no structured provenance or escaping
    // contract. Withhold the WHOLE quoted span, including intervening text,
    // rather than guessing that an embedded delimiter ends the scalar. This
    // also handles escaped quotes, multiline PEM, and several quoted values.
    if let Some(start) = message.find(quotes) {
        let end = message.rfind(quotes).filter(|end| *end > start);
        let mut result = message[..start].to_owned();
        result.push_str(REDACTED_SCALAR);
        if let Some(end) = end {
            result.push_str(&message[end + 1..]);
        }
        result
    } else {
        message.to_owned()
    }
}

/// Replace the error itself, never attach the unsanitized error as a source.
/// Leave unchanged errors intact so native YAML location metadata is preserved.
pub fn sanitize_error<E: serde::de::Error>(error: E) -> E {
    let original = error.to_string();
    let sanitized = sanitize_message(&original);
    if original == sanitized {
        error
    } else {
        E::custom(sanitized)
    }
}

/// JSON document admission with field paths and the parser's line/column.
pub fn from_json_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = serde_path_to_error::deserialize(&mut deserializer)
        .map_err(|error| serde_json::Error::custom(sanitize_message(&error.to_string())))?;
    // The path adapter only deserializes one value. Retain from_slice's rejection
    // of trailing input; accepting a valid prefix would change admission.
    deserializer.end().map_err(sanitize_error)?;
    Ok(value)
}

pub fn from_json_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    from_json_slice(input.as_bytes())
}

pub fn from_json_value<T: DeserializeOwned>(
    input: serde_json::Value,
) -> Result<T, serde_json::Error> {
    serde_path_to_error::deserialize(input)
        .map_err(|error| serde_json::Error::custom(sanitize_message(&error.to_string())))
}

/// YAML already supplies a field path and position at the document boundary.
pub fn from_yaml_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_yaml::Error> {
    serde_yaml::from_str(input).map_err(sanitize_error)
}

pub fn from_yaml_value<T: DeserializeOwned>(
    input: serde_yaml::Value,
) -> Result<T, serde_yaml::Error> {
    serde_path_to_error::deserialize(input)
        .map_err(|error| serde_yaml::Error::custom(sanitize_message(&error.to_string())))
}
