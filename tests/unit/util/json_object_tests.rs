//! Object-only serde admission helpers (issue #5538).
//!
//! serde's derived struct visitors accept a JSON array as a *positional*
//! construction of the struct, so `[]` deserializes into a fully
//! default-constructed value. These helpers force the map branch on the
//! admission boundaries that treat "a default-constructed value" as a
//! meaningful instruction.

use ferrum_edge::util::json_object::{deserialize_optional_object, from_json_object_slice};
use serde::Deserialize;

#[derive(Debug, Default, PartialEq, Deserialize)]
struct Inner {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    threshold: u32,
}

#[derive(Debug, Default, PartialEq, Deserialize)]
struct Outer {
    #[serde(default)]
    name: String,
    #[serde(
        default,
        deserialize_with = "ferrum_edge::util::json_object::deserialize_optional_object"
    )]
    inner: Option<Inner>,
}

/// Plain derived struct, to pin the behavior the helpers exist to prevent.
#[derive(Debug, Default, PartialEq, Deserialize)]
struct Unguarded {
    #[serde(default)]
    name: String,
    #[serde(default)]
    inner: Option<Inner>,
}

#[test]
fn a_derived_struct_visitor_accepts_a_sequence_positionally() {
    // The defect this module closes: without the guard, an array is a valid
    // default construction rather than a type error.
    let from_empty_array: Unguarded =
        serde_json::from_slice(b"[]").expect("serde accepts a positional empty sequence");
    assert_eq!(from_empty_array, Unguarded::default());
    assert_eq!(from_empty_array.name, "");

    let coerced: Unguarded = serde_json::from_value(serde_json::json!({"inner": []}))
        .expect("serde accepts a positional empty sequence for a nested struct");
    assert_eq!(coerced.inner, Some(Inner::default()));
}

#[test]
fn from_json_object_slice_requires_an_object_envelope() {
    let parsed: Outer =
        from_json_object_slice(br#"{"name":"ok"}"#).expect("an object envelope is accepted");
    assert_eq!(parsed.name, "ok");
    assert!(from_json_object_slice::<Outer>(b"{}").is_ok());
    // Leading whitespace is still JSON.
    assert!(from_json_object_slice::<Outer>(b"  \n\t{}").is_ok());

    for rejected in [
        &b"[]"[..],
        br#"["positional", {}]"#,
        br#""a string""#,
        b"5",
        b"true",
        b"null",
    ] {
        assert!(
            from_json_object_slice::<Outer>(rejected).is_err(),
            "{} must not deserialize as an object envelope",
            String::from_utf8_lossy(rejected)
        );
    }
}

#[test]
fn optional_object_fields_reject_sequences_and_keep_null() {
    let guarded: Outer = serde_json::from_value(serde_json::json!({"inner": {"enabled": true}}))
        .expect("an object value is accepted");
    assert_eq!(
        guarded.inner,
        Some(Inner {
            enabled: true,
            threshold: 0
        })
    );
    assert_eq!(guarded.inner.as_ref().map(|inner| inner.threshold), Some(0));

    for documented in [
        serde_json::json!({}),
        serde_json::json!({"inner": null}),
        serde_json::json!({"inner": {}}),
    ] {
        assert!(
            serde_json::from_value::<Outer>(documented.clone()).is_ok(),
            "{documented} is a documented form and must still deserialize"
        );
    }

    for rejected in [
        serde_json::json!({"inner": []}),
        serde_json::json!({"inner": [1, 2]}),
        serde_json::json!({"inner": "text"}),
        serde_json::json!({"inner": 7}),
    ] {
        assert!(
            serde_json::from_value::<Outer>(rejected.clone()).is_err(),
            "{rejected} must be rejected rather than default-constructed"
        );
    }
}

#[test]
fn the_guard_composes_with_deny_unknown_fields_and_field_defaults() {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Closed {
        #[serde(default)]
        known: String,
    }

    let parsed: Closed = from_json_object_slice(br#"{"known":"value"}"#).expect("accepted");
    assert_eq!(parsed.known, "value");
    assert!(from_json_object_slice::<Closed>(br#"{"unknown":"value"}"#).is_err());
    assert!(from_json_object_slice::<Closed>(b"[]").is_err());

    // `deserialize_optional_object` is usable as a bare function too.
    let mut deserializer = serde_json::Deserializer::from_str("{\"enabled\":true}");
    let value: Option<Inner> =
        deserialize_optional_object(&mut deserializer).expect("object accepted");
    assert_eq!(value.map(|inner| inner.enabled), Some(true));
}
