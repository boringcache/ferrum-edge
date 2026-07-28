//! Ordered, duplicate-aware query-string helpers.
//!
//! Backend-visible query identity must not round-trip through the single-value
//! [`std::collections::HashMap`] used for plugin `query_params`. This module
//! parses a raw query into an ordered pair list, applies
//! `request_transformer` mutations with defined duplicate-key semantics, and
//! serializes an exact outbound query string while preserving unmodified
//! encodings byte-for-byte.

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::collections::{HashMap, HashSet};

/// Characters that must be percent-encoded in query names/values we author.
/// Unreserved characters (RFC 3986) stay literal; space becomes `%20` (never
/// `+`) so authored pairs do not introduce form-urlencoded plus ambiguity.
const QUERY_COMPONENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub fn has_conflicting_duplicate_query_key(raw_query: &str) -> bool {
    let mut seen: HashMap<String, String> = HashMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_str(raw_key).decode_utf8_lossy().into_owned();
        let value = percent_decode_str(raw_value)
            .decode_utf8_lossy()
            .into_owned();
        match seen.get(&key) {
            Some(previous) if previous != &value => return true,
            Some(_) => {}
            None => {
                seen.insert(key, value);
            }
        }
    }
    false
}

/// One query pair, retaining wire encoding for names/values that were not
/// rewritten by a transform rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPair {
    /// Encoded name as it should appear on the wire.
    pub raw_name: String,
    /// Percent-decoded name used for rule matching (lossy UTF-8).
    pub decoded_name: String,
    /// `None` preserves a key-without-equals flag (`?flag`). `Some("")` is an
    /// explicit empty value (`?flag=`).
    pub raw_value: Option<String>,
    /// Percent-decoded value used for map materialization (lossy UTF-8).
    pub decoded_value: String,
}

impl QueryPair {
    fn from_raw_segment(pair: &str) -> Self {
        match pair.split_once('=') {
            Some((raw_name, raw_value)) => Self {
                decoded_name: percent_decode_str(raw_name)
                    .decode_utf8_lossy()
                    .into_owned(),
                decoded_value: percent_decode_str(raw_value)
                    .decode_utf8_lossy()
                    .into_owned(),
                raw_name: raw_name.to_string(),
                raw_value: Some(raw_value.to_string()),
            },
            None => Self {
                decoded_name: percent_decode_str(pair).decode_utf8_lossy().into_owned(),
                decoded_value: String::new(),
                raw_name: pair.to_string(),
                raw_value: None,
            },
        }
    }

    fn authored(name: &str, value: &str) -> Self {
        Self {
            raw_name: encode_query_component(name),
            decoded_name: name.to_string(),
            raw_value: Some(encode_query_component(value)),
            decoded_value: value.to_string(),
        }
    }

    fn write_to(&self, out: &mut String) {
        out.push_str(&self.raw_name);
        if let Some(ref value) = self.raw_value {
            out.push('=');
            out.push_str(value);
        }
    }
}

/// Ordered, duplicate-aware query representation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrderedQuery {
    pairs: Vec<QueryPair>,
}

impl OrderedQuery {
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Parse a raw query string. Empty `&` segments are skipped (they are not
    /// parameters). Invalid percent-encoding is retained on the wire form and
    /// decoded lossily for matching — never panics.
    pub fn parse(raw_query: &str) -> Self {
        if raw_query.is_empty() {
            return Self::new();
        }
        let mut pairs = Vec::new();
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            pairs.push(QueryPair::from_raw_segment(pair));
        }
        Self { pairs }
    }

    /// Build from a already-materialized single-value map (synthetic / test
    /// contexts with no retained raw query). Order follows the map iterator.
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        let mut pairs = Vec::with_capacity(map.len());
        for (name, value) in map {
            pairs.push(QueryPair::authored(name, value));
        }
        Self { pairs }
    }

    pub fn contains_decoded_name(&self, name: &str) -> bool {
        self.pairs.iter().any(|pair| pair.decoded_name == name)
    }

    /// Serialize to a query string. Unmodified pairs keep their original
    /// encoding; authored pairs use RFC 3986 percent-encoding (`%20`, never `+`).
    pub fn serialize(&self) -> String {
        if self.pairs.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for (idx, pair) in self.pairs.iter().enumerate() {
            if idx > 0 {
                out.push('&');
            }
            pair.write_to(&mut out);
        }
        out
    }

    /// Collapse to the plugin-visible single-value map (last occurrence wins),
    /// matching [`crate::plugins::RequestContext::materialize_query_params`].
    pub fn to_single_value_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(self.pairs.len());
        for pair in &self.pairs {
            map.insert(pair.decoded_name.clone(), pair.decoded_value.clone());
        }
        map
    }

    /// `add`: append `name=value` only when no existing pair has that decoded
    /// name. Duplicate existing names are left untouched.
    pub fn add(&mut self, name: &str, value: &str) -> bool {
        if self.contains_decoded_name(name) {
            return false;
        }
        self.pairs.push(QueryPair::authored(name, value));
        true
    }

    /// `update`: replace the value of every pair whose decoded name matches.
    /// If none match, append one authored pair (HashMap `insert` create).
    /// Always writes an `=` form (including empty values).
    pub fn update(&mut self, name: &str, value: &str) -> bool {
        let encoded_value = encode_query_component(value);
        let mut found = false;
        for pair in &mut self.pairs {
            if pair.decoded_name == name {
                pair.raw_value = Some(encoded_value.clone());
                pair.decoded_value = value.to_string();
                found = true;
            }
        }
        if found {
            return true;
        }
        self.pairs.push(QueryPair::authored(name, value));
        true
    }

    /// `remove`: drop every pair whose decoded name matches.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.pairs.len();
        self.pairs.retain(|pair| pair.decoded_name != name);
        self.pairs.len() != before
    }

    /// Drop every pair whose raw or decoded name is in `names`.
    ///
    /// Used to remove authentication-owned credential pairs before ordered
    /// query mutations so a later rename/update/add cannot relocate or
    /// re-encode an authenticated secret onto the outbound query. Matches the
    /// same raw-or-decoded name contract as
    /// [`crate::proxy::query_string_after_plugin_strips`].
    pub fn remove_matching_names(&mut self, names: &HashSet<&str>) -> bool {
        if names.is_empty() {
            return false;
        }
        let before = self.pairs.len();
        self.pairs.retain(|pair| {
            !names.contains(pair.raw_name.as_str()) && !names.contains(pair.decoded_name.as_str())
        });
        self.pairs.len() != before
    }

    /// `rename`: rename every matching pair to `new_name`, preserving each
    /// pair's value encoding and key-without-equals shape. Existing pairs
    /// already named `new_name` are left in place (duplicates of `new_name`
    /// may result). No-op when `name` is absent.
    pub fn rename(&mut self, name: &str, new_name: &str) -> bool {
        if name == new_name {
            return false;
        }
        let encoded_new = encode_query_component(new_name);
        let mut changed = false;
        for pair in &mut self.pairs {
            if pair.decoded_name == name {
                pair.raw_name = encoded_new.clone();
                pair.decoded_name = new_name.to_string();
                changed = true;
            }
        }
        changed
    }
}

/// Percent-encode a query component we author. Never panics.
pub fn encode_query_component(input: &str) -> String {
    utf8_percent_encode(input, QUERY_COMPONENT_ENCODE_SET).to_string()
}
