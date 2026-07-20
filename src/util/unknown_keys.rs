//! Cold-path helpers for rejecting unknown JSON object keys with deterministic,
//! path-qualified diagnostics and optional Levenshtein spelling suggestions.
//!
//! Shared by config-admission surfaces (for example `proxy_alerts` and
//! notification channels) so suggestion behavior stays consistent without
//! coupling those modules to each other.

use serde_json::{Map, Value};

/// Reject keys that are not in `allowed`, with a path-qualified error and a
/// spelling suggestion when the typo is close enough to be useful.
///
/// `error_prefix` is prepended verbatim (for example `"proxy_alerts: "` or
/// `""`). Unknown keys are sorted for stable diagnostics.
pub fn reject_unknown_keys(
    object: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
    error_prefix: &str,
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    let details: Vec<String> = unknown
        .into_iter()
        .map(|key| match suggest_key(key, allowed) {
            Some(suggestion) => {
                format!("'{path}.{key}' (did you mean '{suggestion}'?)")
            }
            None => format!("'{path}.{key}'"),
        })
        .collect();
    Err(format!(
        "{error_prefix}unknown configuration key(s): {}",
        details.join(", ")
    ))
}

/// Best Levenshtein match within the suggestion threshold, if any.
///
/// Threshold is 2 for short unknowns (length ≤ 8) and 3 otherwise. Ties keep
/// the first candidate in `allowed` order.
pub fn suggest_key<'a>(unknown: &str, allowed: &[&'a str]) -> Option<&'a str> {
    let mut best: Option<(usize, &'a str)> = None;
    for candidate in allowed {
        let distance = levenshtein(unknown, candidate);
        let is_better = best
            .map(|(best_distance, _)| distance < best_distance)
            .unwrap_or(true);
        if is_better {
            best = Some((distance, *candidate));
        }
    }
    let threshold = if unknown.len() > 8 { 3 } else { 2 };
    best.filter(|(distance, _)| *distance <= threshold)
        .map(|(_, name)| name)
}

/// When a required key is absent, return a present object key that is a
/// near-miss spelling of `required`, if any.
pub fn near_miss_for_missing_key<'a>(
    object: &'a Map<String, Value>,
    required: &str,
) -> Option<&'a str> {
    if object.contains_key(required) {
        return None;
    }
    let mut best: Option<(usize, &str)> = None;
    for key in object.keys() {
        let distance = levenshtein(key, required);
        let threshold = if key.len() > 8 { 3 } else { 2 };
        if distance > threshold {
            continue;
        }
        let is_better = best
            .map(|(best_distance, _)| distance < best_distance)
            .unwrap_or(true);
        if is_better {
            best = Some((distance, key.as_str()));
        }
    }
    best.map(|(_, key)| key)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}
