//! Matching for single JSON-RPC endpoints, without decoding or collapsing paths.

/// Accept the endpoint with or without one trailing slash. Root stays root;
/// repeated slashes, case, escapes, and dot segments are never normalized.
pub fn matches_endpoint_path(path: &str, endpoint: &str) -> bool {
    single_slash_base(path) == single_slash_base(endpoint)
}

fn single_slash_base(path: &str) -> &str {
    if path.len() > 1 && !path.ends_with("//") {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    }
}
