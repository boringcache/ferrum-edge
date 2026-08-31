//! Production Dockerfile base images must be digest-pinned (issue #4444).

use std::collections::HashMap;

const PRODUCTION_DOCKERFILES: &[(&str, &str)] = &[
    ("Dockerfile", include_str!("../../../Dockerfile")),
    ("Dockerfile.release", include_str!("../../../Dockerfile.release")),
    ("Dockerfile.test", include_str!("../../../Dockerfile.test")),
];

const FLOATING_RUST_TAGS: &[&str] = &["latest", "stable", "nightly", "beta"];

fn strip_inline_comment(line: &str) -> &str {
    line.split_once('#').map(|(before, _)| before).unwrap_or(line)
}

fn parse_arg_defaults(dockerfile: &str) -> HashMap<String, String> {
    let mut defaults = HashMap::new();
    for line in dockerfile.lines() {
        let trimmed = strip_inline_comment(line).trim();
        let Some(rest) = trimmed.strip_prefix("ARG ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        defaults.insert(name.trim().to_string(), value.trim().to_string());
    }
    defaults
}

fn from_image_token(line: &str) -> Option<String> {
    let trimmed = strip_inline_comment(line).trim();
    let rest = trimmed.strip_prefix("FROM ")?;
    let image = rest
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim();
    if image.is_empty() {
        return None;
    }
    Some(image.to_string())
}

fn is_local_stage_reference(image: &str) -> bool {
    !image.contains('/')
        && !image.contains('@')
        && !image.contains(':')
        && !image.starts_with("${")
}

fn resolve_image_reference(image: &str, arg_defaults: &HashMap<String, String>) -> String {
    if let Some(var) = image.strip_prefix("${").and_then(|name| name.strip_suffix('}')) {
        return arg_defaults
            .get(var)
            .cloned()
            .unwrap_or_else(|| image.to_string());
    }
    image.to_string()
}

fn assert_digest_pinned(file: &str, line_no: usize, line: &str, resolved: &str) {
    assert!(
        resolved.contains("@sha256:"),
        "{file}:{line_no}: production Dockerfile `FROM` must pin external bases by \
         `@sha256:` digest (allow `scratch` or a local stage alias); got `{line}`"
    );
}

fn assert_rust_channel_approved(file: &str, line_no: usize, line: &str, resolved: &str) {
    let repo = resolved.split('@').next().unwrap_or(resolved);
    let is_rust = repo == "rust"
        || repo.ends_with("/rust")
        || repo.ends_with("/library/rust")
        || repo == "docker.io/library/rust";
    if !is_rust {
        return;
    }

    let tag = resolved
        .split_once('@')
        .and_then(|(before_digest, _)| before_digest.rsplit_once(':'))
        .map(|(_, tag)| tag);
    let Some(tag) = tag else {
        return;
    };

    assert!(
        !FLOATING_RUST_TAGS.contains(&tag),
        "{file}:{line_no}: unapproved floating Rust channel `{tag}` in `{line}`; pin the \
         manifest-list digest and record the human-readable tag in a trailing comment"
    );
}

#[test]
fn production_dockerfiles_pin_external_bases_by_digest() {
    for (file, dockerfile) in PRODUCTION_DOCKERFILES {
        let arg_defaults = parse_arg_defaults(dockerfile);
        for (idx, line) in dockerfile.lines().enumerate() {
            let line_no = idx + 1;
            let Some(image) = from_image_token(line) else {
                continue;
            };
            if image == "scratch" || is_local_stage_reference(&image) {
                continue;
            }

            let resolved = resolve_image_reference(&image, &arg_defaults);
            assert_digest_pinned(file, line_no, line.trim(), &resolved);
            assert_rust_channel_approved(file, line_no, line.trim(), &resolved);
        }
    }
}
