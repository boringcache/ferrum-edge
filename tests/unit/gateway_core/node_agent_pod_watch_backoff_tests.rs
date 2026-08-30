//! Source-shape contract for the node-agent Pods watcher backoff (issue #4307).
//!
//! `kube::runtime::watcher()` yields errors to the consumer and immediately
//! re-attempts the list. The production node-agent cannot inject a kube watcher
//! below that construction boundary (`run_with_pod_stream_for_test` receives an
//! already-built stream), so this file pins the live construction site: every
//! `kube_watcher::watcher(...)` in `src/modes/node_agent.rs` must chain
//! `.default_backoff()` immediately, and a neighboring bare construction cannot
//! satisfy the production-site assertion.

const NODE_AGENT_SRC: &str = include_str!("../../../src/modes/node_agent.rs");

const WATCHER_CALL: &str = "kube_watcher::watcher(";
const DEFAULT_BACKOFF: &str = ".default_backoff(";

fn matching_paren(source: &str, open: usize) -> usize {
    let bytes = source.as_bytes();
    assert_eq!(
        bytes.get(open).copied(),
        Some(b'('),
        "expected '(' at byte {open}"
    );
    let mut depth = 0usize;
    for (offset, byte) in bytes[open..].iter().copied().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parentheses starting at byte {open}");
}

fn region_between<'a>(
    source: &'a str,
    start_marker: &str,
    end_marker: &str,
    context: &str,
) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("{context}: expected to find {start_marker:?}"));
    let rest = &source[start..];
    let end = rest
        .find(end_marker)
        .unwrap_or_else(|| panic!("{context}: expected to find {end_marker:?} after start"))
        + end_marker.len();
    &rest[..end]
}

fn squeeze(source: &str) -> String {
    source.split_whitespace().collect()
}

/// Every `kube_watcher::watcher(...)` in the node-agent module must chain
/// `.default_backoff()` immediately after the call. A second, unbounded
/// construction a few lines away cannot hide behind one backed-off site.
#[test]
fn every_node_agent_kube_watcher_construction_chains_default_backoff() {
    let mut search_from = 0usize;
    let mut count = 0usize;
    while let Some(rel) = NODE_AGENT_SRC[search_from..].find(WATCHER_CALL) {
        let start = search_from + rel;
        let args_open = start + WATCHER_CALL.len() - 1;
        let args_close = matching_paren(NODE_AGENT_SRC, args_open);
        let after = NODE_AGENT_SRC[args_close + 1..].trim_start();
        assert!(
            after.starts_with(DEFAULT_BACKOFF),
            "kube_watcher::watcher(...) at byte {start} must chain .default_backoff() \
             immediately so a neighboring bare construction cannot silently return; got {:?}",
            after.get(..after.len().min(48)).unwrap_or(after)
        );
        count += 1;
        search_from = args_close + 1;
    }
    assert!(
        count >= 1,
        "expected at least one kube_watcher::watcher construction in node_agent.rs"
    );
}

/// The live Pods watch (not the injected test seam) retains the node field
/// selector and applies kube's default backoff at Box::pin construction.
#[test]
fn production_pod_watch_construction_uses_node_selector_and_default_backoff() {
    assert!(
        NODE_AGENT_SRC.contains("WatchStreamExt"),
        "WatchStreamExt must stay in scope for .default_backoff()"
    );

    let construction = region_between(
        NODE_AGENT_SRC,
        "let pods: Api<Pod> = Api::all(client.clone());",
        "run_with_pod_stream(",
        "production pod watch construction",
    );
    let squeezed = squeeze(construction);
    assert!(
        construction.contains("spec.nodeName={}"),
        "node field selector must remain on the production watcher config"
    );
    assert!(
        squeezed.contains("kube_watcher::watcher(pods,watcher_config).default_backoff()"),
        "production stream must be watcher(pods, watcher_config).default_backoff()"
    );
    assert!(
        !squeezed.contains("tokio::time::sleep") && !squeezed.contains(".sleep("),
        "backoff belongs on the stream, not a construction-site sleep"
    );

    let error_arm = region_between(
        NODE_AGENT_SRC,
        "Some(Err(e)) => {",
        "None => {",
        "pod watcher error arm",
    );
    assert!(
        error_arm.contains("metrics.attach_errors.fetch_add(1, Ordering::Relaxed)"),
        "watcher errors must still increment attach_errors"
    );
    assert!(
        !error_arm.contains("sleep") && !error_arm.contains("default_backoff"),
        "the select error arm must not add a second backoff or sleep"
    );
}
