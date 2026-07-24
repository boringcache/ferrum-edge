//! External coverage for periodic capability-probe merge semantics (issue #2940).
//!
//! Transient DNS/connect/refused/timeout failures must preserve a previously
//! `Supported` (or `Unsupported`) classification and never invent an
//! `Unsupported` verdict from a reachability blip alone.

use ferrum_edge::proxy::backend_capabilities::{
    ProtocolSupport, merge_protocol_probe_classification,
};

#[test]
fn transient_probe_preserves_supported_h3_classification() {
    let merged = merge_protocol_probe_classification(
        Some(ProtocolSupport::Supported),
        ProtocolSupport::Unsupported,
        true,
    );
    assert_eq!(merged, ProtocolSupport::Supported);
}

#[test]
fn transient_probe_preserves_unsupported_across_timeout() {
    // Timeout paths probe as Unknown but preserve_previous=true — a prior
    // Unsupported must survive so H3ProbeOutcome::apply writes it onto the
    // fresh refresh record instead of leaving the default Unknown.
    let merged = merge_protocol_probe_classification(
        Some(ProtocolSupport::Unsupported),
        ProtocolSupport::Unknown,
        true,
    );
    assert_eq!(merged, ProtocolSupport::Unsupported);
}

#[test]
fn transient_probe_without_prior_record_stays_unknown() {
    let merged =
        merge_protocol_probe_classification(None, ProtocolSupport::Unsupported, true);
    assert_eq!(merged, ProtocolSupport::Unknown);
}

#[test]
fn non_transient_probe_takes_authoritative_unsupported() {
    let merged = merge_protocol_probe_classification(
        Some(ProtocolSupport::Supported),
        ProtocolSupport::Unsupported,
        false,
    );
    assert_eq!(merged, ProtocolSupport::Unsupported);
}

#[test]
fn h3_probe_outcome_apply_always_writes_merged_classification() {
    // Source contract: after merge_protocol_probe_classification, apply must
    // assign `record.plain_http.h3 = self.h3` even for Unknown, so a
    // timeout-preserved Unsupported is not dropped by the historical
    // "skip Unknown" guard.
    let source = include_str!("../../../src/proxy/mod.rs");
    let apply = source
        .split("impl H3ProbeOutcome {")
        .nth(1)
        .expect("H3ProbeOutcome impl")
        .split("fn append_probe_error(")
        .next()
        .expect("bounded apply body");
    assert!(
        apply.contains("record.plain_http.h3 = self.h3;"),
        "H3ProbeOutcome::apply must always write the merged classification"
    );
    assert!(
        !apply.contains("if !matches!(self.h3, ProtocolSupport::Unknown)"),
        "H3ProbeOutcome::apply must not skip Unknown — that mishandles \
         timeout-preserving Unsupported/Supported on a fresh refresh record"
    );
}

#[test]
fn probe_h3_stamps_last_probe_error_on_transient_failures() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let probe = source
        .split("async fn probe_h3(")
        .nth(1)
        .expect("probe_h3")
        .split("async fn ")
        .next()
        .expect("bounded probe_h3 body");
    assert!(
        probe.contains("is_transient_capability_probe_failure(class)"),
        "probe_h3 must classify transient reachability failures"
    );
    assert!(
        probe.contains("merge_protocol_probe_classification("),
        "probe_h3 must merge against previous_h3"
    );
    assert!(
        probe.contains("HTTP/3 probe timed out for"),
        "probe_h3 timeout must stamp an operator-visible error"
    );
    assert!(
        probe.contains("HTTP/3 probe failed for"),
        "probe_h3 Ok(Err) must stamp last_probe_error even when preserving"
    );
}
