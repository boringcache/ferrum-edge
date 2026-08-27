#![allow(dead_code)]
//! Pod enrollment and lifecycle management for the eBPF node agent.
//!
//! Watches local-node pods via kube-rs, enrolls/unenrolls them based on
//! label/annotation criteria, and delegates BPF attachment to the
//! `EbpfBackend` trait.

use std::collections::HashSet;

use crate::util::mesh_enrollment::{
    inject_annotation_blocks_injection, inject_annotation_opts_in, mesh_label_blocks_injection,
    mesh_label_opts_in,
};

/// Criteria result for whether a pod should be enrolled for eBPF capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentDecision {
    Enroll,
    Skip,
}

/// Default namespaces excluded from enrollment.
pub const DEFAULT_EXCLUDED_NAMESPACES: &[&str] = &["kube-system", "kube-public", "kube-node-lease"];

/// Check whether a pod meets enrollment criteria for eBPF capture.
///
/// A pod is enrolled when:
/// - Has `ferrum.io/mesh: enabled` label OR `ferrum.io/inject: true` annotation
/// - Does NOT have `ferrum.io/injected: "true"` annotation (sidecar capture).
///   The value is checked explicitly so `ferrum.io/injected: "false"` does not
///   skip an otherwise eligible pod.
/// - Not in excluded namespaces
pub fn evaluate_enrollment(
    labels: &std::collections::HashMap<String, String>,
    annotations: &std::collections::HashMap<String, String>,
    namespace: &str,
    excluded_namespaces: &HashSet<String>,
) -> EnrollmentDecision {
    if excluded_namespaces.contains(namespace) {
        return EnrollmentDecision::Skip;
    }

    if inject_annotation_blocks_injection(annotations.get("ferrum.io/inject").map(String::as_str))
        || mesh_label_blocks_injection(labels.get("ferrum.io/mesh").map(String::as_str))
    {
        return EnrollmentDecision::Skip;
    }

    // The injector stamps `ferrum.io/injected: true` on pods that already
    // carry a sidecar; the node agent must not also enroll those for ambient
    // capture. Match on value (`== "true"`) rather than presence so an
    // operator-set `ferrum.io/injected: false` (e.g. on a non-injected pod
    // that should still be ambient-enrolled) does not silently exclude it.
    if annotations
        .get("ferrum.io/injected")
        .is_some_and(|v| v == "true")
    {
        return EnrollmentDecision::Skip;
    }

    let has_mesh_label = mesh_label_opts_in(labels.get("ferrum.io/mesh").map(String::as_str));
    let has_inject_annotation =
        inject_annotation_opts_in(annotations.get("ferrum.io/inject").map(String::as_str));

    if has_mesh_label || has_inject_annotation {
        EnrollmentDecision::Enroll
    } else {
        EnrollmentDecision::Skip
    }
}

/// Parse the pod IP from status.podIP (string form).
pub fn parse_pod_ip(ip_str: &str) -> Option<std::net::Ipv4Addr> {
    ip_str.parse().ok()
}

/// Build the default set of excluded namespaces from the constant list plus
/// any operator overrides.
pub fn build_excluded_namespaces(extra: &[String]) -> HashSet<String> {
    let mut set: HashSet<String> = DEFAULT_EXCLUDED_NAMESPACES
        .iter()
        .map(|s| s.to_string())
        .collect();
    for ns in extra {
        set.insert(ns.clone());
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn default_excluded() -> HashSet<String> {
        build_excluded_namespaces(&[])
    }

    #[test]
    fn enroll_mesh_enabled_label() {
        let labels = make_labels(&[("ferrum.io/mesh", "enabled")]);
        let annotations = HashMap::new();
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Enroll
        );
    }

    #[test]
    fn enroll_inject_true_annotation() {
        let labels = HashMap::new();
        let annotations = make_labels(&[("ferrum.io/inject", "true")]);
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Enroll
        );
    }

    #[test]
    fn skip_already_injected_sidecar() {
        let labels = make_labels(&[("ferrum.io/mesh", "enabled")]);
        let annotations = make_labels(&[("ferrum.io/injected", "true")]);
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn enroll_when_injected_annotation_is_false() {
        // `ferrum.io/injected: false` is a legitimate value an operator might
        // set; it must not silently exclude a pod that is otherwise eligible
        // for ambient capture.
        let labels = make_labels(&[("ferrum.io/mesh", "enabled")]);
        let annotations = make_labels(&[("ferrum.io/injected", "false")]);
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Enroll
        );
    }

    #[test]
    fn skip_excluded_namespace() {
        let labels = make_labels(&[("ferrum.io/mesh", "enabled")]);
        let annotations = HashMap::new();
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "kube-system", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn skip_explicit_opt_out_label() {
        let labels = make_labels(&[("ferrum.io/mesh", "disabled")]);
        let annotations = HashMap::new();
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn skip_explicit_opt_out_annotation() {
        let labels = HashMap::new();
        let annotations = make_labels(&[("ferrum.io/inject", "false")]);
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn skip_false_inject_annotation_spellings() {
        for value in ["false", "False", "FALSE", "0", "f", "F"] {
            let labels = HashMap::new();
            let annotations = make_labels(&[("ferrum.io/inject", value)]);
            assert_eq!(
                evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
                EnrollmentDecision::Skip,
                "ferrum.io/inject={value:?} must skip enrollment"
            );
        }
    }

    #[test]
    fn enroll_true_inject_annotation_spellings() {
        for value in ["true", "True", "TRUE", "1", "t", "T"] {
            let labels = HashMap::new();
            let annotations = make_labels(&[("ferrum.io/inject", value)]);
            assert_eq!(
                evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
                EnrollmentDecision::Enroll,
                "ferrum.io/inject={value:?} must enroll"
            );
        }
    }

    #[test]
    fn skip_mesh_label_false_and_disabled_spellings() {
        for value in ["false", "False", "FALSE", "0", "disabled", "Disabled"] {
            let labels = make_labels(&[("ferrum.io/mesh", value)]);
            let annotations = HashMap::new();
            assert_eq!(
                evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
                EnrollmentDecision::Skip,
                "ferrum.io/mesh={value:?} must skip enrollment"
            );
        }
    }

    #[test]
    fn enroll_mesh_enabled_label_spellings() {
        for value in ["enabled", "Enabled", "ENABLED"] {
            let labels = make_labels(&[("ferrum.io/mesh", value)]);
            let annotations = HashMap::new();
            assert_eq!(
                evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
                EnrollmentDecision::Enroll,
                "ferrum.io/mesh={value:?} must enroll"
            );
        }
    }

    #[test]
    fn skip_unrecognized_mesh_label_value() {
        let labels = make_labels(&[("ferrum.io/mesh", "maybe")]);
        let annotations = HashMap::new();
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn skip_unrecognized_inject_annotation_value() {
        let labels = HashMap::new();
        let annotations = make_labels(&[("ferrum.io/inject", "disabled")]);
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn skip_no_labels_or_annotations() {
        let labels = HashMap::new();
        let annotations = HashMap::new();
        assert_eq!(
            evaluate_enrollment(&labels, &annotations, "default", &default_excluded()),
            EnrollmentDecision::Skip
        );
    }

    #[test]
    fn extra_excluded_namespaces_merged() {
        let excluded = build_excluded_namespaces(&["monitoring".to_string()]);
        assert!(excluded.contains("kube-system"));
        assert!(excluded.contains("monitoring"));
    }

    #[test]
    fn parse_pod_ip_valid_v4() {
        assert_eq!(
            parse_pod_ip("10.0.0.5"),
            Some(std::net::Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[test]
    fn parse_pod_ip_v6_returns_none() {
        assert!(parse_pod_ip("::1").is_none());
    }

    #[test]
    fn parse_pod_ip_invalid() {
        assert!(parse_pod_ip("not-an-ip").is_none());
    }
}
