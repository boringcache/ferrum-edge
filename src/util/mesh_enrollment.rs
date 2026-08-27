//! Shared mesh enrollment / sidecar-injection opt-in and opt-out parsing.
//!
//! `injector::should_inject` and `ebpf::pod_watcher::evaluate_enrollment` must
//! agree on these predicates — the same single-source-of-truth rule applied to
//! egress baggage strip helpers.

/// Parsed value of `sidecar.istio.io/inject` / `ferrum.io/inject` annotations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectAnnotationValue {
    OptIn,
    OptOut,
    Unrecognized,
}

/// Parsed value of the `ferrum.io/mesh` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLabelValue {
    OptIn,
    OptOut,
    Unrecognized,
}

/// Parse inject annotations using Istio's `strconv.ParseBool` spellings.
pub fn parse_inject_annotation(raw: &str) -> InjectAnnotationValue {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => InjectAnnotationValue::OptIn,
        "0" | "f" | "F" | "FALSE" | "false" | "False" => InjectAnnotationValue::OptOut,
        _ => InjectAnnotationValue::Unrecognized,
    }
}

/// Parse the Ferrum mesh label for enrollment/injection decisions.
pub fn parse_mesh_label(raw: &str) -> MeshLabelValue {
    if raw.eq_ignore_ascii_case("enabled") {
        return MeshLabelValue::OptIn;
    }
    if raw.eq_ignore_ascii_case("disabled") {
        return MeshLabelValue::OptOut;
    }
    match parse_inject_annotation(raw) {
        InjectAnnotationValue::OptOut => MeshLabelValue::OptOut,
        InjectAnnotationValue::OptIn | InjectAnnotationValue::Unrecognized => {
            MeshLabelValue::Unrecognized
        }
    }
}

/// A present inject annotation blocks injection when it opts out or is unparseable.
pub fn inject_annotation_blocks_injection(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(raw) => matches!(
            parse_inject_annotation(raw),
            InjectAnnotationValue::OptOut | InjectAnnotationValue::Unrecognized
        ),
    }
}

/// A present inject annotation explicitly opts a workload in.
pub fn inject_annotation_opts_in(value: Option<&str>) -> bool {
    matches!(
        value,
        Some(raw) if parse_inject_annotation(raw) == InjectAnnotationValue::OptIn
    )
}

/// A present mesh label blocks injection when it opts out or is unparseable.
pub fn mesh_label_blocks_injection(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(raw) => matches!(
            parse_mesh_label(raw),
            MeshLabelValue::OptOut | MeshLabelValue::Unrecognized
        ),
    }
}

/// A present mesh label explicitly opts a workload in.
pub fn mesh_label_opts_in(value: Option<&str>) -> bool {
    matches!(
        value,
        Some(raw) if parse_mesh_label(raw) == MeshLabelValue::OptIn
    )
}

/// A present inject annotation value is not a recognized Istio bool spelling.
pub fn inject_annotation_is_unrecognized(value: Option<&str>) -> bool {
    matches!(
        value,
        Some(raw) if parse_inject_annotation(raw) == InjectAnnotationValue::Unrecognized
    )
}

/// A present mesh label value is not a recognized enrollment spelling.
pub fn mesh_label_is_unrecognized(value: Option<&str>) -> bool {
    matches!(
        value,
        Some(raw) if parse_mesh_label(raw) == MeshLabelValue::Unrecognized
    )
}
