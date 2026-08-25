//! Spelling-matrix coverage for shared mesh enrollment predicates (issue #4213).

use ferrum_edge::util::mesh_enrollment::{
    InjectAnnotationValue, MeshLabelValue, inject_annotation_blocks_injection,
    inject_annotation_is_unrecognized, inject_annotation_opts_in, mesh_label_blocks_injection,
    mesh_label_is_unrecognized, mesh_label_opts_in, parse_inject_annotation, parse_mesh_label,
};

#[test]
fn parse_inject_annotation_true_spellings() {
    for value in ["1", "t", "T", "TRUE", "true", "True"] {
        assert_eq!(
            parse_inject_annotation(value),
            InjectAnnotationValue::OptIn,
            "{value:?}"
        );
        assert!(inject_annotation_opts_in(Some(value)));
        assert!(!inject_annotation_blocks_injection(Some(value)));
    }
}

#[test]
fn parse_inject_annotation_false_spellings() {
    for value in ["0", "f", "F", "FALSE", "false", "False"] {
        assert_eq!(
            parse_inject_annotation(value),
            InjectAnnotationValue::OptOut,
            "{value:?}"
        );
        assert!(!inject_annotation_opts_in(Some(value)));
        assert!(inject_annotation_blocks_injection(Some(value)));
    }
}

#[test]
fn parse_inject_annotation_unrecognized_fails_closed() {
    for value in ["disabled", "yes", ""] {
        assert_eq!(
            parse_inject_annotation(value),
            InjectAnnotationValue::Unrecognized,
            "{value:?}"
        );
        assert!(inject_annotation_is_unrecognized(Some(value)));
        assert!(inject_annotation_blocks_injection(Some(value)));
        assert!(!inject_annotation_opts_in(Some(value)));
    }
}

#[test]
fn absent_inject_annotation_neither_opts_in_nor_blocks() {
    assert!(!inject_annotation_blocks_injection(None));
    assert!(!inject_annotation_opts_in(None));
    assert!(!inject_annotation_is_unrecognized(None));
}

#[test]
fn parse_mesh_label_enabled_spellings() {
    for value in ["enabled", "Enabled", "ENABLED"] {
        assert_eq!(parse_mesh_label(value), MeshLabelValue::OptIn, "{value:?}");
        assert!(mesh_label_opts_in(Some(value)));
        assert!(!mesh_label_blocks_injection(Some(value)));
    }
}

#[test]
fn parse_mesh_label_opt_out_spellings() {
    for value in ["disabled", "Disabled", "false", "False", "FALSE", "0", "f", "F"] {
        assert_eq!(parse_mesh_label(value), MeshLabelValue::OptOut, "{value:?}");
        assert!(!mesh_label_opts_in(Some(value)));
        assert!(mesh_label_blocks_injection(Some(value)));
    }
}

#[test]
fn parse_mesh_label_unrecognized_fails_closed() {
    for value in ["true", "True", "maybe", ""] {
        assert_eq!(parse_mesh_label(value), MeshLabelValue::Unrecognized, "{value:?}");
        assert!(mesh_label_is_unrecognized(Some(value)));
        assert!(mesh_label_blocks_injection(Some(value)));
        assert!(!mesh_label_opts_in(Some(value)));
    }
}

#[test]
fn absent_mesh_label_neither_opts_in_nor_blocks() {
    assert!(!mesh_label_blocks_injection(None));
    assert!(!mesh_label_opts_in(None));
    assert!(!mesh_label_is_unrecognized(None));
}
