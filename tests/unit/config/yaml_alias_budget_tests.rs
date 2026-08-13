//! File-config YAML alias/anchor admission (`config::yaml_alias_budget`).
//!
//! The check walks libyaml events, so comments, quoted scalars, tags, and
//! escaped text that merely contain `&`/`*` must not be treated as aliases.
//! Exponential alias graphs fail closed under the shared expansion budgets.

use ferrum_edge::config::stable_file::MAX_GATEWAY_CONFIG_FILE_BYTES;
use ferrum_edge::config::yaml_alias_budget::{
    MAX_YAML_COMPOSITION_NODES, MAX_YAML_EXPANDED_BYTES, YamlAliasBudgetError,
    admit_yaml_alias_expansion,
};

#[test]
fn expanded_byte_budget_matches_the_read_ceiling() {
    assert_eq!(
        MAX_YAML_EXPANDED_BYTES,
        MAX_GATEWAY_CONFIG_FILE_BYTES as usize
    );
}

#[test]
fn ordinary_yaml_without_aliases_is_admitted() {
    admit_yaml_alias_expansion("version: \"1\"\nproxies: []\n").expect("plain YAML");
}

#[test]
fn modest_anchor_reuse_is_admitted() {
    let yaml = concat!(
        "host: &host localhost\n",
        "first: *host\n",
        "second: *host\n",
    );
    admit_yaml_alias_expansion(yaml).expect("finite alias reuse");
}

#[test]
fn comments_with_ampersand_and_star_are_not_aliases() {
    let yaml = concat!(
        "# uses &anchor and *alias in a comment\n",
        "version: \"1\"\n",
        "proxies: []\n",
    );
    admit_yaml_alias_expansion(yaml).expect("comment text is not an alias event");
}

#[test]
fn quoted_scalars_with_anchor_spellings_are_not_aliases() {
    let yaml = concat!(
        "plain: \"foo &bar *baz\"\n",
        "single: '&anchor'\n",
        "double: \"*alias\"\n",
        "ampersand: \"&not-anchor\"\n",
        "star: \"*not-alias\"\n",
        "escaped: \"\\x26not-anchor \\x2Anot-alias\"\n",
    );
    admit_yaml_alias_expansion(yaml).expect("quoted &/* are scalars");
}

#[test]
fn block_scalars_with_ampersand_and_star_are_not_aliases() {
    let yaml = concat!(
        "literal: |\n",
        "  &not-an-anchor\n",
        "  *not-an-alias\n",
        "folded: >\n",
        "  still &plain *text\n",
    );
    admit_yaml_alias_expansion(yaml).expect("block scalars are not alias events");
}

#[test]
fn tagged_scalar_without_alias_is_admitted() {
    let yaml = "value: !!str hello\n";
    admit_yaml_alias_expansion(yaml).expect("core tags are not alias expansion");
}

#[test]
fn modest_tagged_aliases_on_scalar_sequence_and_mapping_are_admitted() {
    let yaml = concat!(
        "host: &host !hostname localhost\n",
        "first: *host\n",
        "second: *host\n",
        "nums: &nums !items [1, 2]\n",
        "nums_copy: *nums\n",
        "meta: &meta !record {k: v}\n",
        "meta_copy: *meta\n",
        "core: &core !!str hello\n",
        "core_copy: *core\n",
    );
    admit_yaml_alias_expansion(yaml).expect("modest tagged aliases");
}

#[test]
fn flow_and_block_forms_without_aliases_are_admitted() {
    admit_yaml_alias_expansion("{a: 1, b: [2, 3]}\n").expect("flow mapping");
    admit_yaml_alias_expansion("a:\n  - 1\n  - 2\n").expect("block sequence");
}

#[test]
fn json_through_yaml_without_aliases_is_admitted() {
    admit_yaml_alias_expansion("{\"version\":\"1\",\"proxies\":[]}")
        .expect("JSON is a YAML subset");
}

#[test]
fn nested_alias_bomb_fails_closed() {
    let yaml = concat!(
        "a: &a [1,2,3,4,5,6,7,8]\n",
        "b: &b [*a,*a,*a,*a,*a,*a,*a,*a]\n",
        "c: &c [*b,*b,*b,*b,*b,*b,*b,*b]\n",
        "d: &d [*c,*c,*c,*c,*c,*c,*c,*c]\n",
        "e: &e [*d,*d,*d,*d,*d,*d,*d,*d]\n",
        "f: &f [*e,*e,*e,*e,*e,*e,*e,*e]\n",
        "g: &g [*f,*f,*f,*f,*f,*f,*f,*f]\n",
        "root: *g\n",
    );
    let err = admit_yaml_alias_expansion(yaml).expect_err("alias bomb");
    assert!(
        matches!(
            err,
            YamlAliasBudgetError::AliasReferenceLimitExceeded
                | YamlAliasBudgetError::ExpandedByteLimitExceeded
                | YamlAliasBudgetError::ExpandedNodeLimitExceeded
                | YamlAliasBudgetError::WorkLimitExceeded
                | YamlAliasBudgetError::DepthExceeded
        ),
        "got {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("exceeds") || rendered.contains("limit"),
        "got {rendered}"
    );
    assert!(
        !rendered.contains("&a") && !rendered.contains("*g") && !rendered.contains("[1,2,3"),
        "diagnostics must not echo the hostile graph: {rendered}"
    );
}

#[test]
fn flow_style_alias_bomb_fails_closed() {
    let yaml = concat!(
        "{a: &a [1,2,3,4,5,6,7,8], ",
        "b: &b [*a,*a,*a,*a,*a,*a,*a,*a], ",
        "c: &c [*b,*b,*b,*b,*b,*b,*b,*b], ",
        "d: &d [*c,*c,*c,*c,*c,*c,*c,*c], ",
        "e: &e [*d,*d,*d,*d,*d,*d,*d,*d], ",
        "f: &f [*e,*e,*e,*e,*e,*e,*e,*e], ",
        "g: *f}",
    );
    let err = admit_yaml_alias_expansion(yaml).expect_err("flow alias bomb");
    assert!(
        matches!(
            err,
            YamlAliasBudgetError::AliasReferenceLimitExceeded
                | YamlAliasBudgetError::ExpandedByteLimitExceeded
                | YamlAliasBudgetError::ExpandedNodeLimitExceeded
                | YamlAliasBudgetError::WorkLimitExceeded
                | YamlAliasBudgetError::DepthExceeded
        ),
        "got {err:?}"
    );
}

#[test]
fn alias_cycle_fails_closed_without_echoing_anchor_name() {
    let yaml = "loop: &attacker-chosen-anchor\n  next: *attacker-chosen-anchor\n";
    let err = admit_yaml_alias_expansion(yaml).expect_err("cycle");
    assert_eq!(err, YamlAliasBudgetError::Cycle);
    let rendered = err.to_string();
    assert_eq!(rendered, "YAML alias cycle detected during expansion");
    assert!(
        !rendered.contains("attacker-chosen-anchor"),
        "cycle diagnostics must not echo the attacker-chosen anchor name: {rendered}"
    );
}

#[test]
fn malformed_yaml_is_left_to_serde_yaml() {
    admit_yaml_alias_expansion("proxies: [\n  not closed")
        .expect("parse failures are serde_yaml's diagnostic");
}

#[test]
fn alias_before_later_malformation_fails_closed_and_redacted() {
    let yaml = concat!(
        "seed: &private-anchor confidential-value\n",
        "copy: *private-anchor\n",
        "broken: [unterminated-secret\n",
    );
    let err = admit_yaml_alias_expansion(yaml).expect_err("alias stream must fail closed");
    assert_eq!(err, YamlAliasBudgetError::InvalidAliasDocument);
    let rendered = err.to_string();
    assert_eq!(
        rendered,
        "YAML document containing aliases is malformed or unsupported"
    );
    assert!(!rendered.contains("private-anchor"));
    assert!(!rendered.contains("confidential-value"));
    assert!(!rendered.contains("unterminated-secret"));
}

#[test]
fn alias_in_a_multi_document_stream_fails_closed() {
    let yaml = concat!(
        "---\n",
        "seed: &private-anchor value\n",
        "copy: *private-anchor\n",
        "---\n",
        "second: document-secret\n",
    );
    let err = admit_yaml_alias_expansion(yaml).expect_err("multi-document alias stream");
    assert_eq!(err, YamlAliasBudgetError::InvalidAliasDocument);
    let rendered = err.to_string();
    assert!(!rendered.contains("private-anchor"));
    assert!(!rendered.contains("document-secret"));
}

#[test]
fn composition_node_exhaustion_fails_before_materialization() {
    let mut yaml = String::with_capacity(MAX_YAML_COMPOSITION_NODES * 6);
    yaml.push_str("seed: &seed 0\ncopy: *seed\nitems:\n");
    for _ in 0..MAX_YAML_COMPOSITION_NODES {
        yaml.push_str("  - 0\n");
    }

    let err = admit_yaml_alias_expansion(&yaml).expect_err("composition node ceiling");
    assert_eq!(err, YamlAliasBudgetError::CompositionNodeLimitExceeded);
    assert_eq!(
        err.to_string(),
        "YAML document exceeds composition node limit"
    );
}

#[test]
fn composition_and_expansion_share_one_work_budget() {
    // Each alias costs one composition lookup plus an alias visit and target
    // visit during expansion. At this size no node/byte/alias cap is reached,
    // so only cumulative (not phase-local) work accounting rejects the graph.
    let alias_count = 400_000;
    let mut yaml = String::with_capacity(alias_count * 8);
    yaml.push_str("seed: &seed 0\nitems:\n");
    for _ in 0..alias_count {
        yaml.push_str("  - *seed\n");
    }

    let err = admit_yaml_alias_expansion(&yaml).expect_err("cumulative work ceiling");
    assert_eq!(err, YamlAliasBudgetError::WorkLimitExceeded);
    assert_eq!(
        err.to_string(),
        "YAML document exceeds admission work limit; reduce alias reuse or nesting"
    );
}

#[test]
fn duplicate_anchor_redefinition_matches_serde_yaml_last_definition() {
    let yaml = concat!(
        "first: &same one\n",
        "before: *same\n",
        "second: &same two\n",
        "after: *same\n",
    );
    admit_yaml_alias_expansion(yaml).expect("serde_yaml accepts anchor redefinition");
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).expect("parse redefined anchor");
    assert_eq!(value["before"].as_str(), Some("one"));
    assert_eq!(value["after"].as_str(), Some("two"));
}

/// Distinctive local-tag prefix used only to prove diagnostics stay redacted.
const HOSTILE_TAG_MARKER: &str = "z9tagbudget";

#[derive(Clone, Copy)]
enum TaggedReplayKind {
    Scalar,
    Sequence,
    Mapping,
}

/// Small source: one anchored node with a large custom tag, then many aliases.
/// Each expansion visit recharges the tag bytes under the shared payload cap.
fn tagged_alias_replay_yaml(kind: TaggedReplayKind, tag_len: usize, alias_count: usize) -> String {
    let marker_prefix = 1 + HOSTILE_TAG_MARKER.len();
    assert!(
        tag_len > marker_prefix,
        "tag_len must include bang, marker, and padding"
    );
    let padding = tag_len - marker_prefix;
    let mut tag = String::with_capacity(tag_len);
    tag.push('!');
    tag.push_str(HOSTILE_TAG_MARKER);
    tag.extend(std::iter::repeat_n('B', padding));

    let value = match kind {
        TaggedReplayKind::Scalar => " x",
        TaggedReplayKind::Sequence => " [x]",
        TaggedReplayKind::Mapping => " {k: v}",
    };
    let mut yaml = String::with_capacity(32 + tag_len + alias_count * 10);
    yaml.push_str("seed: &seed ");
    yaml.push_str(&tag);
    yaml.push_str(value);
    yaml.push('\n');
    yaml.push_str("items:\n");
    for _ in 0..alias_count {
        yaml.push_str("  - *seed\n");
    }
    yaml
}

fn oversized_tagged_alias_replay(kind: TaggedReplayKind) -> String {
    // 256 KiB tag: source stays far below the 64 MiB read ceiling, but
    // alias_count + 1 materializations exceed MAX_YAML_EXPANDED_BYTES.
    let tag_len = 256 * 1024;
    let alias_count = MAX_YAML_EXPANDED_BYTES / tag_len;
    tagged_alias_replay_yaml(kind, tag_len, alias_count)
}

fn assert_expanded_byte_limit_redacted(err: YamlAliasBudgetError) {
    assert_eq!(err, YamlAliasBudgetError::ExpandedByteLimitExceeded);
    let rendered = err.to_string();
    assert_eq!(
        rendered,
        "YAML document exceeds expanded byte limit; reduce alias reuse or document size"
    );
    assert!(
        !rendered.contains(HOSTILE_TAG_MARKER),
        "diagnostics must not echo the hostile tag: {rendered}"
    );
}

#[test]
fn large_tagged_scalar_replayed_through_aliases_hits_expanded_byte_limit() {
    let yaml = oversized_tagged_alias_replay(TaggedReplayKind::Scalar);
    let err = admit_yaml_alias_expansion(&yaml)
        .expect_err("tagged scalar alias replay must hit the payload cap");
    assert_expanded_byte_limit_redacted(err);
}

#[test]
fn large_tagged_sequence_replayed_through_aliases_hits_expanded_byte_limit() {
    let yaml = oversized_tagged_alias_replay(TaggedReplayKind::Sequence);
    let err = admit_yaml_alias_expansion(&yaml)
        .expect_err("tagged sequence alias replay must hit the payload cap");
    assert_expanded_byte_limit_redacted(err);
}

#[test]
fn large_tagged_mapping_replayed_through_aliases_hits_expanded_byte_limit() {
    let yaml = oversized_tagged_alias_replay(TaggedReplayKind::Mapping);
    let err = admit_yaml_alias_expansion(&yaml)
        .expect_err("tagged mapping alias replay must hit the payload cap");
    assert_expanded_byte_limit_redacted(err);
}
