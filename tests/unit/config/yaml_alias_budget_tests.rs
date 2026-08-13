//! File-config YAML alias/anchor admission (`config::yaml_alias_budget`).
//!
//! The check walks libyaml events, so comments, quoted scalars, tags, and
//! escaped text that merely contain `&`/`*` must not be treated as aliases.
//! Exponential alias graphs fail closed under the shared expansion budgets.

use ferrum_edge::config::stable_file::MAX_GATEWAY_CONFIG_FILE_BYTES;
use ferrum_edge::config::yaml_alias_budget::{
    MAX_YAML_EXPANDED_BYTES, YamlAliasBudgetError, admit_yaml_alias_expansion,
};

#[test]
fn expanded_byte_budget_is_twice_the_read_ceiling() {
    assert_eq!(
        MAX_YAML_EXPANDED_BYTES,
        (MAX_GATEWAY_CONFIG_FILE_BYTES as usize).saturating_mul(2)
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
        "escaped: \"\\&not-anchor \\*not-alias\"\n",
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
