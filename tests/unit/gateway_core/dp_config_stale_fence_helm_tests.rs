//! Static Helm/chart contract coverage for issue #4438.
//!
//! The DP stale-config fence (`FERRUM_DP_CONFIG_MAX_STALE_SECONDS` /
//! `FERRUM_DP_CONFIG_STALE_ACTION`) must be first-class on `ferrum-gateway`
//! mode=dp. Hosted CI runs `helm template` inline in `.github/workflows/ci.yml`
//! (not a discoverable cases file), so these tests pin the chart source without
//! a local `helm` binary.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-gateway")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-gateway/{rel}: {e}");
    })
}

#[test]
fn values_default_dp_stale_fence_unset() {
    let values = read("values.yaml");
    let idx = values.find("dp:").expect("values.yaml must declare dp");
    let window = &values[idx..values.len().min(idx + 900)];
    assert!(
        window.contains("configMaxStaleSeconds: \"\""),
        "dp.configMaxStaleSeconds must default to empty (binary 3600s)"
    );
    assert!(
        window.contains("configStaleAction: \"\""),
        "dp.configStaleAction must default to empty (binary fail_closed)"
    );
}

#[test]
fn schema_bounds_dp_stale_fence() {
    let schema = read("values.schema.json");
    assert!(
        schema.contains("\"configMaxStaleSeconds\"")
            && schema.contains("\"minimum\": 0")
            // The optional group is what admits the documented empty-string
            // "unset" form in values.yaml; a bare `^[0-9]+$` rejects it and
            // `helm lint` fails the default render.
            && schema.contains("\"pattern\": \"^([0-9]+)?$\""),
        "schema must bound configMaxStaleSeconds as a non-negative integer or the unset form"
    );
    assert!(
        schema.contains("\"configStaleAction\"")
            && schema.contains("\"fail_closed\"")
            && schema.contains("\"readiness_only\""),
        "schema must enum configStaleAction to the binary's accepted spellings"
    );
}

#[test]
fn reserved_env_includes_dp_stale_fence() {
    let helpers = read("templates/_helpers.tpl");
    let reserved = helpers
        .split("{{- define \"ferrum-gateway.reservedEnv\" -}}")
        .nth(1)
        .and_then(|rest| rest.split("{{- end -}}").next())
        .expect("ferrum-gateway.reservedEnv define");
    for name in [
        "FERRUM_DP_CONFIG_MAX_STALE_SECONDS",
        "FERRUM_DP_CONFIG_STALE_ACTION",
    ] {
        assert!(
            reserved.contains(name),
            "reservedEnv must include {name} so env/extraEnv cannot shadow chart values"
        );
    }
}

#[test]
fn mode_dp_renders_stale_fence_env() {
    let helpers = read("templates/_helpers.tpl");
    let mode_env = helpers
        .split("{{- define \"ferrum-gateway.modeEnv\" -}}")
        .nth(1)
        .and_then(|rest| rest.split("{{- define ").next())
        .expect("ferrum-gateway.modeEnv define");
    assert!(
        mode_env.contains("eq $mode \"dp\"")
            && mode_env.contains("- name: FERRUM_DP_CONFIG_MAX_STALE_SECONDS")
            && mode_env.contains("- name: FERRUM_DP_CONFIG_STALE_ACTION"),
        "mode=dp must render both stale-config env vars when values are set"
    );
}

#[test]
fn helpers_reject_invalid_stale_action_and_max_stale() {
    let helpers = read("templates/_helpers.tpl");
    assert!(
        helpers.contains("dp.configStaleAction must be 'fail_closed' or 'readiness_only'"),
        "render must fail on unknown configStaleAction spellings"
    );
    assert!(
        helpers.contains("dp.configMaxStaleSeconds must be a non-negative integer"),
        "render must fail on non-integer configMaxStaleSeconds"
    );
}

#[test]
fn notes_print_effective_dp_stale_fence_without_secrets() {
    let notes = read("templates/NOTES.txt");
    assert!(
        notes.contains("Stale-config fence:")
            && notes.contains("ferrum-gateway.dpConfigMaxStaleSecondsEffective")
            && notes.contains("ferrum-gateway.dpConfigStaleActionEffective")
            && notes.contains("bounded-last-known-good-configuration-age"),
        "NOTES.txt must print effective DP stale bound/action for dp installs"
    );
    for secret in ["jwt", "secret", "password", "token"] {
        assert!(
            !notes.to_lowercase().contains(&format!("{secret}:")),
            "NOTES.txt must not print secret material ({secret})"
        );
    }
}

#[test]
fn chart_readme_documents_dp_stale_fence_values() {
    let readme = read("README.md");
    assert!(
        readme.contains("dp.configMaxStaleSeconds")
            && readme.contains("dp.configStaleAction")
            && readme.contains("FERRUM_DP_CONFIG_MAX_STALE_SECONDS")
            && readme.contains("FERRUM_DP_CONFIG_STALE_ACTION")
            && readme.contains("fail_closed"),
        "chart README must document DP stale-config first-class values"
    );
}
