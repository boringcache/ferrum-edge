//! Packaging / opt-in contracts for `example_audit_plugin`.
//!
//! Issue #2595: pedagogical examples must not alter the default production
//! plugin registry or schema. They live under `custom_plugins/examples/` and
//! require an explicit `FERRUM_CUSTOM_PLUGINS` listing (CI sets this for tests).

use std::fs;
use std::path::Path;

#[test]
fn example_sources_live_outside_production_discovery_directory() {
    assert!(
        Path::new("custom_plugins/examples/example_audit_plugin.rs").is_file(),
        "example_audit_plugin must live under custom_plugins/examples/"
    );
    assert!(
        Path::new("custom_plugins/examples/example_plugin.rs").is_file(),
        "example_plugin must live under custom_plugins/examples/"
    );
    assert!(
        !Path::new("custom_plugins/example_audit_plugin.rs").is_file(),
        "example_audit_plugin must not sit in the default auto-discovery directory"
    );
    assert!(
        !Path::new("custom_plugins/example_plugin.rs").is_file(),
        "example_plugin must not sit in the default auto-discovery directory"
    );
}

#[test]
fn build_script_requires_explicit_opt_in_for_examples() {
    let build = include_str!("../../build.rs");
    assert!(
        build.contains("custom_plugins/examples")
            || build.contains("examples_dir")
            || build.contains("examples"),
        "build.rs must know about the examples directory"
    );
    assert!(
        build.contains("FERRUM_CUSTOM_PLUGINS"),
        "build.rs must honor FERRUM_CUSTOM_PLUGINS"
    );
    assert!(
        build.contains("example_path") && build.contains("examples_dir.join"),
        "build.rs must resolve opted-in names from the examples directory"
    );
    assert!(
        build.contains("lists unknown plugin stem") || build.contains("unknown plugin stem(s)"),
        "build.rs must fail closed on unresolved FERRUM_CUSTOM_PLUGINS stems"
    );
}

#[test]
fn setup_rust_ci_custom_plugins_list_matches_examples_directory() {
    // Guard against drifting the shared composite action's hardcoded stem list
    // away from custom_plugins/examples/*.rs (F16).
    let action = include_str!("../../.github/actions/setup-rust-ci/action.yml");
    let export_line = action
        .lines()
        .find(|line| line.contains("FERRUM_CUSTOM_PLUGINS="))
        .expect("setup-rust-ci must export FERRUM_CUSTOM_PLUGINS");
    let assigned = export_line
        .split("FERRUM_CUSTOM_PLUGINS=")
        .nth(1)
        .expect("assignment")
        .trim()
        .trim_matches('"')
        .split(">>")
        .next()
        .expect("env assignment")
        .trim()
        .trim_matches('"');
    let mut listed: Vec<&str> = assigned
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    listed.sort_unstable();

    let mut on_disk: Vec<String> = fs::read_dir("custom_plugins/examples")
        .expect("examples dir")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(str::to_string)
            } else {
                None
            }
        })
        .collect();
    on_disk.sort();

    assert_eq!(
        listed,
        on_disk.iter().map(String::as_str).collect::<Vec<_>>(),
        "setup-rust-ci FERRUM_CUSTOM_PLUGINS must list every custom_plugins/examples/*.rs stem"
    );
}

#[test]
fn default_collector_excludes_example_when_not_compiled() {
    // When CI opts examples in, the collector includes them; when a default
    // production artifact is built without FERRUM_CUSTOM_PLUGINS, it must not.
    // This test asserts the runtime registry matches that build-time choice and
    // that migration collection cannot invent example schema without the plugin.
    let names = ferrum_edge::custom_plugins::custom_plugin_names();
    let migrations = ferrum_edge::custom_plugins::collect_all_custom_plugin_migrations();
    let registered = names.contains(&"example_audit_plugin");
    let collected = migrations
        .iter()
        .any(|(name, _)| *name == "example_audit_plugin");
    assert_eq!(
        registered, collected,
        "migration collection must match registry membership for example_audit_plugin"
    );
    if !registered {
        assert!(
            migrations
                .iter()
                .all(|(name, _)| *name != "example_audit_plugin"),
            "unconfigured/default artifact must not contribute example_audit_plugin migrations"
        );
    }
}

#[test]
fn dockerfile_does_not_force_example_opt_in() {
    let dockerfile = include_str!("../../Dockerfile");
    assert!(
        !dockerfile.contains("FERRUM_CUSTOM_PLUGINS"),
        "Dockerfile must leave FERRUM_CUSTOM_PLUGINS unset so examples stay out of images"
    );
}
