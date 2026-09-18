use ferrum_edge::startup::render_startup_error;

#[test]
fn fatal_mesh_startup_preserves_every_cause_in_order() {
    let cause = "mesh.workloads[0]: missing field `selector` at line 3 column 7";
    let context = "failed to load localized mesh config from '/tmp/mesh-invalid.yaml'";
    let error = anyhow::anyhow!(cause)
        .context("invalid mesh configuration document")
        .context(context);

    let message = format!("Fatal error: {}", render_startup_error(error, &[]));

    assert_eq!(
        message,
        format!(
            "Fatal error: failed to load localized mesh config from <redacted scalar>: \
             invalid mesh configuration document: {cause}"
        )
    );
}

#[test]
fn startup_sanitizes_each_cause_before_joining() {
    for quote in ['\'', '"'] {
        let error = anyhow::anyhow!("mesh.services[0].cluster_ips[0]: invalid IP address")
            .context(format!("validator rejected {quote}UNREGISTERED_TOKEN"))
            .context("startup rejected `mesh`");
        assert_eq!(
            render_startup_error(error, &[]),
            "startup rejected `mesh`: validator rejected <redacted scalar>: \
             mesh.services[0].cluster_ips[0]: invalid IP address"
        );
    }
}

#[test]
fn startup_withholds_debug_escaped_semantic_values() {
    let value = "prefix'\"UNREGISTERED_TOKEN\\tail\n";
    let error =
        anyhow::anyhow!("`host` {value:?}: invalid hostname").context("configuration rejected");
    assert_eq!(
        render_startup_error(error, &[]),
        "configuration rejected: `host` <redacted scalar>: invalid hostname"
    );
}

#[test]
fn startup_chain_redacts_database_urls_below_safe_contexts() {
    // Synthetic credentials: model a driver cause retained below a safe wrapper.
    let url = "postgres://fixture-user:fixture-password@localhost/db?token=fixture-token";
    let error = anyhow::anyhow!("driver rejected {url}")
        .context("database initialization failed (credentials withheld)")
        .context("failed to start database mode");

    let message = render_startup_error(error, &[url]);

    assert!(message.starts_with("failed to start database mode: database initialization failed"));
    assert!(message.contains("driver rejected postgres://"));
    for credential in ["fixture-user", "fixture-password", "fixture-token"] {
        assert!(
            !message.contains(credential),
            "credential escaped: {message}"
        );
    }
}

#[test]
fn startup_chain_includes_typed_sources_and_single_errors() {
    #[derive(Debug, thiserror::Error)]
    #[error("could not read mesh file")]
    struct ReadFailure(#[source] std::io::Error);

    let error = anyhow::Error::new(ReadFailure(std::io::Error::from(
        std::io::ErrorKind::PermissionDenied,
    )))
    .context("startup refused");
    let message = render_startup_error(error, &[]);
    let cause = std::io::Error::from(std::io::ErrorKind::PermissionDenied).to_string();

    assert!(message.starts_with("startup refused: could not read mesh file: "));
    assert!(message.ends_with(&cause));
    assert_eq!(
        render_startup_error(anyhow::anyhow!("invalid port"), &[]),
        "invalid port"
    );
}

#[test]
fn startup_redacts_quote_bearing_database_urls_before_withholding_spans() {
    for query in [
        "fixture-token'with-tail",
        "fixture-token\"with-tail",
        "fixture-token'\"tail",
    ] {
        let url = format!("postgres://fixture-user:fixture-password@localhost/db?token={query}");
        let error = anyhow::anyhow!("`next.field`: invalid configuration")
            .context(format!("driver rejected {url}"));
        let rendered = render_startup_error(error, &[&url]);
        for credential in [
            "fixture-user",
            "fixture-password",
            "fixture-token",
            "with-tail",
        ] {
            assert!(!rendered.contains(credential), "{rendered}");
        }
        assert_eq!(
            rendered,
            "<redacted diagnostic>: `next.field`: invalid configuration"
        );
    }
}
