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

#[test]
fn destination_rule_port_level_diagnostics_withhold_supplied_numbers() {
    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use serde_json::json;

    for (ports, token, reason) in [
        (vec![918273641], "918273641", "between 1 and 65535"),
        (vec![31415, 31415], "31415", "duplicate port"),
    ] {
        let object = K8sObject {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "DestinationRule".to_string(),
            metadata: K8sMetadata {
                name: "fixture".to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            },
            spec: json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {"portLevelSettings": ports.into_iter().map(|port| {
                    json!({"port": {"number": port}})
                }).collect::<Vec<_>>()}
            }),
            status: json!({}),
        };
        let options = K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").unwrap(),
        );
        let error = translate_k8s_objects(&[object], options).unwrap_err();
        let rendered = render_startup_error(error.into(), &[]);
        assert!(rendered.contains("trafficPolicy.portLevelSettings"), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        assert!(!rendered.contains(token), "{rendered}");
    }
}

#[test]
fn destination_rule_translation_warning_withholds_document_fields_at_emission() {
    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use serde_json::json;

    let logs = DiagnosticLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let token = "UNREGISTERED_TRANSLATION_5591";
    let object = K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "DestinationRule".to_string(),
        metadata: K8sMetadata {
            name: token.to_string(),
            namespace: "default".to_string(),
            ..Default::default()
        },
        spec: json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {"loadBalancer": {"localityLbSetting": {
                "failoverPriority": [token, token]
            }}}
        }),
        status: json!({}),
    };
    let options = K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").unwrap(),
    );
    translate_k8s_objects(&[object], options).unwrap();
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("failoverPriority contains a duplicate"), "{output}");
    assert!(output.contains("index=1"), "{output}");
    assert!(!output.contains(token), "{output}");
}

#[derive(Clone, Default)]
struct DiagnosticLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for DiagnosticLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DiagnosticLogs {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
