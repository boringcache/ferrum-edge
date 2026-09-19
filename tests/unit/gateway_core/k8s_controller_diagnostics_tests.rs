//! Exercise the controller consumer, including the retained-warning replay.

use super::*;
use crate::config_sources::k8s::K8sMetadata;
use serde_json::json;

#[path = "../../common/diagnostic_logs.rs"]
mod diagnostic_logs;

fn object(kind: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: match kind {
            "Telemetry" => "telemetry.istio.io/v1",
            "PeerAuthentication" => "security.istio.io/v1",
            _ => "networking.istio.io/v1alpha3",
        }
        .to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: "'UNREGISTERED_name\"\\tail".to_string(),
            namespace: "UNREGISTERED_namespace".to_string(),
            uid: String::new(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: json!({}),
    }
}

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "UNREGISTERED_namespace".to_string(),
        TrustDomain::new("cluster.local").unwrap(),
    )
}

#[test]
fn controller_withholds_retained_translation_warning_values() {
    let telemetry = object(
        "Telemetry",
        json!({"tracing": [{"providers": [{"name": "UNREGISTERED_provider"}]}]}),
    );
    let ((translation, errors), logs) = diagnostic_logs::capture_logs(|| {
        translate_with_skip_retries(&[telemetry], options(), &ControllerMetrics::default())
            .expect("warning must not reject the translation")
    });
    assert!(errors.is_empty());
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains("UNREGISTERED_provider")),
        "structured diagnostics must retain their original context"
    );
    let replay = logs
        .lines()
        .find(|line| line.contains("K8s translation warning"))
        .expect("the controller must consume and log the retained warning");
    assert!(replay.contains("extensionProvider"), "{logs}");
    assert!(replay.contains("provider skipped"), "{logs}");
    assert!(!logs.contains("UNREGISTERED"), "{logs}");
}

#[test]
fn controller_withholds_skipped_resource_values_and_retains_status_errors() {
    for (kind, spec, event, reason) in [
        (
            "PeerAuthentication",
            json!({"mtls": {"mode": "'UNREGISTERED_mode\"\\tail"}}),
            "Invalid K8s resource, skipping",
            "mtls.mode unsupported value",
        ),
        (
            "EnvoyFilter",
            json!({}),
            "Unsupported K8s resource skipped",
            "EnvoyFilter is intentionally unsupported",
        ),
    ] {
        let resource = object(kind, spec);
        let metrics = ControllerMetrics::default();
        let ((_, errors), logs) = diagnostic_logs::capture_logs(|| {
            translate_with_skip_retries(&[resource], options(), &metrics)
                .expect("skipping one resource must still yield a translation")
        });
        assert_eq!(errors.len(), 1);
        assert_eq!(metrics.errors.load(std::sync::atomic::Ordering::Relaxed), 1);
        let diagnostic = errors.values().next().unwrap().to_string();
        assert!(diagnostic.contains("UNREGISTERED_name"));
        assert!(diagnostic.contains("UNREGISTERED_namespace"));
        assert!(logs.contains(event), "{logs}");
        assert!(logs.contains(reason), "{logs}");
        for field in ["kind=", "namespace=", "name="] {
            assert!(logs.contains(field), "{logs}");
        }
        if kind == "PeerAuthentication" {
            assert!(diagnostic.contains("UNREGISTERED_mode"));
            assert!(
                logs.contains("UNSET, DISABLE, PERMISSIVE, STRICT"),
                "{logs}"
            );
        }
        assert!(!logs.contains("UNREGISTERED"), "{logs}");
    }
}

#[test]
fn controller_fault_delay_warning_retains_the_fixed_cap() {
    let resource = object(
        "VirtualService",
        json!({
            "hosts": ["example.com"],
            "http": [{
                "fault": {"delay": {"percentage": {"value": 100}, "fixedDelay": "1h"}},
                "route": [{"destination": {"host": "backend", "port": {"number": 8080}}}]
            }]
        }),
    );
    let ((translation, errors), logs) = diagnostic_logs::capture_logs(|| {
        translate_with_skip_retries(&[resource], options(), &ControllerMetrics::default())
            .expect("oversized delay must clamp")
    });
    assert!(errors.is_empty());
    let warning = translation
        .warnings
        .iter()
        .find(|warning| warning.contains("fault.delay.fixedDelay"))
        .expect("clamp warning");
    let rendered = crate::startup::render_startup_error(anyhow::anyhow!(warning.clone()), &[]);
    for output in [&rendered, &logs] {
        assert!(
            output.contains("http[0].fault.delay.fixedDelay"),
            "{output}"
        );
        assert!(
            output.contains("clamping to the Ferrum 60000 ms fault-delay cap"),
            "{output}"
        );
        assert!(!output.contains("3600000"), "{output}");
        assert!(!output.contains("UNREGISTERED"), "{output}");
    }
    assert!(logs.contains("K8s translation warning"), "{logs}");
}
