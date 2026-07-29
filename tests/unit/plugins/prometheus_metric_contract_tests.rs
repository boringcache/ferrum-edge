//! DOC-10: Prometheus metric contract ↔ docs ↔ representative `/metrics`
//! exposition ↔ bundled chart queries.
//!
//! Canonical inventory: `docs/prometheus_metric_contract.json`
//! Operator reference: `docs/prometheus_metrics.md`

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use ferrum_edge::modes::database::DatabaseDeltaPollMetrics;
use ferrum_edge::plugins::mesh::bpf_metrics::MeshBpfMetrics;
use ferrum_edge::plugins::mesh::prometheus_helpers;
use ferrum_edge::plugins::prometheus_metric_contract::{
    BUNDLED_EXTERNAL_METRIC_ALLOWLIST, BUNDLED_PROMETHEUS_RULE_TEMPLATE,
    PROMETHEUS_METRIC_CONTRACT_JSON, PROMETHEUS_METRICS_REFERENCE_MD,
};
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{StreamTransactionSummary, TransactionSummary};
use serde_json::Value;

#[derive(Debug, Clone)]
struct FamilyContract {
    name: String,
    metric_type: String,
    help: String,
    labels: BTreeSet<String>,
    bundled: String,
    emission: String,
}

fn load_contract() -> BTreeMap<String, FamilyContract> {
    let value: Value =
        serde_json::from_str(PROMETHEUS_METRIC_CONTRACT_JSON).expect("contract JSON parses");
    let arr = value.as_array().expect("contract JSON is an array");
    let mut out = BTreeMap::new();
    for item in arr {
        let name = item["name"].as_str().expect("name").to_string();
        let labels = item["labels"]
            .as_array()
            .expect("labels")
            .iter()
            .map(|v| v.as_str().expect("label").to_string())
            .collect::<BTreeSet<_>>();
        assert!(
            out.insert(
                name.clone(),
                FamilyContract {
                    name: name.clone(),
                    metric_type: item["type"].as_str().expect("type").to_string(),
                    help: item["help"].as_str().expect("help").to_string(),
                    labels,
                    bundled: item["bundled"].as_str().expect("bundled").to_string(),
                    emission: item["emission"].as_str().expect("emission").to_string(),
                },
            )
            .is_none(),
            "duplicate contract family {name}"
        );
    }
    out
}

fn parse_exposition_families(text: &str) -> BTreeMap<String, (String, BTreeSet<String>)> {
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    let mut labels: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or_default();
            let ty = parts.next().unwrap_or_default();
            if !name.is_empty() {
                types.insert(name.to_string(), ty.to_string());
                labels.entry(name.to_string()).or_default();
            }
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let name_and_maybe_labels = line.split_once(' ').map(|(a, _)| a).unwrap_or(line);
        let (name, label_body) = if let Some(idx) = name_and_maybe_labels.find('{') {
            let end = name_and_maybe_labels
                .rfind('}')
                .unwrap_or(name_and_maybe_labels.len());
            (
                &name_and_maybe_labels[..idx],
                Some(&name_and_maybe_labels[idx + 1..end]),
            )
        } else {
            (name_and_maybe_labels, None)
        };
        let family = name
            .strip_suffix("_bucket")
            .or_else(|| name.strip_suffix("_sum"))
            .or_else(|| name.strip_suffix("_count"))
            .unwrap_or(name);
        if !types.contains_key(family) {
            continue;
        }
        let entry = labels.entry(family.to_string()).or_default();
        if let Some(body) = label_body {
            for piece in body.split(',') {
                if let Some((key, _)) = piece.split_once('=') {
                    entry.insert(key.to_string());
                }
            }
        }
    }

    let mut out = BTreeMap::new();
    for (name, ty) in types {
        out.insert(name.clone(), (ty, labels.remove(&name).unwrap_or_default()));
    }
    out
}

fn ferrum_metric_names_in_text(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let token = &text[start..i];
            if token.starts_with("ferrum_") || token.starts_with("chargeback_sink_") {
                let family = token
                    .strip_suffix("_bucket")
                    .or_else(|| token.strip_suffix("_sum"))
                    .or_else(|| token.strip_suffix("_count"))
                    .unwrap_or(token);
                names.insert(family.to_string());
            }
            continue;
        }
        i += 1;
    }
    names
}

fn make_summary(proxy_id: &str) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2025-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/contract".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some("Contract".to_string()),
        backend_target: Some("http://localhost:3000".to_string()),
        backend_resolved_ip: None,
        response_status_code: 200,
        latency_total_ms: 12.0,
        latency_gateway_processing_ms: 2.0,
        latency_backend_ttfb_ms: 8.0,
        latency_backend_total_ms: 9.0,
        latency_plugin_execution_ms: 1.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 1.0,
        request_user_agent: Some("contract".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        bytes_sent: 32,
        bytes_received: 64,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn make_stream_summary(proxy_id: &str, protocol: &str) -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("Stream".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: protocol.to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

/// Build a representative authenticated `/metrics` body from public emitters.
///
/// Seeds registry-backed families (including the DOC-10 cited database-delta,
/// remote-discovery, and raw-TCP egress signals), appends process observability
/// families, and appends default-prefix mesh BPF families. Kafka / log-sink /
/// chargeback sink series require live plugin/process state and are covered by
/// the inventory + chart validators rather than this scrape fixture.
fn representative_exposition() -> String {
    let registry = MetricsRegistry::new();
    registry.configure(60, 3600, 0, "contract-ns");
    registry.record(&make_summary("contract-proxy"));
    registry.record_rate_limit_exceeded();
    registry.record_request_mirror_dispatched();
    registry.record_mesh_tcp_egress_connection("hbone", true);
    registry.record_mesh_tcp_egress_connection("mtls", false);
    registry.record_stream(&make_stream_summary("stream-proxy", "tcp"));

    let delta = Arc::new(DatabaseDeltaPollMetrics::default());
    delta.record_poll_completed();
    registry.set_database_delta_poll_metrics(delta);

    let suffix = format!("{}-{}", std::process::id(), line!());
    let cluster = format!("remote-{suffix}");
    let trust_domain = format!("td-{suffix}.example");
    prometheus_helpers::increment_mesh_remote_discovery_poll_failure(
        &cluster,
        &trust_domain,
        &format!("https://cp-{suffix}.example:9443"),
    );
    prometheus_helpers::record_mesh_remote_discovery_poll_success(
        &cluster,
        &trust_domain,
        1_700_000_000,
    );
    prometheus_helpers::record_mesh_cert_expiry_seconds(
        format!("spiffe://example/ns/{suffix}/sa/gw"),
        "spire_agent",
        3600,
    );

    let mut output = registry.render_uncached();
    output.push_str(&ferrum_edge::observability_delivery::render_prometheus());

    let bpf =
        MeshBpfMetrics::new(&serde_json::json!({})).expect("default bpf metrics plugin config");
    output.push_str(&bpf.exporter().render_prometheus());
    output
}

#[test]
fn prometheus_metric_contract_is_sorted_unique_and_well_formed() {
    let contract = load_contract();
    assert!(!contract.is_empty(), "contract must not be empty");
    let names: Vec<_> = contract.keys().cloned().collect();
    assert!(
        names.windows(2).all(|w| w[0] < w[1]),
        "contract family names must be strictly sorted"
    );
    for fam in contract.values() {
        assert!(
            matches!(
                fam.metric_type.as_str(),
                "counter" | "gauge" | "histogram" | "summary"
            ),
            "{} has invalid type {}",
            fam.name,
            fam.metric_type
        );
        assert!(!fam.help.is_empty(), "{} missing help", fam.name);
        assert!(
            matches!(
                fam.bundled.as_str(),
                "alert" | "dashboard" | "alert_and_dashboard" | "documented_only"
            ),
            "{} has invalid bundled {}",
            fam.name,
            fam.bundled
        );
        assert!(
            matches!(
                fam.emission.as_str(),
                "always"
                    | "conditional"
                    | "when_series_present"
                    | "when_plugin_enabled"
                    | "when_process_initialized"
            ),
            "{} has invalid emission {}",
            fam.name,
            fam.emission
        );
    }
    for required in [
        "ferrum_database_delta_consecutive_identical_rejections",
        "ferrum_mesh_tcp_egress_connections_total",
        "ferrum_mesh_remote_discovery_poll_failures_total",
        "ferrum_mesh_remote_discovery_poll_successes_total",
        "ferrum_mesh_remote_discovery_last_success_timestamp_seconds",
        "ferrum_mesh_remote_discovery_endpoint_age_seconds",
    ] {
        assert!(
            contract.contains_key(required),
            "DOC-10 required family missing from contract: {required}"
        );
    }
}

#[test]
fn prometheus_metrics_reference_documents_every_contract_family() {
    let contract = load_contract();
    let doc = PROMETHEUS_METRICS_REFERENCE_MD;
    assert!(
        doc.contains("# Prometheus Metrics Contract (DOC-10)"),
        "operator reference missing DOC-10 title"
    );
    for fam in contract.values() {
        let needle = format!("| `{}` |", fam.name);
        assert!(
            doc.contains(&needle),
            "docs/prometheus_metrics.md missing inventory row for {}",
            fam.name
        );
    }
    for section in [
        "Database rejected-delta polling",
        "Mesh remote-cluster endpoint discovery",
        "Raw-TCP mesh egress",
        "Endpoint-age runbook",
        "Poll-failure runbook",
    ] {
        assert!(
            doc.contains(section),
            "operator reference missing runbook section: {section}"
        );
    }
}

#[test]
fn representative_metrics_exposition_matches_contract() {
    let contract = load_contract();
    let exposition = representative_exposition();
    let emitted = parse_exposition_families(&exposition);

    assert!(
        !emitted.is_empty(),
        "representative exposition produced no metric families"
    );

    let mut undocumented = Vec::new();
    for (name, (ty, label_keys)) in &emitted {
        let Some(fam) = contract.get(name) else {
            undocumented.push(name.clone());
            continue;
        };
        assert_eq!(
            fam.metric_type, *ty,
            "type drift for {name}: contract={} exposition={ty}",
            fam.metric_type
        );
        for key in label_keys {
            assert!(
                fam.labels.contains(key),
                "undocumented label `{key}` on family `{name}` (contract labels: {:?})",
                fam.labels
            );
        }
    }
    assert!(
        undocumented.is_empty(),
        "undocumented metric families in representative /metrics exposition: {undocumented:?}"
    );

    for fam in contract.values().filter(|f| f.emission == "always") {
        // Log-sink families are inventoried as when_process_initialized; the
        // remaining `always` set must appear in this fixture.
        assert!(
            emitted.contains_key(&fam.name),
            "always-emitted family missing from representative exposition: {}",
            fam.name
        );
    }

    for required in [
        "ferrum_database_delta_consecutive_identical_rejections",
        "ferrum_mesh_tcp_egress_connections_total",
        "ferrum_mesh_remote_discovery_poll_failures_total",
        "ferrum_mesh_remote_discovery_poll_successes_total",
        "ferrum_mesh_remote_discovery_last_success_timestamp_seconds",
        "ferrum_mesh_remote_discovery_endpoint_age_seconds",
        "ferrum_mesh_bpf_tcp_events_total",
    ] {
        assert!(
            emitted.contains_key(required),
            "representative exposition missing required family {required}"
        );
    }
}

#[test]
fn bundled_prometheus_rule_metric_refs_are_inventoried_or_allowlisted() {
    let contract = load_contract();
    let allow: BTreeSet<&str> = BUNDLED_EXTERNAL_METRIC_ALLOWLIST.iter().copied().collect();
    let names = ferrum_metric_names_in_text(BUNDLED_PROMETHEUS_RULE_TEMPLATE);
    let mut unknown = Vec::new();
    for name in names {
        if allow.contains(name.as_str()) {
            continue;
        }
        if !contract.contains_key(&name) {
            unknown.push(name);
        }
    }
    assert!(
        unknown.is_empty(),
        "PrometheusRule references unknown Ferrum families: {unknown:?}"
    );
}

#[test]
fn bundled_grafana_dashboard_metric_refs_are_inventoried() {
    let contract = load_contract();
    const DASHBOARDS: &[&str] = &[
        include_str!("../../../charts/ferrum-mesh/dashboards/certificate-posture.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/egress-scope.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/gateway-overview.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/mesh-overview.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/policy-deny.json"),
    ];
    let mut unknown = Vec::new();
    for dash in DASHBOARDS {
        for name in ferrum_metric_names_in_text(dash) {
            if !contract.contains_key(&name) {
                unknown.push(name);
            }
        }
    }
    unknown.sort();
    unknown.dedup();
    assert!(
        unknown.is_empty(),
        "Grafana dashboards reference unknown Ferrum families: {unknown:?}"
    );
}

#[test]
fn bundled_classification_matches_chart_references() {
    let contract = load_contract();
    let mut referenced = ferrum_metric_names_in_text(BUNDLED_PROMETHEUS_RULE_TEMPLATE);
    for dash in [
        include_str!("../../../charts/ferrum-mesh/dashboards/certificate-posture.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/egress-scope.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/gateway-overview.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/mesh-overview.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/policy-deny.json"),
    ] {
        referenced.extend(ferrum_metric_names_in_text(dash));
    }
    for fam in contract.values() {
        let is_ref = referenced.contains(&fam.name);
        match fam.bundled.as_str() {
            "documented_only" => assert!(
                !is_ref,
                "{} is documented_only but appears in bundled charts/alerts",
                fam.name
            ),
            "alert" | "dashboard" | "alert_and_dashboard" => assert!(
                is_ref,
                "{} is classified as {} but is not referenced by bundled charts/alerts",
                fam.name, fam.bundled
            ),
            other => panic!("unexpected bundled value {other}"),
        }
    }
}
