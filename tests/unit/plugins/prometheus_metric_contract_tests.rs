//! DOC-10: Prometheus metric contract ↔ docs ↔ representative `/metrics`
//! exposition ↔ bundled chart queries.
//!
//! Canonical inventory: `docs/prometheus_metric_contract.json`
//! Operator reference: `docs/prometheus_metrics.md`

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use ferrum_edge::modes::database::DatabaseDeltaPollMetrics;
use ferrum_edge::plugins::api_chargeback::{
    ChargebackRegistry, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_RETAINED_BYTES, InstanceScope,
};
use ferrum_edge::plugins::mesh::bpf_metrics::MeshBpfMetrics;
use ferrum_edge::plugins::mesh::prometheus_helpers;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{StreamTransactionSummary, TransactionSummary};
use serde_json::Value;

const PROMETHEUS_METRIC_CONTRACT_JSON: &str =
    include_str!("../../../docs/prometheus_metric_contract.json");
const PROMETHEUS_METRICS_REFERENCE_MD: &str =
    include_str!("../../../docs/prometheus_metrics.md");
const BUNDLED_PROMETHEUS_RULE_TEMPLATE: &str =
    include_str!("../../../charts/ferrum-mesh/templates/alerts-prometheusrule.yaml");
const BUNDLED_EXTERNAL_METRIC_ALLOWLIST: &[&str] =
    &["apiserver_admission_webhook_rejection_count"];
const SAMPLE_SUFFIXES: &[&str] = &["_bucket", "_sum", "_count"];

const API_CHARGEBACK_FAMILIES: &[&str] = &[
    "ferrum_api_bandwidth_charges_total",
    "ferrum_api_bytes_received_total",
    "ferrum_api_bytes_sent_total",
    "ferrum_api_chargeable_calls_total",
    "ferrum_api_chargeback_dropped_charges_total",
    "ferrum_api_chargeback_identity_overflow_total",
    "ferrum_api_chargeback_registry_entries",
    "ferrum_api_chargeback_registry_max_entries",
    "ferrum_api_chargeback_registry_max_retained_bytes",
    "ferrum_api_chargeback_registry_retained_bytes",
    "ferrum_api_charges_total",
    "ferrum_api_stream_connection_charges_total",
    "ferrum_api_stream_connections_total",
];

#[derive(Debug, Clone)]
struct FamilyContract {
    name: String,
    metric_type: String,
    help: String,
    label_order: Vec<String>,
    labels: BTreeSet<String>,
    subsystem: String,
    bundled: String,
    emission: String,
}

#[derive(Debug)]
struct ExpositionFamily {
    help: String,
    metric_type: String,
    labels: BTreeSet<String>,
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
            .collect::<Vec<_>>();
        assert!(
            out.insert(
                name.clone(),
                FamilyContract {
                    name: name.clone(),
                    metric_type: item["type"].as_str().expect("type").to_string(),
                    help: item["help"].as_str().expect("help").to_string(),
                    label_order: labels.clone(),
                    labels: labels.into_iter().collect(),
                    subsystem: item["subsystem"].as_str().expect("subsystem").to_string(),
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

/// Normalize a metric token to its inventoried family.
///
/// Inventoried families that legitimately end in `_bucket` / `_sum` / `_count`
/// stay themselves. A suffix is stripped only when the exact name is not
/// inventoried and the stripped candidate is an inventoried histogram/summary.
fn normalize_family_name(name: &str, contract: &BTreeMap<String, FamilyContract>) -> String {
    if contract.contains_key(name) {
        return name.to_string();
    }
    for suffix in SAMPLE_SUFFIXES {
        if let Some(candidate) = name.strip_suffix(suffix) {
            if let Some(fam) = contract.get(candidate) {
                if fam.metric_type == "histogram" || fam.metric_type == "summary" {
                    return candidate.to_string();
                }
            }
        }
    }
    name.to_string()
}

/// Exposition-local sample → family mapping using `# TYPE` lines as inventory.
fn family_for_sample_name(name: &str, types: &BTreeMap<String, String>) -> Option<String> {
    if types.contains_key(name) {
        return Some(name.to_string());
    }
    for suffix in SAMPLE_SUFFIXES {
        if let Some(candidate) = name.strip_suffix(suffix) {
            if let Some(ty) = types.get(candidate) {
                if ty == "histogram" || ty == "summary" {
                    return Some(candidate.to_string());
                }
            }
        }
    }
    None
}

fn parse_exposition_families(text: &str) -> BTreeMap<String, ExpositionFamily> {
    let mut helps: BTreeMap<String, String> = BTreeMap::new();
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    let mut labels: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let Some((name, help)) = rest.split_once(' ') else {
                continue;
            };
            if let Some(previous) = helps.insert(name.to_string(), help.to_string()) {
                assert_eq!(previous, help, "conflicting HELP declarations for {name}");
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or_default();
            let ty = parts.next().unwrap_or_default();
            if !name.is_empty() {
                if let Some(previous) = types.insert(name.to_string(), ty.to_string()) {
                    assert_eq!(previous, ty, "conflicting TYPE declarations for {name}");
                }
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
        let Some(family) = family_for_sample_name(name, &types) else {
            continue;
        };
        let entry = labels.entry(family).or_default();
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
        out.insert(
            name.clone(),
            ExpositionFamily {
                help: helps.remove(&name).unwrap_or_default(),
                metric_type: ty,
                labels: labels.remove(&name).unwrap_or_default(),
            },
        );
    }
    out
}

fn ferrum_metric_names_in_text(
    text: &str,
    contract: &BTreeMap<String, FamilyContract>,
) -> BTreeSet<String> {
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
                names.insert(normalize_family_name(token, contract));
            }
            continue;
        }
        i += 1;
    }
    names
}

/// Extract `# TYPE` families from Rust string-literal contents only.
fn type_literals_in_rust_source(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for literal in extract_rust_string_literal_contents(text) {
        let mut search_from = 0;
        while let Some(rel) = literal[search_from..].find("# TYPE ") {
            let start = search_from + rel;
            let rest = &literal[start + "# TYPE ".len()..];
            let mut parts = rest.split_whitespace();
            let Some(name) = parts.next() else {
                search_from = start + 1;
                continue;
            };
            let Some(ty) = parts.next() else {
                search_from = start + 1;
                continue;
            };
            if (name.starts_with("ferrum_") || name.starts_with("chargeback_sink_"))
                && matches!(ty, "counter" | "gauge" | "histogram" | "summary")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                found.entry(name.to_string()).or_default().insert(ty.to_string());
            }
            search_from = start + 1;
        }
    }
    found
}

fn extract_rust_string_literal_contents(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
        }
        if bytes[i] == b'r' && i + 1 < bytes.len() && (bytes[i + 1] == b'#' || bytes[i + 1] == b'"')
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                let end_pat = format!("\"{}", "#".repeat(hashes));
                if let Some(rel) = text[j..].find(&end_pat) {
                    out.push(text[j..j + rel].to_string());
                    i = j + rel + end_pat.len();
                    continue;
                }
                break;
            }
        }
        if bytes[i] == b'"' {
            let mut j = i + 1;
            let mut buf = String::new();
            while j < bytes.len() {
                let c = bytes[j];
                if c == b'\\' {
                    if j + 1 >= bytes.len() {
                        break;
                    }
                    let esc = bytes[j + 1];
                    if esc == b'\n' {
                        j += 2;
                        continue;
                    }
                    match esc {
                        b'n' => buf.push('\n'),
                        b't' => buf.push('\t'),
                        b'r' => buf.push('\r'),
                        b'"' | b'\\' => buf.push(esc as char),
                        _ => buf.push(esc as char),
                    }
                    j += 2;
                    continue;
                }
                if c == b'"' {
                    out.push(buf);
                    j += 1;
                    break;
                }
                buf.push(c as char);
                j += 1;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn walk_production_rust_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn scan_production_type_literals() -> BTreeMap<String, BTreeSet<String>> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in walk_production_rust_sources() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (name, types) in type_literals_in_rust_source(&text) {
            found.entry(name).or_default().extend(types);
        }
    }
    found
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
/// families, appends default-prefix mesh BPF families, and appends api_chargeback
/// registry families. Kafka / log-sink / chargeback sink series require live
/// plugin/process state and are covered by the inventory + chart validators
/// rather than this scrape fixture.
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
        format!("https://cp-{suffix}.example:9443"),
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

    let chargeback = ChargebackRegistry::new();
    chargeback.configure(
        60,
        3600,
        0,
        DEFAULT_MAX_ENTRIES,
        DEFAULT_MAX_RETAINED_BYTES,
    );
    let scope = InstanceScope::new("USD", "contract-ns");
    chargeback.record_http(
        &scope,
        "contract-consumer",
        "contract-proxy",
        "Contract API",
        200,
        0.00001,
        64,
        32,
        0.0001,
        0.0002,
    );
    chargeback.record_stream(
        &scope,
        "contract-consumer",
        "stream-proxy",
        "Contract Stream",
        0.0005,
        128,
        256,
        0.0003,
        0.0004,
    );
    output.push_str(
        &chargeback
            .render_prometheus_uncached()
            .expect("chargeback prometheus render"),
    );
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
    for required in API_CHARGEBACK_FAMILIES {
        let fam = contract
            .get(*required)
            .unwrap_or_else(|| panic!("api_chargeback family missing from contract: {required}"));
        assert_eq!(fam.emission, "when_plugin_enabled");
        assert_eq!(fam.subsystem, "api_chargeback");
        assert_eq!(fam.bundled, "documented_only");
    }
    let calls = &contract["ferrum_api_chargeable_calls_total"];
    assert_eq!(calls.metric_type, "counter");
    assert_eq!(
        calls.labels,
        BTreeSet::from([
            "consumer".into(),
            "proxy_id".into(),
            "proxy_name".into(),
            "status_code".into(),
            "currency".into(),
            "namespace".into(),
        ])
    );
    let bandwidth = &contract["ferrum_api_bandwidth_charges_total"];
    assert_eq!(bandwidth.metric_type, "counter");
    assert!(bandwidth.labels.contains("direction"));
    assert!(bandwidth.labels.contains("protocol_family"));
    let entries = &contract["ferrum_api_chargeback_registry_entries"];
    assert_eq!(entries.metric_type, "gauge");
    assert!(entries.labels.is_empty());
}

#[test]
fn prometheus_metrics_reference_documents_every_contract_family() {
    let contract = load_contract();
    let doc = PROMETHEUS_METRICS_REFERENCE_MD;
    assert!(
        doc.contains("# Prometheus Metrics Contract (DOC-10)"),
        "operator reference missing DOC-10 title"
    );
    let inventory_section = doc
        .split_once("## Complete family inventory")
        .and_then(|(_, rest)| rest.split_once("## Bundled observability surfaces"))
        .map(|(inventory, _)| inventory)
        .expect("operator reference has a bounded complete-inventory section");
    let actual_rows = inventory_section
        .lines()
        .filter(|line| line.starts_with("| `"))
        .collect::<Vec<_>>();
    let expected_rows = contract
        .values()
        .map(|fam| {
            let labels = if fam.label_order.is_empty() {
                "—".to_string()
            } else {
                fam.label_order
                    .iter()
                    .map(|label| format!("`{label}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!(
                "| `{}` | {} | {} | `{}` | `{}` | `{}` | {} |",
                fam.name,
                fam.metric_type,
                labels,
                fam.subsystem,
                fam.bundled,
                fam.emission,
                fam.help
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_rows, expected_rows,
        "docs/prometheus_metrics.md complete inventory must be generated exactly from the contract"
    );
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
    for (name, observed) in &emitted {
        let Some(fam) = contract.get(name) else {
            undocumented.push(name.clone());
            continue;
        };
        assert_eq!(
            fam.metric_type, observed.metric_type,
            "type drift for {name}: contract={} exposition={}",
            fam.metric_type,
            observed.metric_type
        );
        assert_eq!(fam.help, observed.help, "HELP drift for family {name}");
        assert_eq!(fam.labels, observed.labels, "label-key drift for family {name}");
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
        "ferrum_api_chargeable_calls_total",
        "ferrum_api_charges_total",
        "ferrum_api_bandwidth_charges_total",
        "ferrum_api_chargeback_registry_entries",
        "ferrum_database_delta_backoff_bucket",
    ] {
        assert!(
            emitted.contains_key(required),
            "representative exposition missing required family {required}"
        );
    }
    let backoff = &emitted["ferrum_database_delta_backoff_bucket"];
    assert_eq!(backoff.metric_type, "gauge");
    assert!(
        backoff.labels.contains("bucket"),
        "backoff bucket gauge labels must include the bucket key: {:?}",
        backoff.labels
    );
}

#[test]
fn bundled_prometheus_rule_metric_refs_are_inventoried_or_allowlisted() {
    let contract = load_contract();
    let allow: BTreeSet<&str> = BUNDLED_EXTERNAL_METRIC_ALLOWLIST.iter().copied().collect();
    let names = ferrum_metric_names_in_text(BUNDLED_PROMETHEUS_RULE_TEMPLATE, &contract);
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
        for name in ferrum_metric_names_in_text(dash, &contract) {
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
    let mut referenced = ferrum_metric_names_in_text(BUNDLED_PROMETHEUS_RULE_TEMPLATE, &contract);
    for dash in [
        include_str!("../../../charts/ferrum-mesh/dashboards/certificate-posture.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/egress-scope.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/gateway-overview.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/mesh-overview.json"),
        include_str!("../../../charts/ferrum-mesh/dashboards/policy-deny.json"),
    ] {
        referenced.extend(ferrum_metric_names_in_text(dash, &contract));
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

#[test]
fn sample_suffix_normalization_preserves_semantic_bucket_gauges() {
    let contract = load_contract();
    assert_eq!(
        normalize_family_name("ferrum_database_delta_backoff_bucket", &contract),
        "ferrum_database_delta_backoff_bucket"
    );
    assert_eq!(
        normalize_family_name("ferrum_request_duration_ms_bucket", &contract),
        "ferrum_request_duration_ms"
    );
    assert_eq!(
        normalize_family_name("ferrum_request_duration_ms_sum", &contract),
        "ferrum_request_duration_ms"
    );
    assert_eq!(
        normalize_family_name("ferrum_request_duration_ms_count", &contract),
        "ferrum_request_duration_ms"
    );

    let exposition = "\
# HELP ferrum_database_delta_backoff_bucket Current rejected-delta retry backoff bucket. Exactly one bucket is 1.\n\
# TYPE ferrum_database_delta_backoff_bucket gauge\n\
ferrum_database_delta_backoff_bucket{bucket=\"none\",namespace=\"ns\"} 1\n\
# HELP ferrum_request_duration_ms Backend response time in milliseconds.\n\
# TYPE ferrum_request_duration_ms histogram\n\
ferrum_request_duration_ms_bucket{le=\"10\",proxy_id=\"p\"} 1\n\
ferrum_request_duration_ms_sum{proxy_id=\"p\"} 1\n\
ferrum_request_duration_ms_count{proxy_id=\"p\"} 1\n\
";
    let parsed = parse_exposition_families(exposition);
    assert_eq!(parsed["ferrum_database_delta_backoff_bucket"].metric_type, "gauge");
    assert!(parsed["ferrum_database_delta_backoff_bucket"]
        .labels
        .contains("bucket"));
    assert_eq!(parsed["ferrum_request_duration_ms"].metric_type, "histogram");
    assert!(parsed["ferrum_request_duration_ms"].labels.contains("le"));
    assert!(!parsed.contains_key("ferrum_database_delta_backoff"));
}

#[test]
fn production_type_literals_are_inventoried_with_matching_types() {
    let contract = load_contract();
    let found = scan_production_type_literals();
    assert!(
        !found.is_empty(),
        "expected production Rust # TYPE string literals under src/"
    );

    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    for (name, types) in &found {
        let Some(fam) = contract.get(name) else {
            missing.push(name.clone());
            continue;
        };
        if types != &BTreeSet::from([fam.metric_type.clone()]) {
            mismatched.push(format!(
                "{name}: contract={} source={types:?}",
                fam.metric_type
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "production # TYPE families missing from inventory: {missing:?}"
    );
    assert!(
        mismatched.is_empty(),
        "production # TYPE type mismatches: {mismatched:?}"
    );

    for name in API_CHARGEBACK_FAMILIES {
        assert!(
            found.contains_key(*name),
            "api_chargeback family missing production # TYPE literal: {name}"
        );
    }
}

#[test]
fn production_type_literal_scanner_has_mutation_and_noise_regressions() {
    let contract = load_contract();
    let synthetic = r#"output.push_str("# TYPE ferrum_contract_mutation_missing_total counter\n");"#;
    let detected = type_literals_in_rust_source(synthetic);
    assert!(
        detected.contains_key("ferrum_contract_mutation_missing_total"),
        "synthetic undocumented # TYPE literal was not detected"
    );
    assert!(
        !contract.contains_key("ferrum_contract_mutation_missing_total"),
        "mutation sentinel must not be present in the inventory"
    );

    let noise = r#"
        // # TYPE ferrum_comment_noise_total counter
        let ferrum_identifier_noise_total = 1;
        /* # TYPE ferrum_block_comment_noise_total gauge */
    "#;
    assert!(
        type_literals_in_rust_source(noise).is_empty(),
        "comment/identifier noise must not be treated as exported # TYPE literals"
    );
}
