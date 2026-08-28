//! Static Helm/chart contract coverage for gateway PrometheusRule alerts (issue #4289).
//!
//! These tests pin mode-gated database-poll freshness and the always-available
//! data-path alert families without requiring a local `helm` binary. Hosted CI
//! still runs `helm template` end-to-end with promtool validation.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-gateway")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-gateway/{rel}: {e}");
    })
}

fn read_ci() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml"))
        .expect("read .github/workflows/ci.yml")
}

#[test]
fn prometheusrule_gates_database_poll_alert_to_database_and_cp_modes() {
    let rules = read("templates/metrics-prometheusrule.yaml");
    assert!(
        rules.contains("{{- if or (eq .Values.mode \"database\") (eq .Values.mode \"cp\") }}"),
        "database poll alert must render only in database/cp modes"
    );
    let poll_start = rules
        .find("FerrumGatewayDatabasePollStale")
        .expect("FerrumGatewayDatabasePollStale alert");
    let gate_start = rules[..poll_start]
        .rfind("{{- if or (eq .Values.mode \"database\") (eq .Values.mode \"cp\") }}")
        .expect("database poll alert must be wrapped in the mode gate");
    let gate_end = rules[poll_start..]
        .find("{{- end }}")
        .expect("database poll mode gate must close");
    let poll_block = &rules[gate_start..poll_start + gate_end];
    assert!(
        poll_block.contains("ferrum_database_poll_last_completed_timestamp_seconds"),
        "gated block must reference the database poll freshness gauge"
    );
    assert!(
        poll_block.contains("absent(ferrum_database_poll_last_completed_timestamp_seconds)"),
        "database/cp poll alert may treat a missing series as stale"
    );
}

#[test]
fn prometheusrule_datapath_group_uses_always_available_families() {
    let rules = read("templates/metrics-prometheusrule.yaml");
    assert!(
        rules.contains("- name: ferrum.gateway.datapath"),
        "chart must ship a mode-independent data-path alert group"
    );
    for needle in [
        "ferrum_overload_shedding_active",
        "ferrum_upstream_targets > 0",
        "ferrum_upstream_unhealthy_targets / ferrum_upstream_targets",
        "ferrum_circuit_breakers{state=\"open\"}",
        "ferrum_frontend_tls_handshake_failures_total{reason=\"error\"}",
    ] {
        assert!(
            rules.contains(needle),
            "data-path alert group missing expected expression fragment: {needle}"
        );
    }
}

#[test]
fn values_and_schema_expose_datapath_alert_thresholds() {
    let values = read("values.yaml");
    for needle in [
        "upstreamUnhealthyRatio",
        "frontendTlsHandshakeErrorsPerSecond",
    ] {
        assert!(
            values.contains(needle),
            "values.yaml must document alert threshold {needle}"
        );
    }
    let schema = read("values.schema.json");
    for needle in ["upstreamUnhealthyRatio", "frontendTlsHandshakeErrorsPerSecond"] {
        assert!(
            schema.contains(needle),
            "values.schema.json must expose alert threshold {needle}"
        );
    }
}

#[test]
fn hosted_ci_asserts_database_poll_alert_mode_gating() {
    let ci = read_ci();
    for needle in [
        "metrics-alerts-file.yaml",
        "FerrumGatewayDatabasePollStale must not render when mode=file",
        "absent(ferrum_database_poll_",
        "metrics-alerts-database.yaml",
        "metrics-alerts-dp.yaml",
    ] {
        assert!(
            ci.contains(needle),
            "hosted gateway chart workflow must assert database poll alert gating: missing {needle}"
        );
    }
}
