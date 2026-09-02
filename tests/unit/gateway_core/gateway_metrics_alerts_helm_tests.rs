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
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml"),
    )
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
        "max by (action, namespace) (ferrum_overload_shedding_active)",
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
    for needle in [
        "upstreamUnhealthyRatio",
        "frontendTlsHandshakeErrorsPerSecond",
    ] {
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

/// Issue #4528: the shipped poll-freshness alert cannot detect a database
/// outage, because the gauge it watches advances on handled errors too. The
/// chart must ship a real availability alert alongside it, and the freshness
/// alert must describe itself as a task-death detector so an operator does not
/// keep trusting it for outages.
#[test]
fn prometheusrule_ships_a_real_database_availability_alert() {
    let rules = read("templates/metrics-prometheusrule.yaml");
    let unavailable = rules
        .find("FerrumGatewayDatabaseUnavailable")
        .expect("chart must ship FerrumGatewayDatabaseUnavailable");
    let stale = rules
        .find("FerrumGatewayDatabasePollStale")
        .expect("FerrumGatewayDatabasePollStale alert");
    assert!(
        unavailable < stale,
        "the availability alert must lead the freshness alert in the config group"
    );
    let gate_start = rules[..unavailable]
        .rfind("{{- if or (eq .Values.mode \"database\") (eq .Values.mode \"cp\") }}")
        .expect("availability alert must be wrapped in the database/cp mode gate");
    let gate_end = rules[unavailable..]
        .find("{{- end }}")
        .expect("mode gate must close")
        + unavailable;
    let gated = &rules[gate_start..gate_end];
    assert!(
        gated.contains("min by (namespace) (ferrum_database_config_source_connected) == 0"),
        "availability alert must watch the config-source gauge, not poll freshness"
    );
    assert!(
        gated.contains("severity: critical"),
        "a frozen configuration source is a critical condition"
    );

    // The freshness alert must no longer claim to detect a failed poll.
    let stale_block = &rules[stale..gate_end];
    assert!(
        !stale_block.contains("No successful database/CP config poll completed"),
        "the freshness alert must stop describing itself as a success detector"
    );
    assert!(
        stale_block.contains("poll-TASK DEATH"),
        "the freshness alert must describe itself as a task-death detector"
    );
}

fn github_heading_slug(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == ' ' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Issue #4547: an alert nobody can act on is not shipped observability. Every
/// alert carries a `runbook_url`, and every anchor it points at is a real
/// heading in the checked-in runbook.
#[test]
fn every_alert_carries_a_runbook_url_resolving_to_a_runbook_heading() {
    let rules = read("templates/metrics-prometheusrule.yaml");
    let alerts: Vec<&str> = rules
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- alert: "))
        .collect();
    let runbooks: Vec<&str> = rules
        .lines()
        .filter_map(|l| l.trim().strip_prefix("runbook_url: "))
        .collect();
    assert!(!alerts.is_empty(), "chart must ship alerts");
    assert_eq!(
        alerts.len(),
        runbooks.len(),
        "every alert needs exactly one runbook_url: alerts={alerts:?} runbooks={runbooks:?}"
    );

    let runbook = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/runbooks/gateway.md"),
    )
    .expect("read docs/runbooks/gateway.md");
    let headings: Vec<String> = runbook
        .lines()
        .filter_map(|l| l.strip_prefix("## "))
        .map(github_heading_slug)
        .collect();

    for alert in &alerts {
        let anchor = github_heading_slug(alert);
        assert!(
            headings.contains(&anchor),
            "docs/runbooks/gateway.md has no `## {alert}` section (anchor #{anchor})"
        );
        assert!(
            rules.contains(&format!("#{anchor}\" $runbook | quote }}}}")),
            "alert {alert} must point its runbook_url at #{anchor}"
        );
    }

    // The base URL is a value so a fork can repoint every link at once.
    assert!(
        rules.contains("$alerts.runbookBaseUrl"),
        "runbook links must be built from metrics.alerts.runbookBaseUrl"
    );
    let values = read("values.yaml");
    assert!(
        values.contains("runbookBaseUrl:"),
        "values.yaml must default the runbook base URL"
    );
    assert!(
        read("values.schema.json").contains("runbookBaseUrl"),
        "values.schema.json must declare runbookBaseUrl"
    );
}

/// Issue #4547: the gateway chart ships Grafana dashboards with the same
/// sidecar wiring the mesh chart uses, opt-in and schema-declared.
#[test]
fn gateway_chart_ships_opt_in_grafana_dashboards() {
    let template = read("templates/observability-dashboards-configmap.yaml");
    assert!(
        template
            .contains("{{- if and .Values.metrics.enabled .Values.metrics.dashboards.enabled }}"),
        "dashboards must be gated on metrics.enabled and metrics.dashboards.enabled"
    );
    assert!(
        template.contains(".Files.Glob \"dashboards/*.json\""),
        "dashboards must be globbed so a new JSON needs no template edit"
    );
    assert!(
        template.contains("grafana_dashboard"),
        "the ConfigMap must carry the Grafana sidecar label"
    );

    let dashboard = std::fs::read_to_string(chart_root().join("dashboards/gateway-overview.json"))
        .expect("charts/ferrum-gateway/dashboards/gateway-overview.json");
    let parsed: serde_json::Value =
        serde_json::from_str(&dashboard).expect("dashboard must be valid JSON");
    assert!(
        parsed["panels"].as_array().is_some_and(|p| !p.is_empty()),
        "dashboard must ship panels"
    );
    for family in [
        "ferrum_requests_total",
        "ferrum_overload_level",
        "ferrum_upstream_unhealthy_targets",
        "ferrum_circuit_breakers",
        "ferrum_connection_pool_entries",
        "ferrum_dp_config_snapshot_age_seconds",
        "ferrum_database_config_source_connected",
        "ferrum_database_poll_failures_total",
    ] {
        assert!(dashboard.contains(family), "dashboard must chart {family}");
    }

    let values = read("values.yaml");
    let schema = read("values.schema.json");
    for needle in [
        "dashboards:",
        "configMapName:",
        "sidecarLabel:",
        "sidecarLabelValue:",
    ] {
        assert!(
            values.contains(needle),
            "values.yaml missing dashboards key {needle}"
        );
    }
    for needle in [
        "\"dashboards\"",
        "\"configMapName\"",
        "\"sidecarLabel\"",
        "\"sidecarLabelValue\"",
    ] {
        assert!(
            schema.contains(needle),
            "values.schema.json missing {needle}"
        );
    }
}

/// Hosted CI is the only place `helm template` + `promtool` actually run, so
/// pin the assertions that would otherwise silently disappear.
#[test]
fn hosted_ci_asserts_runbook_and_dashboard_coverage() {
    let ci = read_ci();
    for needle in [
        "metrics-alerts-runbooks.yaml",
        "Gateway alert without a runbook_url",
        "Dashboards ConfigMap rendered by default",
        "dashboards-enabled.yaml",
        "grafana_dashboard: \"1\"",
    ] {
        assert!(
            ci.contains(needle),
            "hosted gateway chart workflow must assert runbook/dashboard coverage: missing {needle}"
        );
    }
}
