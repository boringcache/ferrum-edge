//! DOC-10 Prometheus metric family contract (docs ↔ `/metrics` ↔ charts).
//!
//! [`PROMETHEUS_METRIC_CONTRACT_JSON`] embeds the canonical machine-readable
//! inventory at `docs/prometheus_metric_contract.json`. External unit tests
//! under `tests/unit/plugins/prometheus_metric_contract_tests.rs` and the
//! hosted CI script `.github/scripts/validate_prometheus_metric_contract.py`
//! fail closed when:
//! - the checked-in operator reference diverges from the inventory
//! - representative `/metrics` exposition introduces undocumented
//!   name/type/label drift
//! - production Rust string-literal `# TYPE` declarations export a family
//!   absent from the inventory (or with a mismatched type)
//! - bundled PrometheusRule / Grafana queries reference unknown Ferrum
//!   families (while allowing an explicit `documented_only` classification)
//!
//! This module is documentation/CI surface only. Scrape rendering must not
//! scan the inventory on the `/metrics` hot path.

/// Canonical DOC-10 inventory JSON (checked in under `docs/`).
pub const PROMETHEUS_METRIC_CONTRACT_JSON: &str =
    include_str!("../../docs/prometheus_metric_contract.json");

/// Checked-in operator reference validated against the inventory.
pub const PROMETHEUS_METRICS_REFERENCE_MD: &str = include_str!("../../docs/prometheus_metrics.md");

/// Bundled PrometheusRule template validated against the inventory.
pub const BUNDLED_PROMETHEUS_RULE_TEMPLATE: &str =
    include_str!("../../charts/ferrum-mesh/templates/alerts-prometheusrule.yaml");

/// Non-Ferrum metric names that bundled alerts may legally reference.
pub const BUNDLED_EXTERNAL_METRIC_ALLOWLIST: &[&str] =
    &["apiserver_admission_webhook_rejection_count"];
