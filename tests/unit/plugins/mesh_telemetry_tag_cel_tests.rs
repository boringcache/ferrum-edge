//! External coverage for Telemetry metric tagOverride CEL compilation and
//! evaluation on the live mesh metric emission path.

use std::collections::HashMap;

use ferrum_edge::modes::mesh::metric_tag_cel::{
    MAX_METRIC_TAG_CEL_EXPR_LEN, MetricTagCelAttr, MetricTagCelContext, MetricTagCelExpr,
    evaluate_metric_tag_cel, parse_metric_tag_cel_expression, sanitize_metric_tag_value,
    validate_metric_tag_cel_for_families,
};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};
use serde_json::json;

fn mesh_identity_metadata(mut metadata: HashMap<String, String>) -> HashMap<String, String> {
    metadata
        .entry("mesh.source.workload".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.source.namespace".into())
        .or_insert_with(|| "default".into());
    metadata
        .entry("mesh.source.principal".into())
        .or_insert_with(|| "spiffe://cluster.local/ns/default/sa/frontend".into());
    metadata
        .entry("mesh.source.app".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.source.service".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.destination.workload".into())
        .or_insert_with(|| "backend".into());
    metadata
        .entry("mesh.destination.namespace".into())
        .or_insert_with(|| "default".into());
    metadata
        .entry("mesh.destination.principal".into())
        .or_insert_with(|| "spiffe://cluster.local/ns/default/sa/backend".into());
    metadata
        .entry("mesh.destination.app".into())
        .or_insert_with(|| "backend".into());
    metadata
        .entry("mesh.destination.service".into())
        .or_insert_with(|| "backend".into());
    metadata
        .entry("mesh.request_protocol".into())
        .or_insert_with(|| "http".into());
    metadata
        .entry("mesh.response_flags".into())
        .or_insert_with(|| "-".into());
    metadata
        .entry("mesh.connection_security_policy".into())
        .or_insert_with(|| "mutual_tls".into());
    metadata
}

#[tokio::test]
async fn cel_tag_override_evaluates_on_live_request_count_path() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "string(destination.port)"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "source_app",
                "operation": {"type": "set", "value": "edge"}
            }]
        }
    }))
    .expect("cel overrides");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/checkout".into());
    ctx.request_authority = Some("reviews.default.svc.cluster.local".into());
    ctx.mesh_outbound_destination_authz_port = Some(9080);
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Outbound);
    let mut headers = HashMap::new();
    assert!(matches!(
        workload_metrics.before_proxy(&mut ctx, &mut headers).await,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("mesh.request.host").map(String::as_str),
        Some("reviews.default.svc.cluster.local")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.destination.port")
            .map(String::as_str),
        Some("9080")
    );
    assert!(
        ctx.metadata
            .get("mesh.metrics.request_count.tag_overrides")
            .is_some_and(|plan| plan.contains("x0,") && plan.contains("s3,4:edge;")),
        "compiled plan should mix CEL and literal opcodes: {:?}",
        ctx.metadata.get("mesh.metrics.request_count.tag_overrides")
    );

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        request_path: "/checkout".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();

    assert!(
        counter.contains(r#"source_workload="reviews.default.svc.cluster.local""#),
        "{counter}"
    );
    assert!(
        counter.contains(r#"destination_service="9080""#),
        "{counter}"
    );
    assert!(counter.contains(r#"source_app="edge""#), "{counter}");
}

#[tokio::test]
async fn cel_reads_original_attribution_not_prior_label_mutations() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set", "value": "overridden"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "source.workload"}
            }]
        }
    }))
    .expect("mixed ordered overrides");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    workload_metrics.before_proxy(&mut ctx, &mut headers).await;

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();

    assert!(counter.contains(r#"source_workload="overridden""#), "{counter}");
    assert!(
        counter.contains(r#"destination_service="frontend""#),
        "CEL must read the original source.workload attribution: {counter}"
    );
}

#[tokio::test]
async fn missing_cel_attribute_emits_empty_label_not_invented_data() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("cel override");
    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    // No request_authority / Host header → request.host missing.
    let mut headers = HashMap::new();
    workload_metrics.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata.remove("mesh.request.host");

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();
    assert!(counter.contains(r#"source_workload="""#), "{counter}");
}

#[test]
fn rejects_unsupported_malformed_and_costly_cel() {
    let err = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.headers[\"authorization\"]"}
            }]
        }
    }))
    .err()
    .expect("headers unsupported");
    assert!(err.contains("unsupported attribute") || err.contains("rejected"));
    assert!(!err.contains("authorization"));

    let err = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "TCP_SENT_BYTES",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.method"}
            }]
        }
    }))
    .err()
    .expect("http-only on tcp");
    assert!(
        err.contains("HTTP-only") || err.contains("unrepresentable") || err.contains("rejected")
    );

    let oversized = format!("request.{}", "x".repeat(MAX_METRIC_TAG_CEL_EXPR_LEN));
    let err = parse_metric_tag_cel_expression(&oversized).expect_err("oversize");
    assert!(err.contains("exceeds maximum length"));
    assert!(!err.contains("xxxxx"));

    let expr = parse_metric_tag_cel_expression("request.host").unwrap();
    assert!(validate_metric_tag_cel_for_families(&expr, true).is_err());
    assert!(sanitize_metric_tag_value("a\nb\"c").contains('_'));
}

#[test]
fn compiled_cel_forms_evaluate_with_missing_attribute_semantics() {
    let host = parse_metric_tag_cel_expression("request.host").expect("request.host");
    assert_eq!(
        host,
        MetricTagCelExpr::Attribute {
            name: MetricTagCelAttr::RequestHost
        }
    );
    let port = parse_metric_tag_cel_expression("string(destination.port)")
        .expect("string destination port");
    assert_eq!(
        port,
        MetricTagCelExpr::StringOfInt {
            attribute: MetricTagCelAttr::DestinationPort
        }
    );
    let fallback =
        parse_metric_tag_cel_expression(r#"has(request.host) ? request.host : "unknown""#)
            .expect("bounded ternary");
    assert!(matches!(fallback, MetricTagCelExpr::HasThenElse { .. }));

    let ctx = MetricTagCelContext {
        source_workload: "frontend",
        source_namespace: "default",
        source_principal: "spiffe://cluster.local/ns/default/sa/frontend",
        source_app: "frontend",
        source_service: "frontend",
        destination_workload: "backend",
        destination_namespace: "default",
        destination_principal: "spiffe://cluster.local/ns/default/sa/backend",
        destination_app: "backend",
        destination_service: "backend",
        request_protocol: "http",
        response_flags: "-",
        connection_security_policy: "mutual_tls",
        request_method: Some("GET"),
        request_host: None,
        response_code: Some(200),
        destination_port: Some(8080),
    };
    assert_eq!(evaluate_metric_tag_cel(&host, ctx), "");
    assert_eq!(evaluate_metric_tag_cel(&port, ctx), "8080");
    assert_eq!(evaluate_metric_tag_cel(&fallback, ctx), "unknown");
    assert_eq!(sanitize_metric_tag_value("a\nb\"c"), "a_b_c");
}

#[tokio::test]
async fn tag_override_reload_update_and_delete_change_emitted_labels() {
    let first = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"},
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("first generation");
    let updated = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"},
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set", "value": "reloaded"}
            }]
        }
    }))
    .expect("updated generation");
    let deleted = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"},
        "metrics": {"tag_overrides": []}
    }))
    .expect("deleted");

    async fn emit(plugin: &WorkloadMetrics) -> String {
        let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
        ctx.request_authority = Some("reviews.default.svc".into());
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        let registry = MetricsRegistry::new();
        let summary = TransactionSummary {
            http_method: "GET".into(),
            response_status_code: 200,
            metadata: mesh_identity_metadata(ctx.metadata),
            ..TransactionSummary::default()
        };
        registry.record(&summary);
        registry
            .render_uncached()
            .lines()
            .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
            .expect("counter")
            .to_string()
    }

    let first_line = emit(&first).await;
    assert!(
        first_line.contains(r#"source_workload="reviews.default.svc""#),
        "{first_line}"
    );

    let updated_line = emit(&updated).await;
    assert!(
        updated_line.contains(r#"source_workload="reloaded""#),
        "{updated_line}"
    );

    let deleted_line = emit(&deleted).await;
    assert!(
        deleted_line.contains(r#"source_workload="frontend""#),
        "{deleted_line}"
    );
}
