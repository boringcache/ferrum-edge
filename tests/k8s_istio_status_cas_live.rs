//! Hosted Kind/apiserver proof that Istio status CAS preserves a foreign
//! condition under a real competing status writer (issue #3838).
//!
//! Exercises Ferrum's production [`IstioStatusWriter`] against a real
//! `status` subresource. After the writer's first identity-matching GET,
//! a second kube-rs client patches a foreign condition onto the same
//! object so the subsequent Ferrum PATCH observes a resourceVersion
//! conflict, re-GETs, and re-merges. Both conditions must survive.
//!
//! Gated on `FERRUM_ISTIO_STATUS_CAS_LIVE=1`. The hosted workflow always
//! sets that variable; an unset variable in CI fails rather than skipping.

use ferrum_edge::_test_support::{
    clear_istio_status_write_intercept_for_test, install_istio_status_write_intercept_for_test,
};
use ferrum_edge::k8s_controller::istio_status::{IstioStatusUpdate, IstioStatusWriter};
use ferrum_edge::k8s_controller::metrics::ControllerMetrics;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams, PostParams};
use kube::{Client, Config};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

const LIVE_NS: &str = "ferrum-istio-status-cas";
const LIVE_NAME: &str = "cas-policy";
const FOREIGN_TYPE: &str = "Reconciled";
const FOREIGN_REASON: &str = "CompetingWriter";
const GET_INTERCEPT_TIMEOUT: Duration = Duration::from_secs(20);
const FERRUM_JOIN_TIMEOUT: Duration = Duration::from_secs(20);
const TEST_DEADLINE: Duration = Duration::from_secs(60);

struct InterceptGuard;

impl Drop for InterceptGuard {
    fn drop(&mut self) {
        clear_istio_status_write_intercept_for_test();
    }
}

struct ResumeOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

fn live_lane_enabled() -> bool {
    match std::env::var("FERRUM_ISTIO_STATUS_CAS_LIVE") {
        Ok(value) if value == "1" => true,
        _ if std::env::var("CI").is_ok() => {
            panic!(
                "CI must set FERRUM_ISTIO_STATUS_CAS_LIVE=1; refusing a silent skip of the API-server competing-writer proof"
            );
        }
        _ => false,
    }
}

fn authorization_policy_resource() -> ApiResource {
    ApiResource {
        group: "security.istio.io".to_string(),
        version: "v1".to_string(),
        api_version: "security.istio.io/v1".to_string(),
        kind: "AuthorizationPolicy".to_string(),
        plural: "authorizationpolicies".to_string(),
    }
}

fn namespace_resource() -> ApiResource {
    ApiResource {
        group: String::new(),
        version: "v1".to_string(),
        api_version: "v1".to_string(),
        kind: "Namespace".to_string(),
        plural: "namespaces".to_string(),
    }
}

fn kube_already_exists(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == 409)
}

fn condition_by_type<'a>(status: &'a Value, condition_type: &str) -> Option<&'a Value> {
    status
        .get("conditions")
        .and_then(Value::as_array)
        .and_then(|conditions| {
            conditions.iter().find(|condition| {
                condition.get("type").and_then(Value::as_str) == Some(condition_type)
            })
        })
}

async fn ensure_namespace(client: Client) {
    let api: Api<DynamicObject> = Api::all_with(client, &namespace_resource());
    let object = DynamicObject::new(LIVE_NS, &namespace_resource());
    match api.create(&PostParams::default(), &object).await {
        Ok(_) => {}
        Err(error) if kube_already_exists(&error) => {}
        Err(error) => panic!("failed to create pinned live namespace: {error}"),
    }
}

async fn ensure_policy(api: &Api<DynamicObject>) -> DynamicObject {
    let object = DynamicObject::new(LIVE_NAME, &authorization_policy_resource())
        .within(LIVE_NS)
        .data(json!({
            "spec": { "action": "ALLOW" }
        }));
    match api.create(&PostParams::default(), &object).await {
        Ok(created) => created,
        Err(error) if kube_already_exists(&error) => api
            .get(LIVE_NAME)
            .await
            .unwrap_or_else(|get_error| panic!("failed to get pinned live policy: {get_error}")),
        Err(error) => panic!("failed to create pinned live AuthorizationPolicy: {error}"),
    }
}

async fn apply_foreign_condition(client: Client) {
    let api: Api<DynamicObject> =
        Api::namespaced_with(client, LIVE_NS, &authorization_policy_resource());
    let live = api
        .get_status(LIVE_NAME)
        .await
        .unwrap_or_else(|error| panic!("competing writer GET status failed: {error}"));
    let resource_version = live
        .metadata
        .resource_version
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("competing writer GET returned no resourceVersion"))
        .to_string();
    let uid = live
        .metadata
        .uid
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("competing writer GET returned no UID"))
        .to_string();
    let mut conditions = live
        .data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    conditions
        .retain(|condition| condition.get("type").and_then(Value::as_str) != Some(FOREIGN_TYPE));
    conditions.push(json!({
        "type": FOREIGN_TYPE,
        "status": "True",
        "reason": FOREIGN_REASON,
        "message": "live-competing-writer",
        "lastTransitionTime": "2026-08-13T00:00:00Z"
    }));
    let patch = json!({
        "metadata": {
            "resourceVersion": resource_version,
            "uid": uid
        },
        "status": {
            "conditions": conditions
        }
    });
    api.patch_status(
        LIVE_NAME,
        &PatchParams {
            field_manager: Some("ferrum-istio-status-cas-live-competitor".to_string()),
            ..PatchParams::default()
        },
        &Patch::Merge(&patch),
    )
    .await
    .unwrap_or_else(|error| panic!("competing writer PATCH status failed: {error}"));
}

#[tokio::test]
#[ignore]
async fn live_competing_writer_preserves_foreign_and_ferrum_conditions() {
    if !live_lane_enabled() {
        return;
    }
    tokio::time::timeout(TEST_DEADLINE, run_live_competing_writer())
        .await
        .expect("Istio status CAS live test exceeded the bounded deadline");
}

async fn run_live_competing_writer() {
    let _ = ferrum_edge::fips::base_crypto_provider().install_default();
    let config = Config::infer()
        .await
        .unwrap_or_else(|error| panic!("failed to infer kubeconfig for live API server: {error}"));
    let client = Client::try_from(config)
        .unwrap_or_else(|error| panic!("failed to build Kubernetes client: {error}"));
    ensure_namespace(client.clone()).await;

    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), LIVE_NS, &authorization_policy_resource());
    let created = ensure_policy(&api).await;
    let planned_uid = created
        .metadata
        .uid
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("created AuthorizationPolicy has no UID"))
        .to_string();

    let metrics = Arc::new(ControllerMetrics::new());
    let writer = IstioStatusWriter::new(client.clone()).with_metrics(Arc::clone(&metrics));
    let update = IstioStatusUpdate {
        api_version: "security.istio.io/v1".to_string(),
        kind: "AuthorizationPolicy".to_string(),
        namespace: LIVE_NS.to_string(),
        name: LIVE_NAME.to_string(),
        uid: planned_uid.clone(),
        status: json!({
            "conditions": [{
                "type": "FerrumAccepted",
                "status": "True",
                "reason": "Accepted",
                "message": "Ferrum accepted",
                "lastTransitionTime": "2026-08-13T00:00:00Z",
                "observedGeneration": 1
            }]
        }),
        ferrum_detail: Some(json!({ "translation": { "result": "ok" } })),
    };

    let _intercept_guard = InterceptGuard;
    let (after_get_tx, after_get_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    install_istio_status_write_intercept_for_test(after_get_tx, resume_rx);
    let mut resume = ResumeOnDrop(Some(resume_tx));

    let ferrum = tokio::spawn(async move { writer.patch_updates(vec![update]).await });
    tokio::time::timeout(GET_INTERCEPT_TIMEOUT, after_get_rx)
        .await
        .expect("timed out waiting for Ferrum's first identity-matching GET")
        .expect("Ferrum GET intercept closed before the competing writer ran");

    apply_foreign_condition(client.clone()).await;
    if let Some(tx) = resume.0.take() {
        let _ = tx.send(());
    }

    tokio::time::timeout(FERRUM_JOIN_TIMEOUT, ferrum)
        .await
        .expect("timed out waiting for IstioStatusWriter after the competing write")
        .expect("IstioStatusWriter task panicked")
        .unwrap_or_else(|error| panic!("IstioStatusWriter patch_updates failed: {error}"));

    let live = api
        .get_status(LIVE_NAME)
        .await
        .unwrap_or_else(|error| panic!("final GET status failed: {error}"));
    assert_eq!(
        live.metadata.uid.as_deref(),
        Some(planned_uid.as_str()),
        "live object UID must still match the planned watch-snapshot UID"
    );
    let status = live
        .data
        .get("status")
        .unwrap_or_else(|| panic!("live object has no status"));
    let ferrum = condition_by_type(status, "FerrumAccepted")
        .unwrap_or_else(|| panic!("FerrumAccepted must survive the competing writer"));
    assert_eq!(ferrum.get("status").and_then(Value::as_str), Some("True"));
    let foreign = condition_by_type(status, FOREIGN_TYPE)
        .unwrap_or_else(|| panic!("foreign condition must survive Ferrum's retry merge"));
    assert_eq!(
        foreign.get("reason").and_then(Value::as_str),
        Some(FOREIGN_REASON)
    );

    let snapshot = metrics.snapshot();
    assert!(
        snapshot.istio_status_conflicts >= 1,
        "real API server must observe at least one resourceVersion conflict, got {}",
        snapshot.istio_status_conflicts
    );
    assert_eq!(snapshot.istio_status_retry_exhausted, 0);
    assert_eq!(snapshot.istio_status_recreated, 0);
    assert_eq!(snapshot.istio_status_missing_uid, 0);
    assert!(
        snapshot.istio_status_retries >= 1,
        "Ferrum must succeed after at least one conflict retry, got {}",
        snapshot.istio_status_retries
    );
}
