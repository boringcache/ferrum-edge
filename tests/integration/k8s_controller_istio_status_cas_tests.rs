//! Conflict-safe Istio status writes.
//!
//! Exercises `IstioStatusWriter` against a CAS-faithful in-process API
//! server: resourceVersion/UID preconditions, JSON Merge Patch array
//! replacement, foreign-controller updates, bounded 409 retry, and
//! abort on delete/recreate / not-found / unsupported status.

use ferrum_edge::k8s_controller::istio_status::{IstioStatusUpdate, IstioStatusWriter};
use ferrum_edge::k8s_controller::metrics::ControllerMetrics;
use http::{Method, Request, Response, StatusCode};
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use kube::client::Body;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

const PLANNED_UID: &str = "uid-planned";
const RECREATED_UID: &str = "uid-recreated";

struct CasObject {
    api_version: String,
    kind: String,
    uid: String,
    resource_version: u64,
    status: Value,
}

struct CasState {
    objects: HashMap<String, CasObject>,
    get_count: usize,
    patch_bodies: Vec<Value>,
    inject_foreign_on_first_get: Option<Value>,
    injected_keys: HashSet<String>,
    recreate_after_next_get: bool,
    delete_after_next_get: bool,
    always_conflict: bool,
    unsupported: bool,
    not_found: bool,
}

impl Default for CasState {
    fn default() -> Self {
        Self {
            objects: HashMap::new(),
            get_count: 0,
            patch_bodies: Vec::new(),
            inject_foreign_on_first_get: None,
            injected_keys: HashSet::new(),
            recreate_after_next_get: false,
            delete_after_next_get: false,
            always_conflict: false,
            unsupported: false,
            not_found: false,
        }
    }
}

fn supported_kinds() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        (
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "authorizationpolicies",
        ),
        (
            "security.istio.io/v1",
            "PeerAuthentication",
            "peerauthentications",
        ),
        (
            "security.istio.io/v1",
            "RequestAuthentication",
            "requestauthentications",
        ),
        (
            "networking.istio.io/v1",
            "DestinationRule",
            "destinationrules",
        ),
        ("networking.istio.io/v1", "VirtualService", "virtualservices"),
        ("networking.istio.io/v1", "ServiceEntry", "serviceentries"),
        ("networking.istio.io/v1", "WorkloadEntry", "workloadentries"),
        ("networking.istio.io/v1", "Sidecar", "sidecars"),
        ("telemetry.istio.io/v1", "Telemetry", "telemetries"),
        (
            "networking.istio.io/v1beta1",
            "ProxyConfig",
            "proxyconfigs",
        ),
    ]
}

fn ferrum_update(api_version: &str, kind: &str, name: &str, uid: &str) -> IstioStatusUpdate {
    IstioStatusUpdate {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        namespace: "default".to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        status: json!({
            "conditions": [{
                "type": "FerrumAccepted",
                "status": "True",
                "reason": "Accepted",
                "message": "Ferrum accepted",
                "lastTransitionTime": "2026-08-13T00:00:00Z",
                "observedGeneration": 3
            }]
        }),
        ferrum_detail: Some(json!({ "translation": { "result": "ok" } })),
    }
}

fn initial_foreign_condition() -> Value {
    json!({
        "type": "Reconciled",
        "status": "True",
        "reason": "Istio",
        "message": "initial",
        "lastTransitionTime": "2026-01-01T00:00:00Z"
    })
}

fn concurrent_foreign_condition() -> Value {
    json!({
        "type": "Reconciled",
        "status": "False",
        "reason": "Istio",
        "message": "concurrent-update",
        "lastTransitionTime": "2026-08-13T12:00:00Z"
    })
}

fn cas_object(api_version: &str, kind: &str, status: Value) -> CasObject {
    CasObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        uid: PLANNED_UID.to_string(),
        resource_version: 1,
        status,
    }
}

fn json_response(status: StatusCode, value: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("serialize mock Kubernetes response"),
        ))
        .expect("build mock Kubernetes response")
}

fn status_failure(code: u16, reason: &str, message: &str) -> Response<Body> {
    json_response(
        StatusCode::from_u16(code).expect("status code"),
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": message,
            "reason": reason,
            "code": code
        }),
    )
}

fn object_to_value(name: &str, object: &CasObject) -> Value {
    json!({
        "apiVersion": object.api_version,
        "kind": object.kind,
        "metadata": {
            "name": name,
            "namespace": "default",
            "uid": object.uid,
            "resourceVersion": object.resource_version.to_string()
        },
        "status": object.status
    })
}

fn upsert_condition(status: &mut Value, condition: Value) {
    if !status.is_object() {
        *status = json!({});
    }
    let conditions = status
        .as_object_mut()
        .expect("status object")
        .entry("conditions")
        .or_insert_with(|| json!([]));
    let Some(array) = conditions.as_array_mut() else {
        *conditions = json!([condition]);
        return;
    };
    if let Some(condition_type) = condition
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
        && let Some(existing) = array.iter_mut().find(|entry| {
            entry.get("type").and_then(Value::as_str) == Some(condition_type.as_str())
        })
    {
        *existing = condition;
        return;
    }
    array.push(condition);
}

fn apply_status_merge(live: &mut Value, patch_status: &Value) {
    if !live.is_object() {
        *live = json!({});
    }
    let Some(live_obj) = live.as_object_mut() else {
        return;
    };
    let Some(patch_obj) = patch_status.as_object() else {
        return;
    };
    for (key, value) in patch_obj {
        live_obj.insert(key.clone(), value.clone());
    }
}

fn parse_status_path(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split('/').collect();
    let ns_idx = parts.iter().position(|part| *part == "namespaces")?;
    let plural = parts.get(ns_idx + 2)?.to_string();
    let name = parts.get(ns_idx + 3)?.to_string();
    Some((plural, name))
}

fn mock_cas_client(state: Arc<Mutex<CasState>>) -> Client {
    let service = service_fn(move |request: Request<Body>| {
        let state = state.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_string();
            if method == Method::PATCH {
                assert_eq!(
                    request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/merge-patch+json")
                );
            }
            let body = request
                .into_body()
                .collect_bytes()
                .await
                .expect("read mock Kubernetes request body");
            let key = parse_status_path(&path).map(|(plural, name)| format!("{plural}/{name}"));
            let mut state = state.lock().expect("lock CAS state");
            let response = match method {
                Method::GET => {
                    state.get_count += 1;
                    if state.unsupported {
                        status_failure(
                            404,
                            "NotFound",
                            "the server could not find the requested resource",
                        )
                    } else if state.not_found {
                        status_failure(404, "NotFound", "authorizationpolicies \"policy\" not found")
                    } else {
                        let Some(key) = key.as_ref() else {
                            return Ok(status_failure(404, "NotFound", "missing resource"));
                        };
                        let Some(object) = state.objects.get(key) else {
                            return Ok(status_failure(
                                404,
                                "NotFound",
                                "authorizationpolicies \"policy\" not found",
                            ));
                        };
                        let name = key.split('/').nth(1).unwrap_or("policy");
                        let response = json_response(StatusCode::OK, object_to_value(name, object));
                        if state.delete_after_next_get {
                            state.objects.remove(key);
                            state.delete_after_next_get = false;
                        } else if state.recreate_after_next_get {
                            if let Some(object) = state.objects.get_mut(key) {
                                object.uid = RECREATED_UID.to_string();
                                object.resource_version = 1;
                                object.status = json!({
                                    "conditions": [initial_foreign_condition()]
                                });
                            }
                            state.recreate_after_next_get = false;
                        } else if let Some(foreign) = state.inject_foreign_on_first_get.clone()
                            && state.injected_keys.insert(key.clone())
                            && let Some(object) = state.objects.get_mut(key)
                        {
                            upsert_condition(&mut object.status, foreign);
                            object.resource_version = object.resource_version.saturating_add(1);
                        }
                        response
                    }
                }
                Method::PATCH => {
                    let patch: Value =
                        serde_json::from_slice(&body).expect("parse status patch body");
                    state.patch_bodies.push(patch.clone());
                    assert!(
                        patch["metadata"]["resourceVersion"].as_str().is_some(),
                        "Istio status writes must never omit resourceVersion"
                    );
                    assert!(
                        patch["metadata"]["uid"].as_str().is_some(),
                        "Istio status writes must never omit uid"
                    );
                    if state.always_conflict {
                        status_failure(409, "Conflict", "the object has been modified")
                    } else if state.unsupported {
                        status_failure(
                            404,
                            "NotFound",
                            "the server could not find the requested resource",
                        )
                    } else if state.not_found {
                        status_failure(404, "NotFound", "authorizationpolicies \"policy\" not found")
                    } else {
                        let Some(key) = key.as_ref() else {
                            return Ok(status_failure(404, "NotFound", "missing resource"));
                        };
                        let Some(object) = state.objects.get_mut(key) else {
                            return Ok(status_failure(
                                404,
                                "NotFound",
                                "authorizationpolicies \"policy\" not found",
                            ));
                        };
                        let expected_rv = object.resource_version.to_string();
                        let patch_rv = patch["metadata"]["resourceVersion"].as_str();
                        let patch_uid = patch["metadata"]["uid"].as_str();
                        if patch_uid != Some(object.uid.as_str()) || patch_rv != Some(&expected_rv)
                        {
                            status_failure(409, "Conflict", "the object has been modified")
                        } else {
                            if let Some(status) = patch.get("status") {
                                apply_status_merge(&mut object.status, status);
                            }
                            object.resource_version = object.resource_version.saturating_add(1);
                            let name = key.split('/').nth(1).unwrap_or("policy");
                            json_response(StatusCode::OK, object_to_value(name, object))
                        }
                    }
                }
                _ => status_failure(405, "MethodNotAllowed", "method not allowed"),
            };
            Ok::<_, Infallible>(response)
        }
    });
    Client::new(service, "default")
}

fn condition_by_type<'a>(status: &'a Value, condition_type: &str) -> Option<&'a Value> {
    status["conditions"].as_array().and_then(|conditions| {
        conditions
            .iter()
            .find(|condition| condition["type"].as_str() == Some(condition_type))
    })
}

fn seed_policy(state: &mut CasState, status: Value) {
    state.objects.insert(
        "authorizationpolicies/policy".to_string(),
        cas_object("security.istio.io/v1", "AuthorizationPolicy", status),
    );
}

fn writer_with_metrics(client: Client) -> (IstioStatusWriter, Arc<ControllerMetrics>) {
    let metrics = Arc::new(ControllerMetrics::new());
    (
        IstioStatusWriter::new(client).with_metrics(Arc::clone(&metrics)),
        metrics,
    )
}

#[tokio::test]
async fn foreign_update_between_get_and_patch_survives_cas_retry() {
    let state = Arc::new(Mutex::new(CasState {
        inject_foreign_on_first_get: Some(concurrent_foreign_condition()),
        ..CasState::default()
    }));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({
            "observedGeneration": 7,
            "validationMessages": [{"type": "INFO", "message": "ok"}],
            "extra": "keep-me",
            "conditions": [initial_foreign_condition()]
        }),
    );
    let (writer, metrics) = writer_with_metrics(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("CAS retry should succeed");

    let state = state.lock().expect("lock CAS state");
    assert_eq!(state.get_count, 2, "a 409 must trigger a fresh status read");
    assert_eq!(state.patch_bodies.len(), 2);

    let first = &state.patch_bodies[0];
    assert_eq!(first["metadata"]["resourceVersion"].as_str(), Some("1"));
    assert_eq!(first["metadata"]["uid"].as_str(), Some(PLANNED_UID));
    assert_eq!(
        condition_by_type(&first["status"], "Reconciled")
            .and_then(|c| c["message"].as_str()),
        Some("initial"),
        "stale patch must not be resent after conflict"
    );

    let retried = &state.patch_bodies[1];
    assert_eq!(retried["metadata"]["resourceVersion"].as_str(), Some("2"));
    let retried_foreign = condition_by_type(&retried["status"], "Reconciled")
        .expect("retry must merge the concurrent foreign condition");
    assert_eq!(retried_foreign["status"].as_str(), Some("False"));
    assert_eq!(retried_foreign["reason"].as_str(), Some("Istio"));
    assert_eq!(retried_foreign["message"].as_str(), Some("concurrent-update"));
    assert!(condition_by_type(&retried["status"], "FerrumAccepted").is_some());

    let live = &state
        .objects
        .get("authorizationpolicies/policy")
        .expect("object")
        .status;
    assert_eq!(live["observedGeneration"].as_i64(), Some(7));
    assert_eq!(live["extra"].as_str(), Some("keep-me"));
    assert_eq!(live["validationMessages"][0]["message"].as_str(), Some("ok"));
    assert_eq!(live["ferrum"]["translation"]["result"].as_str(), Some("ok"));

    let snap = metrics.snapshot();
    assert_eq!(snap.istio_status_conflicts, 1);
    assert_eq!(snap.istio_status_retries, 1);
    assert_eq!(snap.istio_status_retry_exhausted, 0);
}

#[tokio::test]
async fn two_writers_on_different_condition_types_converge() {
    let state = Arc::new(Mutex::new(CasState::default()));
    seed_policy(&mut state.lock().expect("seed"), json!({ "conditions": [] }));
    let ferrum_client = mock_cas_client(state.clone());
    let foreign_client = mock_cas_client(state.clone());
    let ferrum = IstioStatusWriter::new(ferrum_client);
    let ferrum_update = ferrum_update(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "policy",
        PLANNED_UID,
    );
    let foreign_condition = json!({
        "type": "Reconciled",
        "status": "True",
        "reason": "Istio",
        "message": "pilot",
        "lastTransitionTime": "2026-08-13T01:00:00Z"
    });

    let ferrum_task = tokio::spawn(async move { ferrum.patch_updates(vec![ferrum_update]).await });
    let foreign_task = tokio::spawn(async move {
        write_foreign_condition(foreign_client, foreign_condition).await
    });

    ferrum_task
        .await
        .expect("ferrum join")
        .expect("ferrum writer");
    foreign_task
        .await
        .expect("foreign join")
        .expect("foreign writer");

    let state = state.lock().expect("lock CAS state");
    let live = &state
        .objects
        .get("authorizationpolicies/policy")
        .expect("object")
        .status;
    assert!(
        condition_by_type(live, "FerrumAccepted").is_some(),
        "Ferrum condition must survive the competing writer"
    );
    let foreign = condition_by_type(live, "Reconciled").expect("foreign condition");
    assert_eq!(foreign["message"].as_str(), Some("pilot"));
}

async fn write_foreign_condition(client: Client, condition: Value) -> Result<(), kube::Error> {
    let ar = ApiResource {
        group: "security.istio.io".to_string(),
        version: "v1".to_string(),
        api_version: "security.istio.io/v1".to_string(),
        kind: "AuthorizationPolicy".to_string(),
        plural: "authorizationpolicies".to_string(),
    };
    let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
    let params = PatchParams {
        field_manager: Some("istio.io/pilot".to_string()),
        ..PatchParams::default()
    };
    for _ in 0..8 {
        let live = api.get_status("policy").await?;
        let Some(resource_version) = live.metadata.resource_version.clone() else {
            continue;
        };
        let Some(uid) = live.metadata.uid.clone() else {
            continue;
        };
        let mut status = live.data.get("status").cloned().unwrap_or(json!({}));
        upsert_condition(&mut status, condition.clone());
        let patch = json!({
            "metadata": {
                "resourceVersion": resource_version,
                "uid": uid
            },
            "status": {
                "conditions": status.get("conditions").cloned().unwrap_or(json!([]))
            }
        });
        match api
            .patch_status("policy", &params, &Patch::Merge(&patch))
            .await
        {
            Ok(_) => return Ok(()),
            Err(error)
                if matches!(
                    &error,
                    kube::Error::Api(response) if response.code == 409
                ) => {}
            Err(error) => return Err(error),
        }
    }
    panic!("foreign writer exhausted CAS retries");
}

#[tokio::test]
async fn rapid_conflicts_exhaust_retry_without_unversioned_write() {
    let state = Arc::new(Mutex::new(CasState {
        always_conflict: true,
        ..CasState::default()
    }));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({ "conditions": [initial_foreign_condition()] }),
    );
    let (writer, metrics) = writer_with_metrics(mock_cas_client(state.clone()));
    let error = writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect_err("exhausted conflicts must surface a retryable error");
    assert!(
        matches!(error, kube::Error::Api(ref response) if response.code == 409),
        "exhaustion must return the conflict, not an unversioned success"
    );

    let state = state.lock().expect("lock CAS state");
    assert_eq!(state.patch_bodies.len(), 5);
    for patch in &state.patch_bodies {
        assert_eq!(patch["metadata"]["resourceVersion"].as_str(), Some("1"));
        assert_eq!(patch["metadata"]["uid"].as_str(), Some(PLANNED_UID));
    }
    let live = &state
        .objects
        .get("authorizationpolicies/policy")
        .expect("object")
        .status;
    assert!(
        condition_by_type(live, "FerrumAccepted").is_none(),
        "exhausted retry must leave the live foreign status intact"
    );
    let snap = metrics.snapshot();
    assert_eq!(snap.istio_status_conflicts, 5);
    assert_eq!(snap.istio_status_retry_exhausted, 1);
    assert_eq!(snap.istio_status_retries, 0);
}

#[tokio::test]
async fn delete_recreate_same_name_aborts_stale_plan() {
    let state = Arc::new(Mutex::new(CasState {
        recreate_after_next_get: true,
        ..CasState::default()
    }));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({ "conditions": [initial_foreign_condition()] }),
    );
    let (writer, metrics) = writer_with_metrics(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("recreate abort is not a batch failure");

    let state = state.lock().expect("lock CAS state");
    let object = state
        .objects
        .get("authorizationpolicies/policy")
        .expect("recreated object");
    assert_eq!(object.uid, RECREATED_UID);
    assert!(
        condition_by_type(&object.status, "FerrumAccepted").is_none(),
        "stale plan must not land on the recreated UID"
    );
    assert!(
        state
            .patch_bodies
            .iter()
            .all(|patch| patch["metadata"]["uid"].as_str() != Some(RECREATED_UID)),
        "no patch may target the new UID"
    );
    let snap = metrics.snapshot();
    assert_eq!(snap.istio_status_recreated, 1);
}

#[tokio::test]
async fn identity_less_plan_issues_no_get_or_patch_and_cannot_land_on_replacement() {
    let state = Arc::new(Mutex::new(CasState::default()));
    {
        let mut locked = state.lock().expect("seed");
        seed_policy(
            &mut locked,
            json!({
                "conditions": [initial_foreign_condition()]
            }),
        );
        if let Some(object) = locked.objects.get_mut("authorizationpolicies/policy") {
            object.uid = RECREATED_UID.to_string();
        }
    }
    let (writer, metrics) = writer_with_metrics(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            "",
        )])
        .await
        .expect("missing planned UID is a refused skip, not a batch failure");

    let state = state.lock().expect("lock CAS state");
    assert_eq!(state.get_count, 0, "identity-less plan must not GET");
    assert!(
        state.patch_bodies.is_empty(),
        "identity-less plan must not PATCH"
    );
    let object = state
        .objects
        .get("authorizationpolicies/policy")
        .expect("replacement object");
    assert_eq!(object.uid, RECREATED_UID);
    assert!(
        condition_by_type(&object.status, "FerrumAccepted").is_none(),
        "stale identity-less plan must not land on the replacement UID"
    );
    assert_eq!(metrics.snapshot().istio_status_missing_uid, 1);
}

#[tokio::test]
async fn not_found_and_unsupported_abort_without_unversioned_write() {
    let not_found_state = Arc::new(Mutex::new(CasState {
        not_found: true,
        ..CasState::default()
    }));
    let (not_found_writer, not_found_metrics) =
        writer_with_metrics(mock_cas_client(not_found_state.clone()));
    not_found_writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("not-found aborts cleanly");
    assert!(
        not_found_state
            .lock()
            .expect("lock")
            .patch_bodies
            .is_empty()
    );
    assert_eq!(not_found_metrics.snapshot().istio_status_not_found, 1);

    let unsupported_state = Arc::new(Mutex::new(CasState {
        unsupported: true,
        ..CasState::default()
    }));
    let (unsupported_writer, unsupported_metrics) =
        writer_with_metrics(mock_cas_client(unsupported_state.clone()));
    unsupported_writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("unsupported status aborts cleanly");
    assert!(
        unsupported_state
            .lock()
            .expect("lock")
            .patch_bodies
            .is_empty()
    );
    assert_eq!(
        unsupported_metrics.snapshot().istio_status_unsupported,
        1
    );
}

#[tokio::test]
async fn unchanged_ferrum_condition_keeps_live_transition_time() {
    let live_time = "2026-01-01T00:00:00Z";
    let state = Arc::new(Mutex::new(CasState::default()));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({
            "conditions": [{
                "type": "FerrumAccepted",
                "status": "True",
                "reason": "Accepted",
                "message": "Ferrum accepted",
                "lastTransitionTime": live_time,
                "observedGeneration": 2
            }]
        }),
    );
    let writer = IstioStatusWriter::new(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("patch");

    let state = state.lock().expect("lock");
    let patch = &state.patch_bodies[0];
    let condition = condition_by_type(&patch["status"], "FerrumAccepted").expect("owned");
    assert_eq!(condition["lastTransitionTime"].as_str(), Some(live_time));
}

#[tokio::test]
async fn genuine_ferrum_transition_advances_last_transition_time() {
    let state = Arc::new(Mutex::new(CasState::default()));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({
            "conditions": [{
                "type": "FerrumAccepted",
                "status": "False",
                "reason": "Invalid",
                "message": "old",
                "lastTransitionTime": "2026-01-01T00:00:00Z"
            }]
        }),
    );
    let writer = IstioStatusWriter::new(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("patch");

    let state = state.lock().expect("lock");
    let condition =
        condition_by_type(&state.patch_bodies[0]["status"], "FerrumAccepted").expect("owned");
    assert_eq!(condition["status"].as_str(), Some("True"));
    assert_eq!(
        condition["lastTransitionTime"].as_str(),
        Some("2026-08-13T00:00:00Z")
    );
}

#[tokio::test]
async fn malformed_foreign_entries_are_preserved_verbatim() {
    let malformed = json!({ "message": "no-type-entry", "status": "True" });
    let numeric_type = json!({ "type": 1, "message": "nonstring-type" });
    let state = Arc::new(Mutex::new(CasState::default()));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({
            "conditions": [
                malformed,
                numeric_type,
                initial_foreign_condition()
            ]
        }),
    );
    let writer = IstioStatusWriter::new(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("patch");

    let state = state.lock().expect("lock");
    let conditions = state.patch_bodies[0]["status"]["conditions"]
        .as_array()
        .expect("conditions");
    assert!(
        conditions
            .iter()
            .any(|c| c.get("type").is_none() && c["message"].as_str() == Some("no-type-entry"))
    );
    assert!(conditions.iter().any(|c| c["type"] == json!(1)));
    assert!(
        conditions
            .iter()
            .any(|c| c["type"].as_str() == Some("Reconciled"))
    );
}

#[tokio::test]
async fn competing_writer_preserves_foreign_updates_for_all_supported_kinds() {
    let state = Arc::new(Mutex::new(CasState {
        inject_foreign_on_first_get: Some(concurrent_foreign_condition()),
        ..CasState::default()
    }));
    {
        let mut guard = state.lock().expect("seed");
        for (api_version, kind, plural) in supported_kinds() {
            guard.objects.insert(
                format!("{plural}/obj"),
                cas_object(
                    api_version,
                    kind,
                    json!({
                        "observedGeneration": 4,
                        "validationMessages": [{"type": "INFO", "message": "istio"}],
                        "conditions": [initial_foreign_condition()]
                    }),
                ),
            );
        }
    }

    let updates: Vec<IstioStatusUpdate> = supported_kinds()
        .iter()
        .map(|(api_version, kind, _)| ferrum_update(api_version, kind, "obj", PLANNED_UID))
        .collect();
    let (writer, metrics) = writer_with_metrics(mock_cas_client(state.clone()));
    writer
        .patch_updates(updates)
        .await
        .expect("all ten kinds share the CAS helper");

    let state = state.lock().expect("lock");
    assert_eq!(state.objects.len(), 10);
    for (_api_version, kind, plural) in supported_kinds() {
        let object = state
            .objects
            .get(&format!("{plural}/obj"))
            .unwrap_or_else(|| panic!("missing {kind}"));
        let foreign = condition_by_type(&object.status, "Reconciled")
            .unwrap_or_else(|| panic!("{kind} lost the foreign condition"));
        assert_eq!(
            foreign["message"].as_str(),
            Some("concurrent-update"),
            "{kind} must keep the competing writer's latest message"
        );
        assert!(
            condition_by_type(&object.status, "FerrumAccepted").is_some(),
            "{kind} must keep FerrumAccepted"
        );
        assert_eq!(object.status["observedGeneration"].as_i64(), Some(4));
        assert_eq!(
            object.status["validationMessages"][0]["message"].as_str(),
            Some("istio")
        );
    }
    assert!(
        state
            .patch_bodies
            .iter()
            .all(|patch| patch["metadata"]["resourceVersion"].as_str().is_some()
                && patch["metadata"]["uid"].as_str() == Some(PLANNED_UID))
    );
    let snap = metrics.snapshot();
    assert_eq!(snap.istio_status_conflicts, 10);
    assert_eq!(snap.istio_status_retries, 10);
    assert_eq!(snap.istio_status_retry_exhausted, 0);
}

#[tokio::test]
async fn deleted_object_after_get_does_not_unversioned_write() {
    let state = Arc::new(Mutex::new(CasState {
        delete_after_next_get: true,
        ..CasState::default()
    }));
    seed_policy(
        &mut state.lock().expect("seed"),
        json!({ "conditions": [initial_foreign_condition()] }),
    );
    let (writer, metrics) = writer_with_metrics(mock_cas_client(state.clone()));
    writer
        .patch_updates(vec![ferrum_update(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "policy",
            PLANNED_UID,
        )])
        .await
        .expect("delete after GET aborts cleanly");
    let snap = metrics.snapshot();
    assert_eq!(snap.istio_status_not_found, 1);
    assert!(
        state
            .lock()
            .expect("lock")
            .objects
            .get("authorizationpolicies/policy")
            .is_none()
    );
}
