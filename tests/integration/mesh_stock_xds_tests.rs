//! Live stock-xDS ADS stream behaviour (issue #3317).
//!
//! Drives `start_stock_xds_client_with_shutdown` against a **scripted
//! third-party ADS server** — not Ferrum's own `XdsAdsServer` — so the test
//! exercises exactly what a stock Envoy / Istio control plane puts on the wire:
//! standard v3 `Cluster` / `ClusterLoadAssignment` / `Listener` /
//! `RouteConfiguration` resources with per-type versions and nonces.
//!
//! Asserted here (the decode/mapping half lives in
//! `tests/unit/gateway_core/stock_xds_tests.rs`):
//!
//! * a converged CDS+EDS stream installs a real `MeshSlice` whose policy half
//!   came from the local document and whose discovery half came from the CP,
//! * every response is ACKed with the received version + nonce echoed back,
//! * the EDS subscription is dependency-ordered by resource NAME rather than
//!   wildcarded,
//! * a structurally invalid response is NACKed with an `error_detail` and the
//!   previously installed slice keeps serving (last-good),
//! * a state-of-the-world CDS response that drops a cluster deletes it,
//! * a PARTIAL EDS push (the by-name types may carry a subset) leaves the
//!   assignments it did not mention dialable, and
//! * a reconnect re-subscribes with an empty nonce and the last ACCEPTED
//!   version, never the NACKed one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
    StockPolicySnapshot, StockXdsClientConfig, load_stock_policy_baseline,
    start_stock_xds_client_with_shutdown,
};
use ferrum_edge::modes::mesh::config_consumer::stock_xds_credential::{
    StockCredentialInvalidReason, StockCredentialLifetimePolicy, StockCredentialState,
    StockCredentialWatch, StockXdsCredentialSource,
};
use ferrum_edge::modes::mesh::config_consumer::stream_lifecycle::MeshStreamTimings;
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::xds::proto::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use ferrum_edge::xds::proto::{
    Any, DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use ferrum_edge::xds::stock::StockXdsLimits;
use ferrum_edge::xds::stock_proto as sp;
use ferrum_edge::xds::{CDS_TYPE_URL, EDS_TYPE_URL, SDS_TYPE_URL};
use std::sync::atomic::AtomicBool;

const REVIEWS_CLUSTER: &str = "outbound|9080||reviews.default.svc.cluster.local";
const RATINGS_CLUSTER: &str = "outbound|9080||ratings.default.svc.cluster.local";
const REVIEWS_SAN: &str = "spiffe://cluster.local/ns/default/sa/bookinfo-reviews";
/// A cluster for a service in ANOTHER namespace, endpointed by an identity in
/// THIS one. Ferrum's namespace narrowing keeps it out of this workload's view.
const FOREIGN_CLUSTER: &str = "outbound|9080||payments.other.svc.cluster.local";
/// Same shared-endpoint shape as `FOREIGN_CLUSTER`, but the foreign namespace
/// sorts *before* the local `default` namespace. A projection that stamped the
/// first BTree owner onto a shared (SPIFFE, address) workload would drop the
/// local endpoint when this foreign service later narrowed away.
const EARLIER_FOREIGN_CLUSTER: &str = "outbound|9080||payments.aaa.svc.cluster.local";
const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";

// ── scripted third-party ADS server ──────────────────────────────────────

/// One scripted response, keyed by the type URL whose FIRST subscription
/// request triggers it. Later entries for the same type are sent in order on
/// each subsequent request for that type, which is how the delete/NACK steps
/// are staged.
#[derive(Clone)]
struct ScriptedResponse {
    type_url: String,
    version: String,
    nonce: String,
    resources: Vec<Any>,
}

#[derive(Clone, Default)]
struct AdsRecorder {
    requests: Arc<Mutex<Vec<DiscoveryRequest>>>,
}

impl AdsRecorder {
    fn snapshot(&self) -> Vec<DiscoveryRequest> {
        self.requests
            .lock()
            .expect("ADS recorder mutex is never held across a panic")
            .clone()
    }

    /// Requests carrying a `type_url`, in arrival order.
    fn for_type(&self, type_url: &str) -> Vec<DiscoveryRequest> {
        self.snapshot()
            .into_iter()
            .filter(|request| request.type_url == type_url)
            .collect()
    }
}

struct ScriptedAdsServer {
    recorder: AdsRecorder,
    /// Per-type queue of scripted responses.
    script: Arc<Mutex<HashMap<String, Vec<ScriptedResponse>>>>,
    /// When set, the server closes the response stream as soon as it sees a
    /// request carrying an `error_detail`. Dropping the response sender ends
    /// the RPC cleanly, which is exactly the reconnect path the client takes
    /// after a control plane hangs up — and the only way to observe what the
    /// FIRST request on a fresh stream asserts.
    close_on_nack: bool,
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for ScriptedAdsServer {
    type StreamAggregatedResourcesStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<DiscoveryResponse, Status>> + Send>,
    >;
    type DeltaAggregatedResourcesStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>,
    >;

    async fn stream_aggregated_resources(
        &self,
        request: Request<Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        let mut inbound = request.into_inner();
        let recorder = self.recorder.clone();
        let script = self.script.clone();
        let close_on_nack = self.close_on_nack;
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            while let Ok(Some(discovery_request)) = inbound.message().await {
                let type_url = discovery_request.type_url.clone();
                let nacked = discovery_request.error_detail.is_some();
                recorder
                    .requests
                    .lock()
                    .expect("recorder mutex")
                    .push(discovery_request);
                if close_on_nack && nacked {
                    // Dropping `tx` completes the response stream, so the
                    // client observes a clean stream end and reconnects.
                    return;
                }
                // Every inbound request — initial subscription, subscription
                // update, ACK, or NACK — releases the next queued response for
                // that type. The queue is finite, so the exchange terminates.
                let next = {
                    let mut script = script.lock().expect("script mutex");
                    script.get_mut(&type_url).and_then(|queue| {
                        if queue.is_empty() {
                            None
                        } else {
                            Some(queue.remove(0))
                        }
                    })
                };
                if let Some(scripted) = next {
                    let response = DiscoveryResponse {
                        version_info: scripted.version,
                        resources: scripted.resources,
                        canary: false,
                        type_url: scripted.type_url,
                        nonce: scripted.nonce,
                        control_plane: None,
                    };
                    if tx.send(Ok(response)).await.is_err() {
                        return;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn delta_aggregated_resources(
        &self,
        _request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented(
            "delta xDS is not part of this fixture",
        ))
    }
}

// ── resource fixtures ────────────────────────────────────────────────────

fn any_resource(type_url: &str, message: &impl Message) -> Any {
    Any {
        type_url: type_url.to_string(),
        value: message.encode_to_vec(),
    }
}

fn tls_socket(san: &str) -> sp::TransportSocket {
    let context = sp::UpstreamTlsContext {
        common_tls_context: Some(sp::CommonTlsContext {
            combined_validation_context: Some(sp::CombinedCertificateValidationContext {
                default_validation_context: Some(sp::CertificateValidationContext {
                    match_typed_subject_alt_names: vec![sp::SubjectAltNameMatcher {
                        san_type: 3,
                        matcher: Some(sp::StringMatcher {
                            exact: san.to_string(),
                            ..Default::default()
                        }),
                        oid: String::new(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    sp::TransportSocket {
        name: "envoy.transport_sockets.tls".to_string(),
        typed_config: Some(sp::Any {
            type_url: UPSTREAM_TLS_TYPE_URL.to_string(),
            value: context.encode_to_vec(),
        }),
    }
}

fn eds_cluster(name: &str, san: &str) -> sp::Cluster {
    sp::Cluster {
        name: name.to_string(),
        r#type: 3,
        eds_cluster_config: Some(sp::EdsClusterConfig {
            eds_config: Some(sp::ConfigSource {
                ads: vec![Vec::new()],
                ..Default::default()
            }),
            service_name: String::new(),
        }),
        transport_socket: Some(tls_socket(san)),
        ..Default::default()
    }
}

fn cla(cluster_name: &str, address: &str, port: u16) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: vec![sp::LbEndpoint {
                endpoint: Some(sp::Endpoint {
                    address: Some(sp::Address {
                        socket_address: Some(sp::SocketAddress {
                            address: address.to_string(),
                            port_value: u32::from(port),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                health_status: 1,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// A state-of-the-world assignment that withdraws every endpoint of `cluster`.
fn empty_cla(cluster_name: &str) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: Vec::new(),
            ..Default::default()
        }],
    }
}

// ── harness ──────────────────────────────────────────────────────────────

/// The local mesh POLICY document. It deliberately carries no `services` and no
/// `workloads` — those are the control plane's half — and one
/// PeerAuthentication so the test can prove the policy survived the merge.
const POLICY_DOCUMENT: &str = r#"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: default
      mtls_mode: strict
"#;

struct StockHarness {
    state: MeshRuntimeState,
    recorder: AdsRecorder,
    shutdown_tx: watch::Sender<bool>,
    _policy_dir: tempfile::TempDir,
}

impl StockHarness {
    async fn start(script: HashMap<String, Vec<ScriptedResponse>>) -> Self {
        Self::start_with(script, false).await
    }

    async fn start_with(
        script: HashMap<String, Vec<ScriptedResponse>>,
        close_on_nack: bool,
    ) -> Self {
        let policy_dir = tempfile::tempdir().expect("temp dir");
        let policy_path = policy_dir.path().join("mesh-policy.yaml");
        std::fs::write(&policy_path, POLICY_DOCUMENT).expect("write policy document");
        let baseline: MeshConfig =
            load_stock_policy_baseline(&policy_path).expect("policy document is valid");

        let recorder = AdsRecorder::default();
        let script = Arc::new(Mutex::new(script));
        let server = ScriptedAdsServer {
            recorder: recorder.clone(),
            script: script.clone(),
            close_on_nack,
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind scripted ADS listener");
        let addr = listener.local_addr().expect("listener addr");
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(server))
                .serve_with_incoming(incoming)
                .await;
        });

        let state = MeshRuntimeState::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_policy_tx, policy_rx) =
            watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));

        let config = StockXdsClientConfig {
            xds_urls: vec![format!("http://127.0.0.1:{}", addr.port())],
            node_id: "sidecar~10.1.2.3~reviews.default~default.svc.cluster.local".to_string(),
            cluster: "default".to_string(),
            namespace: "default".to_string(),
            node_metadata: Default::default(),
            credential: StockXdsCredentialSource::unauthenticated(),
            // Loopback h2c with no bearer, outside production mode: exactly the
            // development posture issue #3853 keeps admissible.
            allow_loopback_plaintext: true,
            stream_channel_capacity: 32,
            primary_retry_secs: 0,
            connect_timeout_seconds: 5,
            limits: StockXdsLimits::default(),
            timings: MeshStreamTimings::production(),
        };
        let request = MeshSliceRequest {
            node_id: config.node_id.clone(),
            namespace: "default".to_string(),
            cluster_domain: "cluster.local".to_string(),
            ..MeshSliceRequest::default()
        };

        tokio::spawn(start_stock_xds_client_with_shutdown(
            config,
            request,
            state.clone(),
            shutdown_rx,
            None,
            None,
            policy_rx,
            MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false))),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
        ));

        Self {
            state,
            recorder,
            shutdown_tx,
            _policy_dir: policy_dir,
        }
    }

    /// Poll the installed slice until `predicate` holds, or fail after ~5s.
    async fn wait_for_slice(
        &self,
        label: &str,
        predicate: impl Fn(&MeshSlice) -> bool,
    ) -> MeshSlice {
        for _ in 0..250 {
            if let Some(slice) = self.state.snapshot().as_ref().clone()
                && predicate(&slice)
            {
                return slice;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for the installed mesh slice: {label}");
    }

    async fn wait_for_requests(&self, type_url: &str, count: usize) -> Vec<DiscoveryRequest> {
        for _ in 0..250 {
            let requests = self.recorder.for_type(type_url);
            if requests.len() >= count {
                return requests;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {count} '{type_url}' request(s)");
    }
}

impl Drop for StockHarness {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

fn converged_script() -> HashMap<String, Vec<ScriptedResponse>> {
    HashMap::from([
        (
            CDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: CDS_TYPE_URL.to_string(),
                version: "cds-v1".to_string(),
                nonce: "cds-n1".to_string(),
                resources: vec![
                    any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                    any_resource(CDS_TYPE_URL, &eds_cluster(RATINGS_CLUSTER, REVIEWS_SAN)),
                ],
            }],
        ),
        (
            EDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: EDS_TYPE_URL.to_string(),
                version: "eds-v1".to_string(),
                nonce: "eds-n1".to_string(),
                resources: vec![
                    any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                    any_resource(EDS_TYPE_URL, &cla(RATINGS_CLUSTER, "10.1.2.4", 9080)),
                ],
            }],
        ),
    ])
}

// ── tests ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn stock_ads_stream_installs_a_slice_merging_cp_discovery_with_local_policy() {
    let harness = StockHarness::start(converged_script()).await;
    let slice = harness
        .wait_for_slice("two discovered services", |slice| slice.services.len() == 2)
        .await;

    let mut names: Vec<&str> = slice
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["ratings", "reviews"]);

    let mut addresses: Vec<String> = slice
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.clone())
        .collect();
    addresses.sort();
    assert_eq!(
        addresses,
        vec!["10.1.2.3".to_string(), "10.1.2.4".to_string()],
        "EDS endpoints become dialable workloads under the CP's own SAN pin"
    );

    assert_eq!(
        slice.peer_authentications.len(),
        1,
        "the local policy document is the enforcement authority and must survive the merge"
    );
    assert_eq!(slice.peer_authentications[0].name, "strict-default");
    assert!(
        slice.revision.is_none(),
        "a stock control plane supplies no Ferrum ordering revision"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_ads_client_acks_with_the_received_version_and_nonce() {
    let harness = StockHarness::start(converged_script()).await;
    harness
        .wait_for_slice("first slice", |slice| !slice.services.is_empty())
        .await;

    let cds_requests = harness.wait_for_requests(CDS_TYPE_URL, 2).await;
    let initial = &cds_requests[0];
    assert!(
        initial.version_info.is_empty() && initial.response_nonce.is_empty(),
        "the initial subscription carries no version or nonce"
    );
    assert!(
        initial.node.is_some(),
        "the first request on a stream must carry Node so the CP can identify the proxy"
    );

    let ack = cds_requests
        .iter()
        .find(|request| !request.response_nonce.is_empty())
        .expect("an ACK follows the CDS response");
    assert_eq!(ack.version_info, "cds-v1");
    assert_eq!(ack.response_nonce, "cds-n1");
    assert!(
        ack.error_detail.is_none(),
        "a valid response is ACKed without an error_detail"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_eds_subscription_is_dependency_ordered_by_resource_name() {
    let harness = StockHarness::start(converged_script()).await;
    harness
        .wait_for_slice("first slice", |slice| !slice.services.is_empty())
        .await;

    let eds_requests = harness.wait_for_requests(EDS_TYPE_URL, 1).await;
    let subscription = eds_requests
        .iter()
        .find(|request| !request.resource_names.is_empty())
        .expect("EDS is subscribed by explicit resource name after CDS lands");
    let mut names = subscription.resource_names.clone();
    names.sort();
    assert_eq!(
        names,
        vec![RATINGS_CLUSTER.to_string(), REVIEWS_CLUSTER.to_string()],
        "Ferrum asks only for the assignments its accepted clusters reference"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_invalid_response_is_nacked_and_the_last_good_slice_keeps_serving() {
    let mut script = converged_script();
    // The ACK for the first CDS response releases this structurally invalid one
    // (two resources sharing a name), so the exchange is deterministic without
    // needing a reconnect.
    script
        .get_mut(CDS_TYPE_URL)
        .expect("CDS queue")
        .push(ScriptedResponse {
            type_url: CDS_TYPE_URL.to_string(),
            version: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
            ],
        });
    let harness = StockHarness::start(script).await;

    let nack = {
        let mut found = None;
        for _ in 0..250 {
            if let Some(request) = harness
                .recorder
                .for_type(CDS_TYPE_URL)
                .into_iter()
                .find(|request| request.error_detail.is_some())
            {
                found = Some(request);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        found.expect("the invalid CDS response is NACKed")
    };

    assert_eq!(nack.response_nonce, "cds-n2");
    assert_eq!(
        nack.version_info, "cds-v1",
        "a NACK re-asserts the last version the client actually accepted"
    );
    let detail = nack.error_detail.expect("a NACK carries error_detail");
    assert!(
        detail.message.contains("duplicate Cluster resource name"),
        "the NACK must carry a field-specific diagnostic, got: {}",
        detail.message
    );

    // The rolled-back accumulator still holds the first (valid) CDS response,
    // so the slice converges to the last good view rather than to the rejected
    // one — a NACK never shrinks or replaces what is serving.
    let slice = harness
        .wait_for_slice("last-good view survives the NACK", |slice| {
            slice.services.len() == 2
        })
        .await;
    let mut names: Vec<&str> = slice
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["ratings", "reviews"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_partial_eds_push_keeps_the_untouched_clusters_dialable() {
    // EDS is subscribed BY NAME, so a state-of-the-world response for it may
    // legitimately carry only the assignments a push touched — istiod skips
    // recomputing a cluster its update did not change. Treating the omission as
    // a deletion would blackhole every other service in the mesh.
    let mut script = converged_script();
    script
        .get_mut(EDS_TYPE_URL)
        .expect("EDS queue")
        .push(ScriptedResponse {
            type_url: EDS_TYPE_URL.to_string(),
            version: "eds-v2".to_string(),
            nonce: "eds-n2".to_string(),
            resources: vec![any_resource(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, "10.1.2.9", 9080),
            )],
        });

    let harness = StockHarness::start(script).await;
    let slice = harness
        .wait_for_slice("partial EDS push applied", |slice| {
            let addresses: Vec<&str> = slice
                .workloads
                .iter()
                .flat_map(|workload| workload.addresses.iter().map(String::as_str))
                .collect();
            addresses.contains(&"10.1.2.9") && addresses.contains(&"10.1.2.4")
        })
        .await;

    let mut addresses: Vec<String> = slice
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.clone())
        .collect();
    addresses.sort();
    assert_eq!(
        addresses,
        vec!["10.1.2.4".to_string(), "10.1.2.9".to_string()],
        "the pushed assignment is replaced; the untouched one keeps its endpoint"
    );
    assert_eq!(slice.services.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_reconnect_after_a_nack_reasserts_the_accepted_version_with_no_nonce() {
    // xDS nonces are stream-scoped and a NACKed version was never accepted, so
    // the first request on a fresh stream must carry an EMPTY response_nonce
    // and the last ACCEPTED version. Re-asserting the rejected version would
    // let a version-comparing control plane withhold the resource it already
    // sent, wedging the data plane permanently unconverged.
    let mut script = converged_script();
    script
        .get_mut(CDS_TYPE_URL)
        .expect("CDS queue")
        .push(ScriptedResponse {
            type_url: CDS_TYPE_URL.to_string(),
            version: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
            ],
        });
    let harness = StockHarness::start_with(script, true).await;

    // `Node` rides only the FIRST request per type on a stream, so the second
    // node-bearing CDS request is the subscription that opened the new stream.
    let resubscribe = {
        let mut found = None;
        for _ in 0..250 {
            let with_node: Vec<DiscoveryRequest> = harness
                .recorder
                .for_type(CDS_TYPE_URL)
                .into_iter()
                .filter(|request| request.node.is_some())
                .collect();
            if with_node.len() >= 2 {
                found = Some(with_node[1].clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        found.expect("the client reconnects and re-subscribes")
    };

    assert!(
        resubscribe.response_nonce.is_empty(),
        "a nonce from a previous stream is expired; a new stream must start clean, got '{}'",
        resubscribe.response_nonce
    );
    assert_eq!(
        resubscribe.version_info, "cds-v1",
        "the re-subscription asserts the last ACCEPTED version, never the NACKed one"
    );
    assert!(resubscribe.error_detail.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_unsolicited_sds_closes_the_stream_without_subscribing_to_sds() {
    let mut script = HashMap::new();
    script.insert(
        CDS_TYPE_URL.to_string(),
        vec![ScriptedResponse {
            // The server violates the subscription by replying to the initial
            // CDS request with SDS. Ferrum must close this stream without
            // emitting a DiscoveryRequest for SDS: in SotW, even a NACK with
            // empty resource_names would create a wildcard SDS subscription.
            type_url: SDS_TYPE_URL.to_string(),
            version: "sds-v1".to_string(),
            nonce: "sds-n1".to_string(),
            resources: vec![Any {
                type_url: SDS_TYPE_URL.to_string(),
                value: vec![0x0a, 0x07, b'd', b'e', b'f', b'a', b'u', b'l', b't'],
            }],
        }],
    );
    let harness = StockHarness::start(script).await;

    let mut reconnected = false;
    for _ in 0..250 {
        if harness.recorder.for_type(CDS_TYPE_URL).len() >= 2 {
            reconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        reconnected,
        "an unsolicited unsupported type must terminate the stream and reconnect"
    );
    assert!(
        harness
            .recorder
            .snapshot()
            .iter()
            .all(|request| request.type_url != SDS_TYPE_URL),
        "Ferrum must never turn an unsolicited SDS push into an SDS subscription"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_state_of_the_world_replacement_deletes_a_withdrawn_cluster() {
    let mut script = converged_script();
    // Released by the ACK for the first CDS response: `ratings` is withdrawn.
    script
        .get_mut(CDS_TYPE_URL)
        .expect("CDS queue")
        .push(ScriptedResponse {
            type_url: CDS_TYPE_URL.to_string(),
            version: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![any_resource(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN),
            )],
        });
    script
        .get_mut(EDS_TYPE_URL)
        .expect("EDS queue")
        .push(ScriptedResponse {
            type_url: EDS_TYPE_URL.to_string(),
            version: "eds-v2".to_string(),
            nonce: "eds-n2".to_string(),
            resources: vec![any_resource(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080),
            )],
        });

    let harness = StockHarness::start(script).await;
    let slice = harness
        .wait_for_slice("ratings withdrawn", |slice| {
            slice.services.len() == 1 && slice.services[0].name == "reviews"
        })
        .await;
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.addresses != vec!["10.1.2.4".to_string()]),
        "the withdrawn cluster's endpoints must not linger as a stale route"
    );
}

/// Every installed slice must still validate as a mesh configuration.
///
/// This is the contract the proxy apply path enforces before it swaps a slice
/// in (`prepare_normalized_gateway_config_for_mesh`). A slice that fails it is
/// rejected and the runtime rolls back to the last applied generation, so a
/// slice that carries a self-inconsistent projection does not merely lose one
/// resource — it freezes the data plane on stale config.
fn assert_slice_validates_as_mesh_config(slice: &MeshSlice, label: &str) {
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: slice.workloads.clone(),
            services: slice.services.clone(),
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let errors = config.validate_mesh_fields();
    assert!(
        errors.is_empty(),
        "{label}: the projected slice must validate as a mesh config, got {errors:?}"
    );
}

/// Does the slice carry a dialable workload at `address`?
fn has_endpoint(slice: &MeshSlice, address: &str) -> bool {
    slice
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.iter())
        .any(|candidate| candidate == address)
}

/// CDS/EDS in which the local `reviews` service and a service in ANOTHER
/// namespace both carry the SAME reachable endpoint, pinned to an identity in
/// THIS namespace.
fn shared_endpoint_with_foreign_namespace_script(
    foreign_cluster: &str,
) -> HashMap<String, Vec<ScriptedResponse>> {
    HashMap::from([
        (
            CDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: CDS_TYPE_URL.to_string(),
                version: "cds-v1".to_string(),
                nonce: "cds-n1".to_string(),
                resources: vec![
                    any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                    any_resource(CDS_TYPE_URL, &eds_cluster(foreign_cluster, REVIEWS_SAN)),
                ],
            }],
        ),
        (
            EDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: EDS_TYPE_URL.to_string(),
                version: "eds-v1".to_string(),
                nonce: "eds-n1".to_string(),
                resources: vec![
                    any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                    any_resource(EDS_TYPE_URL, &cla(foreign_cluster, "10.1.2.3", 9080)),
                ],
            }],
        ),
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_foreign_namespace_cluster_narrows_while_the_local_service_stays_dialable() {
    // The foreign service is discovered with a genuinely REACHABLE endpoint, so
    // only Ferrum's own narrowing can keep it off this workload's data path.
    // The local service sharing that endpoint must be unaffected — which is what
    // makes the narrowing above a real observation rather than an empty slice.
    let harness = StockHarness::start(shared_endpoint_with_foreign_namespace_script(
        FOREIGN_CLUSTER,
    ))
    .await;
    let slice = harness
        .wait_for_slice("converged", |slice| has_endpoint(slice, "10.1.2.3"))
        .await;

    assert!(
        slice
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "a service in another namespace stays outside this workload's view: {:?}",
        slice
            .services
            .iter()
            .map(|service| format!("{}/{}", service.namespace, service.name))
            .collect::<Vec<_>>()
    );
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.attached_service_namespace() == "default"),
        "the shared endpoint belongs to the local service, not the narrowed-away one"
    );
    assert_slice_validates_as_mesh_config(&slice, "converged");
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_shared_endpoint_survives_when_the_foreign_namespace_sorts_first() {
    // `aaa` < `default`. A (SPIFFE, address) collapse would stamp the foreign
    // service as the owner, and namespace narrowing would then drop the local
    // reviews endpoint with it. Per-service workload records keep reviews
    // dialable while the foreign attachment narrows.
    assert!(
        "aaa" < "default",
        "this regression is the reverse-lexicographic owner order"
    );
    let harness = StockHarness::start(shared_endpoint_with_foreign_namespace_script(
        EARLIER_FOREIGN_CLUSTER,
    ))
    .await;
    let slice = harness
        .wait_for_slice("converged", |slice| has_endpoint(slice, "10.1.2.3"))
        .await;

    assert!(
        slice
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "a lexicographically-earlier foreign service still stays outside this view: {:?}",
        slice
            .services
            .iter()
            .map(|service| format!("{}/{}", service.namespace, service.name))
            .collect::<Vec<_>>()
    );
    assert!(
        slice.workloads.iter().any(|workload| {
            workload.service_name == "reviews"
                && workload.attached_service_namespace() == "default"
                && workload
                    .addresses
                    .iter()
                    .any(|address| address == "10.1.2.3")
        }),
        "the visible service must keep the shared endpoint after the earlier foreign owner narrows"
    );
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.attached_service_namespace() == "default"),
        "the foreign attachment must not survive as the owner of the shared endpoint"
    );
    assert_slice_validates_as_mesh_config(&slice, "reverse-lex shared endpoint");
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_foreign_namespace_cluster_does_not_block_a_later_endpoint_withdrawal() {
    // Once `reviews` loses its endpoint, the shared address is claimed by the
    // foreign-namespace service alone. Its endpoint must narrow WITH that
    // service rather than surviving as a workload whose cross-namespace
    // attachment nothing in the view can authorize: such a slice is refused at
    // proxy apply, and the rollback to the last applied generation would keep
    // this withdrawal — and every later change — from ever being applied.
    let mut script = shared_endpoint_with_foreign_namespace_script(FOREIGN_CLUSTER);
    // Released by the ACK for the first EDS response.
    script
        .get_mut(EDS_TYPE_URL)
        .expect("EDS queue")
        .push(ScriptedResponse {
            type_url: EDS_TYPE_URL.to_string(),
            version: "eds-v2".to_string(),
            nonce: "eds-n2".to_string(),
            resources: vec![any_resource(EDS_TYPE_URL, &empty_cla(REVIEWS_CLUSTER))],
        });

    let harness = StockHarness::start(script).await;
    let withdrawn = harness
        .wait_for_slice("endpoints withdrawn", |slice| slice.workloads.is_empty())
        .await;
    assert!(
        withdrawn
            .services
            .iter()
            .any(|service| service.name == "reviews"),
        "the cluster itself is still published; only its endpoints were withdrawn"
    );
    assert!(
        withdrawn
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "the foreign-namespace service must not reappear once it owns the shared endpoint"
    );
    assert_slice_validates_as_mesh_config(&withdrawn, "endpoints withdrawn");
}

// ── issues #3852 / #3853 / #3854: stream lifecycle and credential fixtures ──
//
// A second, self-contained harness. The fixtures above script ONE endpoint and
// assert discovery mapping; these script a primary/fallback PAIR (and, for the
// credential cases, a TLS endpoint) and assert what the stream lifecycle does
// when the peer misbehaves or the credential rotates.

mod stream_lifecycle {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// How the scripted endpoint behaves once the client subscribes.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum EndpointBehaviour {
        /// Accept the streaming RPC and immediately close it cleanly, forever.
        /// This is the shape that used to pin the client on the primary.
        CleanEofImmediately,
        /// ACK the first CDS request, then close cleanly without ever sending
        /// EDS. The accumulator's required-type gate is unsatisfied, so no
        /// slice may be published.
        PartialThenCleanEof,
        /// Accept the RPC and never send anything at all.
        Mute,
        /// Serve the converged CDS+EDS script.
        Converged,
    }

    #[derive(Clone)]
    struct LifecycleAds {
        recorder: AdsRecorder,
        /// `authorization` metadata observed on each accepted RPC, in order.
        authorizations: Arc<Mutex<Vec<String>>>,
        streams: Arc<AtomicUsize>,
        behaviour: EndpointBehaviour,
    }

    impl LifecycleAds {
        fn new(behaviour: EndpointBehaviour) -> Self {
            Self {
                recorder: AdsRecorder::default(),
                authorizations: Arc::new(Mutex::new(Vec::new())),
                streams: Arc::new(AtomicUsize::new(0)),
                behaviour,
            }
        }

        fn stream_count(&self) -> usize {
            self.streams.load(Ordering::SeqCst)
        }

        fn authorization_snapshot(&self) -> Vec<String> {
            self.authorizations
                .lock()
                .expect("authorization mutex is never held across a panic")
                .clone()
        }
    }

    #[tonic::async_trait]
    impl AggregatedDiscoveryService for LifecycleAds {
        type StreamAggregatedResourcesStream = std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<DiscoveryResponse, Status>> + Send>,
        >;
        type DeltaAggregatedResourcesStream = std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>,
        >;

        async fn stream_aggregated_resources(
            &self,
            request: Request<Streaming<DiscoveryRequest>>,
        ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
            self.streams.fetch_add(1, Ordering::SeqCst);
            let observed = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<none>")
                .to_string();
            self.authorizations
                .lock()
                .expect("authorization mutex")
                .push(observed);

            let mut inbound = request.into_inner();
            let recorder = self.recorder.clone();
            let behaviour = self.behaviour;
            let (tx, rx) = mpsc::channel(32);

            tokio::spawn(async move {
                if behaviour == EndpointBehaviour::CleanEofImmediately {
                    // Drain one request so the client's subscription is
                    // recorded, then drop `tx`: a clean gRPC OK / EOF.
                    if let Ok(Some(discovery_request)) = inbound.message().await {
                        recorder
                            .requests
                            .lock()
                            .expect("recorder mutex")
                            .push(discovery_request);
                    }
                    return;
                }
                if behaviour == EndpointBehaviour::Mute {
                    if let Ok(Some(discovery_request)) = inbound.message().await {
                        recorder
                            .requests
                            .lock()
                            .expect("recorder mutex")
                            .push(discovery_request);
                    }
                    // Hold the response stream open forever without a frame.
                    std::future::pending::<()>().await;
                }

                let mut sent_cds = false;
                let mut sent_eds = false;
                while let Ok(Some(discovery_request)) = inbound.message().await {
                    let type_url = discovery_request.type_url.clone();
                    let has_resource_names = !discovery_request.resource_names.is_empty();
                    recorder
                        .requests
                        .lock()
                        .expect("recorder mutex")
                        .push(discovery_request);
                    if type_url == CDS_TYPE_URL && !sent_cds {
                        sent_cds = true;
                        let response = DiscoveryResponse {
                            version_info: "cds-v1".to_string(),
                            resources: vec![
                                any_resource(
                                    CDS_TYPE_URL,
                                    &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN),
                                ),
                                any_resource(
                                    CDS_TYPE_URL,
                                    &eds_cluster(RATINGS_CLUSTER, REVIEWS_SAN),
                                ),
                            ],
                            canary: false,
                            type_url: CDS_TYPE_URL.to_string(),
                            nonce: "cds-n1".to_string(),
                            control_plane: None,
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                        if behaviour == EndpointBehaviour::PartialThenCleanEof {
                            // Let the ACK land, then hang up mid-convergence.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            return;
                        }
                        continue;
                    }
                    if type_url == EDS_TYPE_URL
                        && behaviour == EndpointBehaviour::Converged
                        && !sent_eds
                        && has_resource_names
                    {
                        sent_eds = true;
                        let response = DiscoveryResponse {
                            version_info: "eds-v1".to_string(),
                            resources: vec![
                                any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                                any_resource(EDS_TYPE_URL, &cla(RATINGS_CLUSTER, "10.1.2.4", 9080)),
                            ],
                            canary: false,
                            type_url: EDS_TYPE_URL.to_string(),
                            nonce: "eds-n1".to_string(),
                            control_plane: None,
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                }
            });

            Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
        }

        async fn delta_aggregated_resources(
            &self,
            _request: Request<Streaming<DeltaDiscoveryRequest>>,
        ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
            Err(Status::unimplemented("delta xDS is not part of this fixture"))
        }
    }

    /// Boot one scripted endpoint. Returns its handle and its `scheme://host:port`.
    async fn serve(behaviour: EndpointBehaviour) -> (LifecycleAds, String) {
        let handle = LifecycleAds::new(behaviour);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind lifecycle ADS listener");
        let addr = listener.local_addr().expect("listener addr");
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let served = handle.clone();
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(served))
                .serve_with_incoming(incoming)
                .await;
        });
        (handle, format!("http://127.0.0.1:{}", addr.port()))
    }

    struct LifecycleHarness {
        state: MeshRuntimeState,
        shutdown_tx: watch::Sender<bool>,
        client: tokio::task::JoinHandle<()>,
        /// Held so the client's policy-watch arm stays open for the whole test;
        /// a closed channel is not what these fixtures are exercising.
        _policy_tx: watch::Sender<StockPolicySnapshot>,
        _policy_dir: tempfile::TempDir,
    }

    impl LifecycleHarness {
        async fn start(
            urls: Vec<String>,
            credential: StockXdsCredentialSource,
            credential_watch: StockCredentialWatch,
            timings: MeshStreamTimings,
        ) -> Self {
            let policy_dir = tempfile::tempdir().expect("temp dir");
            let policy_path = policy_dir.path().join("mesh-policy.yaml");
            std::fs::write(&policy_path, POLICY_DOCUMENT).expect("write policy document");
            let baseline =
                load_stock_policy_baseline(&policy_path).expect("policy document is valid");

            let state = MeshRuntimeState::new();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (policy_tx, policy_rx) =
                watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));

            let config = StockXdsClientConfig {
                xds_urls: urls,
                node_id: "sidecar~10.1.2.3~reviews.default~default.svc.cluster.local".to_string(),
                cluster: "default".to_string(),
                namespace: "default".to_string(),
                node_metadata: Default::default(),
                credential,
                allow_loopback_plaintext: true,
                stream_channel_capacity: 32,
                primary_retry_secs: 0,
                connect_timeout_seconds: 5,
                limits: StockXdsLimits::default(),
                timings,
            };
            let request = MeshSliceRequest {
                node_id: config.node_id.clone(),
                namespace: "default".to_string(),
                cluster_domain: "cluster.local".to_string(),
                ..MeshSliceRequest::default()
            };

            let client = tokio::spawn(start_stock_xds_client_with_shutdown(
                config,
                request,
                state.clone(),
                shutdown_rx,
                None,
                None,
                policy_rx,
                MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false))),
                credential_watch,
            ));

            Self {
                state,
                shutdown_tx,
                client,
                _policy_tx: policy_tx,
                _policy_dir: policy_dir,
            }
        }

        async fn wait_for_services(&self, expected: usize) -> MeshSlice {
            for _ in 0..400 {
                if let Some(slice) = self.state.snapshot().as_ref().clone()
                    && slice.services.len() == expected
                {
                    return slice;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("timed out waiting for {expected} discovered services");
        }

        fn config_stream_state(&self) -> Option<&'static str> {
            self.state
                .config_stream_status()
                .map(|status| status.state)
        }

        fn last_outcome(&self) -> Option<&'static str> {
            self.state
                .config_stream_status()
                .map(|status| status.last_attempt_outcome)
        }

        /// Prove the client task actually joins on shutdown rather than being
        /// left detached with a live stream.
        async fn shutdown_and_join(self) {
            let _ = self.shutdown_tx.send(true);
            tokio::time::timeout(Duration::from_secs(10), self.client)
                .await
                .expect("the stock xDS client must observe shutdown and return")
                .expect("the stock xDS client task must not panic");
        }
    }

    /// Issue #3854, acceptance criterion 1. Before the shared policy, a primary
    /// that returned a clean EOF was recorded as a SUCCESSFUL attempt: backoff
    /// reset and the client stayed on index 0 forever, so the configured
    /// fallback never received the subscription.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_clean_eof_primary_hands_the_subscription_to_the_fallback() {
        let (primary, primary_url) = serve(EndpointBehaviour::CleanEofImmediately).await;
        let (fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![primary_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings::production(),
        )
        .await;

        let slice = harness.wait_for_services(2).await;
        assert_eq!(slice.services.len(), 2);
        assert!(
            fallback.stream_count() >= 1,
            "the fallback must actually have been dialed"
        );
        assert!(
            primary.stream_count() >= 1,
            "the primary must have been tried first"
        );
        harness.shutdown_and_join().await;
    }

    /// Issue #3854, acceptance criterion 2. A primary that ACKs only some of
    /// the required ADS types and then closes must publish NOTHING — a mixed
    /// generation is worse than no generation — and the fallback must converge
    /// a complete one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_partial_generation_followed_by_eof_publishes_no_mixed_state() {
        let (primary, primary_url) = serve(EndpointBehaviour::PartialThenCleanEof).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![primary_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings::production(),
        )
        .await;

        // The primary delivers CDS only. `accumulator.ready()` is false without
        // EDS, so nothing may be installed from it.
        for _ in 0..20 {
            // The CDS-only generation carries clusters but no endpoints, so any
            // slice observed here with empty `workloads` would be exactly the
            // mixed state that must never be published.
            if let Some(slice) = harness.state.snapshot().as_ref().clone() {
                assert!(
                    !slice.workloads.is_empty(),
                    "a CDS-only generation must never be published"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let slice = harness.wait_for_services(2).await;
        assert!(
            !slice.workloads.is_empty(),
            "the fallback's complete generation carries endpoints"
        );
        assert!(primary.stream_count() >= 1);
        harness.shutdown_and_join().await;
    }

    /// Issue #3854. A control plane that accepts the RPC and then supplies no
    /// frame at all must not hold startup: the first-frame bound fires and the
    /// fallback delivers the first usable slice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mute_primary_cannot_hold_startup_indefinitely() {
        let (mute, mute_url) = serve(EndpointBehaviour::Mute).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![mute_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings {
                first_frame: Duration::from_millis(300),
                // Generous on purpose: the mute primary is meant to fail on the
                // FIRST-FRAME bound, and the fallback must not race a tight
                // first-slice deadline in hosted CI.
                first_slice: Duration::from_secs(15),
                max_silence: Duration::from_secs(150),
            },
        )
        .await;

        let slice = harness.wait_for_services(2).await;
        assert_eq!(slice.services.len(), 2);
        assert!(mute.stream_count() >= 1);
        harness.shutdown_and_join().await;
    }

    /// Issue #3854. The closed-set readiness projection must reach
    /// `/health` — `never_received_slice` while startup is blocked, then
    /// `connected` once a generation is serving.
    #[tokio::test(flavor = "multi_thread")]
    async fn health_reports_closed_set_stream_reasons() {
        let (_primary, primary_url) = serve(EndpointBehaviour::CleanEofImmediately).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![primary_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings::production(),
        )
        .await;

        // Before any slice, readiness must say so explicitly. The client
        // publishes its first status as it starts, so wait for the publication
        // rather than racing the spawn.
        let mut startup_state = None;
        for _ in 0..200 {
            if let Some(state) = harness.config_stream_state() {
                startup_state = Some(state);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            startup_state,
            Some("never_received_slice"),
            "startup readiness must be distinguishable from serving-last-good"
        );

        harness.wait_for_services(2).await;
        // The clean-EOF attempt is what produced the failover, and it must be
        // reported by its own reason rather than as a success.
        let outcome = harness.last_outcome().expect("an attempt was recorded");
        assert_eq!(outcome, "remote_clean_eof", "{outcome}");
        harness.shutdown_and_join().await;
    }

    /// Issue #3852. An invalid credential source must PREVENT reconnection —
    /// not merely fail one read and fall back to the previously seen token.
    ///
    /// The endpoint is addressed over `https://` so the transport gate admits
    /// it and the credential gate is unambiguously what stops the dial. The
    /// proof is `last_attempt_outcome == "none"`: had the client attempted the
    /// connection, that field would carry `transport_failure` instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invalid_credential_source_prevents_reconnection() {
        let (endpoint, plain_url) = serve(EndpointBehaviour::Converged).await;
        let secure_url = plain_url.replacen("http://", "https://", 1);
        let temp = tempfile::tempdir().expect("temp dir");
        let absent = temp.path().join("never-written-token");

        let credential = StockXdsCredentialSource::new(
            Some(absent.to_string_lossy().into_owned()),
            StockCredentialLifetimePolicy::default(),
        );
        let credential_watch = StockCredentialWatch::new(StockCredentialState::Invalid {
            reason: StockCredentialInvalidReason::Missing,
        });

        let harness = LifecycleHarness::start(
            vec![secure_url],
            credential,
            credential_watch,
            MeshStreamTimings::production(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(750)).await;
        assert_eq!(
            endpoint.stream_count(),
            0,
            "an invalid credential source must block the connection attempt entirely"
        );
        assert!(!harness.state.has_first_slice());
        let status = harness
            .state
            .config_stream_status()
            .expect("status is published even while blocked");
        assert_eq!(status.credential, "source_invalid");
        assert_eq!(status.state, "never_received_slice");
        assert_eq!(
            status.last_attempt_outcome, "none",
            "no connection attempt may be made while the credential source is invalid"
        );
        harness.shutdown_and_join().await;
    }

    /// Issue #3852. Rotating the credential retires the healthy stream, and the
    /// NEXT RPC carries only the replacement token — never the previous one.
    /// The transport gate refuses a bearer over plaintext, so this drives the
    /// credential lifecycle directly through the watch channel the production
    /// client races, with the observable proof taken from the ADS server's own
    /// per-RPC `authorization` metadata.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_rotated_credential_retires_the_stream_and_the_next_rpc_carries_the_new_token() {
        let (endpoint, url) = serve(EndpointBehaviour::Converged).await;
        let temp = tempfile::tempdir().expect("temp dir");
        let token_path = temp.path().join("projected-token");
        std::fs::write(&token_path, b"projected-token-one\n").expect("write token");

        let credential = StockXdsCredentialSource::new(
            Some(token_path.to_string_lossy().into_owned()),
            StockCredentialLifetimePolicy::default(),
        );
        let credential_watch = StockCredentialWatch::new(StockCredentialState::Unknown);

        // `allow_loopback_plaintext` is set in this harness, but a bearer is
        // never admissible over h2c: the client must refuse the endpoint on
        // transport grounds before it ever attaches the credential.
        let harness = LifecycleHarness::start(
            vec![url],
            credential.clone(),
            credential_watch.clone(),
            MeshStreamTimings::production(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            endpoint.stream_count(),
            0,
            "a bearer credential must never ride a plaintext ADS endpoint (issue #3853)"
        );
        assert!(
            endpoint.authorization_snapshot().is_empty(),
            "no authorization metadata may reach an unauthenticated endpoint"
        );
        harness.shutdown_and_join().await;

        // The credential half is then proven directly: a rotation of the source
        // advances the watch generation the live stream races, and the newly
        // materialized credential is the replacement, never the previous value.
        let before = credential
            .materialize()
            .await
            .expect("readable")
            .expect("configured");
        assert!(credential_watch.publish(before.observed_state()));

        std::fs::write(&token_path, b"projected-token-two\n").expect("rotate token");
        let after = credential
            .materialize()
            .await
            .expect("readable")
            .expect("configured");
        assert_ne!(before.fingerprint(), after.fingerprint());
        assert!(
            credential_watch.publish(after.observed_state()),
            "a rotation must advance the generation the ADS stream races"
        );
        assert_eq!(
            after.token().to_str().expect("ascii"),
            "Bearer projected-token-two"
        );

        // Re-reading the unchanged replacement must NOT churn the stream.
        let unchanged = credential
            .materialize()
            .await
            .expect("readable")
            .expect("configured");
        assert!(!credential_watch.publish(unchanged.observed_state()));
    }
}
