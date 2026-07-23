//! Issue #2472: native gRPC `request_mirror` shadows must use HTTP/2.
//!
//! Cleartext mirrors speak h2c prior knowledge; TLS mirrors negotiate ALPN h2.
//! Both paths must carry synthesised `te: trailers` after the canonical
//! secondary-request header strip.
//!
//! Run with:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests request_mirror_grpc_transport \
//!     -- --ignored --nocapture
//! ```

use std::time::Duration;

use crate::scaffolding::backends::{GrpcStep, MatchRpc, ReceivedStream, ScriptedGrpcBackend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::GrpcClient;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use serde_json::json;

const RPC_PATH: &str = "/helloworld.Greeter/SayHello";
const RPC_BODY: &[u8] = b"mirror-unary";

fn grpc_mirror_yaml(
    primary_port: u16,
    mirror_port: u16,
    mirror_protocol: &str,
    mirror_request_body: bool,
) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-mirror-transport",
            "listen_path": "/grpc",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": primary_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "plugins": [{ "plugin_config_id": "request-mirror" }],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "request-mirror",
            "plugin_name": "request_mirror",
            "scope": "proxy",
            "proxy_id": "grpc-mirror-transport",
            "enabled": true,
            "config": {
                "mirror_host": "127.0.0.1",
                "mirror_port": mirror_port,
                "mirror_protocol": mirror_protocol,
                "percentage": 100.0,
                // Isolate #2472 outbound transport from shared #2190 prebuffer
                // primary-dispatch concerns when the body is not required.
                "mirror_request_body": mirror_request_body,
            },
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn gateway_http_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .expect("gateway http port")
}

async fn wait_for_mirror_stream(mirror: &ScriptedGrpcBackend) -> ReceivedStream {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let streams = mirror.received_streams().await;
            if let Some(stream) = streams.into_iter().next() {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out waiting for gRPC mirror request")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_h2c_prior_knowledge_carries_te_trailers() {
    let primary_res = reserve_port().await.expect("primary port");
    let primary_port = primary_res.port;
    let _primary = ScriptedGrpcBackend::builder_plain(primary_res.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::method(RPC_PATH)))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"primary-ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn primary");

    let mirror_res = reserve_port().await.expect("mirror port");
    let mirror_port = mirror_res.port;
    let mirror = ScriptedGrpcBackend::builder_plain(mirror_res.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::method(RPC_PATH)))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"mirror-ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn h2c mirror");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "http",
            /* mirror_request_body */ false,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(&format!("/grpc{RPC_PATH}"), Bytes::from_static(RPC_BODY))
        .await
        .expect("unary rpc");
    assert_eq!(response.grpc_status(), Some(0), "response={response:?}");

    let observed = wait_for_mirror_stream(&mirror).await;
    assert_eq!(observed.path, RPC_PATH);
    assert_eq!(
        observed.header("content-type"),
        Some("application/grpc"),
        "headers={:?}",
        observed.headers
    );
    assert_eq!(
        observed.header("te"),
        Some("trailers"),
        "h2c gRPC mirror must carry te: trailers; headers={:?}",
        observed.headers
    );
    assert!(
        mirror.handshakes_completed() >= 1,
        "mirror must complete an h2c handshake"
    );
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_tls_alpn_h2_carries_te_trailers() {
    let primary_res = reserve_port().await.expect("primary port");
    let primary_port = primary_res.port;
    let _primary = ScriptedGrpcBackend::builder_plain(primary_res.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::method(RPC_PATH)))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"primary-ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn primary");

    let ca = TestCa::new("request-mirror-grpc-tls").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let mirror_res = reserve_port().await.expect("mirror port");
    let mirror_port = mirror_res.port;
    let mirror = ScriptedGrpcBackend::builder_tls(mirror_res.into_listener(), &cert_pem, &key_pem)
        .expect("tls builder")
        .step(GrpcStep::AcceptRpc(MatchRpc::method(RPC_PATH)))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"mirror-ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn tls+h2 mirror");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "https",
            /* mirror_request_body */ false,
        ))
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(&format!("/grpc{RPC_PATH}"), Bytes::from_static(RPC_BODY))
        .await
        .expect("unary rpc");
    assert_eq!(response.grpc_status(), Some(0), "response={response:?}");

    let observed = wait_for_mirror_stream(&mirror).await;
    assert_eq!(observed.path, RPC_PATH);
    assert_eq!(
        observed.header("te"),
        Some("trailers"),
        "TLS+h2 gRPC mirror must carry te: trailers; headers={:?}",
        observed.headers
    );
    assert!(
        mirror.handshakes_completed() >= 1,
        "mirror must complete an ALPN h2 handshake"
    );
    mirror.assert_no_step_errors().await;
}
