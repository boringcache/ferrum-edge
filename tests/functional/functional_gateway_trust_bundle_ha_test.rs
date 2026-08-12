//! Live multi-backend acceptance and two-replica HA convergence for the
//! namespace-keyed gateway trust-bundle resource (issue #3727).
//!
//! The integration suites prove the store contract in-process against SQLite
//! and the CP projection with no database at all. What only a live, hosted
//! backend can prove is what this file covers:
//!
//! - the same create / read / rotate-with-overlap / compare-and-set / explicit
//!   revoke lifecycle really executes on **every** backend hosted CI
//!   provisions — SQLite, PostgreSQL, MySQL, standalone MongoDB, and the
//!   single-node MongoDB replica set;
//! - a control plane restarted against nothing but the authoritative database
//!   reconstructs the identical trust generation (`generation` digest,
//!   revision, and material);
//! - a rotation is *published* — the `published_generations_total` counter is
//!   incremented at the `ArcSwap` swap, so waiting for it to advance is proof
//!   that change detection escalated, the candidate validated, and the
//!   generation went live;
//! - two control-plane replicas sharing one database converge on the same
//!   committed revision **without a restart**, and concurrent writers racing
//!   from the same read leave exactly one winner;
//! - an interrupted MongoDB write leaves the database crash-consistent: the
//!   gateway is `SIGKILL`ed mid-rotation and the committed document's
//!   `revision` must still be a `config_changes` sequence that exists.
//!
//! That last cell is deliberately scoped to crash consistency and is NOT a
//! visibility proof. It shows a matching change row exists; it cannot show the
//! row was still unconsumed when the document committed, and on standalone
//! mongod a live poller can consume it first. Visibility there is established
//! on the read side by the authoritative poll-path drift check, whose exact
//! interleaving is asserted deterministically in
//! `tests/unit/config/gateway_trust_bundle_tests.rs` — a live server cannot
//! stage that interleaving reproducibly.
//!
//! Hosted CI sets `FERRUM_DB_BACKENDS_REQUIRED=1` plus explicit
//! `FERRUM_TEST_POSTGRES_URL` / `FERRUM_TEST_MYSQL_URL` / `FERRUM_TEST_MONGO_URL`
//! so a missing backend fails the job instead of skipping. The replica set stays
//! opt-in through `FERRUM_TEST_MONGO_REPLICA_SET`, but once declared an
//! unreachable member is a provisioning failure rather than a skip — the same
//! convention `functional_mongodb_test` uses.
//!
//! Run with:
//!   cargo test --test functional_tests functional_gateway_trust_bundle -- --ignored

use crate::common::{
    DbType, TestGateway, continue_if_backend_available, ensure_shared_sql_containers_resumed,
    host_port_from_db_url, mysql_test_url, postgres_test_url, provision_isolated_sql_database,
    tcp_endpoint_reachable,
};
use base64::Engine;
use mongodb::bson::{Document, doc};
use mongodb::options::ClientOptions;
use reqwest::Client;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use uuid::Uuid;

const DEFAULT_MONGO_URL: &str = "mongodb://127.0.0.1:27017/ferrum_test";
/// The namespace the gateway itself serves, so its records are the ones that
/// reach the publication boundary.
const PRIMARY_NAMESPACE: &str = "ferrum";
/// A second tenant used only to prove isolation. Nothing here is ever served.
const PEER_NAMESPACE: &str = "trust-peer-tenant";
const TRUST_DOMAIN: &str = "cluster.local";
const PEER_TRUST_DOMAIN: &str = "peer.local";
/// `config_changes.resource_type` for this resource (`db_loader.rs`).
const TRUST_CHANGE_RESOURCE_TYPE: &str = "gateway_trust_bundle";

// ── Fixtures ────────────────────────────────────────────────────────────────

fn root_ca_der_base64(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test CA key generates");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

fn bundle_body(trust_domain: &str, authorities: &[&str]) -> Value {
    json!({
        "local": {
            "trust_domain": trust_domain,
            "x509_authorities": authorities,
        }
    })
}

fn create_body(trust_domain: &str, authorities: &[&str]) -> Value {
    json!({
        "trust_domain": trust_domain,
        "bundle": bundle_body(trust_domain, authorities),
    })
}

fn rotation_body(trust_domain: &str, expected_revision: u64, authorities: &[&str]) -> Value {
    json!({
        "trust_domain": trust_domain,
        "revision": expected_revision,
        "bundle": bundle_body(trust_domain, authorities),
    })
}

// ── Admin HTTP helpers ──────────────────────────────────────────────────────

async fn decode(response: reqwest::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    // A `204` carries no body; every error and success body here is JSON.
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn trust_post(
    client: &Client,
    gateway: &TestGateway,
    namespace: &str,
    body: Value,
) -> (u16, Value) {
    let response = client
        .post(gateway.admin_url("/gateway-trust-bundles"))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .json(&body)
        .send()
        .await
        .expect("POST /gateway-trust-bundles");
    decode(response).await
}

async fn trust_put(
    client: &Client,
    gateway: &TestGateway,
    namespace: &str,
    id: &str,
    body: Value,
) -> (u16, Value) {
    let response = client
        .put(gateway.admin_url(&format!("/gateway-trust-bundles/{id}")))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .json(&body)
        .send()
        .await
        .expect("PUT gateway trust bundle");
    decode(response).await
}

/// `trust_put` for a request that may be severed mid-flight by an interrupted
/// gateway. A transport failure is an outcome here, not a test failure.
async fn trust_put_allowing_transport_failure(
    client: &Client,
    gateway: &TestGateway,
    namespace: &str,
    id: &str,
    body: Value,
) -> Option<(u16, Value)> {
    let response = client
        .put(gateway.admin_url(&format!("/gateway-trust-bundles/{id}")))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .json(&body)
        .send()
        .await
        .ok()?;
    Some(decode(response).await)
}

async fn trust_get(
    client: &Client,
    gateway: &TestGateway,
    namespace: &str,
    id: &str,
) -> (u16, Value) {
    let response = client
        .get(gateway.admin_url(&format!("/gateway-trust-bundles/{id}")))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("GET gateway trust bundle");
    decode(response).await
}

async fn trust_list(client: &Client, gateway: &TestGateway, namespace: &str) -> (u16, Value) {
    let response = client
        .get(gateway.admin_url("/gateway-trust-bundles"))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("GET /gateway-trust-bundles");
    decode(response).await
}

async fn trust_delete(client: &Client, gateway: &TestGateway, namespace: &str, id: &str) -> u16 {
    client
        .delete(gateway.admin_url(&format!("/gateway-trust-bundles/{id}")))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("DELETE gateway trust bundle")
        .status()
        .as_u16()
}

async fn trust_status(client: &Client, gateway: &TestGateway, namespace: &str) -> (u16, Value) {
    let response = client
        .get(gateway.admin_url("/gateway-trust/status"))
        .header("Authorization", gateway.auth_header())
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("GET /gateway-trust/status");
    decode(response).await
}

/// Authenticated Prometheus scrape. An admin JWT is one of the accepted
/// credentials, so the per-child observability token stays untouched.
async fn scrape_metrics(client: &Client, gateway: &TestGateway) -> String {
    let response = client
        .get(gateway.admin_url("/metrics"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .expect("GET /metrics");
    assert_eq!(
        response.status().as_u16(),
        200,
        "an authenticated /metrics scrape must succeed"
    );
    response.text().await.expect("metrics body is text")
}

fn published_generations(status: &Value) -> u64 {
    status["process"]["published_generations_total"]
        .as_u64()
        .expect("status must carry process.published_generations_total")
}

fn stored_authorities(record: &Value) -> Vec<String> {
    record["bundle"]["local"]["x509_authorities"]
        .as_array()
        .expect("stored record must carry x509 authorities")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("each authority is a base64 string")
                .to_string()
        })
        .collect()
}

// ── Waits ───────────────────────────────────────────────────────────────────

/// Poll `GET /gateway-trust/status` until this process reports `revision` as the
/// namespace's committed trust revision *and* has published at least
/// `at_least_published` trust generations.
///
/// The counter is incremented at the configuration swap, so its advance is the
/// proof that change detection escalated to a full reload, the candidate
/// validated, and the generation went live — not merely that a row was written.
/// Pairing it with the expected revision is what keeps the wait from being
/// satisfied by an *earlier* publication that is still in flight.
async fn wait_for_published_revision(
    client: &Client,
    gateway: &TestGateway,
    namespace: &str,
    revision: u64,
    at_least_published: u64,
    timeout: Duration,
    context: &str,
) -> Value {
    let deadline = Instant::now() + timeout;
    loop {
        let (status, body) = trust_status(client, gateway, namespace).await;
        if status == 200
            && published_generations(&body) >= at_least_published
            && body["bundle"]["revision"].as_u64() == Some(revision)
        {
            return body;
        }
        if Instant::now() >= deadline {
            panic!(
                "{context}: revision {revision} was never published within {timeout:?}; \
                 last status: {body}"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// ── Gateway spawners ────────────────────────────────────────────────────────

async fn spawn_database_gateway(db: DbType, extra_env: &[(String, String)]) -> TestGateway {
    let mut builder = TestGateway::builder()
        .mode_database(db)
        .log_level("warn")
        .db_poll_interval_seconds(1);
    for (key, value) in extra_env {
        builder = builder.env(key.clone(), value.clone());
    }
    builder.spawn().await.expect("spawn database-mode gateway")
}

async fn spawn_cp_replica(db: DbType, extra_env: &[(String, String)]) -> TestGateway {
    let mut builder = TestGateway::builder()
        .mode_cp(db, None)
        .log_level("warn")
        .db_poll_interval_seconds(1);
    for (key, value) in extra_env {
        builder = builder.env(key.clone(), value.clone());
    }
    builder.spawn().await.expect("spawn control-plane replica")
}

// ── The shared acceptance body ──────────────────────────────────────────────

/// State a restarted process must reconstruct from the database alone.
#[derive(Debug)]
struct TrustState {
    generation: String,
    revision: u64,
    authorities: Vec<String>,
}

/// Create → read → reject-invalid → rotate-with-overlap → lose-a-stale-CAS →
/// publish → isolate. Returns the state the database now holds for
/// [`PRIMARY_NAMESPACE`].
///
/// Every assertion here is backend-agnostic on purpose: this is the contract
/// each hosted backend has to satisfy identically, and the value of running it
/// live is that the dialect rendering, the driver's integer decoding, and the
/// backend's own concurrency behaviour are all in the loop.
async fn run_trust_acceptance(client: &Client, gateway: &TestGateway, backend: &str) -> TrustState {
    // 0. An empty namespace reports "not configured" without inventing a record.
    let (status, empty) = trust_status(client, gateway, PRIMARY_NAMESPACE).await;
    assert_eq!(status, 200, "[{backend}] status must answer: {empty}");
    assert_eq!(
        empty["configured"], false,
        "[{backend}] a fresh namespace holds no trust record: {empty}"
    );
    let empty_generation = empty["generation"]
        .as_str()
        .expect("status carries a generation digest")
        .to_string();
    let baseline_published = published_generations(&empty);

    // 1. Create. The body claims another tenant and omits `id`; both must be
    //    decided by the authenticated header, not by the payload.
    let root_a = root_ca_der_base64("acceptance-root-a");
    let mut hostile = create_body(TRUST_DOMAIN, &[root_a.as_str()]);
    hostile["namespace"] = json!(PEER_NAMESPACE);
    hostile["updated_by"] = json!("attacker");
    let (status, created) = trust_post(client, gateway, PRIMARY_NAMESPACE, hostile).await;
    assert_eq!(status, 201, "[{backend}] create must succeed: {created}");
    assert_eq!(
        created["namespace"], PRIMARY_NAMESPACE,
        "[{backend}] the stored namespace comes from the header: {created}"
    );
    assert_eq!(
        created["id"], PRIMARY_NAMESPACE,
        "[{backend}] an omitted id defaults to the server-selected namespace: {created}"
    );
    let created_revision = created["revision"]
        .as_u64()
        .expect("create answers a numeric revision");
    assert!(
        created_revision >= 1,
        "[{backend}] the store assigns a positive revision, got {created_revision}"
    );

    // 1b. Let the create reach the publication boundary before rotating. The
    //     poller collapses a batch of changes into ONE full reload, so waiting
    //     here is what makes the rotation's own publication observable below
    //     instead of being absorbed into the create's.
    let after_create = wait_for_published_revision(
        client,
        gateway,
        PRIMARY_NAMESPACE,
        created_revision,
        baseline_published + 1,
        Duration::from_secs(45),
        &format!("[{backend}] create publication"),
    )
    .await;
    let published_after_create = published_generations(&after_create);

    // 2. Read back through the id route.
    let (status, fetched) = trust_get(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(status, 200, "[{backend}] read must succeed: {fetched}");
    assert_eq!(
        stored_authorities(&fetched),
        vec![root_a.clone()],
        "[{backend}] the material must round-trip through the backend"
    );
    assert_eq!(
        fetched["revision"].as_u64(),
        Some(created_revision),
        "[{backend}] the create response and a later read must agree"
    );

    // 3. A namespace holds at most one record.
    let extra = root_ca_der_base64("acceptance-root-extra");
    let mut second = create_body(TRUST_DOMAIN, &[extra.as_str()]);
    second["id"] = json!("second-record");
    let (status, refusal) = trust_post(client, gateway, PRIMARY_NAMESPACE, second).await;
    assert_eq!(
        status, 409,
        "[{backend}] a second record in one namespace is refused: {refusal}"
    );

    // 4. Malformed and oversized candidates are refused BEFORE publication, and
    //    the previously valid bundle survives untouched.
    let oversized = "A".repeat(24 * 1024);
    let not_a_certificate = base64::engine::general_purpose::STANDARD.encode(b"not DER at all");
    let invalid_candidates: Vec<(&str, Value)> = vec![
        (
            "authority that is not base64",
            rotation_body(TRUST_DOMAIN, created_revision, &["not base64 at all!!"]),
        ),
        (
            "base64 that is not a certificate",
            rotation_body(
                TRUST_DOMAIN,
                created_revision,
                &[not_a_certificate.as_str()],
            ),
        ),
        (
            "authority over the per-entry size cap",
            rotation_body(TRUST_DOMAIN, created_revision, &[oversized.as_str()]),
        ),
        (
            "identity that contradicts the bundle",
            json!({
                "trust_domain": "not-the-bundle.local",
                "revision": created_revision,
                "bundle": bundle_body(TRUST_DOMAIN, &[root_a.as_str()]),
            }),
        ),
    ];
    for (label, candidate) in invalid_candidates {
        let (status, body) = trust_put(
            client,
            gateway,
            PRIMARY_NAMESPACE,
            PRIMARY_NAMESPACE,
            candidate,
        )
        .await;
        assert_eq!(
            status, 400,
            "[{backend}] {label} must be refused at admission: {body}"
        );
        let error = body["error"].as_str().unwrap_or_default();
        assert!(
            !error.contains(&root_a),
            "[{backend}] {label}: a refusal must not echo trust material"
        );
    }
    let (status, unchanged) =
        trust_get(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(status, 200);
    assert_eq!(
        unchanged["revision"].as_u64(),
        Some(created_revision),
        "[{backend}] a refused candidate must not consume a revision: {unchanged}"
    );
    assert_eq!(
        stored_authorities(&unchanged),
        vec![root_a.clone()],
        "[{backend}] a refused candidate must not replace the valid bundle"
    );

    // 5. Rotation with overlap: the incoming root is added alongside the old one
    //    so in-flight workloads keep validating during rollout.
    let root_b = root_ca_der_base64("acceptance-root-b");
    let (status, rotated) = trust_put(
        client,
        gateway,
        PRIMARY_NAMESPACE,
        PRIMARY_NAMESPACE,
        rotation_body(
            TRUST_DOMAIN,
            created_revision,
            &[root_a.as_str(), root_b.as_str()],
        ),
    )
    .await;
    assert_eq!(status, 200, "[{backend}] rotation must succeed: {rotated}");
    let rotated_revision = rotated["revision"]
        .as_u64()
        .expect("rotation answers a numeric revision");
    assert!(
        rotated_revision > created_revision,
        "[{backend}] the store advances the revision itself"
    );
    assert_eq!(
        stored_authorities(&rotated),
        vec![root_a.clone(), root_b.clone()],
        "[{backend}] rotation overlap keeps the outgoing root"
    );

    // 6. The revision that was just consumed is now stale, and a compare-and-set
    //    that asserts it must lose rather than silently overwrite.
    let root_c = root_ca_der_base64("acceptance-root-c");
    let (status, conflict) = trust_put(
        client,
        gateway,
        PRIMARY_NAMESPACE,
        PRIMARY_NAMESPACE,
        rotation_body(TRUST_DOMAIN, created_revision, &[root_c.as_str()]),
    )
    .await;
    assert_eq!(
        status, 409,
        "[{backend}] a stale expectation must be a conflict: {conflict}"
    );
    assert_eq!(
        conflict["expected_revision"].as_u64(),
        Some(created_revision),
        "[{backend}] the conflict reports what the client expected: {conflict}"
    );
    assert_eq!(
        conflict["current_revision"].as_u64(),
        Some(rotated_revision),
        "[{backend}] the conflict reports the committed revision: {conflict}"
    );
    let (_, after_conflict) =
        trust_get(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(
        stored_authorities(&after_conflict),
        vec![root_a.clone(), root_b.clone()],
        "[{backend}] the loser of a compare-and-set must not have written"
    );

    // 7. The rotation has to reach the publication boundary, not just the table.
    let published = wait_for_published_revision(
        client,
        gateway,
        PRIMARY_NAMESPACE,
        rotated_revision,
        published_after_create + 1,
        Duration::from_secs(45),
        &format!("[{backend}] rotation publication"),
    )
    .await;
    assert_eq!(
        published["bundle"]["x509_authority_count"].as_u64(),
        Some(2),
        "[{backend}] status counts authorities without exposing them: {published}"
    );
    let generation = published["generation"]
        .as_str()
        .expect("status carries a generation digest")
        .to_string();
    assert_ne!(
        generation, empty_generation,
        "[{backend}] a rotation must change the generation identity"
    );

    // 8. Redaction: neither the status view nor a scrape may carry material.
    let status_text = published.to_string();
    for authority in [&root_a, &root_b] {
        assert!(
            !status_text.contains(authority.as_str()),
            "[{backend}] the status view must never carry trust material"
        );
    }
    let metrics = scrape_metrics(client, gateway).await;
    for authority in [&root_a, &root_b] {
        assert!(
            !metrics.contains(authority.as_str()),
            "[{backend}] /metrics must never carry trust material"
        );
    }
    for series in [
        "ferrum_gateway_trust_bundle_published_generations_total",
        "ferrum_gateway_trust_bundle_load_rejections_total",
        "ferrum_gateway_trust_bundle_ambiguous_authority_total",
        "ferrum_gateway_trust_bundle_last_published_unix_seconds",
    ] {
        assert!(
            metrics.contains(series),
            "[{backend}] /metrics must expose {series}"
        );
    }

    // 9. Namespace isolation, including through absence and error behaviour.
    let peer_root = root_ca_der_base64("acceptance-peer-root");
    let (status, peer) = trust_post(
        client,
        gateway,
        PEER_NAMESPACE,
        create_body(PEER_TRUST_DOMAIN, &[peer_root.as_str()]),
    )
    .await;
    assert_eq!(status, 201, "[{backend}] peer create must succeed: {peer}");

    let (status, listed) = trust_list(client, gateway, PRIMARY_NAMESPACE).await;
    assert_eq!(status, 200);
    let items = listed["data"]
        .as_array()
        .expect("list answers a data array")
        .clone();
    assert_eq!(
        items.len(),
        1,
        "[{backend}] a list must not leak another tenant's record: {listed}"
    );
    assert_eq!(items[0]["namespace"], PRIMARY_NAMESPACE);
    assert!(
        !listed.to_string().contains(peer_root.as_str()),
        "[{backend}] a list must not carry another tenant's material"
    );

    let (status, cross) = trust_get(client, gateway, PRIMARY_NAMESPACE, PEER_NAMESPACE).await;
    assert_eq!(
        status, 404,
        "[{backend}] another tenant's id must not resolve: {cross}"
    );
    let (status, cross_write) = trust_put(
        client,
        gateway,
        PRIMARY_NAMESPACE,
        PEER_NAMESPACE,
        rotation_body(PEER_TRUST_DOMAIN, 0, &[root_c.as_str()]),
    )
    .await;
    assert_eq!(
        status, 404,
        "[{backend}] a cross-namespace write must not resolve: {cross_write}"
    );
    assert_eq!(
        trust_delete(client, gateway, PRIMARY_NAMESPACE, PEER_NAMESPACE).await,
        404,
        "[{backend}] a cross-namespace delete must not resolve"
    );
    let (status, peer_after) = trust_get(client, gateway, PEER_NAMESPACE, PEER_NAMESPACE).await;
    assert_eq!(
        status, 200,
        "[{backend}] the peer record survives: {peer_after}"
    );
    assert_eq!(stored_authorities(&peer_after), vec![peer_root.clone()]);

    let (_, peer_status) = trust_status(client, gateway, PEER_NAMESPACE).await;
    assert_ne!(
        peer_status["generation"].as_str(),
        Some(generation.as_str()),
        "[{backend}] two tenants must not share a trust generation identity"
    );

    TrustState {
        generation,
        revision: rotated_revision,
        authorities: vec![root_a, root_b],
    }
}

/// A process that has only the database must reconstruct the identical trust
/// generation, and must publish it.
async fn assert_restart_reconstructs(
    client: &Client,
    gateway: &TestGateway,
    expected: &TrustState,
    backend: &str,
) {
    let status = wait_for_published_revision(
        client,
        gateway,
        PRIMARY_NAMESPACE,
        expected.revision,
        1,
        Duration::from_secs(45),
        &format!("[{backend}] restart publication"),
    )
    .await;
    assert_eq!(
        status["generation"].as_str(),
        Some(expected.generation.as_str()),
        "[{backend}] a restart must reconstruct the same generation: {status}"
    );
    let (code, record) = trust_get(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(
        code, 200,
        "[{backend}] the record survives a restart: {record}"
    );
    assert_eq!(
        stored_authorities(&record),
        expected.authorities,
        "[{backend}] a restart must reconstruct the same material"
    );
}

/// Explicit revocation is distinct from "no change": the record goes away, the
/// withdrawal reaches the live generation, and the other tenant is untouched.
///
/// Like every other trust transition, the withdrawal is poll-driven: the
/// `DELETE` is authoritative on the store, and the live configuration follows on
/// the next database poll / full-snapshot publication. So the status view is
/// waited on with the same bounded style the install and rotation cells use,
/// and the wait requires the namespace's material-free generation digest to
/// change. `published_generations_total` deliberately counts only NONEMPTY
/// database trust generations, so an explicit empty-generation revocation must
/// leave that process counter unchanged.
async fn assert_explicit_revocation(client: &Client, gateway: &TestGateway, backend: &str) {
    let (status, before) = trust_status(client, gateway, PRIMARY_NAMESPACE).await;
    assert_eq!(
        status, 200,
        "[{backend}] the status view must be readable before revoking: {before}"
    );
    assert_eq!(
        before["configured"], true,
        "[{backend}] the namespace must start configured: {before}"
    );
    let published_before = published_generations(&before);
    let generation_before = before["generation"]
        .as_str()
        .expect("a configured trust status carries its generation")
        .to_string();

    assert_eq!(
        trust_delete(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await,
        204,
        "[{backend}] explicit revocation must succeed"
    );
    let (status, gone) = trust_get(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(status, 404, "[{backend}] the record is gone: {gone}");

    let timeout = Duration::from_secs(45);
    let deadline = Instant::now() + timeout;
    let after = loop {
        let (status, after) = trust_status(client, gateway, PRIMARY_NAMESPACE).await;
        if status == 200
            && after["configured"] == false
            && after["bundle"].is_null()
            && after["generation"]
                .as_str()
                .is_some_and(|generation| generation != generation_before.as_str())
        {
            break after;
        }
        if Instant::now() >= deadline {
            panic!(
                "[{backend}] the revocation never reached the live publication boundary \
                 within {timeout:?} (the prior generation was {generation_before}); \
                 last status: {after}"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(
        published_generations(&after),
        published_before,
        "[{backend}] an empty revocation publication must not increment the \
         nonempty database-generation counter: {after}"
    );

    assert_eq!(
        trust_delete(client, gateway, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await,
        404,
        "[{backend}] a repeat revocation reports 'nothing matched'"
    );
    let (status, peer) = trust_get(client, gateway, PEER_NAMESPACE, PEER_NAMESPACE).await;
    assert_eq!(
        status, 200,
        "[{backend}] revoking one tenant must not revoke another: {peer}"
    );
}

// ── Per-backend acceptance cells ────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_gateway_trust_bundle_acceptance_sqlite() {
    let client = Client::new();
    // The database file is owned by the test, not by a per-spawn temp dir, so
    // the restarted process opens the very same authoritative store.
    let dir = TempDir::new().expect("temp dir");
    let db_path = dir.path().join("gateway-trust-acceptance.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DbType::Custom {
        db_type: "sqlite".to_string(),
        db_url,
    };

    let mut gateway = spawn_database_gateway(db.clone(), &[]).await;
    let state = run_trust_acceptance(&client, &gateway, "sqlite").await;
    gateway.shutdown();
    drop(gateway);

    let restarted = spawn_database_gateway(db, &[]).await;
    assert_restart_reconstructs(&client, &restarted, &state, "sqlite").await;
    assert_explicit_revocation(&client, &restarted, "sqlite").await;
}

#[tokio::test]
#[ignore]
async fn test_gateway_trust_bundle_acceptance_postgres() {
    ensure_shared_sql_containers_resumed();
    let Some(postgres_url) = postgres_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&postgres_url);
    if !continue_if_backend_available(
        "postgres",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    let (postgres_url, _isolated_db) = provision_isolated_sql_database(&postgres_url);
    let client = Client::new();

    let mut gateway = spawn_database_gateway(DbType::Postgres(postgres_url.clone()), &[]).await;
    let state = run_trust_acceptance(&client, &gateway, "postgres").await;
    gateway.shutdown();
    drop(gateway);

    let restarted = spawn_database_gateway(DbType::Postgres(postgres_url), &[]).await;
    assert_restart_reconstructs(&client, &restarted, &state, "postgres").await;
    assert_explicit_revocation(&client, &restarted, "postgres").await;
}

#[tokio::test]
#[ignore]
async fn test_gateway_trust_bundle_acceptance_mysql() {
    ensure_shared_sql_containers_resumed();
    let Some(mysql_url) = mysql_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&mysql_url);
    if !continue_if_backend_available(
        "mysql",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    let (mysql_url, _isolated_db) = provision_isolated_sql_database(&mysql_url);
    let client = Client::new();

    let mut gateway = spawn_database_gateway(DbType::MySql(mysql_url.clone()), &[]).await;
    let state = run_trust_acceptance(&client, &gateway, "mysql").await;
    gateway.shutdown();
    drop(gateway);

    let restarted = spawn_database_gateway(DbType::MySql(mysql_url), &[]).await;
    assert_restart_reconstructs(&client, &restarted, &state, "mysql").await;
    assert_explicit_revocation(&client, &restarted, "mysql").await;
}

#[tokio::test]
#[ignore]
async fn test_gateway_trust_bundle_acceptance_mongodb_standalone() {
    let Some(mongo_url) = standalone_mongo_url().await else {
        return;
    };
    let client = Client::new();
    let database = unique_mongo_database("acceptance");
    let _cleanup = MongoDatabaseCleanup::new(mongo_url.clone(), database.clone());
    let env = vec![("FERRUM_MONGO_DATABASE".to_string(), database)];

    let mut gateway = spawn_database_gateway(DbType::Mongo(mongo_url.clone()), &env).await;
    let state = run_trust_acceptance(&client, &gateway, "mongodb").await;
    gateway.shutdown();
    drop(gateway);

    let restarted = spawn_database_gateway(DbType::Mongo(mongo_url), &env).await;
    assert_restart_reconstructs(&client, &restarted, &state, "mongodb").await;
    assert_explicit_revocation(&client, &restarted, "mongodb").await;
}

/// The same acceptance body against the single-node replica set, where the
/// change record and the document mutation are one multi-document transaction.
///
/// Opt-in through `FERRUM_TEST_MONGO_REPLICA_SET`; once declared, an
/// unreachable member fails the cell instead of skipping.
#[tokio::test]
#[ignore]
async fn test_gateway_trust_bundle_acceptance_mongodb_replica_set() {
    let Some((mongo_url, replica_set)) = replica_set_mongo_url().await else {
        return;
    };
    let client = Client::new();
    let database = unique_mongo_database("acceptance_rs");
    let _cleanup = MongoDatabaseCleanup::new(mongo_url.clone(), database.clone());
    let env = vec![
        ("FERRUM_MONGO_DATABASE".to_string(), database),
        ("FERRUM_MONGO_REPLICA_SET".to_string(), replica_set),
    ];

    let mut gateway = spawn_database_gateway(DbType::Mongo(mongo_url.clone()), &env).await;
    let state = run_trust_acceptance(&client, &gateway, "mongodb-replica-set").await;
    gateway.shutdown();
    drop(gateway);

    let restarted = spawn_database_gateway(DbType::Mongo(mongo_url), &env).await;
    assert_restart_reconstructs(&client, &restarted, &state, "mongodb-replica-set").await;
    assert_explicit_revocation(&client, &restarted, "mongodb-replica-set").await;
}

// ── MongoDB: an interrupted write leaves no unrecorded trust revision ───────

/// Kill a control plane in the middle of a rotation and prove the database is
/// left crash-consistent: the stored `revision` **is** a `config_changes`
/// sequence that exists, because the signal is written first and supplies it.
/// A redundant change row (a signal for a mutation that did not land) is
/// explicitly allowed — it costs one wasted full reload.
///
/// This is deliberately NOT a visibility proof, and must not be read as one.
/// It shows a matching change row *exists*; it cannot show the row was still
/// unconsumed when the document committed. On standalone mongod a live poller
/// can read that sequence, complete a full reload against the pre-rotation
/// document, and advance its cursor past it before the document lands — after
/// which no signal announces the committed mutation at all. That interleaving
/// cannot be staged deterministically against a live server, so the repair
/// that closes it (the authoritative poll-path drift check, see
/// `crate::config::gateway_trust::detect_gateway_trust_drift`) is proved in
/// `tests/unit/config/gateway_trust_bundle_tests.rs`, which commits the signal
/// and the document as two explicitly ordered steps.
async fn assert_interrupted_write_records_every_committed_revision(
    client: &Client,
    mongo_url: &str,
    replica_set: Option<&str>,
    kill_after: Duration,
    label: &str,
) {
    let database = unique_mongo_database("interrupt");
    let _cleanup = MongoDatabaseCleanup::new(mongo_url.to_string(), database.clone());
    let mut env = vec![("FERRUM_MONGO_DATABASE".to_string(), database.clone())];
    if let Some(replica_set) = replica_set {
        env.push((
            "FERRUM_MONGO_REPLICA_SET".to_string(),
            replica_set.to_string(),
        ));
    }
    let gateway = spawn_database_gateway(DbType::Mongo(mongo_url.to_string()), &env).await;

    let root_a = root_ca_der_base64("interrupt-root-a");
    let (status, created) = trust_post(
        client,
        &gateway,
        PRIMARY_NAMESPACE,
        create_body(TRUST_DOMAIN, &[root_a.as_str()]),
    )
    .await;
    assert_eq!(status, 201, "[{label}] seed create must succeed: {created}");
    let created_revision = created["revision"].as_u64().expect("numeric revision");

    // Sever the process while the rotation is in flight. The PID is captured up
    // front so the killer future borrows nothing from the gateway.
    let pid = gateway.pid().expect("gateway exposes its pid");
    let root_b = root_ca_der_base64("interrupt-root-b");
    let rotation = trust_put_allowing_transport_failure(
        client,
        &gateway,
        PRIMARY_NAMESPACE,
        PRIMARY_NAMESPACE,
        rotation_body(
            TRUST_DOMAIN,
            created_revision,
            &[root_a.as_str(), root_b.as_str()],
        ),
    );
    let killer = async move {
        tokio::time::sleep(kill_after).await;
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    };
    let (outcome, ()) = tokio::join!(rotation, killer);
    drop(gateway);

    // Whatever the interruption caught, the database must not hold a committed
    // trust document whose revision no change row announces.
    let mongo = mongo_client(mongo_url).await;
    let handle = mongo.database(&database);
    let stored = handle
        .collection::<Document>("gateway_trust_bundles")
        .find_one(doc! { "_id": PRIMARY_NAMESPACE })
        .await
        .expect("read the stored trust document")
        .unwrap_or_else(|| panic!("[{label}] the seeded trust document must still exist"));
    let stored_revision = stored
        .get_i64("revision")
        .unwrap_or_else(|error| panic!("[{label}] stored revision must be an Int64: {error}"));
    assert!(
        stored_revision >= 1,
        "[{label}] a stored revision is always positive, got {stored_revision}"
    );

    let announcement = handle
        .collection::<Document>("config_changes")
        .find_one(doc! {
            "namespace": PRIMARY_NAMESPACE,
            "resource_type": TRUST_CHANGE_RESOURCE_TYPE,
            "sequence": stored_revision,
        })
        .await
        .expect("read the config_changes signal");
    assert!(
        announcement.is_some(),
        "[{label}] committed trust revision {stored_revision} has no config_changes row: \
         a poller that already consumed the cursor would never learn about it"
    );

    // The rotation either committed or it did not; both are acceptable outcomes
    // of an interruption, but a reported success must be the committed state.
    if let Some((status, body)) = outcome
        && status == 200
    {
        let reported = body["revision"].as_u64().expect("numeric revision");
        assert_eq!(
            i64::try_from(reported).ok(),
            Some(stored_revision),
            "[{label}] a 200 must describe the committed document: {body}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_mongodb_standalone_leaves_no_unrecorded_trust_revision() {
    let Some(mongo_url) = standalone_mongo_url().await else {
        return;
    };
    let client = Client::new();
    // Two interruption points: one likely inside admission/validation, one
    // likely inside the two-write sequence itself.
    for kill_after in [Duration::from_millis(40), Duration::from_millis(120)] {
        assert_interrupted_write_records_every_committed_revision(
            &client,
            &mongo_url,
            None,
            kill_after,
            "mongodb-standalone",
        )
        .await;
    }
}

#[tokio::test]
#[ignore]
async fn test_mongodb_replica_set_leaves_no_unrecorded_trust_revision() {
    let Some((mongo_url, replica_set)) = replica_set_mongo_url().await else {
        return;
    };
    let client = Client::new();
    assert_interrupted_write_records_every_committed_revision(
        &client,
        &mongo_url,
        Some(&replica_set),
        Duration::from_millis(80),
        "mongodb-replica-set",
    )
    .await;
}

// ── Two-replica HA convergence ──────────────────────────────────────────────

/// Two control planes, one database, no restart between them.
///
/// Replica A commits a rotation; replica B has to observe *and publish* the same
/// committed revision through its own poll cycle. Then both replicas race
/// compare-and-set writes from the same read, and exactly one may win. Finally
/// B is replaced by a fresh process to prove the converged state came from the
/// database rather than from anything either replica held in memory.
async fn run_two_replica_convergence(
    client: &Client,
    db: DbType,
    extra_env: &[(String, String)],
    label: &str,
) {
    let replica_a = spawn_cp_replica(db.clone(), extra_env).await;
    let mut replica_b = spawn_cp_replica(db.clone(), extra_env).await;

    let root_a = root_ca_der_base64("ha-root-a");
    let (status, created) = trust_post(
        client,
        &replica_a,
        PRIMARY_NAMESPACE,
        create_body(TRUST_DOMAIN, &[root_a.as_str()]),
    )
    .await;
    assert_eq!(status, 201, "[{label}] replica A create: {created}");
    let created_revision = created["revision"].as_u64().expect("numeric revision");

    let status_a = wait_for_published_revision(
        client,
        &replica_a,
        PRIMARY_NAMESPACE,
        created_revision,
        1,
        Duration::from_secs(45),
        &format!("[{label}] replica A publication"),
    )
    .await;
    let generation = status_a["generation"]
        .as_str()
        .expect("status carries a generation digest")
        .to_string();
    let published_before_race_a = published_generations(&status_a);

    // The convergence assertion. B never restarted and never saw the admin
    // request; its counter can only advance because its own poll cycle detected
    // the change, validated the candidate, and swapped it live.
    let status_b = wait_for_published_revision(
        client,
        &replica_b,
        PRIMARY_NAMESPACE,
        created_revision,
        1,
        Duration::from_secs(60),
        &format!("[{label}] replica B convergence"),
    )
    .await;
    assert_eq!(
        status_b["generation"].as_str(),
        Some(generation.as_str()),
        "[{label}] both replicas must reconstruct the same generation: {status_b}"
    );
    let published_before_race_b = published_generations(&status_b);

    // Concurrent writers from the same read: exactly one compare-and-set commits
    // and every loser is a typed conflict, not a silent overwrite.
    let authorities: Vec<String> = (0..4)
        .map(|index| root_ca_der_base64(&format!("ha-concurrent-{index}")))
        .collect();
    let mut pending = Vec::new();
    for (index, authority) in authorities.iter().enumerate() {
        // Alternate the replica each write is admitted through, so the race is
        // genuinely cross-process rather than serialized inside one admin server.
        let replica = if index % 2 == 0 {
            &replica_a
        } else {
            &replica_b
        };
        pending.push(trust_put(
            client,
            replica,
            PRIMARY_NAMESPACE,
            PRIMARY_NAMESPACE,
            rotation_body(TRUST_DOMAIN, created_revision, &[authority.as_str()]),
        ));
    }
    let results = futures::future::join_all(pending).await;

    let winners: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, (status, _))| *status == 200)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "[{label}] exactly one concurrent compare-and-set may commit; got {results:?}"
    );
    let winner = winners[0];
    for (index, (status, body)) in results.iter().enumerate() {
        if index == winner {
            continue;
        }
        assert_eq!(
            *status, 409,
            "[{label}] a lost race must be a conflict, not an overwrite: {body}"
        );
        assert_eq!(
            body["expected_revision"].as_u64(),
            Some(created_revision),
            "[{label}] the conflict must report the stale expectation: {body}"
        );
    }
    let committed_revision = results[winner].1["revision"]
        .as_u64()
        .expect("the winner reports a numeric revision");
    assert!(
        committed_revision > created_revision,
        "[{label}] the winning write must advance the revision"
    );

    // Both replicas must publish the winner without a restart. Reading the
    // shared database alone would not prove that either process validated and
    // swapped the winning generation into its live ArcSwap snapshot.
    let converged_a = wait_for_published_revision(
        client,
        &replica_a,
        PRIMARY_NAMESPACE,
        committed_revision,
        published_before_race_a + 1,
        Duration::from_secs(60),
        &format!("[{label}] replica A winning-revision publication"),
    )
    .await;
    let converged_b = wait_for_published_revision(
        client,
        &replica_b,
        PRIMARY_NAMESPACE,
        committed_revision,
        published_before_race_b + 1,
        Duration::from_secs(60),
        &format!("[{label}] replica B winning-revision publication"),
    )
    .await;
    let converged_generation = converged_a["generation"]
        .as_str()
        .expect("status carries a generation digest")
        .to_string();
    assert_eq!(
        converged_b["generation"].as_str(),
        Some(converged_generation.as_str()),
        "[{label}] both replicas must publish the winning generation: {converged_b}"
    );

    // Their admin reads must agree with the just-published winner too.
    let (_, from_a) = trust_get(client, &replica_a, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    let (_, from_b) = trust_get(client, &replica_b, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(
        stored_authorities(&from_a),
        vec![authorities[winner].clone()],
        "[{label}] the committed material must be the winner's"
    );
    assert_eq!(
        stored_authorities(&from_b),
        stored_authorities(&from_a),
        "[{label}] both replicas must read the same committed material"
    );

    // Restart reconstruction: a brand-new process, database only.
    replica_b.shutdown();
    drop(replica_b);
    let replica_b2 = spawn_cp_replica(db, extra_env).await;
    let restarted = wait_for_published_revision(
        client,
        &replica_b2,
        PRIMARY_NAMESPACE,
        committed_revision,
        1,
        Duration::from_secs(45),
        &format!("[{label}] replica B restart reconstruction"),
    )
    .await;
    assert_eq!(
        restarted["generation"].as_str(),
        Some(converged_generation.as_str()),
        "[{label}] a restarted replica must reconstruct the committed generation: {restarted}"
    );
    let (_, after_restart) =
        trust_get(client, &replica_b2, PRIMARY_NAMESPACE, PRIMARY_NAMESPACE).await;
    assert_eq!(
        stored_authorities(&after_restart),
        stored_authorities(&from_a),
        "[{label}] a restarted replica must reconstruct the committed material"
    );
}

#[tokio::test]
#[ignore]
async fn test_two_control_plane_replicas_converge_postgres() {
    ensure_shared_sql_containers_resumed();
    let Some(postgres_url) = postgres_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&postgres_url);
    if !continue_if_backend_available(
        "postgres",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    let (postgres_url, _isolated_db) = provision_isolated_sql_database(&postgres_url);
    let client = Client::new();
    run_two_replica_convergence(&client, DbType::Postgres(postgres_url), &[], "postgres-ha").await;
}

#[tokio::test]
#[ignore]
async fn test_two_control_plane_replicas_converge_mongodb() {
    // Prefer the replica set when CI declared one — that is the topology whose
    // trust write is a real multi-document transaction — and fall back to the
    // always-provisioned standalone otherwise.
    let (mongo_url, replica_set) = match replica_set_mongo_url().await {
        Some((url, replica_set)) => (url, Some(replica_set)),
        None => match standalone_mongo_url().await {
            Some(url) => (url, None),
            None => return,
        },
    };
    let client = Client::new();
    let database = unique_mongo_database("ha");
    let _cleanup = MongoDatabaseCleanup::new(mongo_url.clone(), database.clone());
    let mut env = vec![("FERRUM_MONGO_DATABASE".to_string(), database)];
    if let Some(replica_set) = replica_set {
        env.push(("FERRUM_MONGO_REPLICA_SET".to_string(), replica_set));
    }
    run_two_replica_convergence(&client, DbType::Mongo(mongo_url), &env, "mongodb-ha").await;
}

// ── MongoDB fixtures ────────────────────────────────────────────────────────

fn unique_mongo_database(prefix: &str) -> String {
    format!("ferrum_trust_{prefix}_{}", Uuid::new_v4().simple())
}

async fn mongo_client(url: &str) -> mongodb::Client {
    let mut options = ClientOptions::parse(url)
        .await
        .expect("parse MongoDB connection URL");
    options.connect_timeout = Some(Duration::from_secs(5));
    options.server_selection_timeout = Some(Duration::from_secs(10));
    mongodb::Client::with_options(options).expect("build MongoDB client")
}

/// The always-provisioned standalone. Fails closed under
/// `FERRUM_DB_BACKENDS_REQUIRED=1`, skips locally.
async fn standalone_mongo_url() -> Option<String> {
    let url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "mongodb",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not available at {host_port}"),
    ) {
        return None;
    }
    Some(url)
}

/// The opt-in single-node replica set. Absent declaration is a plain skip;
/// a declared but unreachable member is a provisioning failure.
async fn replica_set_mongo_url() -> Option<(String, String)> {
    let Ok(replica_set) = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET") else {
        println!("SKIP: FERRUM_TEST_MONGO_REPLICA_SET not set — no replica set available");
        return None;
    };
    let url = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET_URL")
        .or_else(|_| std::env::var("FERRUM_TEST_MONGO_URL"))
        .unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "mongodb-replica-set",
        tcp_endpoint_reachable(&host_port).await,
        &format!("declared but not available at {host_port}"),
    ) {
        return None;
    }
    Some((url, replica_set))
}

/// Drops the per-cell MongoDB database so one cell cannot observe another's
/// records. Runs on its own runtime because `Drop` is synchronous.
struct MongoDatabaseCleanup {
    url: String,
    database: String,
}

impl MongoDatabaseCleanup {
    fn new(url: String, database: String) -> Self {
        Self { url, database }
    }
}

impl Drop for MongoDatabaseCleanup {
    fn drop(&mut self) {
        let url = self.url.clone();
        let database = self.database.clone();
        let handle = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                eprintln!("failed to build runtime for MongoDB cleanup of {database}");
                return;
            };
            runtime.block_on(async move {
                match mongodb::Client::with_uri_str(&url).await {
                    Ok(client) => {
                        if let Err(error) = client.database(&database).drop().await {
                            eprintln!("failed to drop MongoDB test database {database}: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("failed to connect for MongoDB test database cleanup: {error}");
                    }
                }
            });
        });
        let _ = handle.join();
    }
}
