//! Gateway SVID source refresh: cadence classification, byte-fingerprint
//! change detection, unchanged suppression, transient-failure last-good
//! retention, and refusal of invalid/mismatched material (issue #3625).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ferrum_edge::identity::spiffe::{SpiffeId, spiffe_id_to_san};
use ferrum_edge::identity::svid_source_watch::{
    GATEWAY_SVID_FILE_POLL_INTERVAL, GatewaySvidCadence, GatewaySvidPollOutcome as Outcome,
    GatewaySvidSourceSet, GatewaySvidSourceTracker, GatewaySvidWatchConfig, gateway_svid_cadence,
    run_gateway_svid_source_rotation_loop,
};
use ferrum_edge::tls::source::{CertSource, MaterialKind};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;

const PROVIDER_DEFAULT: Duration = Duration::from_secs(300);
const SPIFFE_ID: &str = "spiffe://corp.example/ns/gateway/sa/edge";
const INLINE_CERT: &str = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n";
const INLINE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";

struct TestCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn test_ca() -> TestCa {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = params.self_signed(&key).expect("ca cert");
    TestCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

fn issue_svid(ca: &TestCa) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new(SPIFFE_ID).expect("test SPIFFE ID");
    let san = spiffe_id_to_san(&id).expect("spiffe SAN");
    params.subject_alt_names.push(san);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let cert = params.signed_by(&key, &ca.issuer).expect("leaf cert");
    (cert.pem(), key.serialize_pem())
}

struct SvidFiles {
    _dir: TempDir,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    trust_bundle_path: std::path::PathBuf,
}

impl SvidFiles {
    fn source_set(&self) -> GatewaySvidSourceSet {
        GatewaySvidSourceSet::new(
            self.cert_path.to_string_lossy().into_owned(),
            self.key_path.to_string_lossy().into_owned(),
            self.trust_bundle_path.to_string_lossy().into_owned(),
            None,
        )
    }
}

fn valid_svid_files() -> (TestCa, SvidFiles) {
    let ca = test_ca();
    let (cert_pem, key_pem) = issue_svid(&ca);
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("svid-chain.pem");
    let key_path = dir.path().join("svid-key.pem");
    let trust_bundle_path = dir.path().join("trust-bundle.pem");
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    std::fs::write(&trust_bundle_path, &ca.cert_pem).expect("write trust bundle");
    let files = SvidFiles {
        _dir: dir,
        cert_path,
        key_path,
        trust_bundle_path,
    };
    (ca, files)
}

fn cert_source(value: &str) -> CertSource {
    CertSource::parse(value, MaterialKind::Cert)
}

fn cadence_of(value: &str) -> GatewaySvidCadence {
    let source = cert_source(value);
    gateway_svid_cadence(&source, GATEWAY_SVID_FILE_POLL_INTERVAL, PROVIDER_DEFAULT)
}

fn file_cadence() -> GatewaySvidCadence {
    GatewaySvidCadence::File(GATEWAY_SVID_FILE_POLL_INTERVAL)
}

fn provider_cadence(secs: u64) -> GatewaySvidCadence {
    GatewaySvidCadence::Provider(Duration::from_secs(secs))
}

fn tracker_for(sources: &GatewaySvidSourceSet) -> GatewaySvidSourceTracker {
    GatewaySvidSourceTracker::new(sources, GATEWAY_SVID_FILE_POLL_INTERVAL, PROVIDER_DEFAULT)
}

fn poll_at(tracker: &mut GatewaySvidSourceTracker, start: Instant, secs: u64) -> Outcome {
    tracker.poll(start + Duration::from_secs(secs)).outcome
}

fn inline_source_set() -> GatewaySvidSourceSet {
    GatewaySvidSourceSet::new(
        INLINE_CERT.to_string(),
        INLINE_KEY.to_string(),
        INLINE_CERT.to_string(),
        None,
    )
}

// --- cadence classification -------------------------------------------------

#[test]
fn file_sources_use_the_gateway_file_cadence() {
    assert_eq!(cadence_of("/svid/chain.pem"), file_cadence());
    assert_eq!(cadence_of("file:///svid/chain.pem"), file_cadence());
}

#[test]
fn provider_sources_use_the_secret_refresh_cadence() {
    let provider = provider_cadence(300);
    assert_eq!(cadence_of("vault://secret/data/gw#cert"), provider);
    assert_eq!(cadence_of("aws://ferrum/gateway-svid"), provider);
    assert_eq!(cadence_of("azure://https://kv/secrets/gw"), provider);
    assert_eq!(cadence_of("gcp://p/secrets/gw"), provider);
    assert_eq!(cadence_of("k8s://edge/gateway-svid#tls.crt"), provider);
}

#[test]
fn provider_poll_option_overrides_the_secret_refresh_cadence() {
    let fast = cadence_of("vault://secret/data/gw#cert?poll=45s");
    assert_eq!(fast, provider_cadence(45));

    let minutes = cadence_of("vault://secret/data/gw#cert?poll=2m");
    assert_eq!(minutes, provider_cadence(120));
}

#[test]
fn inline_pem_sources_stay_static() {
    let cadence = cadence_of(INLINE_CERT);
    assert_eq!(cadence, GatewaySvidCadence::Static);
    assert!(!cadence.is_refreshable());
    assert_eq!(cadence.interval(), None);
}

#[test]
fn an_all_inline_source_set_is_not_watchable() {
    let sources = inline_source_set();
    let tracker = tracker_for(&sources);

    assert!(!tracker.is_watchable());
}

#[test]
fn a_mixed_source_set_keeps_per_source_cadences() {
    let (_ca, files) = valid_svid_files();
    let sources = GatewaySvidSourceSet::new(
        files.cert_path.to_string_lossy().into_owned(),
        files.key_path.to_string_lossy().into_owned(),
        "vault://secret/data/gw#bundle".to_string(),
        None,
    );
    let tracker = tracker_for(&sources);

    let cadences = tracker.cadences();
    assert_eq!(cadences.len(), 3);
    assert_eq!(cadences[0].1, file_cadence());
    assert_eq!(cadences[1].1, file_cadence());
    assert_eq!(
        cadences[2].1,
        provider_cadence(300),
        "a provider trust bundle must not be dragged onto the 1s file cadence"
    );
    assert!(tracker.is_watchable());
}

// --- change detection -------------------------------------------------------

#[test]
fn first_complete_read_is_a_baseline_and_stable_bytes_stay_unchanged() {
    let (_ca, files) = valid_svid_files();
    let sources = files.source_set();
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();

    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);

    let report = tracker.poll(start + Duration::from_secs(2));
    assert_eq!(report.outcome, Outcome::Unchanged);
    assert_eq!(report.refreshed.len(), 3, "all three files were due");
}

#[test]
fn identical_byte_rewrites_do_not_report_a_change() {
    let (_ca, files) = valid_svid_files();
    let sources = files.source_set();
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();
    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);

    // Same bytes, new mtime: fingerprints are over content, not stat data.
    let bundle = std::fs::read(&files.trust_bundle_path).expect("read bundle");
    std::fs::write(&files.trust_bundle_path, bundle).expect("rewrite bundle");

    assert_eq!(poll_at(&mut tracker, start, 2), Outcome::Unchanged);
}

#[test]
fn changed_bytes_on_any_single_source_report_a_change() {
    let (ca, files) = valid_svid_files();
    let sources = files.source_set();
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();
    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);

    let (rotated_cert, rotated_key) = issue_svid(&ca);
    std::fs::write(&files.cert_path, rotated_cert).expect("rotate cert");
    std::fs::write(&files.key_path, rotated_key).expect("rotate key");
    assert_eq!(poll_at(&mut tracker, start, 2), Outcome::Changed);

    // Committing the observed set makes the next identical poll quiet again.
    tracker.commit();
    assert_eq!(poll_at(&mut tracker, start, 4), Outcome::Unchanged);
}

#[test]
fn uncommitted_change_remains_pending_for_a_coherent_reload_retry() {
    let (ca, files) = valid_svid_files();
    let sources = files.source_set();
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();
    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);

    let (rotated_cert, rotated_key) = issue_svid(&ca);
    std::fs::write(&files.cert_path, rotated_cert).expect("rotate cert");
    std::fs::write(&files.key_path, rotated_key).expect("rotate key");
    assert_eq!(poll_at(&mut tracker, start, 2), Outcome::Changed);

    // A coherent second read can fail after fingerprinting (for example, a
    // provider outage). Until a validated bundle is actually published and
    // commit() is called, stable candidate bytes must stay pending so recovery
    // is retried without requiring another source generation.
    assert_eq!(poll_at(&mut tracker, start, 4), Outcome::Changed);
    tracker.commit();
    assert_eq!(poll_at(&mut tracker, start, 6), Outcome::Unchanged);
}

#[test]
fn a_source_read_failure_keeps_the_last_good_fingerprints() {
    let (_ca, files) = valid_svid_files();
    let sources = files.source_set();
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();
    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);
    let baseline = tracker.current_fingerprints().expect("baseline");

    let cert_pem = std::fs::read(&files.cert_path).expect("read cert");
    std::fs::remove_file(&files.cert_path).expect("remove cert");

    let report = tracker.poll(start + Duration::from_secs(2));
    assert_eq!(report.outcome, Outcome::SourceUnavailable);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].label, "gateway_svid_cert");
    assert_eq!(report.failures[0].kind, MaterialKind::Cert);
    let retained = tracker.current_fingerprints().expect("retained");
    assert_eq!(
        retained, baseline,
        "a failed fetch must not drop the last-good fingerprint"
    );

    // Recovery with the same bytes is not a rotation.
    std::fs::write(&files.cert_path, cert_pem).expect("restore cert");
    assert_eq!(poll_at(&mut tracker, start, 4), Outcome::Unchanged);
}

#[test]
fn faster_source_success_does_not_mask_a_slower_source_outage() {
    let (_ca, files) = valid_svid_files();
    let key_source = format!("file://{}?poll=10s", files.key_path.display());
    let sources = GatewaySvidSourceSet::new(
        files.cert_path.to_string_lossy().into_owned(),
        key_source,
        files.trust_bundle_path.to_string_lossy().into_owned(),
        None,
    );
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();
    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);

    let key_pem = std::fs::read(&files.key_path).expect("read key");
    std::fs::remove_file(&files.key_path).expect("remove key");
    assert_eq!(poll_at(&mut tracker, start, 10), Outcome::SourceUnavailable);

    // The key is healthy again, but its 10s cadence has not elapsed. Faster
    // cert/trust reads must not report recovery while the failed source still
    // carries only its stale last-good fingerprint.
    std::fs::write(&files.key_path, key_pem).expect("restore key");
    assert_eq!(poll_at(&mut tracker, start, 11), Outcome::Idle);
    assert_eq!(poll_at(&mut tracker, start, 20), Outcome::Unchanged);
}

#[test]
fn next_delay_follows_the_soonest_configured_cadence() {
    let (_ca, files) = valid_svid_files();
    let sources = files.source_set();
    let mut tracker = tracker_for(&sources);
    let start = Instant::now();
    assert_eq!(poll_at(&mut tracker, start, 0), Outcome::Baseline);

    assert_eq!(tracker.next_delay(start), GATEWAY_SVID_FILE_POLL_INTERVAL);
    let overdue = start + Duration::from_secs(5);
    assert_eq!(tracker.next_delay(overdue), Duration::ZERO);
}

// --- end-to-end loop --------------------------------------------------------

#[tokio::test]
async fn watch_loop_refuses_mismatched_material_and_publishes_rotations() {
    let (ca, files) = valid_svid_files();
    let published = Arc::new(AtomicU64::new(0));
    let counter = published.clone();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let config = GatewaySvidWatchConfig {
        sources: files.source_set(),
        file_interval: Duration::from_secs(1),
        provider_interval: PROVIDER_DEFAULT,
        publish: Box::new(move |bundle| {
            assert_eq!(bundle.spiffe_id.to_string(), SPIFFE_ID);
            counter.fetch_add(1, Ordering::SeqCst) + 1
        }),
    };
    let task = tokio::spawn(run_gateway_svid_source_rotation_loop(
        config,
        Some(shutdown_rx),
    ));

    // Let the baseline settle before mutating anything.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(published.load(Ordering::SeqCst), 0);

    // A key that does not pair with the published cert is a torn generation:
    // the loader must refuse it and the SVID slot must not be republished.
    let (_orphan_cert, orphan_key) = issue_svid(&ca);
    std::fs::write(&files.key_path, orphan_key).expect("write bad key");
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(
        published.load(Ordering::SeqCst),
        0,
        "mismatched cert/key material must not be published"
    );

    // A complete, valid replacement publishes exactly one rotation.
    let (rotated_cert, rotated_key) = issue_svid(&ca);
    std::fs::write(&files.key_path, rotated_key).expect("write key");
    std::fs::write(&files.cert_path, rotated_cert).expect("write cert");

    let deadline = Instant::now() + Duration::from_secs(15);
    while published.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        published.load(Ordering::SeqCst),
        1,
        "a valid complete replacement must publish exactly one rotation"
    );

    // Stable material does not churn.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(published.load(Ordering::SeqCst), 1);

    shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("watcher exits on shutdown")
        .expect("watcher task did not panic");
}

#[tokio::test]
async fn watch_loop_exits_when_every_source_is_static() {
    let published = Arc::new(AtomicU64::new(0));
    let counter = published.clone();
    let config = GatewaySvidWatchConfig {
        sources: inline_source_set(),
        file_interval: Duration::from_secs(1),
        provider_interval: PROVIDER_DEFAULT,
        publish: Box::new(move |_bundle| counter.fetch_add(1, Ordering::SeqCst) + 1),
    };

    let task = tokio::spawn(run_gateway_svid_source_rotation_loop(config, None));

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("static source set exits immediately")
        .expect("watcher task did not panic");
    assert_eq!(published.load(Ordering::SeqCst), 0);
}
