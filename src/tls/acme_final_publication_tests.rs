//! Final ACME renewal publication boundary (issue #2409 / PR #3506).
//!
//! The already-CA-valid order is persisted as `Valid` first and certificate
//! material second under one lease-fenced critical section. Partial persistence
//! failures must never leave published material beside a stale `Processing`
//! order, must not request reload, and must not be accounted as a successful
//! renewal.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::tls::acme::{
    AcmeCertificateRecord, AcmeCertificateStore, AcmeError, AcmeHttp01ChallengeRecord,
    AcmeHttp01OrderInput, AcmeIssuedCertificateInput, AcmeOrderRecord, AcmeOrderStatus,
    AcmeOrderStore, FinalRenewalPublication, apply_final_renewal_publication,
    commit_final_renewal_publication, inject_final_publication_certificate_write_fault_for_tests,
};
use crate::tls::lease::{RenewalLeaseKeeper, TlsLeaseStore, acme_renewal_lease_name};
use crate::tls::private_file::{PrivateFileFault, inject_private_file_fault_for_tests};
use crate::tls::source::subscription::{install_force_reload_probe, remove_force_reload_probe};
use tempfile::TempDir;

const DIRECTORY_URL: &str = "https://acme.example/directory";

fn generated_cert_and_key() -> (String, String) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params =
        rcgen::CertificateParams::new(vec!["example.com".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    (cert.pem(), key_pair.serialize_pem())
}

fn sample_certificate(id: &str, cert_pem: &str, key_pem: &str) -> AcmeCertificateRecord {
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: id.to_string(),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        order_url: Some("https://acme.example/order/1".to_string()),
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        chain_pem: None,
    })
    .expect("acme certificate record")
}

fn processing_order(id: &str, certificate_id: &str) -> AcmeOrderRecord {
    AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
        id: id.to_string(),
        certificate_id: Some(certificate_id.to_string()),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
        order_url: Some("https://acme.example/order/1".to_string()),
        status: AcmeOrderStatus::Processing,
        http01_challenges: vec![AcmeHttp01ChallengeRecord {
            identifier: "example.com".to_string(),
            token: "tok_processing".to_string(),
            key_authorization: "tok_processing.thumbprint".to_string(),
        }],
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        error: None,
    })
    .expect("acme order record")
}

fn takeover_document(name: &str) -> String {
    format!(
        concat!(
            r#"{{"version":99,"leases":{{"{name}":{{"#,
            r#""holder":"replica-b","#,
            r#""acquired_at":"2026-01-01T00:00:00Z","#,
            r#""expires_at":"2999-01-01T00:00:00Z","#,
            r#""fence":9999}}}}}}"#
        ),
        name = name
    )
}

/// Happy path: one fenced commit marks the order Valid then publishes
/// certificate material, and reload is requested.
#[tokio::test]
async fn final_publication_commits_order_then_certificate_under_one_lease_fence() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = Arc::new(AcmeCertificateStore::open(dir.path()).expect("open cert store"));
    let orders = Arc::new(AcmeOrderStore::open(dir.path()).expect("open order store"));
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let leases = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "replica-a".to_string())
            .expect("open lease store"),
    );
    let name = acme_renewal_lease_name("edge-cert");
    let held = leases
        .try_acquire(&name, Duration::from_secs(60))
        .expect("claim")
        .expect("won");
    let keeper = RenewalLeaseKeeper::start(held, Duration::from_secs(60));

    let surface = "final_publication_order_then_cert_complete_reload";
    let mut probe = install_force_reload_probe(surface);

    let outcome = keeper
        .commit_fenced({
            let certificates = Arc::clone(&certificates);
            let orders = Arc::clone(&orders);
            move || commit_final_renewal_publication(&certificates, &orders, issued, order)
        })
        .await
        .expect("lease still held");
    assert!(matches!(outcome, FinalRenewalPublication::Complete));

    let reloaded = apply_final_renewal_publication(outcome).expect("complete publication");
    assert!(
        reloaded.contains(&surface),
        "successful publication must request material reload"
    );
    assert!(
        probe.try_recv().is_ok(),
        "the registered surface must observe the reload request"
    );

    let stored = certificates
        .get_certificate("edge-cert")
        .expect("cert published");
    assert_eq!(stored.cert_pem, cert_pem);
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Valid
    );
    remove_force_reload_probe(surface);
    let _ = keeper.finish().await;
}

/// If ownership is already gone, neither final write runs.
#[tokio::test]
async fn final_publication_runs_neither_write_when_lease_is_lost() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = Arc::new(AcmeCertificateStore::open(dir.path()).expect("open cert store"));
    let orders = Arc::new(AcmeOrderStore::open(dir.path()).expect("open order store"));
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let leases = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "replica-a".to_string())
            .expect("open lease store"),
    );
    let name = acme_renewal_lease_name("edge-cert");
    let held = leases
        .try_acquire(&name, Duration::from_secs(60))
        .expect("claim")
        .expect("won");
    let keeper = RenewalLeaseKeeper::start(held, Duration::from_secs(60));

    std::fs::write(
        dir.path().join("tls-leases.json"),
        takeover_document(&name),
    )
    .expect("simulate takeover");

    let entered = Arc::new(AtomicBool::new(false));
    let saw_entry = Arc::clone(&entered);
    let outcome = keeper
        .commit_fenced({
            let certificates = Arc::clone(&certificates);
            let orders = Arc::clone(&orders);
            move || {
                saw_entry.store(true, Ordering::SeqCst);
                commit_final_renewal_publication(&certificates, &orders, issued, order)
            }
        })
        .await;
    assert!(
        outcome.is_err(),
        "a superseded owner must not enter the final publication closure"
    );
    assert!(
        !entered.load(Ordering::SeqCst),
        "fail-closed fencing must skip both final writes"
    );
    assert!(matches!(
        certificates.get_certificate("edge-cert"),
        Err(AcmeError::NotFound(_))
    ));
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing
    );
    let _ = keeper.finish().await;
}

/// Order-store persistence failure under the lease fence: no certificate is
/// published, Processing remains, reload is not requested, and accounting is an
/// explicit failure.
#[test]
fn order_store_failure_publishes_no_certificate_and_skips_reload() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let surface = "final_publication_order_failure_no_reload";
    let mut probe = install_force_reload_probe(surface);
    let _fault = inject_private_file_fault_for_tests(PrivateFileFault::Rename);
    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(
        outcome,
        FinalRenewalPublication::OrderNotCommitted(_)
    ));

    let error = apply_final_renewal_publication(outcome).expect_err("order write failed");
    let message = error.to_string();
    assert!(
        message.contains("marking the ACME order valid failed before certificate publication"),
        "error must state the order write failed before publication: {message}"
    );
    assert!(
        !message.contains("BEGIN CERTIFICATE")
            && !message.contains("BEGIN PRIVATE KEY")
            && !message.contains(&key_pem)
            && !message.contains(&cert_pem),
        "error must not disclose certificate or key material"
    );
    assert!(
        probe.try_recv().is_err(),
        "order failure must not request reload"
    );
    assert!(matches!(
        certificates.get_certificate("edge-cert"),
        Err(AcmeError::NotFound(_))
    ));
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing,
        "failed order write must leave the prior Processing status"
    );
    remove_force_reload_probe(surface);
}

/// Certificate-store failure after a successful order Valid write: order is
/// Valid, prior/no new cert remains, reload is not requested, and the outcome
/// is an explicit failure (never a successful renewal).
#[test]
fn certificate_store_failure_after_order_valid_skips_reload() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (old_cert_pem, old_key_pem) = generated_cert_and_key();
    let prior = sample_certificate("edge-cert", &old_cert_pem, &old_key_pem);
    certificates
        .upsert_certificate(prior, false)
        .expect("seed prior certificate");
    let (new_cert_pem, new_key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &new_cert_pem, &new_key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let surface = "final_publication_cert_failure_after_order_no_reload";
    let mut probe = install_force_reload_probe(surface);
    let _fault =
        inject_final_publication_certificate_write_fault_for_tests(PrivateFileFault::Rename);
    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(
        outcome,
        FinalRenewalPublication::OrderCommittedMaterialNotPublished(_)
    ));

    let error = apply_final_renewal_publication(outcome).expect_err("cert write failed");
    let message = error.to_string();
    assert!(
        message.contains(
            "ACME order was marked valid but renewed certificate material failed to publish"
        ),
        "error must state order committed without material: {message}"
    );
    assert!(
        !message.contains("BEGIN CERTIFICATE")
            && !message.contains("BEGIN PRIVATE KEY")
            && !message.contains(&new_key_pem)
            && !message.contains(&new_cert_pem)
            && !message.contains(&old_key_pem),
        "error must not disclose certificate or key material"
    );
    assert!(
        probe.try_recv().is_err(),
        "certificate failure after order Valid must not request reload"
    );

    let stored = certificates
        .get_certificate("edge-cert")
        .expect("prior certificate remains");
    assert_eq!(
        stored.cert_pem, old_cert_pem,
        "failed certificate write must leave the prior material"
    );
    assert_ne!(stored.cert_pem, new_cert_pem);
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Valid,
        "order Valid must stick so Processing cannot block a later retry"
    );
    // apply_final_renewal_publication returned Err above: this path is never a
    // successful renewal count.
    remove_force_reload_probe(surface);
}

/// The production helper itself commits order Valid then certificate with no
/// window for a separate lease release between them.
#[test]
fn commit_final_renewal_publication_marks_order_valid_before_certificate() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(outcome, FinalRenewalPublication::Complete));
    assert_eq!(
        certificates
            .get_certificate("edge-cert")
            .expect("published")
            .cert_pem,
        cert_pem
    );
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Valid
    );
}
