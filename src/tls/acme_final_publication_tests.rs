//! Final ACME renewal publication boundary (issue #2409 / PR #3506).
//!
//! Certificate material and the order `Valid` transition must share one
//! lease-fenced critical section. A persistence failure after the certificate
//! write must still request material reload and must not be accounted as a
//! skip that claims nothing was published.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::tls::acme::{
    AcmeCertificateRecord, AcmeCertificateStore, AcmeError, AcmeHttp01ChallengeRecord,
    AcmeHttp01OrderInput, AcmeIssuedCertificateInput, AcmeOrderRecord, AcmeOrderStatus,
    AcmeOrderStore, FinalRenewalPublication, apply_final_renewal_publication,
    commit_final_renewal_publication,
};
use crate::tls::lease::{FencedCommit, RenewalLeaseKeeper, TlsLeaseStore, acme_renewal_lease_name};
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

/// Happy path: one fenced commit publishes certificate material and marks the
/// order Valid, then reload is requested.
#[tokio::test]
async fn final_publication_commits_certificate_then_order_under_one_lease_fence() {
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

    let surface = "final_publication_complete_reload";
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
}

/// Certificate commit + order persistence failure under the lease fence:
/// material is live, reload is requested, and accounting is an explicit failure.
#[test]
fn fenced_certificate_success_with_order_failure_requests_reload() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let leases = TlsLeaseStore::open_with_holder(dir.path(), "replica-a".to_string())
        .expect("open lease store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let name = acme_renewal_lease_name("edge-cert");
    let held = leases
        .try_acquire(&name, Duration::from_secs(60))
        .expect("claim")
        .expect("won");
    let fence = held.fence();
    std::mem::forget(held);

    let fenced = leases
        .commit_fenced(&name, fence, || {
            match certificates.upsert_certificate(issued, true) {
                Ok(_) => {
                    let _fault = inject_private_file_fault_for_tests(PrivateFileFault::Rename);
                    let mut updated = order;
                    updated.status = AcmeOrderStatus::Valid;
                    updated.error = None;
                    match orders.upsert_order(updated, true) {
                        Ok(_) => FinalRenewalPublication::Complete,
                        Err(error) => {
                            FinalRenewalPublication::MaterialPublishedOrderIncomplete(error)
                        }
                    }
                }
                Err(error) => FinalRenewalPublication::MaterialNotPublished(error),
            }
        })
        .expect("fenced commit answers");

    let FencedCommit::Committed(outcome) = fenced else {
        panic!("live claim must run the final publication closure");
    };
    assert!(matches!(
        outcome,
        FinalRenewalPublication::MaterialPublishedOrderIncomplete(_)
    ));

    let surface = "final_publication_partial_reload";
    let mut probe = install_force_reload_probe(surface);
    let error = apply_final_renewal_publication(outcome).expect_err("incomplete order");
    let message = error.to_string();
    assert!(
        message.contains("renewed certificate material was published"),
        "error must state material was published: {message}"
    );
    assert!(
        message.contains("marking the ACME order valid failed"),
        "error must state the order update is incomplete: {message}"
    );
    assert!(
        !message.contains("BEGIN CERTIFICATE") && !message.contains(&key_pem),
        "error must not disclose certificate or key material"
    );
    assert!(
        probe.try_recv().is_ok(),
        "published material must still request reload"
    );

    let stored = certificates
        .get_certificate("edge-cert")
        .expect("published cert remains");
    assert_eq!(stored.cert_pem, cert_pem);
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing,
        "failed order write must leave the prior Processing status"
    );
    remove_force_reload_probe(surface);
}

/// The production helper itself commits certificate then order with no window
/// for a separate lease release between them.
#[test]
fn commit_final_renewal_publication_marks_order_valid_after_certificate() {
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

/// A certificate-store failure publishes nothing and does not request reload.
#[test]
fn certificate_failure_publishes_nothing_and_skips_reload() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem);
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let _fault = inject_private_file_fault_for_tests(PrivateFileFault::Rename);
    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(
        outcome,
        FinalRenewalPublication::MaterialNotPublished(_)
    ));

    let surface = "final_publication_no_reload_on_cert_failure";
    let mut probe = install_force_reload_probe(surface);
    let error = apply_final_renewal_publication(outcome).expect_err("cert failed");
    assert!(
        !error.to_string().contains("material was published"),
        "certificate failure must not claim material was published"
    );
    assert!(
        probe.try_recv().is_err(),
        "no material means no reload request"
    );
    assert!(matches!(
        certificates.get_certificate("edge-cert"),
        Err(AcmeError::NotFound(_))
    ));
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing
    );
    remove_force_reload_probe(surface);
}
