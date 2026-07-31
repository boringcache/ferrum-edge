//! Issue #2409: two-instance coherence for the file-backed ACME stores.
//!
//! Each store opened over the same directory stands in for one gateway replica
//! sharing a writable volume. The order store matters most: the duplicate
//! renewal guard asks it whether an active order already exists, and a
//! process-local answer let every replica conclude "no" and order the same
//! certificate independently.

use ferrum_edge::tls::acme::{
    AcmeAccountStore, AcmeCertificateRecord, AcmeCertificateStore, AcmeError,
    AcmeHttp01ChallengeRecord, AcmeHttp01OrderInput, AcmeIssuedCertificateInput, AcmeOrderRecord,
    AcmeOrderStatus, AcmeOrderStore,
};

const DIRECTORY_URL: &str = "https://acme.example/directory";
const ACCOUNT_ID: &str = "https://acme.example/acct/1";

fn certificate(id: &str, cert_pem: &str) -> AcmeCertificateRecord {
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: id.to_string(),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some(ACCOUNT_ID.to_string()),
        order_url: Some("https://acme.example/order/1".to_string()),
        cert_pem: cert_pem.to_string(),
        key_pem: "key-pem".to_string(),
        chain_pem: None,
    })
    .expect("acme certificate record")
}

/// A pending HTTP-01 renewal order — the shape the duplicate-renewal guard
/// looks for.
fn pending_order(id: &str, certificate_id: &str, token: &str) -> AcmeOrderRecord {
    AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
        id: id.to_string(),
        certificate_id: Some(certificate_id.to_string()),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some(ACCOUNT_ID.to_string()),
        account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
        order_url: Some("https://acme.example/order/1".to_string()),
        status: AcmeOrderStatus::PendingChallenges,
        http01_challenges: vec![AcmeHttp01ChallengeRecord {
            identifier: "example.com".to_string(),
            token: token.to_string(),
            key_authorization: format!("{token}.thumbprint"),
        }],
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        error: None,
    })
    .expect("acme order record")
}

fn create_order(store: &AcmeOrderStore, id: &str, cert_id: &str, token: &str) {
    let record = pending_order(id, cert_id, token);
    store.upsert_order(record, false).expect("create order");
}

fn order_ids(store: &AcmeOrderStore) -> Vec<String> {
    let summaries = store.list_orders().expect("list orders");
    let mut ids: Vec<String> = summaries.into_iter().map(|entry| entry.id).collect();
    ids.sort();
    ids
}

fn certificate_ids(store: &AcmeCertificateStore) -> Vec<String> {
    let summaries = store.list_certificates().expect("list certs");
    let mut ids: Vec<String> = summaries.into_iter().map(|entry| entry.id).collect();
    ids.sort();
    ids
}

#[test]
fn an_order_created_by_one_instance_blocks_the_others_duplicate_renewal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeOrderStore::open(dir.path()).expect("open A");
    let instance_b = AcmeOrderStore::open(dir.path()).expect("open B");

    // B primes its view before A orders, which is exactly the state a replica
    // is in when its renewal scan runs.
    let before = instance_b.latest_order_for_certificate("edge-cert");
    assert!(before.expect("B scans").is_none());

    create_order(&instance_a, "renew-a", "edge-cert", "tok_a");

    let after = instance_b.latest_order_for_certificate("edge-cert");
    let seen = after.expect("B rescans").expect("B sees A's order");
    assert_eq!(seen.id, "renew-a");
    assert_eq!(seen.status, AcmeOrderStatus::PendingChallenges);
}

#[test]
fn interleaved_order_writes_from_two_instances_preserve_both() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeOrderStore::open(dir.path()).expect("open A");
    let instance_b = AcmeOrderStore::open(dir.path()).expect("open B");

    // Both replicas prime their caches on the empty document first: this is the
    // stale-snapshot condition that used to make the second write clobber the
    // first.
    assert!(order_ids(&instance_a).is_empty());
    assert!(order_ids(&instance_b).is_empty());

    create_order(&instance_a, "order-a", "cert-a", "tok_a");
    create_order(&instance_b, "order-b", "cert-b", "tok_b");

    let expected = vec!["order-a".to_string(), "order-b".to_string()];
    let restarted = AcmeOrderStore::open(dir.path()).expect("reopen");
    assert_eq!(order_ids(&restarted), expected, "durable state holds both");

    // Challenge serving is the request-path consumer of this document, so it
    // must answer for both instances' live challenges.
    assert!(instance_a.http01_key_authorization("tok_b").is_some());
    assert!(instance_b.http01_key_authorization("tok_a").is_some());
}

#[test]
fn an_order_id_collision_across_instances_is_a_conflict_not_a_clobber() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeOrderStore::open(dir.path()).expect("open A");
    let instance_b = AcmeOrderStore::open(dir.path()).expect("open B");

    assert!(order_ids(&instance_b).is_empty());
    create_order(&instance_a, "renew-1", "edge-cert", "tok_a");

    let duplicate = pending_order("renew-1", "edge-cert", "tok_b");
    let error = instance_b
        .upsert_order(duplicate, false)
        .expect_err("B must not silently replace A's order");
    assert!(matches!(error, AcmeError::OrderAlreadyExists(_)));
    assert!(instance_b.http01_key_authorization("tok_a").is_some());
    assert!(instance_b.http01_key_authorization("tok_b").is_none());
}

#[test]
fn a_delete_of_a_completed_order_is_observed_by_the_other_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeOrderStore::open(dir.path()).expect("open A");
    let instance_b = AcmeOrderStore::open(dir.path()).expect("open B");

    create_order(&instance_a, "renew-1", "edge-cert", "tok_a");
    assert!(instance_b.get_order("renew-1").is_ok());

    instance_a.delete_order("renew-1").expect("A deletes");

    let error = instance_b.get_order("renew-1").expect_err("B sees it");
    assert!(matches!(error, AcmeError::OrderNotFound(_)));
    assert!(instance_b.http01_key_authorization("tok_a").is_none());
}

#[test]
fn interleaved_certificate_writes_from_two_instances_preserve_both() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeCertificateStore::open(dir.path()).expect("open A");
    let instance_b = AcmeCertificateStore::open(dir.path()).expect("open B");

    assert!(certificate_ids(&instance_a).is_empty());
    assert!(certificate_ids(&instance_b).is_empty());

    let from_a = certificate("cert-a", "pem-a");
    instance_a
        .upsert_certificate(from_a, false)
        .expect("A writes");
    let from_b = certificate("cert-b", "pem-b");
    instance_b
        .upsert_certificate(from_b, false)
        .expect("B writes from its pre-A snapshot");

    let expected = vec!["cert-a".to_string(), "cert-b".to_string()];
    let restarted = AcmeCertificateStore::open(dir.path()).expect("reopen");
    let ids = certificate_ids(&restarted);
    assert_eq!(ids, expected, "durable state holds both");
}

#[test]
fn a_renewed_certificate_is_visible_to_the_other_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeCertificateStore::open(dir.path()).expect("open A");
    let instance_b = AcmeCertificateStore::open(dir.path()).expect("open B");

    let first = certificate("edge-cert", "pem-v1");
    let seeded = instance_a.upsert_certificate(first, false);
    seeded.expect("A issues the certificate");
    let before = instance_b.get_certificate("edge-cert").expect("B reads");
    assert_eq!(before.cert_pem, "pem-v1");

    let renewed = certificate("edge-cert", "pem-v2");
    let stored = instance_a.upsert_certificate(renewed, true);
    stored.expect("A renews the certificate");

    let after = instance_b
        .get_certificate("edge-cert")
        .expect("B observes the renewal");
    assert_eq!(after.cert_pem, "pem-v2");
}

#[test]
fn account_credentials_written_by_one_instance_are_readable_by_the_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = AcmeAccountStore::open(dir.path()).expect("open A");
    let instance_b = AcmeAccountStore::open(dir.path()).expect("open B");

    assert!(instance_b.list_accounts().expect("B lists").is_empty());

    instance_a
        .upsert_account(
            ACCOUNT_ID.to_string(),
            DIRECTORY_URL.to_string(),
            r#"{"private_key":"a"}"#.to_string(),
        )
        .expect("A persists credentials");

    let read = instance_b.get_credentials(DIRECTORY_URL, ACCOUNT_ID);
    let credentials = read.expect("B reads").expect("B sees A's account");
    assert_eq!(credentials, r#"{"private_key":"a"}"#);

    // A second account written by B must not erase A's.
    instance_b
        .upsert_account(
            "https://acme.example/acct/2".to_string(),
            DIRECTORY_URL.to_string(),
            r#"{"private_key":"b"}"#.to_string(),
        )
        .expect("B persists a second account");
    assert_eq!(instance_a.list_accounts().expect("A lists").len(), 2);
}
