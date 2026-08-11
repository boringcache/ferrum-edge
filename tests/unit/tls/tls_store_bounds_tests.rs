//! Issue #3737: bound persistent TLS state documents and ACME/managed retention.
//!
//! Covers exact-limit and limit+1 whole-document I/O, previous-state preservation
//! on oversized candidate writes, managed create vs overwrite/delete at the
//! logical record limit, ACME active/recoverable retention with bounded terminal
//! history, bounded event-log load/compaction, secret-safe oversized diagnostics,
//! and multi-process atomic visibility of successful mutations.

use std::io::Cursor;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::config::env_config::{
    DEFAULT_TLS_ACME_TERMINAL_ORDER_HISTORY, DEFAULT_TLS_MANAGED_MAX_RECORDS,
    DEFAULT_TLS_STORE_MAX_DOCUMENT_BYTES, HARD_MAX_TLS_STORE_MAX_DOCUMENT_BYTES,
    MIN_TLS_STORE_MAX_DOCUMENT_BYTES, TLS_ACME_MAX_ACCOUNTS_KEY, TLS_ACME_MAX_CERTIFICATES_KEY,
    TLS_ACME_TERMINAL_ORDER_HISTORY_KEY, TLS_MANAGED_MAX_RECORDS_KEY,
    TLS_STORE_MAX_DOCUMENT_BYTES_KEY, parse_tls_acme_max_accounts, parse_tls_acme_max_certificates,
    parse_tls_acme_terminal_order_history, parse_tls_managed_max_records,
    parse_tls_store_max_document_bytes,
};
use ferrum_edge::config::public_env_inventory::PUBLIC_FERRUM_ENV_SETTINGS;
use ferrum_edge::tls::acme::{
    AcmeCertificateRecord, AcmeCertificateStatus, AcmeCertificateStore, AcmeError, AcmeOrderRecord,
    AcmeOrderStatus, AcmeOrderStore,
};
use ferrum_edge::tls::events::{TlsEventFilter, TlsEventLog, TlsSourceEvent, TlsSourceEventMaterial};
use ferrum_edge::tls::managed::{ManagedTlsError, ManagedTlsRecord, ManagedTlsStore};
use ferrum_edge::tls::shared_store::{
    SharedStoreError, SharedStoreFile, StoreIdentityMode, TlsPersistentStoreKind,
    TlsStoreIoDirection, VersionedStoreFile, read_bounded_document_bytes,
};
use serde::{Deserialize, Serialize};

const DOC_LIMIT: usize = 2048;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ProbeDocument {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    value: String,
}

impl VersionedStoreFile for ProbeDocument {
    fn store_version(&self) -> u64 {
        self.version
    }

    fn set_store_version(&mut self, version: u64) {
        self.version = version;
    }
}

fn open_probe(
    path: std::path::PathBuf,
    max_document_bytes: usize,
) -> SharedStoreFile<ProbeDocument> {
    SharedStoreFile::open_with_limits(
        path,
        StoreIdentityMode::platform_default(),
        TlsPersistentStoreKind::Managed,
        max_document_bytes,
    )
    .expect("open probe store")
}

fn sample_managed(id: &str) -> ManagedTlsRecord {
    ManagedTlsRecord::new_jwks(
        id.to_string(),
        format!("name-{id}"),
        None,
        r#"{"keys":[]}"#.to_string(),
    )
}

fn sample_order(id: &str, certificate_id: &str, status: AcmeOrderStatus) -> AcmeOrderRecord {
    let now = Utc::now();
    AcmeOrderRecord {
        id: id.to_string(),
        certificate_id: Some(certificate_id.to_string()),
        domains: vec!["example.test".to_string()],
        directory_url: "https://acme.example.test/directory".to_string(),
        account_id: Some("acct".to_string()),
        order_url: Some(format!("https://acme.example.test/order/{id}")),
        status,
        http01_challenges: Vec::new(),
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        finalization: None,
        account_credentials_json: None,
        error: None,
        created_at: now,
        updated_at: now,
    }
}

fn sample_certificate(id: &str) -> AcmeCertificateRecord {
    let now = Utc::now();
    AcmeCertificateRecord {
        id: id.to_string(),
        domains: vec!["example.test".to_string()],
        directory_url: "https://acme.example.test/directory".to_string(),
        account_id: Some("acct".to_string()),
        order_url: Some(format!("https://acme.example.test/order/{id}")),
        status: AcmeCertificateStatus::Issued,
        cert_pem: "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n"
            .to_string(),
        key_pem: "-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n".to_string(),
        chain_pem: None,
        issued_at: Some(now),
        not_after: Some(now),
        created_at: now,
        updated_at: now,
    }
}

fn event_with(cert_id: &str) -> TlsSourceEvent {
    TlsSourceEvent {
        id: 0,
        at: Utc::now(),
        surface: "proxy_https".to_string(),
        outcome: "rotated".to_string(),
        sources: vec![TlsSourceEventMaterial {
            label: "cert".to_string(),
            cert_id: cert_id.to_string(),
            source_id: "managed://certificates/x#cert".to_string(),
            scheme: "managed".to_string(),
            kind: "cert".to_string(),
            fingerprint_sha256: Some("abc".to_string()),
        }],
        revision: Some(1),
        error: None,
    }
}

#[test]
fn config_parsers_cover_absent_clamp_and_fail_closed() {
    assert_eq!(
        parse_tls_store_max_document_bytes(None).expect("absent"),
        DEFAULT_TLS_STORE_MAX_DOCUMENT_BYTES
    );
    assert_eq!(
        parse_tls_store_max_document_bytes(Some("2048")).expect("valid"),
        2048
    );
    assert_eq!(
        parse_tls_store_max_document_bytes(Some("999999999")).expect("clamp"),
        HARD_MAX_TLS_STORE_MAX_DOCUMENT_BYTES
    );
    let zero = parse_tls_store_max_document_bytes(Some("0")).expect_err("0 rejected");
    assert!(zero.contains(TLS_STORE_MAX_DOCUMENT_BYTES_KEY));
    assert!(!zero.contains("=0"));
    let malformed = parse_tls_store_max_document_bytes(Some("16MiB")).expect_err("malformed");
    assert!(malformed.contains(TLS_STORE_MAX_DOCUMENT_BYTES_KEY));
    assert!(!malformed.contains("16MiB"));

    assert_eq!(
        parse_tls_managed_max_records(None).expect("absent"),
        DEFAULT_TLS_MANAGED_MAX_RECORDS
    );
    assert!(
        parse_tls_managed_max_records(Some("0"))
            .expect_err("0")
            .contains(TLS_MANAGED_MAX_RECORDS_KEY)
    );
    assert!(
        parse_tls_acme_max_certificates(Some("0"))
            .expect_err("0")
            .contains(TLS_ACME_MAX_CERTIFICATES_KEY)
    );
    assert!(
        parse_tls_acme_max_accounts(Some("0"))
            .expect_err("0")
            .contains(TLS_ACME_MAX_ACCOUNTS_KEY)
    );
    assert_eq!(
        parse_tls_acme_terminal_order_history(None).expect("absent"),
        DEFAULT_TLS_ACME_TERMINAL_ORDER_HISTORY
    );
    assert_eq!(
        parse_tls_acme_terminal_order_history(Some("0")).expect("zero history"),
        0
    );
    assert!(
        parse_tls_acme_terminal_order_history(Some("nope"))
            .expect_err("malformed")
            .contains(TLS_ACME_TERMINAL_ORDER_HISTORY_KEY)
    );

    for key in [
        TLS_STORE_MAX_DOCUMENT_BYTES_KEY,
        TLS_MANAGED_MAX_RECORDS_KEY,
        TLS_ACME_MAX_CERTIFICATES_KEY,
        TLS_ACME_MAX_ACCOUNTS_KEY,
        TLS_ACME_TERMINAL_ORDER_HISTORY_KEY,
    ] {
        assert!(
            PUBLIC_FERRUM_ENV_SETTINGS.contains(&key),
            "public inventory must list {key}"
        );
    }
    assert!(MIN_TLS_STORE_MAX_DOCUMENT_BYTES >= 1024);
}

#[test]
fn bounded_document_reader_accepts_exact_limit_and_rejects_limit_plus_one() {
    let exact = read_bounded_document_bytes(
        &mut Cursor::new(vec![b'x'; DOC_LIMIT]),
        std::path::Path::new("probe.json"),
        DOC_LIMIT,
    )
    .expect("exact limit");
    assert_eq!(exact.len(), DOC_LIMIT);

    let error = read_bounded_document_bytes(
        &mut Cursor::new(vec![b'y'; DOC_LIMIT + 1]),
        std::path::Path::new("probe.json"),
        DOC_LIMIT,
    )
    .expect_err("limit+1");
    match error {
        SharedStoreError::Oversized {
            max_bytes,
            direction,
            path,
        } => {
            assert_eq!(max_bytes, DOC_LIMIT);
            assert_eq!(direction, TlsStoreIoDirection::Read);
            assert_eq!(path, "probe.json");
            let rendered = error.to_string();
            assert!(rendered.contains("exceeds the configured byte ceiling"));
            assert!(!rendered.contains("yyyy"));
        }
        other => panic!("expected Oversized, got {other}"),
    }
}

#[test]
fn shared_store_rejects_oversized_on_disk_without_replacing_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("probe-store.json");
    let store = open_probe(path.clone(), DOC_LIMIT);
    store
        .mutate(|document| {
            document.value = "ok".to_string();
            Ok::<_, SharedStoreError>(())
        })
        .expect("seed");
    let before = store.snapshot().expect("snapshot before").value.clone();
    assert_eq!(before, "ok");

    // Replace the on-disk document with an oversized payload without going
    // through the store writer, simulating corruption / hostile rewrite.
    let oversized = format!(
        r#"{{"version":9,"value":"{}"}}"#,
        "Z".repeat(DOC_LIMIT + 1)
    );
    assert!(oversized.len() > DOC_LIMIT);
    std::fs::write(&path, oversized.as_bytes()).expect("write oversized");

    let error = store.snapshot().expect_err("oversized read must fail");
    assert!(matches!(
        error,
        SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Read,
            ..
        }
    ));
    // Fresh open must also fail closed rather than adopt an empty map.
    let reopen = SharedStoreFile::<ProbeDocument>::open_with_limits(
        path,
        StoreIdentityMode::platform_default(),
        TlsPersistentStoreKind::Managed,
        DOC_LIMIT,
    );
    assert!(matches!(
        reopen,
        Err(SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Read,
            ..
        })
    ));
}

#[test]
fn oversized_candidate_write_preserves_previous_authoritative_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("probe-store.json");
    let store = open_probe(path.clone(), DOC_LIMIT);
    store
        .mutate(|document| {
            document.value = "authoritative".to_string();
            Ok::<_, SharedStoreError>(())
        })
        .expect("seed");

    let error = store
        .mutate(|document| {
            document.value = "X".repeat(DOC_LIMIT + 64);
            Ok::<_, SharedStoreError>(())
        })
        .expect_err("oversized candidate must refuse before rename");
    assert!(matches!(
        error,
        SharedStoreError::Oversized {
            direction: TlsStoreIoDirection::Write,
            ..
        }
    ));

    let live = store.snapshot().expect("live snapshot");
    assert_eq!(live.value, "authoritative");
    let reopened = open_probe(path, DOC_LIMIT);
    assert_eq!(reopened.snapshot().expect("reopen").value, "authoritative");
}

#[test]
fn managed_creates_stop_at_logical_limit_while_overwrite_and_delete_remain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open_with_limits(dir.path(), 64 * 1024, 2, None).expect("open");

    store
        .upsert(sample_managed("one"), false)
        .expect("create one");
    store
        .upsert(sample_managed("two"), false)
        .expect("create two");
    let refused = store
        .upsert(sample_managed("three"), false)
        .expect_err("third create must refuse");
    assert!(matches!(refused, ManagedTlsError::RecordLimitReached));
    assert!(!refused.to_string().contains("three"));

    let mut overwrite = sample_managed("one");
    overwrite.name = "renamed".to_string();
    let updated = store.upsert(overwrite, true).expect("overwrite at limit");
    assert_eq!(updated.name, "renamed");

    store.delete("two").expect("delete at limit");
    store
        .upsert(sample_managed("three"), false)
        .expect("create after delete");
}

#[test]
fn acme_terminal_history_stays_bounded_across_many_cycles_without_dropping_active() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = AcmeOrderStore::open_with_limits(dir.path(), 3, None).expect("open");

    // Active/recoverable orders must survive unbounded renewal cycles.
    for status in [
        AcmeOrderStatus::PendingChallenges,
        AcmeOrderStatus::Ready,
        AcmeOrderStatus::Processing,
    ] {
        let id = format!("active-{}", status as u8);
        store
            .upsert_order(sample_order(&id, "cert-a", status), false)
            .expect("active upsert");
    }

    for cycle in 0..200 {
        let id = format!("term-{cycle}");
        store
            .upsert_order(sample_order(&id, "cert-a", AcmeOrderStatus::Failed), false)
            .expect("terminal upsert");
    }

    let orders = store.list_orders().expect("list");
    let active = orders
        .iter()
        .filter(|order| {
            matches!(
                order.status,
                AcmeOrderStatus::PendingChallenges
                    | AcmeOrderStatus::Ready
                    | AcmeOrderStatus::Processing
            )
        })
        .count();
    let terminal = orders
        .iter()
        .filter(|order| matches!(order.status, AcmeOrderStatus::Failed))
        .count();
    assert_eq!(active, 3, "active/recoverable orders must be retained");
    assert_eq!(terminal, 3, "terminal history must stay at the configured bound");
    assert!(
        store.get_order("active-0").is_ok()
            || store.get_order("active-1").is_ok()
            || store.get_order("active-2").is_ok()
    );
}

#[test]
fn acme_certificate_creates_stop_at_logical_limit_while_overwrite_remains() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        AcmeCertificateStore::open_with_limits(dir.path(), 64 * 1024, 1, None).expect("open");
    store
        .upsert_certificate(sample_certificate("cert-a"), false)
        .expect("create");
    let refused = store
        .upsert_certificate(sample_certificate("cert-b"), false)
        .expect_err("second create");
    assert!(matches!(refused, AcmeError::RecordLimitReached));

    let mut updated = sample_certificate("cert-a");
    updated.domains = vec!["rotated.example.test".to_string()];
    store
        .upsert_certificate(updated, true)
        .expect("overwrite at limit");
    store.delete_certificate("cert-a").expect("delete");
    store
        .upsert_certificate(sample_certificate("cert-b"), false)
        .expect("create after delete");
}

#[test]
fn event_log_bounds_load_and_compacts_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tls-events.json");

    // Seed a valid log with more entries than capacity, still under the byte ceiling.
    {
        let log = TlsEventLog::open_with_document_limit(2, Some(path.clone()), 64 * 1024)
            .expect("open seed");
        log.record(event_with("cert-a"));
        log.record(event_with("cert-b"));
        log.record(event_with("cert-c"));
        log.record(event_with("cert-d"));
    }

    let reloaded = TlsEventLog::open_with_document_limit(2, Some(path.clone()), 64 * 1024)
        .expect("reload");
    let events = reloaded.list(&TlsEventFilter::default());
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sources[0].cert_id, "cert-c");
    assert_eq!(events[1].sources[0].cert_id, "cert-d");

    // Oversized on-disk input must fail without adopting unbounded content.
    std::fs::write(&path, vec![b'{'; DOC_LIMIT + 8]).expect("write oversized");
    let error = TlsEventLog::open_with_document_limit(2, Some(path), DOC_LIMIT)
        .expect_err("oversized event log");
    assert!(error.contains("exceeds the configured byte ceiling"));
    assert!(!error.contains(&"x".repeat(32)));
}

#[test]
fn multi_process_mutation_is_atomic_and_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let store_a = Arc::new(
        ManagedTlsStore::open_with_limits(&path, 64 * 1024, 64, None).expect("open a"),
    );
    let store_b = Arc::new(
        ManagedTlsStore::open_with_limits(&path, 64 * 1024, 64, None).expect("open b"),
    );

    let writer = {
        let store_a = Arc::clone(&store_a);
        thread::spawn(move || {
            for index in 0..20 {
                let id = format!("rec-{index}");
                store_a
                    .upsert(sample_managed(&id), true)
                    .unwrap_or_else(|error| panic!("upsert {id}: {error}"));
                thread::sleep(Duration::from_millis(1));
            }
        })
    };

    let mut saw_partial_json = false;
    for _ in 0..40 {
        match store_b.get("rec-5") {
            Ok(record) => {
                assert_eq!(record.id, "rec-5");
                assert!(!saw_partial_json);
                break;
            }
            Err(ManagedTlsError::NotFound(_)) => {}
            Err(ManagedTlsError::Parse(_)) => {
                saw_partial_json = true;
                panic!("reader observed a partial/corrupt document");
            }
            Err(error) => panic!("unexpected reader error: {error}"),
        }
        thread::sleep(Duration::from_millis(2));
    }
    writer.join().expect("writer joins");
    store_b.get("rec-19").expect("final record visible");
}
