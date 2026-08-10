//! Issue #3736: bound every TLS material source before whole-value buffering.
//!
//! Covers exact limit / limit+1, bounded file streaming, every material kind,
//! each source class (file, inline, provider/k8s loader boundaries, managed,
//! ACME), redacted oversized diagnostics, startup refusal, and live-reload
//! last-known-good retention with observable `load_error`.

use std::io::{Cursor, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::env_config::{
    DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES, HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES,
};
use ferrum_edge::tls::acme::{
    AcmeCertificateRecord, AcmeCertificateStore, AcmeError, AcmeIssuedCertificateInput,
};
use ferrum_edge::tls::events::{TlsEventFilter, global_event_log};
use ferrum_edge::tls::managed::{ManagedTlsError, ManagedTlsRecord, ManagedTlsStore};
use ferrum_edge::tls::source::subscription::{
    MaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
    spawn_material_set_reload_task,
};
use ferrum_edge::tls::source::{
    CertSource, MaterialError, MaterialKind, enforce_material_byte_limit_with,
    load_material_blocking_with, read_bounded_material_bytes,
};
use tokio::sync::watch;

const LIMIT: usize = 64;

fn assert_oversized(error: MaterialError, kind: MaterialKind) {
    match error {
        MaterialError::Oversized {
            kind: got_kind,
            max_bytes,
        } => {
            assert_eq!(got_kind, kind);
            assert_eq!(max_bytes, LIMIT);
        }
        other => panic!("expected Oversized, got {other}"),
    }
}

fn assert_redacted(error: &MaterialError, forbidden: &[&str]) {
    let rendered = error.to_string();
    for fragment in forbidden {
        assert!(
            !rendered.contains(fragment),
            "oversized diagnostic leaked '{fragment}': {rendered}"
        );
    }
    assert!(
        rendered.contains("exceeds the configured maximum"),
        "stable oversized classification missing: {rendered}"
    );
}

#[test]
fn file_material_at_exact_limit_loads_and_limit_plus_one_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    for kind in [
        MaterialKind::Cert,
        MaterialKind::Key,
        MaterialKind::CaBundle,
        MaterialKind::Crl,
        MaterialKind::Ocsp,
        MaterialKind::Jwks,
    ] {
        let exact = dir.path().join(format!("{kind}-exact.bin"));
        std::fs::write(&exact, vec![b'x'; LIMIT]).expect("write exact");
        let loaded = load_material_blocking_with(
            &CertSource::parse(exact.to_string_lossy().into_owned(), kind),
            kind,
            LIMIT,
        )
        .unwrap_or_else(|error| panic!("{kind} at exact limit must load: {error}"));
        assert_eq!(loaded.bytes.expose_secret().len(), LIMIT);

        let over = dir.path().join(format!("{kind}-over.bin"));
        std::fs::write(&over, vec![b'y'; LIMIT + 1]).expect("write over");
        let error = load_material_blocking_with(
            &CertSource::parse(over.to_string_lossy().into_owned(), kind),
            kind,
            LIMIT,
        )
        .expect_err("limit+1 must refuse");
        assert_oversized(error, kind);
    }
}

#[test]
fn file_uri_source_honours_the_same_ceiling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("via-uri.bin");
    std::fs::write(&path, vec![b'z'; LIMIT + 1]).expect("write");
    let source = CertSource::parse(format!("file://{}", path.display()), MaterialKind::Cert);
    let error = load_material_blocking_with(&source, MaterialKind::Cert, LIMIT)
        .expect_err("oversize");
    assert_oversized(error, MaterialKind::Cert);
}

#[cfg(unix)]
#[test]
fn non_regular_fifo_is_terminated_by_the_streaming_byte_budget() {
    use std::os::unix::ffi::OsStrExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("material.fifo");
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("c path");
    // SAFETY: `path_c` is a live NUL-terminated path; mode is ordinary perms.
    assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);

    let writer_path = path.clone();
    let writer = std::thread::spawn(move || {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&writer_path)
            .expect("open fifo writer");
        // limit+1 stays within ordinary pipe capacity; tolerate BrokenPipe if
        // the bounded reader closes after limit+1 before the write completes.
        match file.write_all(&vec![b'f'; LIMIT + 1]) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => panic!("unexpected fifo writer error: {error}"),
        }
    });

    let error = load_material_blocking_with(
        &CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Key),
        MaterialKind::Key,
        LIMIT,
    )
    .expect_err("fifo past the ceiling must refuse");
    assert_oversized(error, MaterialKind::Key);
    writer.join().expect("writer exits");
}

#[test]
fn bounded_reader_seam_rejects_after_metadata_precheck_would_have_passed() {
    // Race-free proof of the streaming budget: a reader that already passed any
    // metadata precheck still terminates at limit+1 without retaining the whole
    // value.
    let error = read_bounded_material_bytes(
        Cursor::new(vec![b'g'; LIMIT + 1]),
        MaterialKind::CaBundle,
        LIMIT,
    )
    .expect_err("limit+1 reader must refuse");
    assert_oversized(error, MaterialKind::CaBundle);

    let ok = read_bounded_material_bytes(Cursor::new(vec![b'g'; LIMIT]), MaterialKind::CaBundle, LIMIT)
        .expect("exact limit reader must accept");
    assert_eq!(ok.len(), LIMIT);
}

#[test]
fn inline_pem_honours_the_shared_ceiling() {
    let header = "-----BEGIN CERTIFICATE-----\n";
    let footer = "\n-----END CERTIFICATE-----\n";

    let inline_exact = {
        let fill = LIMIT.saturating_sub(header.len() + footer.len());
        format!("{header}{}{footer}", "B".repeat(fill))
    };
    assert_eq!(inline_exact.len(), LIMIT);
    let loaded = load_material_blocking_with(
        &CertSource::parse(inline_exact, MaterialKind::Cert),
        MaterialKind::Cert,
        LIMIT,
    )
    .expect("exact inline PEM must load");
    assert_eq!(loaded.bytes.expose_secret().len(), LIMIT);

    let inline_over = {
        let fill = (LIMIT + 1).saturating_sub(header.len() + footer.len());
        format!("{header}{}{footer}", "C".repeat(fill))
    };
    assert_eq!(inline_over.len(), LIMIT + 1);
    let error = load_material_blocking_with(
        &CertSource::parse(inline_over, MaterialKind::Cert),
        MaterialKind::Cert,
        LIMIT,
    )
    .expect_err("oversize inline PEM must refuse");
    assert_oversized(error, MaterialKind::Cert);
}

#[test]
fn shared_length_gate_covers_every_material_kind() {
    for kind in [
        MaterialKind::Cert,
        MaterialKind::Key,
        MaterialKind::CaBundle,
        MaterialKind::Crl,
        MaterialKind::Ocsp,
        MaterialKind::Jwks,
    ] {
        enforce_material_byte_limit_with(LIMIT, kind, LIMIT).expect("exact limit ok");
        let error = enforce_material_byte_limit_with(LIMIT + 1, kind, LIMIT)
            .expect_err("limit+1 must refuse");
        assert_oversized(error, kind);
    }
}

#[test]
fn provider_and_kubernetes_loaders_enforce_before_into_bytes_or_clone() {
    let source = include_str!("../../../src/tls/source/mod.rs");

    let provider = source
        .split("fn load_secret_material_with(")
        .nth(1)
        .expect("provider loader exists")
        .split("fn load_k8s_secret_material_with(")
        .next()
        .expect("provider loader ends");
    let provider_gate = provider
        .find("enforce_material_byte_limit_with(resolved.value.len()")
        .expect("provider length gate before conversion");
    let provider_into_bytes = provider
        .find("resolved.value.into_bytes()")
        .expect("provider into_bytes");
    assert!(
        provider_gate < provider_into_bytes,
        "provider bound must precede into_bytes"
    );

    let k8s = source
        .split("fn load_k8s_secret_material_with(")
        .nth(1)
        .expect("k8s loader exists")
        .split("fn load_managed_material_with(")
        .next()
        .expect("k8s loader ends");
    let k8s_gate = k8s
        .find("enforce_material_byte_limit_with(value.0.len()")
        .expect("k8s length gate before clone");
    let k8s_clone = k8s.find("value.0.clone()").expect("k8s clone");
    assert!(k8s_gate < k8s_clone, "k8s bound must precede clone");
}

#[test]
fn managed_store_refuses_oversized_admission_and_load_for_every_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open_with_material_limit(dir.path(), LIMIT).expect("open store");

    let over = "m".repeat(LIMIT + 1);
    let cases: Vec<ManagedTlsRecord> = vec![
        ManagedTlsRecord::new_certificate(
            "cert-over".into(),
            "cert-over".into(),
            None,
            over.clone(),
            "k".repeat(32),
            None,
        ),
        ManagedTlsRecord::new_ca_bundle("ca-over".into(), "ca-over".into(), None, over.clone()),
        ManagedTlsRecord::new_crl("crl-over".into(), "crl-over".into(), None, over.clone()),
        ManagedTlsRecord::new_ocsp_response(
            "ocsp-over".into(),
            "ocsp-over".into(),
            None,
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(vec![0u8; LIMIT + 1])
            },
        ),
        ManagedTlsRecord::new_jwks("jwks-over".into(), "jwks-over".into(), None, over),
    ];

    for record in cases {
        let id = record.id.clone();
        let error = store
            .upsert(record, false)
            .expect_err("oversized managed admission must fail");
        assert!(
            matches!(error, ManagedTlsError::MaterialTooLarge),
            "id={id}: {error}"
        );
        assert!(
            !error.to_string().contains("m".repeat(8).as_str()),
            "managed oversized diagnostic must not echo material"
        );
    }

    // Persist within-limit material under a high ceiling, then prove the
    // common-load boundary still rejects under a lower explicit limit.
    let wide = ManagedTlsStore::open_with_material_limit(dir.path(), LIMIT).expect("reopen");
    let ok =
        ManagedTlsRecord::new_jwks("jwks-ok".into(), "jwks-ok".into(), None, "j".repeat(LIMIT));
    wide.upsert(ok, false).expect("within-limit upsert");
    let error = wide
        .material_with_limit("jwks/jwks-ok#jwks", MaterialKind::Jwks, 8)
        .expect_err("pre-existing oversize relative to new ceiling must fail");
    assert!(matches!(error, ManagedTlsError::MaterialTooLarge));
}

#[test]
fn managed_combined_cert_chain_uses_checked_length_before_construction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open_with_material_limit(dir.path(), LIMIT).expect("open");
    // Individually under the ceiling, combined (with newline) exceeds it.
    let cert = "c".repeat(LIMIT - 1);
    let chain = "h".repeat(2);
    let record = ManagedTlsRecord::new_certificate(
        "combo".into(),
        "combo".into(),
        None,
        cert,
        "k".repeat(32),
        Some(chain),
    );
    let error = store
        .upsert(record, false)
        .expect_err("combined cert+chain must refuse before construction");
    assert!(matches!(error, ManagedTlsError::MaterialTooLarge));
}

#[test]
fn acme_store_refuses_oversized_admission_and_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        AcmeCertificateStore::open_with_material_limit(dir.path(), LIMIT).expect("open acme store");

    let over = "a".repeat(LIMIT + 1);
    let record = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: "acme-over".into(),
        domains: vec!["example.test".into()],
        directory_url: "https://acme.example/directory".into(),
        account_id: Some("acct".into()),
        order_url: None,
        cert_pem: over.clone(),
        key_pem: "k".repeat(32),
        chain_pem: None,
    })
    .expect("record construction");
    let error = store
        .upsert_certificate(record, false)
        .expect_err("oversized ACME admission must fail");
    assert!(matches!(error, AcmeError::MaterialTooLarge));

    let ok = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: "acme-ok".into(),
        domains: vec!["example.test".into()],
        directory_url: "https://acme.example/directory".into(),
        account_id: Some("acct".into()),
        order_url: None,
        cert_pem: "c".repeat(LIMIT),
        key_pem: "k".repeat(32),
        chain_pem: None,
    })
    .expect("within-limit record");
    store
        .upsert_certificate(ok, false)
        .expect("within-limit ACME upsert");
    let error = store
        .material_with_limit("certificates/acme-ok#cert", MaterialKind::Cert, 8)
        .expect_err("existing ACME material past the new ceiling must fail at load");
    assert!(matches!(error, AcmeError::MaterialTooLarge));
}

#[test]
fn oversized_error_is_source_redacted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_path = dir.path().join("supersecret-vault-path-do-not-leak.pem");
    std::fs::write(&secret_path, vec![b's'; LIMIT + 1]).expect("write");
    let path_str = secret_path.display().to_string();
    let error = load_material_blocking_with(
        &CertSource::parse(path_str.clone(), MaterialKind::Key),
        MaterialKind::Key,
        LIMIT,
    )
    .expect_err("oversize");
    assert_redacted(
        &error,
        &[
            path_str.as_str(),
            "supersecret",
            "vault-path",
            &"s".repeat(16),
        ],
    );

    let inline = {
        let header = "-----BEGIN PRIVATE KEY-----\n";
        let footer = "\n-----END PRIVATE KEY-----\n";
        let fill = (LIMIT + 1).saturating_sub(header.len() + footer.len());
        format!("{header}{}{footer}", "K".repeat(fill))
    };
    let error = load_material_blocking_with(
        &CertSource::parse(inline.clone(), MaterialKind::Key),
        MaterialKind::Key,
        LIMIT,
    )
    .expect_err("oversize inline");
    assert_redacted(&error, &["BEGIN PRIVATE KEY", "KKKKKKKK", inline.as_str()]);
}

#[test]
fn default_ceiling_is_finite_production_posture() {
    assert_eq!(
        DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES,
        HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES
    );
    assert!(DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES > 0);
    let rejected = ferrum_edge::config::env_config::parse_tls_max_material_size_bytes(Some("0"))
        .expect_err("0 must fail closed");
    assert!(rejected.contains("not unlimited"));
}

#[tokio::test]
async fn live_reload_retains_last_known_good_on_oversized_rotation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watched.pem");
    std::fs::write(&path, vec![b'v'; LIMIT]).expect("seed good material");
    let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);
    let surface = "test_material_size_cap_reload";

    let rebuilds = Arc::new(AtomicUsize::new(0));
    let rebuilds_clone = rebuilds.clone();
    let rebuild = Box::new(move || {
        rebuilds_clone.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let (revision_tx, mut revision_rx) = watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = spawn_material_set_reload_task(
        MaterialSetReloadConfig {
            surface,
            sources: vec![WatchedMaterialSource::new(
                "cert",
                source,
                MaterialKind::Cert,
            )],
            interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: LIMIT,
            rebuild,
        },
        Some(shutdown_rx),
    );

    // Force an initial successful rotation off changed-but-valid bytes.
    std::fs::write(&path, {
        let mut bytes = vec![b'v'; LIMIT];
        bytes[0] = b'w';
        bytes
    })
    .expect("rewrite good changed bytes");
    assert!(request_material_set_reload(surface));
    tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
        .await
        .expect("first rotation")
        .expect("watcher alive");
    let revision_after_good = *revision_rx.borrow();
    let rebuilds_after_good = rebuilds.load(Ordering::SeqCst);
    assert!(revision_after_good >= 1);
    assert!(rebuilds_after_good >= 1);

    let events_before = global_event_log()
        .list(&TlsEventFilter {
            surface: Some(surface.to_string()),
            outcome: Some("load_error".to_string()),
            ..Default::default()
        })
        .len();

    // Oversized candidate must not rebuild or advance revision, and must
    // record a bounded load_error event.
    std::fs::write(&path, vec![b'x'; LIMIT + 1]).expect("write oversized");
    assert!(request_material_set_reload(surface));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut saw_load_error = false;
    while tokio::time::Instant::now() < deadline {
        let events = global_event_log().list(&TlsEventFilter {
            surface: Some(surface.to_string()),
            outcome: Some("load_error".to_string()),
            ..Default::default()
        });
        if events.len() > events_before {
            let latest = events.last().expect("load_error event");
            assert!(
                latest
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("exceeds the configured maximum")),
                "load_error must carry the stable oversized classification: {latest:?}"
            );
            saw_load_error = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        saw_load_error,
        "oversized rotation must record an observable load_error event"
    );
    assert_eq!(
        *revision_rx.borrow(),
        revision_after_good,
        "oversized rotation must retain last-known-good revision"
    );
    assert_eq!(
        rebuilds.load(Ordering::SeqCst),
        rebuilds_after_good,
        "oversized load must not invoke rebuild"
    );

    shutdown_tx.send_replace(true);
    task.await.expect("watcher exits");
}
