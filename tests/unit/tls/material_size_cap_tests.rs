//! Issue #3736: bound every TLS material source before whole-value buffering.
//!
//! Covers exact limit / limit+1, bounded file streaming, every material kind,
//! each source class (file, inline, shared provider/k8s length gate, managed,
//! ACME), redacted oversized diagnostics, startup refusal, and live-reload
//! last-known-good retention.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::env_config::{
    DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES, HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES,
};
use ferrum_edge::tls::acme::{AcmeCertificateRecord, AcmeCertificateStore, AcmeError, AcmeIssuedCertificateInput};
use ferrum_edge::tls::managed::{
    ManagedTlsError, ManagedTlsRecord, ManagedTlsStore,
};
use ferrum_edge::tls::source::subscription::{
    MaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
    spawn_material_set_reload_task,
};
use ferrum_edge::tls::source::{
    CertSource, MaterialError, MaterialKind, enforce_material_byte_limit,
    load_material_blocking, override_tls_max_material_size_bytes_for_tests,
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
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
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
        let loaded = load_material_blocking(
            &CertSource::parse(exact.to_string_lossy().into_owned(), kind),
            kind,
        )
        .unwrap_or_else(|error| panic!("{kind} at exact limit must load: {error}"));
        assert_eq!(loaded.bytes.expose_secret().len(), LIMIT);

        let over = dir.path().join(format!("{kind}-over.bin"));
        std::fs::write(&over, vec![b'y'; LIMIT + 1]).expect("write over");
        let error = load_material_blocking(
            &CertSource::parse(over.to_string_lossy().into_owned(), kind),
            kind,
        )
        .expect_err("limit+1 must refuse");
        assert_oversized(error, kind);
    }
}

#[test]
fn file_uri_source_honours_the_same_ceiling() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("via-uri.bin");
    std::fs::write(&path, vec![b'z'; LIMIT + 1]).expect("write");
    let source = CertSource::parse(format!("file://{}", path.display()), MaterialKind::Cert);
    let error = load_material_blocking(&source, MaterialKind::Cert).expect_err("oversize");
    assert_oversized(error, MaterialKind::Cert);
}

#[cfg(unix)]
#[test]
fn non_regular_fifo_is_terminated_by_the_streaming_byte_budget() {
    use std::os::unix::ffi::OsStrExt as _;

    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
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
        // Write well past the ceiling; the reader must stop at limit+1.
        file.write_all(&vec![b'f'; LIMIT + 4096])
            .expect("write fifo payload");
    });

    let error = load_material_blocking(
        &CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Key),
        MaterialKind::Key,
    )
    .expect_err("fifo past the ceiling must refuse");
    assert_oversized(error, MaterialKind::Key);
    writer.join().expect("writer exits");
}

#[test]
fn file_that_grows_after_metadata_is_still_capped_by_take_limit_plus_one() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("growing.bin");
    // Start at exactly the limit so metadata precheck passes.
    std::fs::write(&path, vec![b'a'; LIMIT]).expect("seed");

    let grow_path = path.clone();
    let grower = std::thread::spawn(move || {
        // Keep appending while the loader may be reading. Even if the race
        // window is missed and the first read succeeds at exactly LIMIT, a
        // second open after growth must still refuse — both outcomes prove
        // the streaming budget, never an unbounded fallback.
        for _ in 0..50 {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&grow_path)
                .expect("append");
            let _ = file.write_all(b"GROW");
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    // Busy-load until the file is observably past the ceiling, then assert
    // the bounded loader rejects without needing the whole value retained.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut saw_oversized = false;
    while std::time::Instant::now() < deadline {
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as usize > LIMIT {
            match load_material_blocking(
                &CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::CaBundle),
                MaterialKind::CaBundle,
            ) {
                Err(MaterialError::Oversized { .. }) => {
                    saw_oversized = true;
                    break;
                }
                Ok(material) => {
                    assert!(
                        material.bytes.expose_secret().len() <= LIMIT,
                        "loader must never retain more than the ceiling"
                    );
                }
                Err(other) => panic!("unexpected load error while racing growth: {other}"),
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    grower.join().expect("grower exits");
    assert!(
        saw_oversized,
        "once the file grew past the ceiling the bounded reader must reject it"
    );
}

#[test]
fn inline_pem_honours_the_shared_ceiling() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let header = "-----BEGIN CERTIFICATE-----\n";
    let footer = "\n-----END CERTIFICATE-----\n";

    let inline_exact = {
        let fill = LIMIT.saturating_sub(header.len() + footer.len());
        format!("{header}{}{footer}", "B".repeat(fill))
    };
    assert_eq!(inline_exact.len(), LIMIT);
    let loaded = load_material_blocking(
        &CertSource::parse(inline_exact, MaterialKind::Cert),
        MaterialKind::Cert,
    )
    .expect("exact inline PEM must load");
    assert_eq!(loaded.bytes.expose_secret().len(), LIMIT);

    let inline_over = {
        let fill = (LIMIT + 1).saturating_sub(header.len() + footer.len());
        format!("{header}{}{footer}", "C".repeat(fill))
    };
    assert_eq!(inline_over.len(), LIMIT + 1);
    let error = load_material_blocking(
        &CertSource::parse(inline_over, MaterialKind::Cert),
        MaterialKind::Cert,
    )
    .expect_err("oversize inline PEM must refuse");
    assert_oversized(error, MaterialKind::Cert);
}

#[test]
fn shared_length_gate_covers_provider_and_kubernetes_material_kinds() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    for kind in [
        MaterialKind::Cert,
        MaterialKind::Key,
        MaterialKind::CaBundle,
        MaterialKind::Crl,
        MaterialKind::Ocsp,
        MaterialKind::Jwks,
    ] {
        enforce_material_byte_limit(LIMIT, kind).expect("exact limit ok");
        let error =
            enforce_material_byte_limit(LIMIT + 1, kind).expect_err("limit+1 must refuse");
        assert_oversized(error, kind);
    }
}

#[test]
fn managed_store_refuses_oversized_admission_and_load_for_every_kind() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open store");

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
            // base64 of LIMIT+1 bytes is larger still; use a short-but-over decoded payload.
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

    // Persist a within-limit JWKS record, then prove the common-load boundary
    // still rejects if an override lowers the ceiling afterward.
    let ok = ManagedTlsRecord::new_jwks(
        "jwks-ok".into(),
        "jwks-ok".into(),
        None,
        "j".repeat(LIMIT),
    );
    store.upsert(ok, false).expect("within-limit upsert");
    drop(_guard);
    let _lower = override_tls_max_material_size_bytes_for_tests(8);
    let error = store
        .material("jwks/jwks-ok#jwks", MaterialKind::Jwks)
        .expect_err("corrupted/pre-existing oversize relative to new ceiling must fail");
    assert!(matches!(error, ManagedTlsError::MaterialTooLarge));
}

#[test]
fn acme_store_refuses_oversized_admission_and_load() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = AcmeCertificateStore::open(dir.path()).expect("open acme store");

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
    drop(_guard);
    let _lower = override_tls_max_material_size_bytes_for_tests(8);
    let error = store
        .material("certificates/acme-ok#cert", MaterialKind::Cert)
        .expect_err("existing ACME material past the new ceiling must fail at load");
    assert!(matches!(error, AcmeError::MaterialTooLarge));
}

#[test]
fn oversized_error_is_source_redacted() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_path = dir
        .path()
        .join("supersecret-vault-path-do-not-leak.pem");
    std::fs::write(&secret_path, vec![b's'; LIMIT + 1]).expect("write");
    let path_str = secret_path.display().to_string();
    let error = load_material_blocking(
        &CertSource::parse(path_str.clone(), MaterialKind::Key),
        MaterialKind::Key,
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
    let error = load_material_blocking(
        &CertSource::parse(inline.clone(), MaterialKind::Key),
        MaterialKind::Key,
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
    // No production path exposes an unlimited material source budget.
    let parsed_zero = ferrum_edge::config::env_config::parse_tls_max_material_size_bytes(Some("0"))
        .expect("0 is numeric");
    assert!(parsed_zero > 0);
}

#[tokio::test]
async fn live_reload_retains_last_known_good_on_oversized_rotation() {
    let _guard = override_tls_max_material_size_bytes_for_tests(LIMIT);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watched.pem");
    std::fs::write(&path, vec![b'v'; LIMIT]).expect("seed good material");
    let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);

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
            surface: "test_material_size_cap_reload",
            sources: vec![WatchedMaterialSource::new(
                "cert",
                source,
                MaterialKind::Cert,
            )],
            interval: Duration::from_millis(40),
            revision_tx,
            rebuild,
        },
        Some(shutdown_rx),
    );

    // Force an initial successful rotation off the seed bytes.
    tokio::time::sleep(Duration::from_millis(60)).await;
    std::fs::write(&path, {
        let mut bytes = vec![b'v'; LIMIT];
        bytes[0] = b'w';
        bytes
    })
    .expect("rewrite good changed bytes");
    assert!(request_material_set_reload("test_material_size_cap_reload"));
    tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
        .await
        .expect("first rotation")
        .expect("watcher alive");
    let revision_after_good = *revision_rx.borrow();
    let rebuilds_after_good = rebuilds.load(Ordering::SeqCst);
    assert!(revision_after_good >= 1);
    assert!(rebuilds_after_good >= 1);

    // Oversized candidate must not rebuild or advance revision.
    std::fs::write(&path, vec![b'x'; LIMIT + 1]).expect("write oversized");
    assert!(request_material_set_reload("test_material_size_cap_reload"));
    tokio::time::sleep(Duration::from_millis(200)).await;
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
