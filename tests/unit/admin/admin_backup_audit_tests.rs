//! Unit tests for backup security-audit helpers and redaction canaries.

use ferrum_edge::admin::audit::{
    self, AuditActor, AuditAdmitSink, AuditEvent, AuditRequestContext, AUDIT_REQUEST_ID_MAX_LEN,
    BACKUP_RESOURCES_INVALID_SENTINEL, append_local_fallback_event, backup_failure_diff,
    backup_resources_audit_value, backup_success_diff, extract_or_generate_request_id,
    list_local_fallback_events,
};
use ferrum_edge::admin::jwt_auth::AdminRole;
use hyper::HeaderMap;
use serde_json::json;
use std::collections::HashSet;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tracing_subscriber::fmt::MakeWriter;

const JWT_CANARY: &str = "super-secret-jwt-value-never-in-audit";
const COOKIE_CANARY: &str = "cookie=session-canary; Authorization: Bearer jwt-canary";
const PAYLOAD_FRAGMENT_CANARY: &str =
    r#"{"consumers":[{"credentials":{"jwt":[{"secret":"leak"}]}}]}"#;
const RESOURCES_CANARY: &str = "canary-token-credential-value-should-never-persist";
const BEARER_FRAGMENT: &str = "eyJhbGciOiJIUzI1NiJ9.payload.sig";

/// Local tracing sink (same shape as admin_tests SharedAdminLogWriter).
#[derive(Clone, Default)]
struct SharedBackupAuditLogWriter(Arc<Mutex<Vec<u8>>>);

impl SharedBackupAuditLogWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap_or_default()
    }
}

impl Write for SharedBackupAuditLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBackupAuditLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_backup_audit_logs() -> (SharedBackupAuditLogWriter, tracing::subscriber::DefaultGuard) {
    let writer = SharedBackupAuditLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    (writer, tracing::subscriber::set_default(subscriber))
}

fn assert_logs_omit_hostile_canaries(logs: &str) {
    for canary in [
        JWT_CANARY,
        COOKIE_CANARY,
        PAYLOAD_FRAGMENT_CANARY,
        RESOURCES_CANARY,
        BEARER_FRAGMENT,
        "Bearer ",
        "Cookie:",
        "eyJhbGciOi",
        "basicauth",
    ] {
        assert!(
            !logs.contains(canary),
            "backup audit helper leaked canary {canary:?} into tracing output:\n{logs}"
        );
    }
}

fn admin_actor() -> AuditActor {
    AuditActor {
        sub: "backup-operator".to_string(),
        role: AdminRole::Admin,
        allowed_namespaces: ferrum_edge::grpc::auth::AllowedNamespaces::empty(),
    }
}

#[test]
fn backup_success_diff_is_fixed_shape_without_payload_bytes() {
    let diff = backup_success_diff(
        "database",
        json!("all"),
        json!({
            "proxies": 1,
            "consumers": 2,
            "plugin_configs": 0,
            "upstreams": 1,
            "api_specs": 0
        }),
        4096,
    );
    let rendered = serde_json::to_string(&diff).expect("serialize");
    assert_eq!(diff["data_source"], "database");
    assert_eq!(diff["bytes"], 4096);
    assert_eq!(diff["counts"]["consumers"], 2);
    assert!(!rendered.contains(JWT_CANARY));
    assert!(!rendered.contains(PAYLOAD_FRAGMENT_CANARY));
    assert!(!rendered.contains("Authorization"));
    assert!(!rendered.contains("Bearer "));
}

#[test]
fn backup_failure_diff_uses_closed_failure_categories_only() {
    let diff = backup_failure_diff(
        audit::failure_category::VALIDATION_FAILED,
        json!(["api_specs"]),
    );
    assert_eq!(diff["failure_category"], "validation_failed");
    assert_eq!(diff["resources"], json!(["api_specs"]));
    assert!(diff.get("error").is_none());
    assert!(diff.get("message").is_none());
}

#[test]
fn backup_resources_audit_value_sorts_and_uses_all_sentinel() {
    assert_eq!(backup_resources_audit_value(None), json!("all"));
    let mut filter = HashSet::new();
    filter.insert("consumers");
    filter.insert("proxies");
    assert_eq!(
        backup_resources_audit_value(Some(&filter)),
        json!(["consumers", "proxies"])
    );
}

#[test]
fn backup_resources_audit_value_never_persists_unknown_raw_token() {
    let mut filter = HashSet::new();
    filter.insert("proxies");
    filter.insert(RESOURCES_CANARY);
    let value = backup_resources_audit_value(Some(&filter));
    assert_eq!(value, json!(BACKUP_RESOURCES_INVALID_SENTINEL));
    let rendered = serde_json::to_string(&value).unwrap();
    assert!(!rendered.contains(RESOURCES_CANARY));
    assert!(!rendered.contains("credential"));
}

#[test]
fn request_id_accepts_safe_header_and_rejects_hostile_values() {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", "req-abc_123.OK:1".parse().unwrap());
    assert_eq!(extract_or_generate_request_id(&headers), "req-abc_123.OK:1");

    let mut hostile = HeaderMap::new();
    hostile.insert(
        "x-request-id",
        format!("Bearer {BEARER_FRAGMENT}").parse().unwrap(),
    );
    let generated = extract_or_generate_request_id(&hostile);
    assert_ne!(generated, format!("Bearer {BEARER_FRAGMENT}"));
    assert!(uuid::Uuid::parse_str(&generated).is_ok());

    let mut oversized = HeaderMap::new();
    let long = "a".repeat(AUDIT_REQUEST_ID_MAX_LEN + 1);
    oversized.insert("x-correlation-id", long.parse().unwrap());
    assert!(uuid::Uuid::parse_str(&extract_or_generate_request_id(&oversized)).is_ok());
}

#[test]
fn audit_request_context_uses_canonical_peer_not_forwarded_header() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    headers.insert("x-real-ip", "198.51.100.7".parse().unwrap());
    headers.insert("x-request-id", "corr-1".parse().unwrap());
    let ctx = AuditRequestContext::from_peer_and_headers(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        &headers,
    );
    assert_eq!(ctx.source_address, "127.0.0.1");
    assert_eq!(ctx.request_id, "corr-1");
    assert!(!ctx.source_address.contains("203.0.113.9"));
    assert!(!ctx.source_address.contains("198.51.100.7"));
}

#[test]
fn backup_event_builder_attaches_context_and_outcome() {
    let ctx = AuditRequestContext {
        source_address: "10.0.0.5".to_string(),
        request_id: "rid-9".to_string(),
    };
    let event = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        backup_success_diff("cached", json!("all"), json!({}), 12),
    )
    .with_request_context(&ctx)
    .with_outcome(audit::outcome::SUCCESS);
    assert_eq!(event.source_address, "10.0.0.5");
    assert_eq!(event.request_id, "rid-9");
    assert_eq!(event.outcome, "success");
    assert_eq!(event.action, "backup");
}

#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_persists_event_without_secret_canaries() {
    let dir = TempDir::new().expect("tempdir");
    let event = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        backup_failure_diff(audit::failure_category::FORBIDDEN, json!("all")),
    )
    .with_outcome(audit::outcome::DENIED);
    assert!(!serde_json::to_string(&event).unwrap().contains(COOKIE_CANARY));

    append_local_fallback_event(dir.path(), &event).expect("append");
    let listed = list_local_fallback_events(dir.path()).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, event.id);
    assert_eq!(listed[0].outcome, "denied");
    let raw = std::fs::read_to_string(dir.path().join("admin-audit-fallback.json")).unwrap();
    assert!(!raw.contains(COOKIE_CANARY));
    assert!(!raw.contains("Bearer "));
    assert!(!raw.contains("basicauth"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let file_mode = std::fs::metadata(dir.path().join("admin-audit-fallback.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
    }
}

#[cfg(unix)]
#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_rejects_symlink_directory() {
    let parent = TempDir::new().expect("tempdir");
    let real = parent.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = parent.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let event = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        json!({}),
    );
    let err = append_local_fallback_event(&link, &event).expect_err("symlink dir");
    assert!(err.to_string().contains("symlink"));
}

#[cfg(unix)]
#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_rejects_symlink_data_file() {
    let dir = TempDir::new().expect("tempdir");
    let outside = dir.path().join("outside.json");
    std::fs::write(&outside, b"[]").unwrap();
    let data = dir.path().join("admin-audit-fallback.json");
    std::os::unix::fs::symlink(&outside, &data).unwrap();
    let event = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        json!({}),
    );
    let err = append_local_fallback_event(dir.path(), &event).expect_err("symlink data");
    assert!(err.to_string().contains("symlink"));
}

#[cfg(unix)]
#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_rejects_non_regular_data_target() {
    let dir = TempDir::new().expect("tempdir");
    let data = dir.path().join("admin-audit-fallback.json");
    std::fs::create_dir(&data).unwrap();
    let event = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        json!({}),
    );
    let err = append_local_fallback_event(dir.path(), &event).expect_err("non-regular");
    assert!(err.to_string().contains("regular file"));
}

fn sample_backup_event() -> AuditEvent {
    AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        backup_success_diff("cached", json!("all"), json!({"proxies": 0}), 2),
    )
    .with_outcome(audit::outcome::SUCCESS)
}

#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_fails_closed_on_process_lock_contention() {
    let _holder = ferrum_edge::_test_support::hold_audit_local_fallback_process_lock_for_test()
        .expect("hold process lock");
    let dir = TempDir::new().expect("tempdir");
    // Mutex is not reentrant: same-thread try_lock while held fails immediately.
    let err = append_local_fallback_event(dir.path(), &sample_backup_event())
        .expect_err("contended process lock must fail closed");
    assert!(
        err.to_string().contains("process lock contended"),
        "unexpected error: {err}"
    );
}

#[cfg(unix)]
#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_fails_closed_on_cross_process_lock_contention() {
    use std::os::unix::io::AsRawFd;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path()).unwrap();
    let lock_path = dir.path().join("admin-audit-fallback.lock");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open lock file");
    let flock_rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(flock_rc, 0, "test setup must hold exclusive flock");

    let event = sample_backup_event();
    let path = dir.path().to_path_buf();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = append_local_fallback_event(&path, &event);
        let _ = tx.send(result);
    });
    // Generous channel timeout only guards against a hang; the functional
    // assertion is the admission failure itself.
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cross-process lock contention must return promptly");
    let err = result.expect_err("contended flock must fail closed");
    assert!(
        err.to_string().contains("cross-process lock contended"),
        "unexpected error: {err}"
    );
    drop(held);
}

#[cfg(unix)]
#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn list_local_fallback_fails_closed_on_cross_process_lock_contention() {
    use std::os::unix::io::AsRawFd;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path()).unwrap();
    let lock_path = dir.path().join("admin-audit-fallback.lock");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open lock file");
    let flock_rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(flock_rc, 0, "test setup must hold exclusive flock");

    let path = dir.path().to_path_buf();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = list_local_fallback_events(&path);
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("list flock contention must return promptly");
    let err = result.expect_err("contended flock must fail closed on list");
    assert!(
        err.to_string().contains("cross-process lock contended"),
        "unexpected error: {err}"
    );
    drop(held);
}

#[test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
fn local_fallback_multiple_appends_retain_both_events() {
    let dir = TempDir::new().expect("tempdir");
    let first = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        backup_success_diff("cached", json!("all"), json!({"proxies": 0}), 2),
    )
    .with_outcome(audit::outcome::SUCCESS);
    let second = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        backup_failure_diff(audit::failure_category::FORBIDDEN, json!("all")),
    )
    .with_outcome(audit::outcome::DENIED);

    append_local_fallback_event(dir.path(), &first).expect("first append");
    // Second publish must replace the existing destination (Windows
    // `std::fs::rename` cannot); both events must remain readable.
    append_local_fallback_event(dir.path(), &second).expect("second append");

    let listed = list_local_fallback_events(dir.path()).expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, first.id);
    assert_eq!(listed[0].outcome, "success");
    assert_eq!(listed[1].id, second.id);
    assert_eq!(listed[1].outcome, "denied");
}

#[test]
fn local_fallback_windows_replace_uses_movefileex_replace_existing() {
    const AUDIT_SOURCE: &str = include_str!("../../../src/admin/audit.rs");
    assert!(
        AUDIT_SOURCE.contains("replace_local_fallback_file"),
        "fallback publish must go through the platform replace helper"
    );
    assert!(
        AUDIT_SOURCE.contains("MOVEFILE_REPLACE_EXISTING"),
        "Windows path must request replace-existing semantics"
    );
    assert!(
        AUDIT_SOURCE.contains("MOVEFILE_WRITE_THROUGH"),
        "Windows path must request write-through durability"
    );
    assert!(
        AUDIT_SOURCE.contains("MoveFileExW"),
        "Windows path must use MoveFileExW"
    );
    // Never delete the live destination before publish (visibility gap).
    assert!(
        !AUDIT_SOURCE.contains("remove_file(path)")
            && !AUDIT_SOURCE.contains("remove_file(destination)"),
        "must not unlink the live fallback destination before replace"
    );
    // Bare std rename is only allowed on the non-Windows branch.
    let windows_fn = AUDIT_SOURCE
        .split("fn replace_local_fallback_file_windows")
        .nth(1)
        .unwrap_or("");
    let windows_body = windows_fn.split("fn write_temp_fallback_file").next().unwrap_or("");
    assert!(
        !windows_body.contains("fs::rename("),
        "Windows replace must not call std::fs::rename"
    );
}

#[tokio::test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
async fn admit_security_sensitive_event_uses_local_fallback_without_db() {
    let dir = TempDir::new().expect("tempdir");
    let event = AuditEvent::new(
        &admin_actor(),
        "backup",
        "gateway_config",
        "ferrum",
        "ferrum",
        backup_success_diff("cached", json!("all"), json!({"proxies": 0}), 2),
    )
    .with_outcome(audit::outcome::SUCCESS);
    // No enabled flag: backup security admission is unconditional.
    let sink = audit::admit_security_sensitive_event(None, &event, Some(dir.path()))
        .await
        .expect("local admit");
    assert_eq!(sink, AuditAdmitSink::LocalFallback);
    let listed = list_local_fallback_events(dir.path()).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].diff["data_source"], "cached");
    assert_eq!(listed[0].diff["bytes"], 2);
}

fn hostile_backup_event(outcome: audit::AuditOutcome) -> AuditEvent {
    // Plant hostile strings only in fields that fixed-shape logging must not
    // echo. Diff stays canonical; actor/resource carry canaries to prove the
    // admit/attempt failure paths withhold them.
    let mut actor = admin_actor();
    actor.sub = format!("{JWT_CANARY}|{COOKIE_CANARY}|{BEARER_FRAGMENT}");
    let diff = if outcome == audit::outcome::SUCCESS {
        backup_success_diff("cached", json!("all"), json!({"proxies": 0}), 2)
    } else {
        backup_failure_diff(
            audit::failure_category::VALIDATION_FAILED,
            json!(BACKUP_RESOURCES_INVALID_SENTINEL),
        )
    };
    AuditEvent::new(
        &actor,
        "backup",
        &format!("gateway_config:{PAYLOAD_FRAGMENT_CANARY}"),
        RESOURCES_CANARY,
        RESOURCES_CANARY,
        diff,
    )
    .with_outcome(outcome)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(admin_audit_local_fallback_lock)]
async fn admit_security_sensitive_failure_logs_omit_hostile_canaries() {
    let (logs, _guard) = capture_backup_audit_logs();
    let event = hostile_backup_event(audit::outcome::SUCCESS);

    #[cfg(unix)]
    {
        let parent = TempDir::new().expect("tempdir");
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = audit::admit_security_sensitive_event(None, &event, Some(link.as_path()))
            .await
            .expect_err("symlink fallback must fail closed");
        assert!(
            err.to_string().contains("could not be admitted"),
            "unexpected admit error: {err}"
        );
    }

    #[cfg(not(unix))]
    {
        let _holder = ferrum_edge::_test_support::hold_audit_local_fallback_process_lock_for_test()
            .expect("hold process lock");
        let dir = TempDir::new().expect("tempdir");
        let err = audit::admit_security_sensitive_event(None, &event, Some(dir.path()))
            .await
            .expect_err("contended fallback must fail closed");
        assert!(
            err.to_string().contains("could not be admitted"),
            "unexpected admit error: {err}"
        );
    }

    let captured = logs.contents();
    assert_logs_omit_hostile_canaries(&captured);
    assert!(
        captured.contains("audit_security_admit_local_fallback")
            || captured.contains("Failed to admit security-sensitive audit event to local fallback"),
        "expected local-fallback admit failure surface:\n{captured}"
    );
    assert!(
        captured.contains("detail_withheld"),
        "admit failure must withhold detail:\n{captured}"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(admin_audit_local_fallback_lock)]
async fn record_backup_attempt_failure_logs_omit_hostile_canaries() {
    let (logs, _guard) = capture_backup_audit_logs();
    let event = hostile_backup_event(audit::outcome::VALIDATION_FAILED);

    #[cfg(unix)]
    {
        let parent = TempDir::new().expect("tempdir");
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        audit::record_backup_attempt_best_effort(None, &event, Some(link.as_path())).await;
    }

    #[cfg(not(unix))]
    {
        let _holder = ferrum_edge::_test_support::hold_audit_local_fallback_process_lock_for_test()
            .expect("hold process lock");
        let dir = TempDir::new().expect("tempdir");
        audit::record_backup_attempt_best_effort(None, &event, Some(dir.path())).await;
    }

    let captured = logs.contents();
    assert_logs_omit_hostile_canaries(&captured);
    assert!(
        captured.contains("backup_audit_attempt")
            || captured.contains("Authenticated backup attempt could not be audited"),
        "expected best-effort backup attempt failure surface:\n{captured}"
    );
    assert!(
        captured.contains("detail_withheld"),
        "attempt failure must withhold detail:\n{captured}"
    );
}
