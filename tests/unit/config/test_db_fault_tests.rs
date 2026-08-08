//! Regression coverage for the debug-only DB outage fault control.
//!
//! Proves the control file trips `DatabaseStore::pool()` onto a closed pool
//! (ordinary `PoolClosed` connectivity failure) and clears cleanly — without
//! mutating live SQLite/WAL/SHM files.

use std::sync::OnceLock;

use crate::unit::env_lock::EnvGuard;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::test_db_fault::{self, CONTROL_ENV};
use futures_util::FutureExt as _;

fn fault_control_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tokio::test]
async fn fault_control_trips_pool_to_closed_and_restores() {
    let _fault_guard = fault_control_lock().lock().await;

    test_db_fault::disarm_for_tests();

    let dir = tempfile::tempdir().expect("tempdir");
    let control = dir.path().join("fault");
    test_db_fault::arm_path(control.clone()).await;
    assert!(
        test_db_fault::is_armed(),
        "injector must arm when a control path is configured"
    );
    assert!(
        test_db_fault::tripped_fault_pool().is_none(),
        "absent control file must not trip"
    );

    let db_path = dir.path().join("live.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("connect live store");

    // Healthy path: real pool answers.
    sqlx::query("SELECT 1")
        .fetch_one(&store.pool())
        .await
        .expect("healthy pool must serve SELECT 1");

    // Trip outage via control file — live DB bytes stay intact.
    std::fs::write(&control, b"1").expect("create control");
    let before = std::fs::read(&db_path).expect("read live db");
    let fault_pool = test_db_fault::tripped_fault_pool().expect("tripped pool");
    let err = match sqlx::query("SELECT 1").fetch_one(&fault_pool).await {
        Ok(_) => panic!("tripped fault pool must refuse acquires"),
        Err(err) => err,
    };
    assert!(
        matches!(err, sqlx::Error::PoolClosed),
        "expected PoolClosed, got {err:?}"
    );
    let err = match sqlx::query("SELECT 1").fetch_one(&store.pool()).await {
        Ok(_) => panic!("DatabaseStore::pool must return fault pool while tripped"),
        Err(err) => err,
    };
    assert!(
        matches!(err, sqlx::Error::PoolClosed),
        "store.pool() while tripped must be PoolClosed, got {err:?}"
    );
    let after = std::fs::read(&db_path).expect("re-read live db");
    assert_eq!(
        before, after,
        "tripping the fault must not mutate the live SQLite file"
    );

    // Restore.
    std::fs::remove_file(&control).expect("clear control");
    assert!(
        test_db_fault::tripped_fault_pool().is_none(),
        "cleared control file must un-trip"
    );
    sqlx::query("SELECT 1")
        .fetch_one(&store.pool())
        .await
        .expect("restored pool must serve SELECT 1 again");

    test_db_fault::disarm_for_tests();
}

#[tokio::test]
async fn arm_from_env_requires_control_path() {
    let _fault_guard = fault_control_lock().lock().await;
    let env = EnvGuard::new(&[CONTROL_ENV]);

    test_db_fault::disarm_for_tests();
    env.unset(CONTROL_ENV);
    test_db_fault::arm_from_env()
        .now_or_never()
        .expect("unset control env must not suspend");
    assert!(
        !test_db_fault::is_armed(),
        "unset {CONTROL_ENV} must leave injector inert"
    );
    assert!(test_db_fault::tripped_fault_pool().is_none());
}
