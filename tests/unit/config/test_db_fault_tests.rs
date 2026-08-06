//! Regression coverage for the debug-only DB outage fault control.
//!
//! Proves the control file trips `DatabaseStore::pool()` onto a closed pool
//! (ordinary `PoolClosed` connectivity failure) and clears cleanly — without
//! mutating live SQLite/WAL/SHM files.

use crate::unit::env_lock::ENV_LOCK;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::test_db_fault::{self, CONTROL_ENV};
use std::time::Duration;

#[tokio::test]
async fn fault_control_trips_pool_to_closed_and_restores() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

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
    let err = sqlx::query("SELECT 1")
        .fetch_one(&fault_pool)
        .await
        .expect_err("tripped fault pool must refuse acquires");
    assert!(
        matches!(err, sqlx::Error::PoolClosed),
        "expected PoolClosed, got {err:?}"
    );
    let err = sqlx::query("SELECT 1")
        .fetch_one(&store.pool())
        .await
        .expect_err("DatabaseStore::pool must return fault pool while tripped");
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
    tokio::time::sleep(Duration::from_millis(1)).await;
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
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    test_db_fault::disarm_for_tests();
    // SAFETY: ENV_LOCK is held for the whole test.
    unsafe {
        std::env::remove_var(CONTROL_ENV);
    }
    test_db_fault::arm_from_env().await;
    assert!(
        !test_db_fault::is_armed(),
        "unset {CONTROL_ENV} must leave injector inert"
    );
    assert!(test_db_fault::tripped_fault_pool().is_none());
}
