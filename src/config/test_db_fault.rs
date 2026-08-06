//! TEST-ONLY config-database fault injection for functional outage fixtures.
//!
//! # Contract
//!
//! This module exists so `tests/functional/functional_db_outage_test.rs` can
//! make the config database unavailable through ordinary recoverable errors
//! without overwriting a live SQLite database, WAL, or memory-mapped SHM file
//! while the gateway holds those files open. Historical SIGBUS / incomplete-HTTP
//! failures showed that corrupting mapped SQLite state can kill or destabilize
//! the child process instead of exercising the intended outage path.
//!
//! # Safety gates (must all hold)
//!
//! - **Debug builds only.** Active logic is behind `cfg(debug_assertions)`.
//!   Release / normal production binaries keep empty stubs, contain no control
//!   surface, and ignore the env var entirely.
//! - **Startup-armed only.** The control path is read once from
//!   `FERRUM_TEST_DB_FAULT_CONTROL` when a [`crate::config::db_loader::DatabaseStore`]
//!   connects. Unset / empty means the injector stays inert for the process.
//! - **No proxy hot-path work.** [`tripped_fault_pool`] is consulted only from
//!   [`DatabaseStore::pool`](crate::config::db_loader::DatabaseStore::pool) and
//!   related admin/poll DB access — never from the proxy request path.
//! - **No admin API.** Outage is flipped by creating or removing the control
//!   file from the test harness, not via any management endpoint.
//! - **Not a product configuration knob.** Intentionally omitted from
//!   `ferrum.conf` / operator `docs/configuration.md`; documented for harness
//!   authors in `docs/functional_testing_database.md`.
//!
//! When the control file exists, [`DatabaseStore::pool`](crate::config::db_loader::DatabaseStore::pool)
//! returns a pre-closed pool so acquires fail with `sqlx::Error::PoolClosed`,
//! which the poll loop and admin paths already treat as connectivity loss.

/// Env var naming the control file path. Present only as a debug-build test
/// harness seam; see module docs.
pub const CONTROL_ENV: &str = "FERRUM_TEST_DB_FAULT_CONTROL";

#[cfg(debug_assertions)]
mod active {
    use super::CONTROL_ENV;
    use sqlx::AnyPool;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};
    use tracing::warn;

    struct Control {
        path: PathBuf,
        fault_pool: AnyPool,
    }

    static CONTROL: RwLock<Option<Arc<Control>>> = RwLock::new(None);

    /// Arm the injector from `FERRUM_TEST_DB_FAULT_CONTROL` if set.
    pub async fn arm_from_env() {
        let path = match std::env::var(CONTROL_ENV) {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return;
                }
                PathBuf::from(trimmed)
            }
            Err(_) => return,
        };
        arm_path(path).await;
    }

    /// Test/harness helper: arm against an explicit control path.
    pub async fn arm_path(path: PathBuf) {
        sqlx::any::install_default_drivers();
        let fault_pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("TEST-ONLY db fault pool must connect");
        fault_pool.close().await;

        let control = Arc::new(Control { path, fault_pool });
        {
            let mut guard = CONTROL
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *guard = Some(control.clone());
        }

        warn!(
            path = %control.path.display(),
            "TEST-ONLY database fault control armed (debug builds only; not a production surface)"
        );
    }

    /// Clear any armed control (unit tests). Production callers never need this.
    pub fn disarm_for_tests() {
        let mut guard = CONTROL
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
    }

    /// When armed and the control file exists, return the closed fault pool.
    pub fn tripped_fault_pool() -> Option<AnyPool> {
        let guard = CONTROL
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let control = guard.as_ref()?;
        if control.path.exists() {
            Some(control.fault_pool.clone())
        } else {
            None
        }
    }

    /// Whether the injector is armed (control path configured), regardless of trip.
    pub fn is_armed() -> bool {
        CONTROL
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }
}

#[cfg(debug_assertions)]
pub use active::{arm_from_env, arm_path, disarm_for_tests, is_armed, tripped_fault_pool};

#[cfg(not(debug_assertions))]
mod release_stubs {
    use sqlx::AnyPool;
    use std::path::PathBuf;

    pub async fn arm_from_env() {}

    pub async fn arm_path(_path: PathBuf) {}

    pub fn disarm_for_tests() {}

    pub fn tripped_fault_pool() -> Option<AnyPool> {
        None
    }

    pub fn is_armed() -> bool {
        false
    }
}

#[cfg(not(debug_assertions))]
pub use release_stubs::{arm_from_env, arm_path, disarm_for_tests, is_armed, tripped_fault_pool};
