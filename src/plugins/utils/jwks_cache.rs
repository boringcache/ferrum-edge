//! Global JWKS key store cache shared across plugin instances.
//!
//! When multiple proxies (or multiple providers within one proxy) reference
//! the same JWKS URI, they share a single [`JwksKeyStore`] — avoiding
//! redundant HTTP fetches and duplicate background refresh tasks.
//!
//! The cache is keyed by the resolved `jwks_uri` string. It is lazily
//! initialized on first access and lives for the process lifetime.
//!
//! On config reload, [`retain_active_uris`] removes entries for JWKS URIs
//! that are no longer referenced by any active JWKS consumer, aborting their
//! background refresh tasks after any retired in-flight consumers finish.

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

use super::PluginHttpClient;
use super::jwks_store::JwksKeyStore;

/// A cached JWKS entry: the key store plus its background refresh task handle.
struct JwksCacheEntry {
    store: Arc<JwksKeyStore>,
    refresh_handle: JoinHandle<()>,
    retirement_epoch: Arc<AtomicU64>,
}

const RETIRED_STORE_REAP_INTERVAL: Duration = Duration::from_millis(100);

/// Global, process-wide cache of JWKS key stores keyed by `jwks_uri`.
static JWKS_CACHE: OnceLock<Arc<DashMap<String, JwksCacheEntry>>> = OnceLock::new();

fn global_cache() -> &'static Arc<DashMap<String, JwksCacheEntry>> {
    JWKS_CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

/// Get or create a shared [`JwksKeyStore`] for the given JWKS URI.
///
/// If a store already exists for this URI (created by another plugin instance
/// or another provider), the existing store is returned — no duplicate fetch
/// or background refresh task is spawned.
///
/// On first creation the store starts a single shared background refresh task.
/// That task performs the initial fetch and then continues periodic refreshes.
pub fn get_or_create_jwks_store(
    jwks_uri: &str,
    http_client: &PluginHttpClient,
    refresh_interval: Duration,
) -> Arc<JwksKeyStore> {
    let cache = global_cache();

    // Fast path: store already exists
    if let Some(entry) = cache.get(jwks_uri) {
        // A new consumer revives an entry that may have been marked retired by
        // a concurrent plugin-cache publication. Bumping the epoch invalidates
        // any pending last-owner reaper before cloning the store.
        entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
        return Arc::clone(&entry.value().store);
    }

    // Slow path: create new store (DashMap entry API handles races)
    let entry = cache.entry(jwks_uri.to_string()).or_insert_with(|| {
        info!("JWKS cache: creating shared store for {}", jwks_uri);
        let store = JwksKeyStore::new(jwks_uri.to_string(), http_client.clone());
        let refresh_handle = store.start_background_refresh(refresh_interval);
        JwksCacheEntry {
            store: Arc::new(store),
            refresh_handle,
            retirement_epoch: Arc::new(AtomicU64::new(0)),
        }
    });
    entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
    entry.value().store.clone()
}

/// Remove JWKS cache entries whose URIs are not in `active_uris`.
///
/// Aborts the background refresh task for each removed entry so leaked tokio
/// tasks don't accumulate across config reloads. Stores still owned by a
/// retired plugin generation are reaped after their final external owner
/// drops. Called by `PluginCache::rebuild()` and `PluginCache::apply_delta()`
/// after the new plugin set is constructed.
pub fn retain_active_uris(active_uris: &HashSet<String>) {
    let cache = global_cache();
    cache.retain(|uri, entry| {
        if active_uris.contains(uri) {
            // Cancel a reaper scheduled by an older publication if this URI is
            // active again in the newly committed plugin generation.
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            true
        } else if Arc::strong_count(&entry.store) > 1 {
            // Keep refreshes alive while an old plugin generation, an in-flight
            // request, or an asynchronously publishing discovery worker still
            // owns the store. The epoch-bound reaper removes it promptly after
            // the cache becomes the final owner, without requiring another
            // configuration reload.
            schedule_retired_store_reaper(uri.clone(), entry);
            true
        } else {
            info!("JWKS cache: removing stale store for {}", uri);
            entry.refresh_handle.abort();
            false
        }
    });
}

fn schedule_retired_store_reaper(uri: String, entry: &JwksCacheEntry) {
    let retirement_epoch = Arc::clone(&entry.retirement_epoch);
    let epoch = retirement_epoch
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    let store = Arc::downgrade(&entry.store);
    let cache = Arc::clone(global_cache());

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RETIRED_STORE_REAP_INTERVAL).await;
            if retirement_epoch.load(Ordering::Acquire) != epoch {
                return;
            }
            if store.strong_count() > 1 {
                continue;
            }

            if let Some((_, stale)) = cache.remove_if(&uri, |_, current| {
                Arc::ptr_eq(&current.retirement_epoch, &retirement_epoch)
                    && retirement_epoch.load(Ordering::Acquire) == epoch
                    && Arc::strong_count(&current.store) == 1
            }) {
                info!("JWKS cache: removing retired store for {}", uri);
                stale.refresh_handle.abort();
            }
            return;
        }
    });
}

/// Clear the global JWKS cache. Used in tests to isolate state between runs.
#[allow(dead_code)]
pub fn clear_jwks_cache() {
    if let Some(cache) = JWKS_CACHE.get() {
        // Abort all background refresh tasks before clearing
        for entry in cache.iter() {
            entry.value().refresh_handle.abort();
        }
        cache.clear();
    }
}
