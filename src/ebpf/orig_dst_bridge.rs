//! Original-destination → node-waypoint identity bridge (GAP-1b).
//!
//! In node-waypoint topology one mesh-proxy listener accepts traffic for many
//! pods. The eBPF `connect4`/`connect6` programs (running in each source pod's
//! cgroup) record the original destination keyed by socket cookie into the
//! `FERRUM_ORIG_DST4`/`FERRUM_ORIG_DST6` LRU maps, stamped with the source
//! pod's UID and SPIFFE hash (see `ebpf/ferrum-ebpf/src/connect{4,6}.rs` and
//! `FERRUM_WORKLOAD_IDENTITY`). The node-agent pins those maps at the
//! well-known paths.
//!
//! This bridge runs inside the **mesh-proxy** (node-waypoint topology). It
//! opens the pinned maps by path and mirrors their cookie→identity records
//! into the [`NodeWaypointIdentityResolver`] so the accept path's
//! `resolve_stream`/`resolve_cookie` can answer with a real identity. Before
//! this bridge existed, `record_orig_dst4`/`record_orig_dst6` had ZERO
//! production callers and the resolver's cookie map was always empty — every
//! node-waypoint accept failed closed.
//!
//! ## Why polling
//!
//! The orig-dst maps are LRU hash maps, not ringbufs: the kernel does not
//! signal userspace on insert. The bridge therefore polls on a short interval
//! and re-syncs the resolver's cookie records from the live map. Stale cookies
//! (sockets the kernel evicted from the LRU, or closed connections) are aged
//! out of the resolver so its map cannot grow unboundedly relative to the BPF
//! map.
//!
//! ## Startup race and node-agent restart
//!
//! Like the SOCK_OPS consumer, the mesh-proxy may start before the node-agent
//! has pinned the maps; the bridge retries with backoff. A node-agent restart
//! re-pins fresh maps at the same path (new inode); the bridge re-stats the
//! pin and re-opens so it never reads an orphaned map.
//!
//! ## Build matrix
//!
//! The real reader is `#[cfg(all(feature = "ebpf", target_os = "linux"))]`.
//! Every other build (the shipping default, macOS dev, Windows) gets the
//! no-op stub: it logs once that no orig-dst bridge runs and returns, so the
//! resolver stays empty and the accept path fails closed — exactly the
//! documented degraded behavior.

#![allow(dead_code)]

use std::sync::Arc;

use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;

/// Default poll interval for the orig-dst bridge. Short enough that a cookie
/// record is mirrored into the resolver well within a TCP handshake's worth of
/// time after the source pod's `connect()`, but long enough that the map scan
/// is negligible on a busy node.
pub const ORIG_DST_BRIDGE_POLL_INTERVAL_MS: u64 = 200;

/// Run the orig-dst bridge until the shutdown signal fires.
///
/// On builds without the eBPF feature (or off Linux) this logs once and
/// returns immediately; the resolver stays empty so the node-waypoint accept
/// path fails closed on every cookie. Spawn via
/// `tokio::spawn(run_orig_dst_bridge(...))`.
pub async fn run_orig_dst_bridge(
    resolver: Arc<NodeWaypointIdentityResolver>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        production::run_pinned_bridge(resolver, shutdown_rx).await
    }
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    {
        let _ = resolver;
        let _ = shutdown_rx;
        tracing::warn!(
            "Node-waypoint orig-dst bridge skipped: this build has no eBPF capture \
             (built without the `ebpf` feature or non-Linux target). Source identity \
             cannot be recovered from socket cookies, so every node-waypoint accept \
             will fail closed. Run a node-agent-capable Linux image built with \
             --features ebpf to enable ambient capture."
        );
        Ok(())
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod production {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    use aya::maps::{HashMap as BpfHashMap, MapData};
    use ferrum_ebpf_common::{OrigDst4, OrigDst6, OrigDstKey};
    use tracing::{debug, info, warn};

    use super::ORIG_DST_BRIDGE_POLL_INTERVAL_MS;
    use crate::ebpf::{BPF_ORIG_DST4_PIN_PATH, BPF_ORIG_DST6_PIN_PATH};
    use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;

    type OrigDst4Map = BpfHashMap<MapData, OrigDstKey, OrigDst4>;
    type OrigDst6Map = BpfHashMap<MapData, OrigDstKey, OrigDst6>;

    const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
    const BACKOFF_MAX: Duration = Duration::from_secs(30);
    /// Re-stat the pin paths this often to catch a node-agent restart that
    /// re-pinned fresh maps at the same path (new inode).
    const INODE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

    pub async fn run_pinned_bridge(
        resolver: Arc<NodeWaypointIdentityResolver>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let (mut maps, mut inodes) = match wait_for_pinned_maps(&mut shutdown_rx).await {
            WaitOutcome::Found(pair) => pair,
            WaitOutcome::Shutdown => {
                info!("Node-waypoint orig-dst bridge shutting down before maps were pinned");
                return Ok(());
            }
        };

        info!(
            orig_dst4_pin = BPF_ORIG_DST4_PIN_PATH,
            orig_dst6_pin = BPF_ORIG_DST6_PIN_PATH,
            "Node-waypoint orig-dst bridge attached; mirroring cookie records into resolver"
        );

        let mut poll =
            tokio::time::interval(Duration::from_millis(ORIG_DST_BRIDGE_POLL_INTERVAL_MS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut inode_check = tokio::time::interval(INODE_CHECK_INTERVAL);
        inode_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Node-waypoint orig-dst bridge shutting down");
                        return Ok(());
                    }
                }
                _ = poll.tick() => {
                    sync_once(&maps, &resolver);
                }
                _ = inode_check.tick() => {
                    let current = MapInodes::read();
                    if current != inodes {
                        warn!(
                            "Orig-dst pin inode changed (node-agent restart); re-opening maps"
                        );
                        match open_pinned_maps() {
                            Some((reopened, reopened_inodes)) => {
                                maps = reopened;
                                inodes = reopened_inodes;
                                // The resolver's cookie records reference the
                                // previous map generation; clear them so a
                                // stale cookie cannot resolve to an evicted
                                // pod. The next poll re-populates from the
                                // fresh map.
                                resolver.clear_cookie_records();
                            }
                            None => {
                                debug!(
                                    "Orig-dst maps not yet re-pinnable after inode change; \
                                     retrying on next inode check"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// One poll: re-sync the resolver's cookie records from the live BPF maps.
    /// New/updated cookies are inserted; cookies the kernel evicted from the
    /// LRU are removed from the resolver so its map tracks the BPF map.
    fn sync_once(maps: &OpenMaps, resolver: &NodeWaypointIdentityResolver) {
        let mut live_cookies: HashSet<u64> = HashSet::new();

        for result in maps.orig_dst4.iter() {
            match result {
                Ok((key, record)) => {
                    live_cookies.insert(key.cookie);
                    resolver.record_orig_dst4(key.cookie, record);
                }
                Err(e) => {
                    debug!(error = %e, "orig-dst4 map iteration error; skipping entry");
                }
            }
        }
        for result in maps.orig_dst6.iter() {
            match result {
                Ok((key, record)) => {
                    live_cookies.insert(key.cookie);
                    resolver.record_orig_dst6(key.cookie, record);
                }
                Err(e) => {
                    debug!(error = %e, "orig-dst6 map iteration error; skipping entry");
                }
            }
        }

        resolver.retain_cookie_records(&live_cookies);
    }

    struct OpenMaps {
        orig_dst4: OrigDst4Map,
        orig_dst6: OrigDst6Map,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct MapInodes {
        v4: Option<u64>,
        v6: Option<u64>,
    }

    impl MapInodes {
        fn read() -> Self {
            Self {
                v4: pin_inode(BPF_ORIG_DST4_PIN_PATH),
                v6: pin_inode(BPF_ORIG_DST6_PIN_PATH),
            }
        }
    }

    enum WaitOutcome {
        Found((OpenMaps, MapInodes)),
        Shutdown,
    }

    async fn wait_for_pinned_maps(
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> WaitOutcome {
        let mut backoff = BACKOFF_INITIAL;
        loop {
            if *shutdown_rx.borrow() {
                return WaitOutcome::Shutdown;
            }
            if let Some((maps, inodes)) = open_pinned_maps() {
                return WaitOutcome::Found((maps, inodes));
            }
            debug!(
                orig_dst4_pin = BPF_ORIG_DST4_PIN_PATH,
                backoff_secs = backoff.as_secs(),
                "Orig-dst maps not pinned yet (node-agent may still be starting); retrying"
            );
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        return WaitOutcome::Shutdown;
                    }
                }
            }
        }
    }

    fn open_pinned_maps() -> Option<(OpenMaps, MapInodes)> {
        let v4_data = MapData::from_pin(BPF_ORIG_DST4_PIN_PATH).ok()?;
        let orig_dst4 = OrigDst4Map::try_from(v4_data)
            .map_err(|e| warn!(error = %e, "FERRUM_ORIG_DST4 pin type mismatch"))
            .ok()?;
        let v6_data = MapData::from_pin(BPF_ORIG_DST6_PIN_PATH).ok()?;
        let orig_dst6 = OrigDst6Map::try_from(v6_data)
            .map_err(|e| warn!(error = %e, "FERRUM_ORIG_DST6 pin type mismatch"))
            .ok()?;
        let inodes = MapInodes::read();
        Some((
            OpenMaps {
                orig_dst4,
                orig_dst6,
            },
            inodes,
        ))
    }

    fn pin_inode(path: &str) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|meta| meta.ino())
    }
}
