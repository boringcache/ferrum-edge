//! Authoritative mesh config revisions for a Kubernetes-controller control
//! plane (issue #3611).
//!
//! `modes::mesh::revision` orders mesh slices by `(authority, sequence)` and
//! quarantines a fallback control plane whose sequence is behind the accepted
//! one. A DB-backed CP feeds that gate from its store's durable
//! `config_changes` cursor. A CP running the Kubernetes CRD controller had no
//! sequence at all, so it published no revision and the gate stayed inert in
//! exactly the multi-replica topology the mesh charts deploy. This module
//! supplies the missing sequence.
//!
//! # What the sequence has to be
//!
//! Two CP replicas watching the same Kubernetes API server must publish
//! sequences that are *comparable* (same number space), *shared* (derived from
//! cluster state, not from either process), and *monotonic* (never rewinding
//! inside one authority). Only one value in the Kubernetes API satisfies all
//! three: the `resourceVersion`, which on every etcd-backed API server is the
//! cluster-global etcd revision. It is minted by the store, identical for every
//! client, and never reused or decreased for the life of the cluster.
//!
//! What is emphatically NOT usable:
//!
//! * **max over live object metadata.** Deleting the highest-versioned object in
//!   a scope *lowers* that maximum. A replica that restarts after such a
//!   deletion relists, recomputes a lower maximum, and publishes a revision
//!   below the one its still-running peer already published — a rewind inside
//!   one authority, which the data-plane gate never auto-adopts. In a quiet
//!   namespace it would need an operator reset to recover.
//! * **a wall clock or a process-local counter.** Neither is shared, and the
//!   gate exists precisely because `MeshSlice.version` (a CP-local timestamp)
//!   was not.
//! * **the current cluster revision read at reconcile time.** It says what the
//!   cluster is at, not what this replica's reflectors have converged through.
//!   A stalled watcher would make it claim freshness it does not have.
//!
//! # Evidence, not optimism
//!
//! The tracker keeps, per watch scope, the highest revision that scope is
//! *proven* converged through. Two kinds of evidence establish it:
//!
//! * **A boundary read** taken immediately BEFORE a watcher generation starts.
//!   kube-rs consumes list metadata and watch bookmarks internally and surfaces
//!   neither ([`kube::runtime::watcher::Event`] has no bookmark variant), so the
//!   generation's own list revision is unavailable. Instead the caller performs
//!   a one-item consistent list on the same resource and scope; whatever
//!   revision it returns is necessarily ≤ the revision of the generation's own
//!   list, because `watcher::Config` defaults to
//!   [`kube::runtime::watcher::ListSemantic::MostRecent`] — an unset
//!   `resourceVersion`, i.e. a quorum read at the *current* etcd revision, which
//!   is ≥ every revision any client has already observed. The boundary is
//!   adopted only when that generation reports `InitDone`, at which point its
//!   store holds a list computed at or after the boundary.
//! * **Observed watch events.** A watch resumed from a list revision delivers
//!   every change in order, so having processed an event stamped `r` proves the
//!   scope has seen everything up to `r`. Deletions count: a `DELETED` watch
//!   event carries the object stamped with the *deletion* revision, so a
//!   deletion advances the watermark instead of lowering it.
//!
//! Listed objects are held back until `InitDone` because the reflector buffers
//! an initial list and commits it atomically at that event. Advancing on an
//! object the store has not yet published would claim convergence the snapshot
//! does not have.
//!
//! # The coherence point
//!
//! A reconcile snapshot is the union of independently converging scopes, so it
//! is not a coherent cluster snapshot at any single revision. The strongest true
//! statement is: *it contains every change up to the MINIMUM of its scopes'
//! watermarks* (and possibly some later ones). That minimum is therefore the
//! sequence, and the aggregation rules follow from it:
//!
//! * the scope set is pinned under the same `ResourceStoreSet` lock that
//!   materializes the snapshot, and the watermark is read BEFORE
//!   `snapshot_all()` — the stores can only move forward in between, so the
//!   snapshot is never older than the sequence claims;
//! * a registered scope with no evidence yet (initial list in flight, relist not
//!   finished, `resourceVersion` unparsable) makes the whole watermark
//!   unavailable — a snapshot missing a resource type must not be stamped as if
//!   it were complete;
//! * an unavailable watermark does not publish an unsequenced or optimistic
//!   frame. [`K8sConfigRevisionTracker::publish`] retains the last published
//!   sequence and refuses to advance, so content still reaches data planes (an
//!   equal revision installs, by the gate's reconnect-replay rule) while
//!   ordering never overstates.
//!
//! # Monotonicity
//!
//! Per scope the watermark is a running maximum, so it never falls. The
//! aggregate minimum *can* fall when the scope set grows (a CRD installed later
//! adds a scope whose evidence is younger), so publication applies an in-process
//! floor — the same device the DB path uses — and never emits a sequence below
//! one it already published. Across a restart no floor is needed: a fresh
//! boundary read returns a current etcd revision, which is ≥ anything the
//! previous process could have observed.
//!
//! # Assumption, stated
//!
//! Kubernetes documents `resourceVersion` as opaque and does not guarantee
//! comparability across resource types. On every etcd-backed API server it is
//! the shared etcd revision, which is what makes a cross-type minimum
//! meaningful. The tracker therefore requires each value to parse as a `u64` and
//! treats anything else as *no evidence* — an API server whose versions are not
//! numeric produces no watermark and the CP publishes no advance, rather than
//! ordering on values it cannot interpret.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::modes::mesh::revision::MeshConfigRevision;

/// Identity of one watch scope: `(api_version, kind, scope)`.
///
/// Exactly the triple [`super::resource_store::CrdResourceStore`] is keyed by,
/// so tracker entries and reflector stores line up one-to-one.
pub type K8sWatchScopeKey = (String, String, String);

/// Build a [`K8sWatchScopeKey`].
pub fn watch_scope_key(api_version: &str, kind: &str, scope: &str) -> K8sWatchScopeKey {
    (api_version.to_string(), kind.to_string(), scope.to_string())
}

/// Longest `resourceVersion` accepted for parsing. `u64::MAX` is 20 digits; a
/// longer string cannot be a revision this tracker can order and is refused
/// before `parse` so a pathological value cannot be mistaken for one.
const MAX_RESOURCE_VERSION_DIGITS: usize = 20;

/// Parse a Kubernetes `resourceVersion` into an orderable revision.
///
/// Accepts ASCII digits only. `parse::<u64>()` alone would also accept a leading
/// `+`, which no API server emits and which would make two spellings of the same
/// revision compare unequal as strings while comparing equal as numbers.
///
/// Returns `None` for anything else — empty, signed, over-long, non-numeric, or
/// overflowing. The caller treats `None` as *no evidence*, never as zero. The
/// rejected value is never logged: it is API-server-supplied text that reaches
/// operator-facing records only through bounded diagnostics.
pub fn parse_resource_version(raw: &str) -> Option<u64> {
    if raw.is_empty() || raw.len() > MAX_RESOURCE_VERSION_DIGITS {
        return None;
    }
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>().ok()
}

/// Convergence evidence for one watch scope.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ScopeEvidence {
    /// Highest revision the scope's REGISTERED store is proven converged
    /// through. `None` until its first `InitDone`.
    converged: Option<u64>,
    /// Boundary captured before the current generation's list, pending adoption
    /// at that generation's first `InitDone`. Taken on adoption so a later
    /// kube-rs-internal relist inside the same generation cannot re-adopt a
    /// boundary that is by then older than the list it is describing.
    pending_boundary: Option<u64>,
    /// Highest revision among objects delivered by an initial list that has not
    /// reached `InitDone`. Held back because the reflector has not published
    /// them to the store yet.
    listed_max: Option<u64>,
}

impl ScopeEvidence {
    fn commit_list(&mut self) {
        let adopted = [self.pending_boundary.take(), self.listed_max.take()];
        for candidate in adopted.into_iter().flatten() {
            self.converged = Some(raise(self.converged, candidate));
        }
    }
}

/// Raise a running maximum. The one place a watermark ever changes, so it can
/// only ever move forward.
fn raise(current: Option<u64>, candidate: u64) -> u64 {
    current.map_or(candidate, |current| current.max(candidate))
}

/// Snapshot of tracker counters for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct K8sRevisionStats {
    /// Publications that could not advance because at least one registered
    /// scope had no convergence evidence, and retained the last sequence.
    pub withheld_advances: u64,
    /// Publications that emitted no revision at all because none had ever been
    /// established (pre-first-convergence).
    pub unsequenced_publications: u64,
    /// `resourceVersion` values that could not be parsed as an orderable
    /// revision. A non-zero value means this cluster's version space is not the
    /// numeric etcd one and ordering is unavailable by design.
    pub unparsable_resource_versions: u64,
}

/// Per-scope Kubernetes convergence evidence and the sequence published from it.
///
/// Cold path only: watcher event handling (config plane) and reconcile
/// publication. Nothing on the proxy request path touches it, so a plain
/// `Mutex` around the small per-scope map is correct and cheaper to reason about
/// than a lock-free structure that must not tear between a scope's boundary and
/// its listed maximum.
#[derive(Debug)]
pub struct K8sConfigRevisionTracker {
    /// Ordering domain this CP advertises, or `None` when revision publication
    /// is disabled (`FERRUM_MESH_CONFIG_AUTHORITY_ID=`).
    authority: Option<String>,
    scopes: Mutex<HashMap<K8sWatchScopeKey, ScopeEvidence>>,
    /// In-process monotonic floor for the published sequence.
    floor: AtomicU64,
    /// Whether a sequence has ever been established. Distinguishes "publish
    /// nothing" (bootstrap) from "republish the floor" (refuse to advance).
    established: AtomicBool,
    /// Whether the last publication withheld an advance, so the operator-facing
    /// warning fires on the edge rather than once per reconcile.
    withholding: AtomicBool,
    withheld_advances: AtomicU64,
    unsequenced_publications: AtomicU64,
    unparsable_resource_versions: AtomicU64,
}

impl K8sConfigRevisionTracker {
    /// Create a tracker for `authority`, or a disabled one (`None`) that never
    /// publishes a revision.
    pub fn new(authority: Option<String>) -> Self {
        Self {
            authority,
            scopes: Mutex::new(HashMap::new()),
            floor: AtomicU64::new(0),
            established: AtomicBool::new(false),
            withholding: AtomicBool::new(false),
            withheld_advances: AtomicU64::new(0),
            unsequenced_publications: AtomicU64::new(0),
            unparsable_resource_versions: AtomicU64::new(0),
        }
    }

    /// Whether this tracker publishes revisions at all.
    pub fn is_enabled(&self) -> bool {
        self.authority.is_some()
    }

    pub fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }

    /// Register the boundary captured before a watcher generation's list.
    ///
    /// Deliberately does NOT clear `converged`: a replacement generation is
    /// make-before-break, so the previous generation's store stays registered
    /// and its evidence stays valid until the replacement's `InitDone` swaps it
    /// in. A frozen store cannot become less converged than it already was.
    pub fn begin_generation(&self, scope: &K8sWatchScopeKey, boundary: Option<u64>) {
        let mut scopes = self.lock_scopes();
        let evidence = scopes.entry(scope.clone()).or_default();
        evidence.pending_boundary = boundary;
        evidence.listed_max = None;
    }

    /// Record an object delivered by an initial list (`InitApply`).
    ///
    /// Buffered until [`Self::commit_list`] because the reflector publishes an
    /// initial list to its store atomically at `InitDone`.
    pub fn observe_listed(&self, scope: &K8sWatchScopeKey, resource_version: Option<&str>) {
        let Some(revision) = self.parse_observed(resource_version) else {
            return;
        };
        // `get_mut`, never `entry`: a scope whose store was deregistered must
        // not be resurrected by a late event, and the common path then costs no
        // key allocation.
        let mut scopes = self.lock_scopes();
        if let Some(evidence) = scopes.get_mut(scope) {
            evidence.listed_max = Some(raise(evidence.listed_max, revision));
        }
    }

    /// Record an incremental watch event (`Apply` / `Delete`) the reflector has
    /// already applied to the live store.
    ///
    /// A deletion carries the deletion revision, so a withdrawal advances the
    /// watermark rather than lowering it — the failure mode that rules
    /// max-over-live-objects out entirely.
    pub fn observe_applied(&self, scope: &K8sWatchScopeKey, resource_version: Option<&str>) {
        let Some(revision) = self.parse_observed(resource_version) else {
            return;
        };
        let mut scopes = self.lock_scopes();
        if let Some(evidence) = scopes.get_mut(scope) {
            evidence.converged = Some(raise(evidence.converged, revision));
        }
    }

    /// Adopt the pending boundary and the buffered list maximum (`InitDone`).
    ///
    /// Callers that swap a replacement store into the store set must do so
    /// BEFORE calling this: until the swap the evidence would describe a store
    /// nothing can read.
    pub fn commit_list(&self, scope: &K8sWatchScopeKey) {
        let mut scopes = self.lock_scopes();
        if let Some(evidence) = scopes.get_mut(scope) {
            evidence.commit_list();
        }
    }

    /// Drop a scope whose store has been deregistered.
    ///
    /// Its objects leave the reconcile snapshot at the same moment, so its
    /// evidence must leave with them; retaining a frozen watermark for content
    /// that is no longer in the snapshot would describe neither.
    pub fn forget_scope(&self, scope: &K8sWatchScopeKey) {
        self.lock_scopes().remove(scope);
    }

    /// Convergence watermark for exactly `scopes` — the minimum over their
    /// per-scope evidence.
    ///
    /// `None` when any listed scope has no evidence yet, or when the set is
    /// empty (no watchers registered means no snapshot worth sequencing). The
    /// caller must pin `scopes` from the same `ResourceStoreSet` lock it
    /// materializes the snapshot under, and must call this BEFORE materializing.
    pub fn converged_watermark<'a, I>(&self, scopes: I) -> Option<u64>
    where
        I: IntoIterator<Item = &'a K8sWatchScopeKey>,
    {
        let evidence = self.lock_scopes();
        let mut watermark: Option<u64> = None;
        let mut any = false;
        for scope in scopes {
            any = true;
            let converged = evidence.get(scope).and_then(|entry| entry.converged)?;
            watermark = Some(watermark.map_or(converged, |low| low.min(converged)));
        }
        if !any {
            return None;
        }
        watermark
    }

    /// Turn a watermark into the revision to stamp on this publication.
    ///
    /// * `Some(watermark)` — publish `max(watermark, floor)`, which keeps the
    ///   sequence monotonic when the aggregate minimum dips because the scope
    ///   set grew.
    /// * `None` with a sequence already established — republish the floor. The
    ///   content still reaches data planes (an equal revision installs, by the
    ///   gate's reconnect-replay rule) while the ordering claim does not move.
    /// * `None` with nothing established — publish no revision. Data planes
    ///   bootstrap unversioned, exactly as they did before this feature; the
    ///   first established sequence then bootstraps the gate.
    ///
    /// Publication never regresses from a revision to none, because `established`
    /// is sticky: an `Unversioned` frame after a versioned one is a quarantine.
    pub fn publish(&self, watermark: Option<u64>) -> Option<MeshConfigRevision> {
        let authority = self.authority.as_deref()?;
        let sequence = match watermark {
            Some(watermark) => {
                let previous = self.floor.fetch_max(watermark, Ordering::AcqRel);
                self.established.store(true, Ordering::Release);
                if self.withholding.swap(false, Ordering::Relaxed) {
                    tracing::info!(
                        sequence = previous.max(watermark),
                        "Kubernetes mesh config revision evidence is complete again; resuming \
                         authoritative sequence advancement"
                    );
                }
                previous.max(watermark)
            }
            None if self.established.load(Ordering::Acquire) => {
                self.withheld_advances.fetch_add(1, Ordering::Relaxed);
                let retained = self.floor.load(Ordering::Acquire);
                if !self.withholding.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        retained_sequence = retained,
                        "At least one Kubernetes watch scope has no resourceVersion convergence \
                         evidence; retaining the last authoritative mesh config revision and \
                         refusing to advance it"
                    );
                }
                retained
            }
            None => {
                let unsequenced = &self.unsequenced_publications;
                unsequenced.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        Some(MeshConfigRevision::new(authority, sequence))
    }

    pub fn stats(&self) -> K8sRevisionStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        K8sRevisionStats {
            withheld_advances: load(&self.withheld_advances),
            unsequenced_publications: load(&self.unsequenced_publications),
            unparsable_resource_versions: load(&self.unparsable_resource_versions),
        }
    }

    fn parse_observed(&self, resource_version: Option<&str>) -> Option<u64> {
        let raw = resource_version?;
        match parse_resource_version(raw) {
            Some(revision) => Some(revision),
            None => {
                // Never echo the value: it is API-server-supplied text and the
                // count alone is the actionable signal.
                let unparsable = &self.unparsable_resource_versions;
                unparsable.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Lock helper that keeps a poisoned mutex usable. The guarded state is
    /// plain evidence with no broken invariant to preserve, and a panic in one
    /// watcher task must not wedge config publication for the process.
    fn lock_scopes(&self) -> std::sync::MutexGuard<'_, HashMap<K8sWatchScopeKey, ScopeEvidence>> {
        match self.scopes.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
