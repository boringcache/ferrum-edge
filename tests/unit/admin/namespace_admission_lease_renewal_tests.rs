//! Namespace config admission lease renewal under datastore stalls (#4146).
//!
//! The production renewer is driven directly against a fault-injecting lease
//! backend, on a timing envelope scaled from production's 120s/30s/1s to
//! 2400ms/600ms/40ms. The 4:1 lease-to-renew-interval ratio is preserved, and
//! every bound the renewer applies is derived from that envelope, so the scaled
//! runs exercise the identical arithmetic.

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    TestLeaseBackend, TestLeaseRenewalOutcome, TestLeaseRenewalTiming,
    run_namespace_config_admission_renewal_for_test,
};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const LEASE_DURATION_MS: u64 = 2_400;
const RENEW_INTERVAL_MS: u64 = 600;
const RETRY_INTERVAL_MS: u64 = 40;

fn scaled_timing() -> TestLeaseRenewalTiming {
    TestLeaseRenewalTiming {
        lease_duration_ms: LEASE_DURATION_MS,
        renew_interval_ms: RENEW_INTERVAL_MS,
        retry_interval_ms: RETRY_INTERVAL_MS,
    }
}

/// A single `config_admission_locks` row with injectable faults.
struct FakeLeaseRow {
    owner: String,
    generation: u64,
    expires_at: Instant,
    /// No renewal or acquisition answers before this instant. Models the
    /// datastore stall that precedes the observed lost-ownership errors.
    stalled_until: Option<Instant>,
    /// Number of remaining renewals that report "not yours" without touching
    /// the row. Models a late-applied statement or datastore clock skew: the
    /// row itself is untouched and still this owner's.
    renew_refusals: u32,
    /// When set, the next reclaim reports this generation instead of the
    /// stored one, as if a foreign owner had held and released the row.
    reclaim_generation_override: Option<u64>,
    renew_calls: u32,
    acquire_calls: u32,
    release_calls: u32,
}

struct FakeLeaseBackend {
    lease_duration: Duration,
    row: Mutex<FakeLeaseRow>,
}

impl FakeLeaseBackend {
    fn new(owner: &str, generation: u64) -> Self {
        let lease_duration = Duration::from_millis(LEASE_DURATION_MS);
        Self {
            lease_duration,
            row: Mutex::new(FakeLeaseRow {
                owner: owner.to_string(),
                generation,
                expires_at: Instant::now() + lease_duration,
                stalled_until: None,
                renew_refusals: 0,
                reclaim_generation_override: None,
                renew_calls: 0,
                acquire_calls: 0,
                release_calls: 0,
            }),
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, FakeLeaseRow> {
        match self.row.lock() {
            Ok(row) => row,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn stall_for(&self, stall: Duration) {
        self.locked().stalled_until = Some(Instant::now() + stall);
    }

    fn refuse_renewals(&self, count: u32) {
        self.locked().renew_refusals = count;
    }

    fn hand_row_to(&self, owner: &str) {
        let mut row = self.locked();
        row.owner = owner.to_string();
        row.generation += 1;
        row.expires_at = Instant::now() + self.lease_duration;
    }

    fn override_reclaim_generation(&self, generation: u64) {
        self.locked().reclaim_generation_override = Some(generation);
    }

    fn counts(&self) -> (u32, u32, u32) {
        let row = self.locked();
        (row.renew_calls, row.acquire_calls, row.release_calls)
    }

    /// Block while a stall window is open. The guard is dropped first so a
    /// concurrent caller is not serialized behind the sleep.
    async fn wait_out_stall(&self) {
        let stalled_until = self.locked().stalled_until;
        if let Some(deadline) = stalled_until {
            let now = Instant::now();
            if deadline > now {
                tokio::time::sleep(deadline - now).await;
            }
        }
    }
}

#[async_trait]
impl ferrum_edge::config::db_backend::NamespaceConfigAdmissionLeaseBackend for FakeLeaseBackend {
    async fn try_acquire_namespace_config_admission_lease(
        &self,
        _namespace: &str,
        owner: &str,
    ) -> Result<Option<u64>, anyhow::Error> {
        self.wait_out_stall().await;
        let mut row = self.locked();
        row.acquire_calls += 1;
        let now = Instant::now();
        let claimable = row.owner == owner || row.expires_at <= now;
        if !claimable {
            return Ok(None);
        }
        if row.owner != owner {
            row.owner = owner.to_string();
            row.generation += 1;
        }
        row.expires_at = now + self.lease_duration;
        if let Some(generation) = row.reclaim_generation_override.take() {
            return Ok(Some(generation));
        }
        Ok(Some(row.generation))
    }

    async fn renew_namespace_config_admission_lease(
        &self,
        _namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> {
        self.wait_out_stall().await;
        let mut row = self.locked();
        row.renew_calls += 1;
        if row.renew_refusals > 0 {
            row.renew_refusals -= 1;
            return Ok(false);
        }
        let now = Instant::now();
        if row.owner != owner || row.expires_at <= now {
            return Ok(false);
        }
        row.expires_at = now + self.lease_duration;
        Ok(true)
    }

    async fn release_namespace_config_admission_lease(
        &self,
        _namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> {
        let mut row = self.locked();
        row.release_calls += 1;
        if row.owner != owner {
            return Ok(false);
        }
        row.expires_at = Instant::now();
        Ok(true)
    }
}

/// A stall two and a half renew intervals long — well past one renewal
/// interval, well inside the lease TTL — must be ridden out, not treated as a
/// loss.
///
/// Before #4146 the single unbounded `await` absorbed the whole stall and the
/// lease had already expired by the time the statement applied.
#[tokio::test]
async fn stall_longer_than_a_renew_interval_but_shorter_than_the_ttl_keeps_ownership() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-a", 7));
    backend.stall_for(Duration::from_millis(1_500));
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-a",
        7,
        scaled_timing(),
        Duration::from_millis(2_000),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Stopped,
        "a stall inside the lease window must not end the renewer: {observed:?}"
    );
    assert!(
        observed.still_held,
        "ownership must survive a stall shorter than the TTL: {observed:?}"
    );
    assert!(
        observed.retries >= 1,
        "the stall must be visible as at least one retried attempt: {observed:?}"
    );
    assert!(
        observed.renewals >= 1,
        "the renewer must have completed a renewal after the stall: {observed:?}"
    );
}

/// A stall that outlives the lease window still invalidates. The retry budget
/// is derived from the remaining validity, so it can never outlive real expiry.
#[tokio::test]
async fn stall_longer_than_the_ttl_fails_closed() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-b", 3));
    backend.stall_for(Duration::from_millis(20_000));
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-b",
        3,
        scaled_timing(),
        Duration::from_millis(6_000),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Expired,
        "a stall past the lease window must fail closed: {observed:?}"
    );
    assert!(
        !observed.still_held,
        "an expired lease must never report itself as held: {observed:?}"
    );
    assert_eq!(
        observed.renewals, 0,
        "nothing was renewable during the stall: {observed:?}"
    );
    assert!(
        observed.retries >= 2,
        "the window must be spent on bounded retries, not one blocking wait: {observed:?}"
    );

    let (_, acquires, releases) = backend.counts();
    assert_eq!(
        acquires, 0,
        "an expiring renewer must not claim a row it cannot prove: {observed:?}"
    );
    assert_eq!(
        releases, 0,
        "an expiring renewer has nothing to release: {observed:?}"
    );
}

/// A refused renewal whose row is still this owner's at the same generation is
/// re-acquired, not treated as a loss. Generation continuity is the proof that
/// no other writer was ever admitted.
#[tokio::test]
async fn refused_renewal_is_reclaimed_at_the_same_generation() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-c", 11));
    backend.refuse_renewals(1);
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-c",
        11,
        scaled_timing(),
        Duration::from_millis(1_500),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Stopped,
        "a same-generation reclaim must keep the renewer alive: {observed:?}"
    );
    assert!(
        observed.still_held,
        "a same-generation reclaim must keep the lease held: {observed:?}"
    );
    assert_eq!(
        observed.reclaims, 1,
        "exactly one reclaim should have recovered the window: {observed:?}"
    );

    let (_, acquires, releases) = backend.counts();
    assert_eq!(acquires, 1, "the reclaim is one acquisition: {observed:?}");
    assert_eq!(
        releases, 0,
        "a successful reclaim must not release the row it just proved: {observed:?}"
    );
}

/// When another writer genuinely holds the namespace, the renewer fails closed
/// instead of reclaiming. This is the split-brain fence.
#[tokio::test]
async fn ownership_taken_by_another_writer_fails_closed() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-d", 5));
    backend.hand_row_to("someone-else");
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-d",
        5,
        scaled_timing(),
        Duration::from_millis(1_500),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Lost,
        "a foreign owner must end the renewer: {observed:?}"
    );
    assert!(
        !observed.still_held,
        "a lost lease must never report itself as held: {observed:?}"
    );
    assert_eq!(
        observed.reclaims, 0,
        "a foreign owner is not reclaimable: {observed:?}"
    );
}

/// A reclaim that comes back at a generation this guard never acquired proves a
/// foreign owner was admitted. The claim it just took is released rather than
/// left holding the namespace for a full lease duration.
#[tokio::test]
async fn reclaim_at_a_foreign_generation_is_lost_and_releases_the_claim() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-e", 2));
    backend.refuse_renewals(1);
    backend.override_reclaim_generation(9);
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-e",
        2,
        scaled_timing(),
        Duration::from_millis(1_500),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Lost,
        "a generation change proves another writer was admitted: {observed:?}"
    );
    assert!(
        !observed.still_held,
        "a lost lease must never report itself as held: {observed:?}"
    );
    assert_eq!(
        observed.reclaims, 0,
        "a foreign generation is not a successful reclaim: {observed:?}"
    );

    let (_, acquires, releases) = backend.counts();
    assert_eq!(acquires, 1, "the reclaim attempt ran: {observed:?}");
    assert_eq!(
        releases, 1,
        "the unusable claim must be released, not leaked for a lease duration: {observed:?}"
    );
}
