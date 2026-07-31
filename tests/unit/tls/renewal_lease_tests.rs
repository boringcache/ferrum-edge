//! Issue #2409: exactly one instance renews a given ACME certificate.
//!
//! Every serving replica runs its own renewal scheduler. The shared lease table
//! is what makes the renewal decision single-writer: a claim is granted to one
//! holder, excludes *every* other acquirer while it is live — including one
//! presenting the same instance identity — expires on its own so a crashed
//! holder fails over, and carries a fence so a superseded holder cannot
//! resurrect its claim.
//!
//! The claim also has to survive the operation it guards. ACME does not fence
//! side effects for Ferrum, so a static TTL bounds nothing once an
//! order/finalize cycle runs long; `RenewalLeaseKeeper` heartbeats the claim for
//! the whole renewal and cancels the in-flight work the moment it is lost.

//! Store commits are additionally *fenced*: the mutation runs while the lease
//! table's own exclusive lock is held, so acquisition and takeover cannot cross
//! it and a superseded owner can never land a stale write beside the new
//! owner's.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ferrum_edge::tls::lease::{
    FencedCommit, GuardedCleanup, RenewalLeaseKeeper, TlsLeaseError, TlsLeaseStore,
    acme_renewal_lease_name,
};

/// One replica's view of the shared lease table.
fn instance(dir: &Path, holder: &str) -> Arc<TlsLeaseStore> {
    let opened = TlsLeaseStore::open_with_holder(dir, holder.to_string());
    Arc::new(opened.expect("open lease store"))
}

/// Poll the persisted record until a heartbeat has advanced `expires_at` past
/// `beyond`, or give up after `timeout`.
///
/// Event driven rather than a blind sleep: a paused scheduler costs latency
/// here instead of turning correct production behaviour into a red test, and
/// the absence of any beat still fails (through the caller's diagnostic) rather
/// than passing because a sleep happened to be long enough.
async fn wait_for_extension(
    store: &Arc<TlsLeaseStore>,
    name: &str,
    beyond: DateTime<Utc>,
    timeout: Duration,
) -> Option<DateTime<Utc>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(record)) = store.peek(name)
            && record.expires_at > beyond
        {
            return Some(record.expires_at);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Sleep until wall-clock time is past `moment`, in bounded steps, so the
/// "operation" outlives a specific expiry rather than a guessed duration.
async fn sleep_until_past(moment: DateTime<Utc>) {
    loop {
        let Ok(remaining) = (moment - Utc::now()).to_std() else {
            return;
        };
        tokio::time::sleep(remaining.max(Duration::from_millis(25))).await;
    }
}

#[test]
fn only_one_instance_can_hold_a_renewal_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A must win the first claim");
    assert_eq!(lease.holder(), "replica-a");
    assert_eq!(lease.name(), name);

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(denied.is_none(), "a live claim must exclude the other");

    let record = instance_b.peek(&name).expect("B reads");
    assert_eq!(record.expect("claim present").holder, "replica-a");
}

#[test]
fn an_expired_claim_fails_over_to_another_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let short = Duration::from_millis(150);

    let held = instance_a.try_acquire(&name, short).expect("A claims");
    let lease = held.expect("A must win the first claim");
    // A crashed holder never releases. Leaking the guard reproduces that
    // exactly: only expiry can hand the claim over.
    std::mem::forget(lease);

    let denied = instance_b.try_acquire(&name, short).expect("B attempts");
    assert!(denied.is_none(), "the claim is still live");

    std::thread::sleep(Duration::from_millis(400));

    let taken = instance_b.try_acquire(&name, short).expect("B retries");
    let lease = taken.expect("an expired claim must fail over");
    assert_eq!(lease.holder(), "replica-b");
}

#[test]
fn releasing_a_claim_lets_another_instance_take_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A must win the first claim");
    lease.release().expect("A releases");

    let taken = instance_b.try_acquire(&name, ttl).expect("B claims");
    let lease = taken.expect("B must take the released claim");
    assert_eq!(lease.holder(), "replica-b");
}

#[test]
fn dropping_a_claim_releases_it_for_another_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    {
        let held = instance_a.try_acquire(&name, ttl).expect("A claims");
        assert!(held.is_some(), "A must win the first claim");
    }

    let taken = instance_b.try_acquire(&name, ttl).expect("B claims");
    assert!(taken.is_some(), "a dropped claim must not wedge renewal");
}

#[test]
fn a_superseded_holder_cannot_renew_its_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let short = Duration::from_millis(150);

    let held = instance_a.try_acquire(&name, short).expect("A claims");
    let stale = held.expect("A must win the first claim");
    std::thread::sleep(Duration::from_millis(400));

    let taken = instance_b.try_acquire(&name, short).expect("B claims");
    let fresh = taken.expect("B takes over the expired claim");
    assert_ne!(stale.fence(), fresh.fence(), "takeover bumps the fence");

    let renewed = stale.renew(short).expect("stale renew is answered");
    assert!(!renewed, "a superseded holder must not extend the claim");

    let record = instance_a.peek(&name).expect("read");
    assert_eq!(record.expect("claim present").holder, "replica-b");
}

#[test]
fn a_live_holder_can_extend_its_own_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(400);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A must win the first claim");
    let before = instance_a.peek(&name).expect("read").expect("present");

    assert!(lease.renew(Duration::from_secs(60)).expect("renew"));

    let after = instance_a.peek(&name).expect("read").expect("present");
    assert!(after.expires_at > before.expires_at, "renewal extends");
    assert_eq!(after.fence, before.fence, "renewal keeps the fence");

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(denied.is_none(), "the extended claim still excludes B");
}

#[test]
fn distinct_certificates_get_independent_claims() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let first = acme_renewal_lease_name("cert-one");
    let second = acme_renewal_lease_name("cert-two");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&first, ttl).expect("A claims");
    assert!(held.is_some(), "A takes the first certificate");
    let held = instance_b.try_acquire(&second, ttl).expect("B claims");
    assert!(held.is_some(), "B renews a different certificate");

    let denied = instance_b.try_acquire(&first, ttl).expect("B attempts");
    assert!(denied.is_none(), "the first claim is still A's");
}

/// A second process presenting the *same* holder identity must be denied while
/// the claim is live. Two processes can share an identity through a duplicated
/// `FERRUM_TLS_STORE_INSTANCE_ID` or an overlapping rolling replacement, and
/// letting the newcomer reacquire would bump the fence and start a second
/// renewal while the original is still driving external ACME work — which the
/// original would only notice at its next explicit check.
#[test]
fn a_second_instance_with_the_same_identity_cannot_take_a_live_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let original = held.expect("A must win the first claim");

    let twin = instance(dir.path(), "replica-a");
    let denied = twin.try_acquire(&name, ttl).expect("the twin attempts");
    assert!(
        denied.is_none(),
        "a live claim must exclude a same-identity acquirer too"
    );

    let record = twin.peek(&name).expect("read").expect("claim present");
    assert_eq!(
        record.fence,
        original.fence(),
        "a denied acquisition must not advance the fence under the live holder"
    );
    assert!(
        original.renew(ttl).expect("the original renews"),
        "the original holder keeps its claim"
    );
}

/// Crash recovery for a same-identity restart happens through expiry, not
/// through immediate reclamation — and the takeover advances the fence, so the
/// dead generation can no longer renew or release.
#[test]
fn a_same_identity_restart_reclaims_only_after_expiry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let short = Duration::from_millis(150);

    let held = instance_a.try_acquire(&name, short).expect("A claims");
    let crashed = held.expect("A must win the first claim");
    let crashed_fence = crashed.fence();
    // A crashed holder never releases; leaking the guard reproduces that.
    std::mem::forget(crashed);

    let restarted = instance(dir.path(), "replica-a");
    let denied = restarted.try_acquire(&name, short).expect("restart attempts");
    assert!(denied.is_none(), "the claim is still live");

    std::thread::sleep(Duration::from_millis(400));

    let taken = restarted.try_acquire(&name, short).expect("restart retries");
    let lease = taken.expect("an expired claim must be reclaimable");
    assert_eq!(lease.holder(), "replica-a");
    assert!(
        lease.fence() > crashed_fence,
        "takeover must advance the fence past the crashed generation"
    );
}

/// A configured instance id is validated, never sanitized. Silently dropping
/// disallowed characters or truncating an overlong value maps two distinct
/// configured identities onto one, which is exactly the collision that lets a
/// second process reacquire a live claim.
#[test]
fn an_invalid_configured_instance_id_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");

    let empty = TlsLeaseStore::open_with_holder(dir.path(), String::new());
    assert!(matches!(empty, Err(TlsLeaseError::InvalidInstanceId(_))));

    let blank = TlsLeaseStore::open_with_holder(dir.path(), "   ".to_string());
    assert!(matches!(blank, Err(TlsLeaseError::InvalidInstanceId(_))));

    // Would previously have been sanitized to `pod-a1`, colliding with a real
    // `pod-a1` replica.
    let punctuated = TlsLeaseStore::open_with_holder(dir.path(), "pod-a/1".to_string());
    assert!(matches!(
        punctuated,
        Err(TlsLeaseError::InvalidInstanceId(_))
    ));

    // Would previously have been truncated to the shared 128-character prefix.
    let overlong = format!("{}-one", "n".repeat(128));
    let overlong = TlsLeaseStore::open_with_holder(dir.path(), overlong);
    assert!(matches!(overlong, Err(TlsLeaseError::InvalidInstanceId(_))));

    let accepted = TlsLeaseStore::open_with_holder(dir.path(), "pod-a.ns:1".to_string());
    assert_eq!(accepted.expect("valid identity").holder(), "pod-a.ns:1");
}

/// The failure message names the rule, never the configured value: an instance
/// id is operator-supplied text that flows into logs and shared state.
#[test]
fn an_invalid_instance_id_error_does_not_echo_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rejected = "pod-a/secret-looking-value";
    let error = TlsLeaseStore::open_with_holder(dir.path(), rejected.to_string())
        .err()
        .expect("must be rejected");
    assert!(
        !error.to_string().contains(rejected),
        "the diagnostic must not echo the configured identity"
    );
}

/// Two configured identities that a sanitizer would collapse must stay
/// distinct: whichever holds the claim, the other is excluded.
#[test]
fn identities_that_a_sanitizer_would_collide_stay_distinct() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = instance(dir.path(), "pod-a-1");
    let second = instance(dir.path(), "pod-a-2");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = first.try_acquire(&name, ttl).expect("first claims");
    assert!(held.is_some(), "the first identity wins");
    let denied = second.try_acquire(&name, ttl).expect("second attempts");
    assert!(denied.is_none(), "a distinct identity is excluded");
}

// ---------------------------------------------------------------------------
// Continuous lease maintenance for the whole external renewal operation.
//
// The TTL alone bounds nothing: ACME does not fence side effects for Ferrum, so
// an order/finalize cycle that outruns the TTL would let a second replica
// acquire and start ordering while the first is still polling. The keeper is
// what closes that window.
// ---------------------------------------------------------------------------

/// A renewal that outlives the claim's *original* expiry still has exactly one
/// owner, because the heartbeat keeps extending it while the work is in flight.
///
/// The proof is state driven, not timing driven. A persisted extension is
/// observed first (so a missing heartbeat fails on the diagnostic timeout, not
/// on a sleep that was merely long enough), then the operation is run until
/// wall-clock time is genuinely past the original expiry, then exclusion is
/// re-asserted. The TTL is deliberately generous — production clamps it to at
/// least 60 seconds — so a scheduler pause on a shared runner cannot expire a
/// claim the heartbeat is servicing correctly.
#[tokio::test]
async fn a_long_operation_retains_exactly_one_owner_via_the_heartbeat() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    // Beats every 2s; tolerates a ~4s pause between beats.
    let ttl = Duration::from_secs(6);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    let original_expiry = instance_a.peek(&name).expect("read").expect("present").expires_at;

    // Proof one: a beat actually reached the shared table. Without a heartbeat
    // this never happens and the test fails here.
    let extended = wait_for_extension(&instance_a, &name, original_expiry, Duration::from_secs(60))
        .await
        .expect("the heartbeat must persist an extension of the claim");
    assert!(
        extended > original_expiry,
        "the persisted claim must have been extended past its original expiry"
    );

    // Proof two: stand in for account registration, order creation, challenge
    // publication, propagation, polling, and finalization — work that runs
    // until the original expiry is genuinely in the past.
    keeper
        .guarded(sleep_until_past(original_expiry))
        .await
        .expect("the claim survives work that outlives its original TTL");
    assert!(
        Utc::now() > original_expiry,
        "the operation must have crossed the original expiry"
    );
    keeper.ensure_owned().await.expect("still the owner");

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(
        denied.is_none(),
        "the heartbeat must keep the claim live for the whole operation"
    );

    keeper.finish().await.expect("release");

    let taken = instance_b.try_acquire(&name, ttl).expect("B retries");
    assert!(
        taken.is_some(),
        "a released claim must hand over immediately"
    );
}

/// A lease table showing another live holder, as a replica that was paused past
/// its expiry and then resumed would find.
fn takeover_document(name: &str) -> String {
    format!(
        concat!(
            r#"{{"version":99,"leases":{{"{name}":{{"#,
            r#""holder":"replica-b","#,
            r#""acquired_at":"2026-01-01T00:00:00Z","#,
            r#""expires_at":"2999-01-01T00:00:00Z","#,
            r#""fence":9999}}}}}}"#
        ),
        name = name
    )
}

/// Losing the claim cancels the in-flight operation instead of letting it run to
/// completion and publish final state.
#[tokio::test]
async fn losing_the_claim_cancels_in_flight_work() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // Another instance took the claim over while this one was stalled. The next
    // heartbeat must see the foreign holder and higher fence.
    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate a takeover by another instance");

    // Stands in for the rest of the ACME cycle: polling, finalization, download.
    let remaining_work = tokio::time::sleep(Duration::from_secs(30));
    let outcome = keeper.guarded(remaining_work).await;
    assert!(
        outcome.is_err(),
        "guarded work must be cancelled once the claim is lost"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");
    assert!(
        keeper.ensure_owned().await.is_err(),
        "a superseded holder must not be allowed to publish final state"
    );

    // The takeover survives: the superseded holder must not have released or
    // rewritten the new owner's claim.
    let record = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(record.holder, "replica-b");
    assert_eq!(record.fence, 9999);
}

/// A store that cannot be read or written fails closed: the renewal is
/// cancelled rather than continued on the assumption that the claim still
/// holds.
#[tokio::test]
async fn a_heartbeat_store_error_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // Corrupt the shared lease table the way a truncated write or a foreign
    // writer would. Every subsequent read fails closed rather than degrading to
    // an empty document.
    std::fs::write(dir.path().join("tls-leases.json"), b"{ not json").expect("corrupt the table");

    let long = tokio::time::sleep(Duration::from_secs(30));
    let outcome = keeper.guarded(long).await;
    assert!(
        outcome.is_err(),
        "an unreadable lease table must cancel the renewal"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");
    assert!(
        keeper.ensure_owned().await.is_err(),
        "final state must not be published after a heartbeat store error"
    );
}

/// An abandoned keeper stops heartbeating. Without this a keeper dropped
/// without `finish()` — an early return, a panic, a cancelled scheduler — would
/// keep a claim alive for a renewal nobody is driving, wedging the certificate
/// until the process exits.
#[tokio::test]
async fn an_abandoned_keeper_stops_heartbeating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    assert!(!keeper.is_lost());
    // Dropped without `finish()`.
    std::mem::drop(keeper);

    let after_drop = instance_a.peek(&name).expect("read").expect("present");
    tokio::time::sleep(Duration::from_millis(900)).await;
    let later = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(
        after_drop.expires_at, later.expires_at,
        "a dropped keeper must not keep extending its claim"
    );

    let taken = instance_b.try_acquire(&name, ttl).expect("B retries");
    assert!(
        taken.is_some(),
        "the certificate must become reclaimable again"
    );
}

// ---------------------------------------------------------------------------
// Fenced commits.
//
// The lease table and the account/order/certificate stores are separate
// documents behind separate locks, so an ownership check on each side of a
// write bounds nothing: a claim that expires mid-write lets another replica
// acquire and publish while the stale write still lands, and the after-check
// detects a loss it cannot undo. The commit therefore runs while the lease
// store's own exclusive lock is held.
// ---------------------------------------------------------------------------

/// A superseded owner's target-store mutation must never run at all — detecting
/// the loss afterwards would be too late to unpublish a certificate.
#[tokio::test]
async fn a_target_store_mutation_cannot_run_after_ownership_is_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // Another instance took the claim over while this one was stalled.
    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate a takeover by another instance");

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    let outcome = keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await;
    assert!(
        outcome.is_err(),
        "a superseded owner must not be allowed to commit"
    );
    assert!(
        !published.load(Ordering::SeqCst),
        "the target-store mutation must not run once ownership is gone"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");

    // The new owner's claim is untouched: a refused commit writes nothing.
    let record = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(record.holder, "replica-b");
    assert_eq!(record.fence, 9999);
}

/// An absent claim — the lease table was reset, or the record pruned — is the
/// same fail-closed answer as a superseded one.
#[tokio::test]
async fn a_missing_claim_refuses_the_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    std::fs::write(
        dir.path().join("tls-leases.json"),
        br#"{"version":7,"leases":{}}"#,
    )
    .expect("reset the lease table");

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    let outcome = keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await;
    assert!(outcome.is_err(), "an absent claim must refuse the commit");
    assert!(
        !published.load(Ordering::SeqCst),
        "the target-store mutation must not run without a claim"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");
}

/// A takeover cannot be granted while a fenced commit is in flight, even once
/// the claim's nominal TTL has elapsed — the acquirer blocks on the same lease
/// lock. Once the commit has finished, the newly expired claim is acquirable
/// and the stale owner cannot commit a second time.
#[test]
fn a_takeover_cannot_cross_a_fenced_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    // Short enough that the nominal TTL elapses during the commit below.
    let ttl = Duration::from_millis(500);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A wins");
    let fence = lease.fence();
    // No heartbeat and no release: the owner is mid-write when its claim ages
    // out. Leaking the guard reproduces that without racing the commit.
    std::mem::forget(lease);

    let finished = Arc::new(AtomicBool::new(false));
    let commit_flag = Arc::clone(&finished);
    let committing = Arc::clone(&instance_a);
    let commit_name = name.clone();
    let commit = std::thread::spawn(move || {
        committing.commit_fenced(&commit_name, fence, move || {
            // A slow account/order/certificate mutation.
            std::thread::sleep(Duration::from_millis(1_500));
            commit_flag.store(true, Ordering::SeqCst);
            "published"
        })
    });

    // Well past the nominal TTL, and well before the commit completes.
    std::thread::sleep(Duration::from_millis(700));
    assert!(
        !finished.load(Ordering::SeqCst),
        "the commit must still be in flight"
    );

    let taken = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(
        finished.load(Ordering::SeqCst),
        "a takeover must not be granted while a fenced commit holds the lease lock"
    );
    assert!(
        taken.is_some(),
        "once the commit released the lock, the expired claim must be acquirable"
    );

    let outcome = commit
        .join()
        .expect("commit thread")
        .expect("the commit is answered");
    assert_eq!(
        outcome,
        FencedCommit::Committed("published"),
        "a commit that started under a live claim finishes under it"
    );

    let second = Arc::new(AtomicBool::new(false));
    let second_flag = Arc::clone(&second);
    let refused = instance_a
        .commit_fenced(&name, fence, move || {
            second_flag.store(true, Ordering::SeqCst);
        })
        .expect("the second attempt is answered");
    assert_eq!(
        refused,
        FencedCommit::NotOwner,
        "the stale owner is superseded once the takeover landed"
    );
    assert!(
        !second.load(Ordering::SeqCst),
        "a superseded owner must not perform a second commit"
    );
}

/// A target-store failure is not a lease failure: it propagates to the caller
/// and leaves the claim exactly as it was, rather than rewriting or releasing
/// the record another holder may be relying on.
#[test]
fn a_target_store_error_propagates_without_disturbing_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A wins");
    let before = instance_a.peek(&name).expect("read").expect("present");

    let outcome = instance_a
        .commit_fenced(&name, lease.fence(), || {
            Err::<(), String>("shared TLS store write failed".to_string())
        })
        .expect("the commit itself succeeds");
    assert_eq!(
        outcome,
        FencedCommit::Committed(Err("shared TLS store write failed".to_string())),
        "the target store's own error must be carried out to the caller"
    );

    let after = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(
        before, after,
        "a failed target-store write must not rewrite or release the claim"
    );

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(denied.is_none(), "the claim is still exclusively A's");
    assert!(
        lease.renew(ttl).expect("A renews"),
        "A must still be able to maintain the claim it never lost"
    );
}

// ---------------------------------------------------------------------------
// Cleanup is a side effect too.
// ---------------------------------------------------------------------------

/// Losing the claim cancels DNS-01 cleanup. The instance that took over
/// republishes the same `_acme-challenge` names, so a superseded instance
/// retracting them would break the new owner's validation — and nothing later
/// in the renewal may publish either.
#[tokio::test]
async fn losing_the_claim_cancels_dns_cleanup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // The takeover lands as finalization completes, i.e. exactly when cleanup
    // would otherwise run unguarded.
    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate a takeover by another instance");

    let retracted = Arc::new(AtomicBool::new(false));
    let retract = Arc::clone(&retracted);
    // Stands in for the DNS-01 cleanup hook: slow enough that the heartbeat
    // observes the takeover while it is in flight.
    let cleanup = async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        retract.store(true, Ordering::SeqCst);
        Ok::<(), String>(())
    };
    assert_eq!(
        keeper.guarded_cleanup(cleanup).await,
        GuardedCleanup::Lost,
        "cleanup must be cancelled when the claim is lost"
    );
    assert!(
        !retracted.load(Ordering::SeqCst),
        "a superseded instance must not retract the new owner's challenge records"
    );

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    let commit = keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await;
    assert!(
        commit.is_err(),
        "an abandoned renewal must not progress into final publication"
    );
    assert!(
        !published.load(Ordering::SeqCst),
        "no unguarded side effect may follow a cancelled cleanup"
    );
}

/// An ordinary cleanup-hook failure is *not* loss: it is reported so the caller
/// can log it, and the renewal keeps going under the claim it still holds.
#[tokio::test]
async fn an_ordinary_cleanup_failure_keeps_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    let cleanup = async { Err::<(), String>("hook exited 1".to_string()) };
    assert_eq!(
        keeper.guarded_cleanup(cleanup).await,
        GuardedCleanup::Failed("hook exited 1".to_string()),
        "a hook failure must be reported rather than treated as loss"
    );
    assert!(!keeper.is_lost(), "the claim is still held");

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await
        .expect("certificate processing continues under the same claim");
    assert!(published.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------
// Heartbeat shutdown.
// ---------------------------------------------------------------------------

/// `finish()` settles the heartbeat before releasing the claim.
///
/// Aborting the heartbeat task is not settlement: if it is parked on a
/// `spawn_blocking` extension, dropping that join handle neither cancels nor
/// joins the blocking work, so a beat can still land *after* the release and
/// leave a claim alive that nobody is driving.
#[tokio::test]
async fn finish_settles_an_in_flight_heartbeat_before_release() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    // Beats every 200ms, so the loop is demonstrably active before `finish()`.
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    let acquired = instance_a.peek(&name).expect("read").expect("present").expires_at;

    wait_for_extension(&instance_a, &name, acquired, Duration::from_secs(30))
        .await
        .expect("the heartbeat must be running before finish() is exercised");

    keeper.finish().await.expect("release");

    let released = instance_a.peek(&name).expect("read").expect("present");
    assert!(
        released.expires_at <= Utc::now(),
        "finish() must leave the claim released"
    );

    // Nothing may land afterwards. An aborted-but-unjoined beat would have been
    // free to extend the record here, resurrecting a released claim.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let later = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(
        released, later,
        "no heartbeat may land after finish() returned"
    );

    let taken = instance_b.try_acquire(&name, ttl).expect("B claims");
    assert!(
        taken.is_some(),
        "a settled, released claim hands over immediately"
    );
}
