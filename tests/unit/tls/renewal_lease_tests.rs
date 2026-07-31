//! Issue #2409: exactly one instance renews a given ACME certificate.
//!
//! Every serving replica runs its own renewal scheduler. The shared lease table
//! is what makes the renewal decision single-writer: a claim is granted to one
//! holder, excludes the others while it is live, expires on its own so a
//! crashed holder fails over, and carries a fence so a superseded holder cannot
//! resurrect its claim.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::tls::lease::{TlsLeaseStore, acme_renewal_lease_name};

/// One replica's view of the shared lease table.
fn instance(dir: &Path, holder: &str) -> Arc<TlsLeaseStore> {
    let opened = TlsLeaseStore::open_with_holder(dir, holder.to_string());
    Arc::new(opened.expect("open lease store"))
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

#[test]
fn a_restarted_instance_reclaims_its_own_live_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    std::mem::forget(held.expect("A must win the first claim"));

    // Same pinned instance identity after a restart: the replica takes its own
    // claim back instead of waiting out its own lease.
    let restarted = instance(dir.path(), "replica-a");
    let taken = restarted.try_acquire(&name, ttl).expect("A restarts");
    let lease = taken.expect("an instance reclaims its own live claim");
    assert_eq!(lease.holder(), "replica-a");
}
