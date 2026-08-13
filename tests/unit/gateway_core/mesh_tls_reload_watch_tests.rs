//! Generation-consumption coverage for mesh/ConfigSync gRPC TLS reload waits.
//!
//! Native MeshSubscribe and xDS ADS share `wait_optional_tls_reload`. A fresh
//! `watch::Receiver` clone stays immediately `changed()` after a send when the
//! stored receiver is only `borrow()`ed, which used to cancel every reconnect
//! attempt. These tests lock the last-observed-revision predicate: one
//! generation wakes once, a later generation wakes again, an unchanged
//! generation stays pending, and a generation published between check and arm
//! is not lost.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ferrum_edge::modes::mesh::config_consumer::common::{
    wait_for_shutdown, wait_optional_tls_reload,
};
use tokio::sync::watch;

const PENDING: Duration = Duration::from_millis(80);
const COMPLETE: Duration = Duration::from_secs(1);

const NATIVE_CLIENT: &str =
    include_str!("../../../src/modes/mesh/config_consumer/native_client.rs");
const XDS_CLIENT: &str = include_str!("../../../src/modes/mesh/config_consumer/xds_client.rs");
const STOCK_XDS_CLIENT: &str =
    include_str!("../../../src/modes/mesh/config_consumer/stock_xds_client.rs");
const DP_CLIENT: &str = include_str!("../../../src/grpc/dp_client.rs");

fn assert_pending<T>(result: Result<T, tokio::time::error::Elapsed>, detail: &str) {
    assert!(result.is_err(), "{detail}");
}

async fn wait_reload(rx: &watch::Receiver<u64>, last_revision: u64) {
    wait_optional_tls_reload(Some(rx.clone()), last_revision).await;
}

#[tokio::test]
async fn one_revision_wakes_once_rather_than_forever() {
    let (tx, stored_rx) = watch::channel(0u64);
    tx.send(1).expect("publish gen1");
    assert!(
        stored_rx.has_changed().expect("tls reload sender is alive"),
        "stored receiver stays unmarked when callers only borrow()"
    );

    tokio::time::timeout(COMPLETE, wait_reload(&stored_rx, 0))
        .await
        .expect("first unseen generation must wake");

    assert_pending(
        tokio::time::timeout(PENDING, wait_reload(&stored_rx, 1)).await,
        "an already-accepted generation must not retrigger on a fresh clone",
    );
}

#[tokio::test]
async fn later_revision_wakes_again_after_the_first_was_accepted() {
    let (tx, stored_rx) = watch::channel(0u64);
    tx.send(1).expect("publish gen1");
    tokio::time::timeout(COMPLETE, wait_reload(&stored_rx, 0))
        .await
        .expect("gen1 must wake");

    tx.send(2).expect("publish gen2");
    tokio::time::timeout(COMPLETE, wait_reload(&stored_rx, 1))
        .await
        .expect("a later generation must wake after gen1 was accepted");

    assert_pending(
        tokio::time::timeout(PENDING, wait_reload(&stored_rx, 2)).await,
        "accepted gen2 must stay pending until another generation arrives",
    );
}

#[tokio::test]
async fn unchanged_revision_stays_pending() {
    let (_tx, stored_rx) = watch::channel(0u64);
    assert_pending(
        tokio::time::timeout(PENDING, wait_reload(&stored_rx, 0)).await,
        "unchanged initial generation must not wake a reload wait",
    );
}

#[tokio::test]
async fn missing_reload_receiver_stays_pending() {
    assert_pending(
        tokio::time::timeout(PENDING, wait_optional_tls_reload(None, 0)).await,
        "no TLS reload watch must park rather than fire",
    );
}

#[tokio::test]
async fn already_published_generation_is_not_lost_on_a_fresh_clone() {
    let (tx, stored_rx) = watch::channel(0u64);
    tx.send(1).expect("publish before wait is armed");
    tokio::time::timeout(COMPLETE, wait_reload(&stored_rx, 0))
        .await
        .expect("a generation published before the wait must still wake once");
}

#[tokio::test]
async fn generation_published_after_the_wait_is_armed_is_not_lost() {
    let (tx, stored_rx) = watch::channel(0u64);
    let wait_rx = stored_rx.clone();
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let wait = tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = wait_reload(&wait_rx, 0) => {}
            _ = async {
                let _ = armed_tx.send(());
                std::future::pending::<()>().await;
            } => {}
        }
    });
    armed_rx.await.expect("reload wait armed");
    tx.send(1).expect("publish after wait is parked");
    tokio::time::timeout(COMPLETE, wait)
        .await
        .expect("armed wait must observe the later send")
        .expect("reload wait task");
}

#[tokio::test]
async fn dropped_sender_parks_after_the_last_accepted_generation() {
    let (tx, stored_rx) = watch::channel(0u64);
    tx.send(1).expect("publish gen1");
    drop(tx);

    tokio::time::timeout(COMPLETE, wait_reload(&stored_rx, 0))
        .await
        .expect("last published generation must still be observable");
    assert_pending(
        tokio::time::timeout(PENDING, wait_reload(&stored_rx, 1)).await,
        "a dead watch must park after the accepted generation, not spin",
    );
}

#[tokio::test]
async fn accepted_revision_allows_connect_progress_instead_of_reload_storm() {
    let (tx, stored_rx) = watch::channel(0u64);
    tx.send(1).expect("publish gen1");

    let mut last_tls_revision = *stored_rx.borrow();
    assert_eq!(last_tls_revision, 1);

    let mut connected = false;
    tokio::select! {
        biased;
        _ = wait_reload(&stored_rx, last_tls_revision) => {
            panic!("accepted TLS revision must not retrigger and cancel reconnect");
        }
        _ = async {
            connected = true;
        } => {}
    }
    assert!(
        connected,
        "after rebuilding to the accepted generation the connect attempt must proceed"
    );

    last_tls_revision = *stored_rx.borrow();
    assert_pending(
        tokio::time::timeout(PENDING, wait_reload(&stored_rx, last_tls_revision)).await,
        "reconnect loop must not remain in the reload arm after accepting gen1",
    );
}

#[tokio::test]
async fn client_loop_observes_one_revision_once_then_reconnects() {
    let (tx, stored_rx) = watch::channel(0u64);
    let reload_wakes = Arc::new(AtomicU32::new(0));
    let connect_attempts = Arc::new(AtomicU32::new(0));
    let (stop_tx, stop_rx) = watch::channel(false);

    let wakes = reload_wakes.clone();
    let connects = connect_attempts.clone();
    let handle = tokio::spawn(async move {
        let mut last_tls_revision = *stored_rx.borrow();
        let mut stop_rx = stop_rx;
        loop {
            if *stop_rx.borrow() {
                return;
            }
            let current = *stored_rx.borrow();
            if current != last_tls_revision {
                last_tls_revision = current;
            }
            tokio::select! {
                _ = wait_for_shutdown(&mut stop_rx) => return,
                _ = wait_optional_tls_reload(
                    Some(stored_rx.clone()),
                    last_tls_revision,
                ) => {
                    wakes.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                _ = async {
                    connects.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                } => {}
            }
        }
    });

    tx.send(1).expect("publish gen1");
    tokio::time::sleep(PENDING).await;
    stop_tx.send(true).expect("stop client loop");
    tokio::time::timeout(COMPLETE, handle)
        .await
        .expect("client loop stopped")
        .expect("client loop task");

    assert!(
        reload_wakes.load(Ordering::SeqCst) <= 1,
        "one published revision must not storm the reload arm, got {}",
        reload_wakes.load(Ordering::SeqCst)
    );
    assert!(
        connect_attempts.load(Ordering::SeqCst) >= 1,
        "after consuming the accepted generation the native/xDS reconnect loop \
         must reach a new connection attempt"
    );
}

#[test]
fn native_and_xds_clients_wait_against_the_accepted_tls_revision() {
    let unmarked_clone_wait =
        "wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone()))";
    for (label, source) in [
        ("native MeshSubscribe", NATIVE_CLIENT),
        ("xDS ADS", XDS_CLIENT),
        ("stock xDS ADS", STOCK_XDS_CLIENT),
        ("ConfigSync DP", DP_CLIENT),
    ] {
        let waits = source.matches("wait_optional_tls_reload(").count()
            - source.matches("fn wait_optional_tls_reload(").count();
        assert!(
            waits >= 3,
            "{label} must arm TLS reload waits on the reconnect loop"
        );
        assert!(
            !source.contains(unmarked_clone_wait),
            "{label} must not wait on an unmarked clone without last_tls_revision"
        );
        assert!(
            source.contains("last_tls_revision"),
            "{label} must rebuild and wait against the accepted TLS revision"
        );
        let accepted_arg = source.matches("last_tls_revision,").count()
            + source.matches("last_tls_revision)").count();
        assert!(
            accepted_arg >= waits,
            "{label} must pass last_tls_revision into every wait_optional_tls_reload call \
             (waits={waits}, accepted_args={accepted_arg})"
        );
    }
}
