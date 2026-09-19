use std::sync::{Arc, Mutex, OnceLock};

use tracing::subscriber::Interest;
use tracing::{Dispatch, Metadata, Subscriber};

// tracing-core 0.1.36 uses the hitting thread's dispatcher when its registry
// contains at most one dispatcher. A sibling with no subscriber can therefore
// cache `never` on a first-use callsite while our fmt capture is active.
// Dispatch::new registers even an inactive subscriber; retaining this distinct
// dispatch makes every capture own a second live registry entry. Registration
// then reads the registry under its lock, and `sometimes` forces the event to
// consult the capturing thread's subscriber instead of trusting cached `never`.
// Keep the floor alive between captures too, so dispatcher pruning cannot undo
// it. This does not install or replace the process-global default subscriber.
static INTEREST_FLOOR: OnceLock<Dispatch> = OnceLock::new();

struct InterestFloorSubscriber;

impl Subscriber for InterestFloorSubscriber {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[derive(Clone, Default)]
struct MeshDiagnosticWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for MeshDiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn capture_mesh_diagnostics<R>(f: impl FnOnce() -> R) -> (R, String) {
    INTEREST_FLOOR.get_or_init(|| Dispatch::new(InterestFloorSubscriber));
    let writer = MeshDiagnosticWriter::default();
    let sink = writer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || sink.clone())
        .finish();
    // Constructing the capture dispatch rebuilds previously cached interests
    // with both subscribers alive, including callsites cached as `never`.
    let dispatch = Dispatch::new(subscriber);
    let result = tracing::dispatcher::with_default(&dispatch, f);
    let log = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    (result, log)
}

#[test]
fn captures_debug_callsite_first_used_by_a_silent_sibling() {
    fn first_use(owner: &str) {
        tracing::debug!(owner, "mesh first-use diagnostic");
    }

    let ((), log) = capture_mesh_diagnostics(|| {
        tracing::debug!("mesh diagnostic before first use");
        // No new registered dispatcher and no cache rebuild between the
        // sibling's first hit and this thread's hit of the identical callsite.
        // Joining fixes the bad ordering without sleeps or capture retries.
        std::thread::spawn(|| {
            tracing::dispatcher::with_default(&Dispatch::none(), || {
                first_use("silent-sibling-canary");
            });
        })
        .join()
        .unwrap();
        first_use("capture-owner");
        tracing::debug!("mesh diagnostic after first use");
    });
    for message in [
        "mesh diagnostic before first use",
        "mesh first-use diagnostic",
        "mesh diagnostic after first use",
        "capture-owner",
    ] {
        assert_eq!(log.matches(message).count(), 1, "{log}");
    }
    assert!(!log.contains("silent-sibling-canary"), "{log}");
}

#[test]
fn capture_rebuilds_a_previously_disabled_callsite() {
    use tracing::callsite::Callsite;

    let callsite = tracing::callsite! {
        name: "mesh cached-never regression",
        kind: tracing::metadata::Kind::EVENT,
        target: "mesh_diagnostic_capture",
        level: tracing::Level::DEBUG,
        fields:
    };
    // Only this fixture emits through this callsite. Seed the stale interest
    // directly so this case also runs when sibling captures already exist.
    callsite.set_interest(Interest::never());
    let ((), log) = capture_mesh_diagnostics(|| {
        let interest = callsite.interest();
        assert!(interest.is_sometimes());
        assert!(tracing::dispatcher::get_default(|dispatch| {
            dispatch.enabled(callsite.metadata())
        }));
        tracing::Event::dispatch(
            callsite.metadata(),
            &callsite.metadata().fields().value_set(&[]),
        );
        tracing::debug!("mesh cached-never recovered");
    });
    // The fieldless event still has a DEBUG level line; the second event
    // verifies that ordinary macros retain the same capture destination.
    assert_eq!(log.lines().count(), 2, "{log}");
    assert!(log.contains("mesh cached-never recovered"), "{log}");
}

#[test]
fn concurrent_captures_keep_their_own_writers_and_debug_filter() {
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = ["mesh-capture-left", "mesh-capture-right"]
        .into_iter()
        .map(|owner| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                capture_mesh_diagnostics(|| {
                    barrier.wait();
                    tracing::debug!(owner, "mesh concurrent diagnostic");
                    tracing::trace!("mesh trace excluded");
                    barrier.wait();
                    owner
                })
            })
        })
        .collect();
    for worker in workers {
        let (owner, log) = worker.join().unwrap();
        assert!(log.contains(owner), "{log}");
        assert_eq!(log.lines().count(), 1, "{log}");
        assert_eq!(log.matches("mesh concurrent diagnostic").count(), 1, "{log}");
        assert!(!log.contains("mesh trace excluded"), "{log}");
        let other = if owner == "mesh-capture-left" {
            "mesh-capture-right"
        } else {
            "mesh-capture-left"
        };
        assert!(!log.contains(other), "{log}");
    }
}
