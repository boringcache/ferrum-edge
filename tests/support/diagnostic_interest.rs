use std::sync::OnceLock;

use tracing::{Dispatch, Metadata, Subscriber, subscriber::Interest};

// tracing-core 0.1.36 uses the hitting thread's dispatcher when its registry
// contains at most one dispatcher. A silent sibling can cache `never` on a
// first-use callsite even while another thread has a fmt capture installed.
// Keep a distinct, inactive Dispatch alive so every capture registers alongside
// this floor. The registry then computes `sometimes` under its lock and events
// consult the current subscriber, preserving each capture's own level filter.
// This never installs a global or thread-local default subscriber.
static INTEREST_FLOOR: OnceLock<Dispatch> = OnceLock::new();

// Call before constructing EVERY capture dispatch, including repeated/nested
// captures: registering the capture rebuilds existing cached interests with
// the floor alive. This is not a general upstream race fix: a JustOne rebuild
// already in flight before the first initialization is not synchronized by our
// registration. Do not replace the owned floor with test-order assumptions or
// claim that it retroactively repairs that bootstrap interleaving.
pub(crate) fn ensure_interest_floor() {
    INTEREST_FLOOR.get_or_init(|| Dispatch::new(InterestFloorSubscriber));
}

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

// Each expansion owns a distinct first-use callsite and calls the actual
// capture entry point without pre-initializing tracing. Run each test alone in
// hosted CI as well as in the parallel lib suite: unrelated live subscribers
// in the full suite can mask a missing initializer. No test resets shared
// tracing state or assumes that another test has installed a subscriber.
macro_rules! capture_regression {
    ($capture:path, $level:expr $(, excluded = $excluded:expr)?) => {
        #[test]
        fn capture_keeps_first_use_and_concurrent_writers() {
            fn first_use(owner: &str) {
                tracing::event!($level, owner, "first-use diagnostic");
            }

            let ((), log) = $capture(|| {
                tracing::event!($level, "diagnostic before first use");
                // Join fixes the ordering. No dispatcher registration or
                // explicit rebuild intervenes between these two site hits.
                std::thread::spawn(|| {
                    tracing::dispatcher::with_default(&tracing::Dispatch::none(), || {
                        first_use("silent-sibling-canary");
                    });
                })
                .join()
                .unwrap();
                first_use("capture-owner");
                tracing::event!($level, "diagnostic after first use");
            });
            for message in [
                "diagnostic before first use",
                "first-use diagnostic",
                "diagnostic after first use",
                "capture-owner",
            ] {
                assert_eq!(log.matches(message).count(), 1, "{log}");
            }
            assert_eq!(log.lines().count(), 3, "{log}");
            assert!(!log.contains("silent-sibling-canary"), "{log}");

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let workers: Vec<_> = ["capture-left", "capture-right"]
                .into_iter()
                .map(|owner| {
                    let barrier = std::sync::Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        $capture(|| {
                            barrier.wait();
                            tracing::event!($level, owner, "outer before nested capture");
                            let ((), nested) = $capture(|| {
                                tracing::event!($level, owner, "nested diagnostic");
                            });
                            tracing::event!($level, owner, "outer after nested capture");
                            $(tracing::event!($excluded, "excluded diagnostic");)?
                            barrier.wait();
                            (owner, nested)
                        })
                    })
                })
                .collect();
            for worker in workers {
                let ((owner, nested), log) = worker.join().unwrap();
                assert_eq!(log.lines().count(), 2, "{log}");
                assert_eq!(log.matches(owner).count(), 2, "{log}");
                for message in ["outer before nested capture", "outer after nested capture"] {
                    assert_eq!(log.matches(message).count(), 1, "{log}");
                }
                assert!(!log.contains("nested diagnostic"), "{log}");
                assert!(!log.contains("excluded diagnostic"), "{log}");
                assert_eq!(nested.lines().count(), 1, "{nested}");
                assert_eq!(nested.matches("nested diagnostic").count(), 1, "{nested}");
                assert!(nested.contains(owner), "{nested}");
                let other = if owner == "capture-left" {
                    "capture-right"
                } else {
                    "capture-left"
                };
                assert!(!log.contains(other), "{log}");
                assert!(!nested.contains(other), "{nested}");
            }
        }
    };
    (subscriber = $logs:path, $level:expr) => {
        mod capture_regression {
            // Match the guard-based xDS, localized-file and federation callers;
            // output is read while the guard is still alive there too.
            fn capture<R>(action: impl FnOnce() -> R) -> (R, String) {
                let logs = <$logs>::default();
                let _guard = tracing::subscriber::set_default(logs.subscriber());
                let result = action();
                (result, logs.output())
            }

            crate::diagnostic_test_interest::capture_regression!(capture, $level);
        }
    };
}

pub(crate) use capture_regression;
