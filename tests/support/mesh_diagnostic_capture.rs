use std::sync::{Arc, Mutex};

use tracing::Dispatch;

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
    crate::diagnostic_test_interest::ensure_interest_floor();
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

crate::diagnostic_test_interest::capture_regression!(
    capture_mesh_diagnostics,
    tracing::Level::DEBUG,
    excluded = tracing::Level::TRACE
);

#[test]
fn capture_rebuilds_a_previously_disabled_callsite() {
    use tracing::{callsite::Callsite, subscriber::Interest};

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
