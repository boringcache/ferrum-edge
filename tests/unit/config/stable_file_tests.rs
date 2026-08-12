//! Shared bounded stable-file reader (`config::stable_file`) — issue #3776.
//!
//! Covers exact limit / limit+1, sparse oversized metadata, growth past the
//! streaming ceiling, FIFO/socket/device/directory rejection, projected-secret
//! symlink rotation, path replacement / torn content fail-closed behavior, and
//! UTF-8 refusal without content leakage.

use std::path::Path;
use std::time::Duration;

use ferrum_edge::config::stable_file::{
    MAX_FERRUM_CONF_BYTES, MAX_GATEWAY_CONFIG_FILE_BYTES, MAX_MESH_CONFIG_FILE_BYTES,
    StableFileError, StableFileReadOptions, detect_json_or_yaml_extension,
    format_stable_file_error, read_stable_file,
};

const TEST_LIMIT: u64 = 64;

fn opts(max_bytes: u64) -> StableFileReadOptions<'static> {
    StableFileReadOptions {
        max_bytes,
        source_name: "test config",
        max_attempts: 3,
        retry_delay: Duration::from_millis(1),
    }
}

#[test]
fn documented_ceilings_match_issue_contract() {
    assert_eq!(MAX_FERRUM_CONF_BYTES, 1024 * 1024);
    assert_eq!(MAX_GATEWAY_CONFIG_FILE_BYTES, 64 * 1024 * 1024);
    assert_eq!(MAX_MESH_CONFIG_FILE_BYTES, 64 * 1024 * 1024);
}

#[test]
fn exact_limit_loads_and_limit_plus_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exact = dir.path().join("exact.conf");
    std::fs::write(&exact, vec![b'a'; TEST_LIMIT as usize]).unwrap();
    let loaded = read_stable_file(&exact, opts(TEST_LIMIT)).expect("exact limit must load");
    assert_eq!(loaded.len() as u64, TEST_LIMIT);

    let over = dir.path().join("over.conf");
    std::fs::write(&over, vec![b'b'; (TEST_LIMIT + 1) as usize]).unwrap();
    let err = read_stable_file(&over, opts(TEST_LIMIT)).expect_err("limit+1 must refuse");
    match err {
        StableFileError::TooLarge { len, max_bytes } => {
            assert_eq!(max_bytes, TEST_LIMIT);
            assert!(len > TEST_LIMIT);
        }
        other => panic!("expected TooLarge, got {other}"),
    }
}

#[test]
fn sparse_oversized_metadata_is_fast_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sparse.conf");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(TEST_LIMIT + 1).unwrap();
    drop(file);

    let err = read_stable_file(&path, opts(TEST_LIMIT)).expect_err("sparse oversized");
    match err {
        StableFileError::TooLarge { len, max_bytes } => {
            assert_eq!(len, TEST_LIMIT + 1);
            assert_eq!(max_bytes, TEST_LIMIT);
        }
        other => panic!("expected TooLarge, got {other}"),
    }
}

#[test]
fn missing_path_is_not_found() {
    let err = read_stable_file(
        Path::new("/nonexistent/ferrum-stable-file.conf"),
        opts(TEST_LIMIT),
    )
    .expect_err("missing");
    assert!(matches!(err, StableFileError::NotFound));
}

#[test]
fn invalid_utf8_is_rejected_without_byte_leakage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-utf8.conf");
    std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
    let err = read_stable_file(&path, opts(TEST_LIMIT)).expect_err("utf8");
    assert!(matches!(err, StableFileError::NotUtf8(_)));
    let rendered = format_stable_file_error(&path, opts(TEST_LIMIT), &err);
    assert!(
        !rendered.contains('\u{fffd}') && !rendered.as_bytes().contains(&0xff),
        "diagnostics must not echo raw file bytes: {rendered}"
    );
}

#[test]
fn detect_format_preserves_yaml_superset_for_unknown_extensions() {
    assert!(detect_json_or_yaml_extension(
        Path::new("mesh.unknown"),
        "mesh:\n  services: []\n"
    ));
    assert!(detect_json_or_yaml_extension(
        Path::new("mesh.unknown"),
        "{\"mesh\":{}}"
    ));
    assert!(detect_json_or_yaml_extension(
        Path::new("mesh.unknown"),
        "{mesh: {services: []}}"
    ));
    assert!(detect_json_or_yaml_extension(
        Path::new("a.yaml"),
        "{not-json"
    ));
    assert!(!detect_json_or_yaml_extension(Path::new("a.json"), "mesh:"));
}

#[cfg(unix)]
mod unix_targets {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn fifo_is_rejected_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("config.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let started = Instant::now();
        let err = read_stable_file(&fifo, opts(TEST_LIMIT)).expect_err("fifo");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "FIFO rejection must not wait for a producer"
        );
        assert!(
            matches!(err, StableFileError::NotRegularFile) || matches!(err, StableFileError::Io(_)),
            "expected non-regular rejection, got {err}"
        );
    }

    #[test]
    fn unix_socket_is_rejected_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("config.sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        let started = Instant::now();
        let err = read_stable_file(&sock, opts(TEST_LIMIT)).expect_err("socket");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(err, StableFileError::NotRegularFile));
    }

    #[test]
    fn directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_stable_file(dir.path(), opts(TEST_LIMIT)).expect_err("dir");
        assert!(matches!(err, StableFileError::NotRegularFile));
    }

    #[test]
    fn character_device_is_rejected_promptly() {
        let started = Instant::now();
        let err = read_stable_file(Path::new("/dev/null"), opts(TEST_LIMIT)).expect_err("device");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(err, StableFileError::NotRegularFile));
    }

    #[test]
    fn block_device_is_rejected_promptly_when_present() {
        // `/dev/zero` is a character device on macOS/Linux; prefer a real block
        // device when the runner exposes one, otherwise accept char-device proof
        // from the dedicated `/dev/null` test above.
        for candidate in ["/dev/disk0", "/dev/sda", "/dev/loop0", "/dev/vda"] {
            let path = Path::new(candidate);
            if !path.exists() {
                continue;
            }
            let started = Instant::now();
            let err = read_stable_file(path, opts(TEST_LIMIT)).expect_err("block device");
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(
                matches!(err, StableFileError::NotRegularFile)
                    || matches!(err, StableFileError::Io(_)),
                "expected non-regular rejection for {candidate}, got {err}"
            );
            return;
        }
    }

    #[test]
    fn projected_secret_symlink_to_regular_file_is_supported() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("..data");
        std::fs::create_dir(&data).unwrap();
        let target = data.join("config");
        std::fs::write(&target, "FERRUM_LOG_LEVEL=info\n").unwrap();
        let link = dir.path().join("config");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let loaded = read_stable_file(&link, opts(4096)).expect("symlink target");
        assert!(loaded.contains("FERRUM_LOG_LEVEL"));
    }

    #[test]
    fn atomic_symlink_target_rotation_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let data_v1 = dir.path().join("..data_v1");
        let data_v2 = dir.path().join("..data_v2");
        std::fs::create_dir(&data_v1).unwrap();
        std::fs::create_dir(&data_v2).unwrap();
        std::fs::write(data_v1.join("config"), "FERRUM_LOG_LEVEL=debug\n").unwrap();
        std::fs::write(data_v2.join("config"), "FERRUM_LOG_LEVEL=warn\n").unwrap();

        let data_link = dir.path().join("..data");
        std::os::unix::fs::symlink(&data_v1, &data_link).unwrap();
        let live = dir.path().join("config");
        std::os::unix::fs::symlink(data_link.join("config"), &live).unwrap();

        let first = read_stable_file(&live, opts(4096)).expect("v1");
        assert!(first.contains("debug"));

        // Kubernetes-style atomic data-dir swap.
        let staging = dir.path().join("..data_staging");
        std::os::unix::fs::symlink(&data_v2, &staging).unwrap();
        std::fs::rename(&staging, &data_link).unwrap();

        let second = read_stable_file(&live, opts(4096)).expect("v2");
        assert!(second.contains("warn"));
    }

    #[test]
    fn path_replacement_during_read_fails_closed_or_yields_one_stable_generation() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.conf");
        std::fs::write(&live, "AAAA").unwrap();

        let stop = Arc::new(Mutex::new(false));
        let writer_stop = Arc::clone(&stop);
        let writer_path = live.clone();
        let writer = thread::spawn(move || {
            let mut flip = false;
            while !*writer_stop.lock().unwrap() {
                let body = if flip { "AAAA" } else { "BBBB" };
                let staging = writer_path.with_extension("staging");
                let _ = std::fs::write(&staging, body);
                let _ = std::fs::rename(&staging, &writer_path);
                flip = !flip;
                thread::sleep(Duration::from_millis(1));
            }
        });

        let deadline = Instant::now() + Duration::from_millis(500);
        let mut saw_ok = false;
        let mut saw_reject = false;
        while Instant::now() < deadline {
            match read_stable_file(&live, opts(TEST_LIMIT)) {
                Ok(content) => {
                    saw_ok = true;
                    assert!(
                        content == "AAAA" || content == "BBBB",
                        "must never publish mixed content, got {content:?}"
                    );
                }
                Err(StableFileError::Unstable(_)) => saw_reject = true,
                Err(StableFileError::Io(_)) => saw_reject = true,
                Err(other) => panic!("unexpected error: {other}"),
            }
        }

        *stop.lock().unwrap() = true;
        writer.join().unwrap();
        assert!(
            saw_ok || saw_reject,
            "replacement churn must yield stable generations and/or fail-closed rejects"
        );
    }

    #[test]
    fn growth_past_streaming_ceiling_is_refused() {
        // Start below the ceiling, then require the concurrent writer to prove
        // that growth has begun before the reader assertions start. Without
        // this handshake the reader loop can beat the writer's first schedule.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("growing.conf");
        std::fs::write(&path, vec![b'x'; 8]).unwrap();

        let stop = Arc::new(Mutex::new(false));
        let writer_stop = Arc::clone(&stop);
        let writer_path = path.clone();
        let (growth_started_tx, growth_started_rx) = std::sync::mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            let mut growth_started_tx = Some(growth_started_tx);
            while !*writer_stop.lock().unwrap() {
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&writer_path)
                    .unwrap();
                if file.write_all(&[b'y'; 128]).is_ok()
                    && let Some(started_tx) = growth_started_tx.take()
                {
                    let _ = started_tx.send(());
                }
                thread::sleep(Duration::from_millis(1));
            }
        });

        if let Err(error) = growth_started_rx.recv_timeout(Duration::from_secs(2)) {
            *stop.lock().unwrap() = true;
            writer.join().unwrap();
            panic!("writer did not begin the growth scenario: {error}");
        }

        let mut saw_too_large_or_unstable = false;
        for _ in 0..20 {
            match read_stable_file(&path, opts(32)) {
                Ok(content) => {
                    assert!(content.len() <= 32, "must never retain past the ceiling");
                }
                Err(StableFileError::TooLarge { .. }) | Err(StableFileError::Unstable(_)) => {
                    saw_too_large_or_unstable = true;
                    break;
                }
                Err(StableFileError::Io(_)) => {}
                Err(other) => panic!("unexpected: {other}"),
            }
        }

        *stop.lock().unwrap() = true;
        writer.join().unwrap();
        assert!(
            saw_too_large_or_unstable,
            "growth past the streaming ceiling must fail closed"
        );
    }
}
