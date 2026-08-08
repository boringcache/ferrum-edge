//! Admission rules for Unix-domain-socket backend paths (issue #3261).
//!
//! This validator is the single fail-closed gate between an operator-authored
//! (or carrier-decoded) `unix://` endpoint and `UnixStream::connect`, so every
//! rule it enforces is pinned here — including the ones that only matter for a
//! hostile input.

use ferrum_edge::util::unix_socket::{
    MAX_UNIX_SOCKET_PATH_BYTES, UnixSocketPathRejection, validate_unix_socket_path,
};

#[test]
fn admits_ordinary_absolute_socket_paths() {
    for path in [
        "/var/run/app.sock",
        "/tmp/x",
        "/run/ferrum/inner-dir/grpc.sock",
        // A dot INSIDE a component is fine; only a whole `.` / `..` component
        // is a traversal segment.
        "/var/run/app.v2.sock",
        "/var/run/..hidden.sock",
    ] {
        assert_eq!(
            validate_unix_socket_path(path),
            Ok(()),
            "{path:?} should be admitted"
        );
    }
}

#[test]
fn rejects_relative_and_abstract_paths() {
    // Relative paths resolve against the process CWD — not a reviewable
    // location. Abstract (`\0`-prefixed) and `@`-prefixed sockets are not part
    // of Istio's `defaultEndpoint` grammar and fall out of the same rule.
    for path in ["var/run/app.sock", "./app.sock", "@abstract", "app.sock"] {
        assert_eq!(
            validate_unix_socket_path(path),
            Err(UnixSocketPathRejection::NotAbsolute),
            "{path:?} must fail closed as non-absolute"
        );
    }
}

#[test]
fn rejects_traversal_components() {
    for path in [
        "/var/../etc/passwd",
        "/var/run/../../etc/shadow",
        "/var/./run/app.sock",
        "/..",
    ] {
        assert_eq!(
            validate_unix_socket_path(path),
            Err(UnixSocketPathRejection::TraversalComponent),
            "{path:?} must fail closed rather than being normalized"
        );
    }
}

#[test]
fn rejects_structurally_ambiguous_paths() {
    assert_eq!(
        validate_unix_socket_path(""),
        Err(UnixSocketPathRejection::Empty)
    );
    assert_eq!(
        validate_unix_socket_path("/var//run/app.sock"),
        Err(UnixSocketPathRejection::EmptyComponent)
    );
    // A trailing slash names a directory, never a socket. `/` is the extreme
    // case of the same rule.
    assert_eq!(
        validate_unix_socket_path("/var/run/"),
        Err(UnixSocketPathRejection::TrailingSlash)
    );
    assert_eq!(
        validate_unix_socket_path("/"),
        Err(UnixSocketPathRejection::TrailingSlash)
    );
    // Nothing is trimmed: silently trimming would dial a different path than
    // the operator wrote.
    assert_eq!(
        validate_unix_socket_path(" /var/run/app.sock"),
        Err(UnixSocketPathRejection::SurroundingWhitespace)
    );
    assert_eq!(
        validate_unix_socket_path("/var/run/app.sock\n"),
        Err(UnixSocketPathRejection::SurroundingWhitespace)
    );
}

#[test]
fn rejects_nul_and_control_characters() {
    // An interior NUL would truncate `sun_path`, so the kernel would bind/dial
    // a DIFFERENT path than the one reviewed.
    assert_eq!(
        validate_unix_socket_path("/var/run/app\u{0}.sock"),
        Err(UnixSocketPathRejection::InteriorNul)
    );
    assert_eq!(
        validate_unix_socket_path("/var/run/app\u{7}.sock"),
        Err(UnixSocketPathRejection::ControlCharacter)
    );
    // A NUL is also a control character; the NUL rule must win so the
    // diagnostic names the sharper failure.
    assert_eq!(
        validate_unix_socket_path("/\u{0}"),
        Err(UnixSocketPathRejection::InteriorNul)
    );
}

#[test]
fn enforces_the_portable_sockaddr_un_budget() {
    // 103 bytes = the usable `sun_path` budget on the SMALLEST supported
    // platform (macOS/BSD reserve 104 including the NUL; Linux allows 108), so
    // a path admitted on one platform always dials on another.
    assert_eq!(MAX_UNIX_SOCKET_PATH_BYTES, 103);
    let at_limit = format!("/{}", "a".repeat(MAX_UNIX_SOCKET_PATH_BYTES - 1));
    assert_eq!(at_limit.len(), MAX_UNIX_SOCKET_PATH_BYTES);
    assert_eq!(validate_unix_socket_path(&at_limit), Ok(()));

    let over_limit = format!("/{}", "a".repeat(MAX_UNIX_SOCKET_PATH_BYTES));
    assert_eq!(
        validate_unix_socket_path(&over_limit),
        Err(UnixSocketPathRejection::TooLong)
    );

    // The budget is in BYTES, not characters: a multi-byte path that looks
    // short must still be measured on the wire.
    let multibyte = format!("/{}", "é".repeat(60));
    assert!(multibyte.chars().count() < MAX_UNIX_SOCKET_PATH_BYTES);
    assert_eq!(
        validate_unix_socket_path(&multibyte),
        Err(UnixSocketPathRejection::TooLong)
    );
}

#[test]
fn every_rejection_reason_is_specific_and_leaks_no_path() {
    let reasons = [
        UnixSocketPathRejection::Empty,
        UnixSocketPathRejection::SurroundingWhitespace,
        UnixSocketPathRejection::NotAbsolute,
        UnixSocketPathRejection::TraversalComponent,
        UnixSocketPathRejection::EmptyComponent,
        UnixSocketPathRejection::TrailingSlash,
        UnixSocketPathRejection::InteriorNul,
        UnixSocketPathRejection::ControlCharacter,
        UnixSocketPathRejection::TooLong,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for reason in reasons {
        let text = reason.reason();
        assert!(!text.is_empty());
        assert!(
            seen.insert(text),
            "reason {text:?} is not unique; a status report could not distinguish the rules"
        );
    }
}
