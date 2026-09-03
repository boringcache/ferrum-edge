use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::http3::config::{
    H3_FRONTEND_RECEIVE_WINDOW, H3_FRONTEND_SEND_WINDOW, H3_FRONTEND_STREAM_RECEIVE_WINDOW,
    Http3ServerConfig,
};

#[test]
fn test_http3_server_config_default_values() {
    let config = Http3ServerConfig::default();

    assert_eq!(config.max_concurrent_streams, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    // Default() uses conservative frontend values for untrusted clients
    assert_eq!(
        config.stream_receive_window,
        H3_FRONTEND_STREAM_RECEIVE_WINDOW
    );
    assert_eq!(config.receive_window, H3_FRONTEND_RECEIVE_WINDOW);
    assert_eq!(config.send_window, H3_FRONTEND_SEND_WINDOW);
    assert_eq!(config.initial_mtu, 1500);
    // Default mirrors EnvConfig::default().frontend_tls_handshake_timeout_seconds (10s).
    assert_eq!(config.handshake_timeout, Duration::from_secs(10));
}

#[test]
fn test_http3_server_config_handshake_timeout_from_env_config() {
    // Non-zero value: forwarded as Duration::from_secs.
    let env = EnvConfig {
        frontend_tls_handshake_timeout_seconds: 7,
        ..Default::default()
    };
    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.handshake_timeout, Duration::from_secs(7));
}

#[test]
fn test_http3_server_config_handshake_timeout_zero_disables() {
    // 0 disables — forwarded as Duration::ZERO so the listener can branch on
    // `.is_zero()` to skip the `tokio::time::timeout` wrapper. Mirrors the
    // TCP/TLS and DTLS frontend "0 disables" semantic.
    let env = EnvConfig {
        frontend_tls_handshake_timeout_seconds: 0,
        ..Default::default()
    };
    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.handshake_timeout, Duration::ZERO);
    assert!(config.handshake_timeout.is_zero());
}

#[test]
fn test_http3_server_config_default_env_propagates_handshake_timeout() {
    // EnvConfig::default() default for frontend_tls_handshake_timeout_seconds
    // is 10 seconds and must round-trip through Http3ServerConfig.
    let env = EnvConfig::default();
    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(
        config.handshake_timeout,
        Duration::from_secs(env.frontend_tls_handshake_timeout_seconds)
    );
    assert_eq!(config.handshake_timeout, Duration::from_secs(10));
}

#[test]
fn test_http3_server_config_initial_mtu_from_env() {
    let env = EnvConfig {
        http3_initial_mtu: 1350,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.initial_mtu, 1350);
}

#[test]
fn test_http3_server_config_from_env_config_defaults() {
    // EnvConfig::default() should produce the same values as Http3ServerConfig::default()
    // (conservative frontend values for untrusted clients)
    let env = EnvConfig::default();
    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(
        config.stream_receive_window,
        H3_FRONTEND_STREAM_RECEIVE_WINDOW
    );
    assert_eq!(config.receive_window, H3_FRONTEND_RECEIVE_WINDOW);
    assert_eq!(config.send_window, H3_FRONTEND_SEND_WINDOW);
}

#[test]
fn test_http3_server_config_from_env_config_custom_values() {
    let env = EnvConfig {
        http3_max_streams: 500,
        http3_idle_timeout: 60,
        http3_stream_receive_window: 4_194_304, // 4 MiB
        http3_receive_window: 16_777_216,       // 16 MiB
        http3_send_window: 2_097_152,           // 2 MiB
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 500);
    assert_eq!(config.idle_timeout, Duration::from_secs(60));
    assert_eq!(config.stream_receive_window, 4_194_304);
    assert_eq!(config.receive_window, 16_777_216);
    assert_eq!(config.send_window, 2_097_152);
}

#[test]
fn test_http3_server_config_from_env_config_zero_idle_timeout() {
    let env = EnvConfig {
        http3_idle_timeout: 0,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.idle_timeout, Duration::from_secs(0));
}

#[test]
fn test_http3_server_config_from_env_config_large_windows() {
    let env = EnvConfig {
        http3_stream_receive_window: 128 * 1024 * 1024, // 128 MiB
        http3_receive_window: 512 * 1024 * 1024,        // 512 MiB
        http3_send_window: 64 * 1024 * 1024,            // 64 MiB
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.stream_receive_window, 128 * 1024 * 1024);
    assert_eq!(config.receive_window, 512 * 1024 * 1024);
    assert_eq!(config.send_window, 64 * 1024 * 1024);
}

#[test]
fn test_http3_server_config_from_env_config_min_streams() {
    let env = EnvConfig {
        http3_max_streams: 1,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 1);
}

// ---------------------------------------------------------------------------
// Issue #4538: the H3 field-section caps must sit below `http::HeaderMap`'s
// real 24,576-entry construction ceiling, not below the 32,768 `MAX_SIZE`
// constant that ceiling is derived from.
// ---------------------------------------------------------------------------

/// `HeaderMap::try_with_capacity` refuses above 24,576 entries, so that — not
/// `MAX_SIZE = 1 << 15` — is the number every H3 field-section cap has to stay
/// under. Pinned here so an `http` bump that moves `MAX_SIZE` or
/// `to_raw_capacity` is caught in this test rather than in production, where
/// the vendored h3's `HeaderMap::with_capacity` turns it into a process abort.
#[test]
fn header_map_construction_ceiling_is_24576_entries_not_max_size() {
    use ferrum_edge::http3::config::H3_HEADER_MAP_MAX_FIELDS;

    assert_eq!(H3_HEADER_MAP_MAX_FIELDS, 24_576);
    assert!(
        http::HeaderMap::<()>::try_with_capacity(24_576).is_ok(),
        "24_576 -> raw 32_768 -> next_power_of_two 32_768, which is not above MAX_SIZE"
    );
    assert!(
        http::HeaderMap::<()>::try_with_capacity(24_577).is_err(),
        "24_577 -> raw 32_769 -> next_power_of_two 65_536, which is above MAX_SIZE"
    );
    assert!(http::HeaderMap::<()>::try_with_capacity(32_768).is_err());
}

/// Every field count the QPACK decoder can admit under the byte cap yields a
/// constructible `HeaderMap`. This assertion fails on the pre-#4538 cap
/// (`1_048_575`, which admits 32,767 fields) and is the regression guard.
#[test]
fn field_section_cap_admits_only_constructible_field_counts() {
    use ferrum_edge::http3::config::{
        H3_BACKEND_RESPONSE_FIELD_SECTION_SIZE_CAP, H3_FIELD_SECTION_SIZE_CAP,
        H3_HEADER_MAP_MAX_FIELDS,
    };

    // QPACK accounts at least 32 bytes per decoded field and bounds only the
    // accumulated size, so the admitted field count is exactly cap / 32.
    let admitted_fields = H3_FIELD_SECTION_SIZE_CAP / 32;
    assert!(
        admitted_fields <= H3_HEADER_MAP_MAX_FIELDS,
        "the byte cap admits {admitted_fields} decoded fields, above the {H3_HEADER_MAP_MAX_FIELDS} \
         entries `HeaderMap` can be constructed with"
    );
    assert!(
        http::HeaderMap::<()>::try_with_capacity(admitted_fields as usize).is_ok(),
        "the largest field section the cap admits must build a HeaderMap"
    );

    // The backend response path is bounded by the same ceiling: a compromised
    // upstream can emit hostile QPACK literals as readily as a client can.
    assert_eq!(
        H3_BACKEND_RESPONSE_FIELD_SECTION_SIZE_CAP,
        H3_FIELD_SECTION_SIZE_CAP
    );
}

/// Both the frontend request policy and the backend response policy are capped,
/// however large the operator's configured header policy is.
#[test]
fn both_h3_field_section_policies_are_field_count_capped() {
    use ferrum_edge::http3::config::{
        H3_FIELD_SECTION_SIZE_CAP, H3_HEADER_MAP_MAX_FIELDS,
        h3_backend_response_max_field_section_size, h3_max_field_section_size,
    };

    for configured in [usize::MAX, 1_048_576, 786_464, 400_000] {
        let request_fields = h3_max_field_section_size(configured) / 32;
        let response_fields = h3_backend_response_max_field_section_size(configured) / 32;
        assert!(
            request_fields <= H3_HEADER_MAP_MAX_FIELDS,
            "frontend policy admits {request_fields} fields (configured={configured})"
        );
        assert!(
            response_fields <= H3_HEADER_MAP_MAX_FIELDS,
            "backend response policy admits {response_fields} fields (configured={configured})"
        );
    }

    assert_eq!(
        h3_max_field_section_size(usize::MAX),
        H3_FIELD_SECTION_SIZE_CAP
    );
    // Below the cap the operator's policy is still carried through verbatim.
    assert_eq!(h3_max_field_section_size(32_768), 32_768);
}

/// The buffered-frame ceiling keeps its 2x headroom above the advertised
/// policy even at the cap, so a field section that merely overshoots is still
/// QPACK-decoded and answered with the graceful 431 rather than aborted.
#[test]
fn buffered_frame_headroom_survives_the_field_section_cap() {
    use ferrum_edge::http3::config::{
        H3_FIELD_SECTION_SIZE_CAP, QUIC_VARINT_MAX_U64, h3_max_buffered_frame_len,
        h3_max_field_section_size,
    };

    for configured in [H3_FIELD_SECTION_SIZE_CAP as usize, usize::MAX, 1_048_576] {
        let advertised = h3_max_field_section_size(configured);
        let ceiling = h3_max_buffered_frame_len(configured);
        assert_eq!(advertised, H3_FIELD_SECTION_SIZE_CAP);
        assert_eq!(ceiling, advertised * 2);
        assert!(ceiling > advertised);
        assert!(ceiling <= QUIC_VARINT_MAX_U64);
    }
}

/// A header policy above the field-count-safe bound is a startup error, not a
/// silent clamp: above it the advertised SETTINGS_MAX_FIELD_SECTION_SIZE would
/// no longer be the operator's configured policy.
#[test]
fn validation_refuses_a_header_policy_above_the_field_count_bound() {
    use ferrum_edge::http3::config::{H3_FIELD_SECTION_SIZE_CAP, validate_h3_field_section_limits};

    let cap = H3_FIELD_SECTION_SIZE_CAP as usize;
    assert!(
        validate_h3_field_section_limits(cap).is_ok(),
        "the bound itself must be admitted"
    );
    let err = validate_h3_field_section_limits(cap + 1)
        .expect_err("one byte above the bound must fail configuration admission");
    assert!(
        err.contains("FERRUM_MAX_HEADER_SIZE_BYTES"),
        "the refusal must name the offending variable: {err}"
    );
    assert!(
        err.contains(&H3_FIELD_SECTION_SIZE_CAP.to_string()),
        "the refusal must state the maximum: {err}"
    );

    // The default policy and the previously-permitted 1 MiB region.
    assert!(validate_h3_field_section_limits(32_768).is_ok());
    assert!(validate_h3_field_section_limits(1_048_575).is_err());
}
