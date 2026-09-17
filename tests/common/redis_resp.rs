//! RESP wire fixtures every fake Redis peer in the test suites shares.
//!
//! `RedisRateLimitClient` screens each connection it establishes and then asks
//! that connection for the server clock with a standalone `TIME`
//! (`RedisRateLimitClient::probe_server_time`). Exactly three replies leave the
//! connection usable: a well-formed clock, a `NOPERM` verdict, and an
//! unknown-command verdict. Everything else — including the `+OK` a catch-all
//! stub answers — is an endpoint the client cannot pair with a clock, so the
//! connection is dropped unpublished and every command that would have run on
//! it fails.
//!
//! A real Redis answers `TIME`, so a fixture standing in for one has to answer
//! it too. It answers it from here, so the wire shape and the two verdict
//! replies live in exactly one place across the unit, integration, and
//! functional targets.

use std::time::{Duration, SystemTime};

/// RESP bulk string of the `TIME` command name, as it appears on the wire.
///
/// The probe is a standalone command, so this matches the whole argument of a
/// `*1\r\n$4\r\nTIME\r\n` array.
pub const TIME_CMD: &[u8] = b"$4\r\nTIME\r\n";

/// What a restrictive Redis ACL answers when `TIME` is not granted.
pub const TIME_DENIED_REPLY: &[u8] = b"-NOPERM this user has no permissions to run 'time'\r\n";

/// What a RESP-compatible server that does not implement `TIME` answers.
pub const TIME_UNKNOWN_COMMAND_REPLY: &[u8] = b"-ERR unknown command 'TIME'\r\n";

/// RESP encoding of a Redis `TIME` reply: Unix seconds and the microseconds
/// inside that second, both as bulk strings.
pub fn encode_server_time(now: Duration) -> Vec<u8> {
    let seconds = now.as_secs().to_string();
    let micros = now.subsec_micros().to_string();
    format!(
        "*2\r\n${}\r\n{seconds}\r\n${}\r\n{micros}\r\n",
        seconds.len(),
        micros.len()
    )
    .into_bytes()
}

/// The `TIME` reply of a fixture that does not model a clock of its own.
///
/// It reports this host's clock, which is also the clock the client samples
/// its replies against, so the learned offset settles near zero and sub-bucket
/// selection is exactly what an uncorrected client would have chosen. A
/// fixture that needs a genuinely skewed server clock builds its own reply with
/// [`encode_server_time`].
pub fn host_clock_time_reply() -> Vec<u8> {
    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap_or_default();
    encode_server_time(now)
}
