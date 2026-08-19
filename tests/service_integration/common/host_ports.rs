//! Host-port allocation for service-integration testcontainers.
//!
//! Docker maps a container port onto a host port. Choosing that host port with
//! `127.0.0.1:0` (or letting Docker auto-assign) lands inside Linux
//! `/proc/sys/net/ipv4/ip_local_port_range`. The mapping is then a classic
//! bind-drop-rebind race: the probe socket is released, an unrelated ephemeral
//! connection or sibling container claims the number, and Docker fails with
//! `port is already allocated` (issue #3999; same family as #3993).
//!
//! This helper probes candidate ports **outside** the ephemeral source range
//! and retries container start only when Docker reports a genuine host-port
//! bind collision. Other start failures fail immediately so image-pull or
//! wait-condition breakage cannot hide behind a timeout.

use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::sync::{Mutex, OnceLock};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// First port probed for container host mappings. Matches the mesh fixture
/// allocator (issue #3993): above well-known services, typically below the
/// Linux ephemeral floor of 32768.
pub const HOST_PORT_PROBE_START: u16 = 10_240;

/// Bound retries when Docker reports the chosen host port was stolen before
/// the container bind completed. Fresh ports are allocated on every attempt.
pub const HOST_PORT_COLLISION_ATTEMPTS: u32 = 5;

/// IANA suggested dynamic/private range, used only when `/proc` is unavailable
/// (non-Linux CI/dev hosts).
#[cfg(not(target_os = "linux"))]
const FALLBACK_EPHEMERAL_FIRST: u16 = 49_152;
#[cfg(not(target_os = "linux"))]
const FALLBACK_EPHEMERAL_LAST: u16 = 65_535;

static USED_HOST_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

fn used_host_ports() -> &'static Mutex<HashSet<u16>> {
    USED_HOST_PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Why a host-port probe could not return a mapping.
#[derive(Debug)]
pub enum HostPortAllocError {
    Exhausted {
        ephemeral_first: u16,
        ephemeral_last: u16,
        probe_first: u16,
        probe_last: u16,
    },
    BindFailed {
        port: u16,
        source: io::Error,
    },
}

impl std::fmt::Display for HostPortAllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted {
                ephemeral_first,
                ephemeral_last,
                probe_first,
                probe_last,
            } => write!(
                f,
                "no free service-integration host port outside ephemeral range \
                 {ephemeral_first}-{ephemeral_last} in probe window \
                 {probe_first}-{probe_last}"
            ),
            Self::BindFailed { port, source } => {
                write!(f, "probe host port {port}: {source}")
            }
        }
    }
}

impl std::error::Error for HostPortAllocError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BindFailed { source, .. } => Some(source),
            Self::Exhausted { .. } => None,
        }
    }
}

/// Parse `/proc/sys/net/ipv4/ip_local_port_range` (`"<first> <last>\n"`).
pub fn parse_ephemeral_port_range(raw: &str) -> Result<(u16, u16), String> {
    let mut fields = raw.split_whitespace();
    let first = fields
        .next()
        .ok_or_else(|| "ephemeral port range is empty".to_string())?
        .parse::<u16>()
        .map_err(|error| format!("parse ephemeral port range start: {error}"))?;
    let last = fields
        .next()
        .ok_or_else(|| "ephemeral port range has no end".to_string())?
        .parse::<u16>()
        .map_err(|error| format!("parse ephemeral port range end: {error}"))?;
    if fields.next().is_some() || first > last {
        return Err(format!("invalid ephemeral port range: {raw:?}"));
    }
    Ok((first, last))
}

fn ephemeral_port_range() -> Result<(u16, u16), BoxError> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .map_err(|error| format!("read host ephemeral port range: {error}"))?;
        parse_ephemeral_port_range(&raw).map_err(Into::into)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok((FALLBACK_EPHEMERAL_FIRST, FALLBACK_EPHEMERAL_LAST))
    }
}

/// True when a container-start error is a host-port bind collision rather than
/// a real fixture failure (image pull, wait condition, process crash, …).
///
/// Matches Docker's `port is already allocated` and the kernel `EADDRINUSE`
/// phrasing. Does **not** match generic "failed to start a container" or
/// "failed to set up container networking" text, which would blanket-retry
/// unrelated breakage.
pub fn is_host_port_collision(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("port is already allocated")
        || lower.contains("address already in use")
        || lower.contains("eaddrinuse")
}

/// Probe one currently-free host port outside the ephemeral source range.
///
/// The listener is dropped before return so Docker can bind `0.0.0.0:port`.
/// Callers must treat the remaining gap as a race and wrap container start
/// with [`retry_on_host_port_collision`].
pub fn allocate_host_port() -> Result<u16, BoxError> {
    let (ephemeral_first, ephemeral_last) = ephemeral_port_range()?;
    let mut used = used_host_ports()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let pid_offset = (std::process::id() % 2048) as u16;
    let start = HOST_PORT_PROBE_START.saturating_add(pid_offset);
    allocate_host_port_with(
        ephemeral_first..=ephemeral_last,
        HOST_PORT_PROBE_START,
        u16::MAX,
        start,
        &mut used,
        |port| std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).map(|_| ()),
    )
    .map_err(Into::into)
}

/// Allocate `N` distinct host ports from the same process-wide used set.
pub fn allocate_host_ports<const N: usize>() -> Result<[u16; N], BoxError> {
    let mut ports = [0u16; N];
    for slot in &mut ports {
        *slot = allocate_host_port()?;
    }
    Ok(ports)
}

/// Injectable allocator used by unit tests (range bounds, used-set, exhaustion).
pub fn allocate_host_port_with(
    ephemeral: RangeInclusive<u16>,
    probe_first: u16,
    probe_last: u16,
    start: u16,
    used: &mut HashSet<u16>,
    mut try_bind: impl FnMut(u16) -> io::Result<()>,
) -> Result<u16, HostPortAllocError> {
    if probe_first > probe_last {
        return Err(HostPortAllocError::Exhausted {
            ephemeral_first: *ephemeral.start(),
            ephemeral_last: *ephemeral.end(),
            probe_first,
            probe_last,
        });
    }
    let start = start.clamp(probe_first, probe_last);
    let candidates = (start..=probe_last).chain(probe_first..start);
    for port in candidates {
        if ephemeral.contains(&port) || used.contains(&port) {
            continue;
        }
        match try_bind(port) {
            Ok(()) => {
                used.insert(port);
                return Ok(port);
            }
            Err(error)
                if error.kind() == io::ErrorKind::AddrInUse
                    || error.kind() == io::ErrorKind::PermissionDenied
                    || error.kind() == io::ErrorKind::AddrNotAvailable =>
            {
                continue;
            }
            Err(error) => {
                return Err(HostPortAllocError::BindFailed {
                    port,
                    source: error,
                });
            }
        }
    }
    Err(HostPortAllocError::Exhausted {
        ephemeral_first: *ephemeral.start(),
        ephemeral_last: *ephemeral.end(),
        probe_first,
        probe_last,
    })
}

/// Run `start_once` until it succeeds, retrying only host-port bind collisions.
///
/// `start_once` must allocate fresh host ports on every invocation. Non-collision
/// errors are returned immediately so a broken image or wait condition still
/// fails the CI-required fixture loudly.
pub async fn retry_on_host_port_collision<F, Fut, T>(mut start_once: F) -> Result<T, BoxError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, BoxError>>,
{
    let mut last_err: Option<BoxError> = None;
    for _ in 1..=HOST_PORT_COLLISION_ATTEMPTS {
        match start_once().await {
            Ok(value) => return Ok(value),
            Err(err) if is_host_port_collision(&err.to_string()) => {
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    let last = last_err
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown host-port collision".to_string());
    Err(format!(
        "container host port was still allocated after \
         {HOST_PORT_COLLISION_ATTEMPTS} attempts: {last}"
    )
    .into())
}
