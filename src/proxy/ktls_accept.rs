//! Frontend-TLS TCP kTLS handoff driven by rustls's **unbuffered** server
//! handshake (issue #3619, superseding the refuse-closed gate of issue #2955).
//!
//! # Why the buffered accept path could never hand off
//!
//! `ServerConnection::dangerous_extract_secrets` refuses only when secret
//! extraction is disabled, the handshake is incomplete, or *outbound* records
//! are still buffered. It silently discards (a) decrypted-but-unread received
//! plaintext and (b) residual *inbound* bytes in rustls's private deframer —
//! in particular the head of a partial TLS record. kTLS resumes decryption
//! straight from the socket at the extracted `rx` sequence number, so handoff
//! is sound only when the next byte the kernel reads is the first byte of that
//! record. Case (b) is not observable through the buffered API, so the
//! buffered path was pinned closed.
//!
//! # How this module makes the handoff provable
//!
//! The handshake runs on [`UnbufferedServerConnection`], whose input buffer is
//! caller-owned, and this module reads the socket **one whole TLS record at a
//! time** and only while rustls reports `BlockedHandshake`. That gives three
//! properties by construction at the moment `ConnectionState::WriteTraffic` is
//! reached:
//!
//! 1. No decrypted plaintext is staged. `process_tls_records` yields
//!    `ReadTraffic`/`ReadEarlyData` *before* `WriteTraffic` whenever any
//!    plaintext exists, so reaching `WriteTraffic` proves there is none.
//! 2. No outbound record is pending. `EncodeTlsData`/`TransmitTlsData` are
//!    likewise emitted first, and `dangerous_into_kernel_connection` re-checks
//!    `sendable_tls` itself.
//! 3. The caller-owned inbound buffer is empty and the socket is positioned at
//!    a record boundary. Records are appended whole and rustls reports the
//!    bytes it consumed via `UnbufferedStatus::discard`; the loop refuses
//!    handoff if anything is left over. A client that coalesces application
//!    data with its handshake tail simply leaves that record in the *socket*
//!    receive queue, where the kernel record layer picks it up — the exact
//!    case that motivated #2955.
//!
//! # Fail-safe fallback contract
//!
//! [`try_ktls_accept`] is allowed to touch the socket destructively only after
//! every recoverable refusal has been made. Everything that can decline —
//! kernel/cipher probes, secret-extraction opt-in, ClientHello facts (TLS 1.3
//! offered, a finite-limit AES-GCM suite among the selectable offers, no
//! kernel-supported unlimited AEAD suite), an SNI this path cannot reproduce
//! as faithfully as `ServerConnection::server_name()` would, and
//! `TCP_ULP` install — happens before any TLS byte is consumed (the ClientHello
//! is only `MSG_PEEK`ed) and returns [`KtlsAcceptOutcome::Declined`] with a
//! stream the ordinary buffered tokio-rustls accept can continue using.
//!
//! # The traffic keys carry a confidentiality budget across the handoff
//!
//! rustls stops counting protected messages the moment
//! `dangerous_into_kernel_connection` is called, and its `kernel` module makes
//! aborting before the suite's `CipherSuiteCommon::confidentiality_limit` the
//! caller's responsibility. Finite-limit TLS 1.2 AES-GCM suites are therefore
//! removed from ClientHello eligibility before the handshake consumes the
//! socket: Linux cannot report a race-free bound for records already admitted
//! before a post-accept `SO_RCVBUF` pin (`FIONREAD` omits out-of-order skbs),
//! so those connections keep the ordinary buffered rustls relay. Only
//! ChaCha20-Poly1305 (rustls `confidentiality_limit: u64::MAX`) remains
//! eligible; it builds no confidentiality guard, pins nothing, and keeps
//! ordinary receive autotuning. The defensive budget machinery in
//! [`crate::proxy::ktls_confidentiality`] stays fail-closed if a future caller
//! ever presents a limited suite, but it is not a basis for making AES-GCM
//! eligible again.
//!
//! # TLS 1.3 is refused, not silently mishandled
//!
//! The kernel holds a static copy of the application traffic secret and this
//! module does not implement KeyUpdate rekeying, so a TLS 1.3 client is
//! declined *before* any handshake work (from the `supported_versions`
//! extension in the peeked ClientHello) and the userspace rustls relay is used
//! instead. TLS 1.2 has no in-band rekey, so a static kernel key is correct
//! for its whole lifetime.

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::modes::mesh::node_waypoint_observability::{
    NodeWaypointHboneHandshakePhase, record_hbone_handshake,
};
use crate::proxy::ktls_confidentiality::{
    KtlsConfidentialityPolicy, KtlsDirection, KtlsSessionLimits, observe_record_seq,
};
use crate::socket_opts::ktls;

/// Largest `TLSCiphertext.length` any TLS 1.2/1.3 peer may send
/// (`2^14 + 2048`). A record header claiming more is rejected outright rather
/// than allowed to size an allocation.
const MAX_TLS_RECORD_LEN: usize = 16_384 + 2048;

/// Hard ceiling on the caller-owned inbound handshake buffer. rustls bounds
/// handshake message sizes itself, but a peer that dribbles handshake records
/// rustls has not yet consumed must not be able to grow this without bound.
const MAX_INBOUND_HANDSHAKE_BYTES: usize = 128 * 1024;

/// Hard ceiling on the outbound flight buffer. Server flights (certificate
/// chain + key exchange) are a few KiB; this only exists so a pathological
/// `InsufficientSize` request cannot drive an unbounded allocation.
const MAX_OUTBOUND_FLIGHT_BYTES: usize = 256 * 1024;

/// Initial outbound flight buffer. Grown on demand from `EncodeTlsData`.
const INITIAL_OUTBOUND_FLIGHT_BYTES: usize = 8 * 1024;

/// Delay between ClientHello peeks while the hello is still arriving.
/// `peek()` returns as soon as ≥1 byte is readable, so back-to-back peeks
/// would busy-loop (mirrors `sni::SNI_PEEK_RETRY_INTERVAL`).
const HELLO_PEEK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// A frontend-TLS TCP connection whose keys now live in the kernel.
///
/// The socket carries **plaintext** to userspace from here on: the kernel TLS
/// ULP decrypts on read and encrypts on write, which is what makes `splice(2)`
/// legal on a TLS-terminating relay.
pub(crate) struct KtlsAccepted {
    /// The kTLS-installed socket. Reads yield decrypted application bytes.
    pub(crate) stream: TcpStream,
    /// SNI hostname parsed from the ClientHello (already ASCII-lowercased).
    pub(crate) sni_hostname: Option<String>,
    /// Verified client certificate chain (leaf first), when mTLS is configured.
    pub(crate) peer_certificates: Option<Vec<Vec<u8>>>,
    /// Per-direction traffic-key confidentiality budget the relay must enforce
    /// now that rustls no longer can (issue #3619).
    pub(crate) confidentiality: KtlsConfidentialityPolicy,
}

/// Result of attempting the unbuffered kTLS accept.
pub(crate) enum KtlsAcceptOutcome {
    /// kTLS keys are installed; relay with `splice(2)`.
    Installed(Box<KtlsAccepted>),
    /// Nothing was consumed from the socket and nothing was written to it.
    /// The caller MUST complete the ordinary buffered tokio-rustls accept.
    Declined(TcpStream),
    /// The connection is unusable (I/O failure, handshake rejection, timeout,
    /// or a kernel install failure past the point of no return).
    Failed(io::Error),
}

/// Attempt a Linux kTLS handoff for a frontend-TLS TCP connection.
///
/// Returns [`KtlsAcceptOutcome::Declined`] with the pristine stream for every
/// unsupported platform state, unsupported version/cipher, disabled opt-in,
/// kernel probe failure, or unprovable ClientHello — never a dropped
/// connection. `Failed` is reserved for a connection that a buffered accept
/// could not have rescued either (peer I/O error, handshake rejection,
/// handshake timeout) plus the single documented residual below.
///
/// ## Residual unrecoverable window
///
/// Once the handshake has completed and `dangerous_into_kernel_connection`
/// has consumed the rustls session, a failing `setsockopt(SOL_TLS, TLS_TX/RX)`
/// leaves no userspace TLS state to relay with. That window is guarded by (a)
/// the startup per-cipher probe, which performs the identical `TCP_ULP` + key
/// install for this exact cipher on a real loopback socket, and (b) the
/// `TCP_ULP` install performed on *this* socket before the handshake starts.
/// What remains is ENOMEM-class kernel failure.
///
/// ## Handshake budget
///
/// `deadline` is the caller's *single* frontend-TLS admission deadline, not a
/// fresh per-stage allowance. Everything this function does — ClientHello
/// peeking and the unbuffered handshake alike — draws from it, and the caller
/// passes the same `Instant` to the buffered fallback, so a peer that dribbles
/// a partial hello cannot consume the budget here and then be granted a second
/// full one on the fallback path.
pub(crate) async fn try_ktls_accept(
    stream: TcpStream,
    config: &Arc<ServerConfig>,
    deadline: Option<Instant>,
    handshake_timeout_secs: u64,
    peer: &SocketAddr,
    record_mesh_mtls_metric: bool,
) -> KtlsAcceptOutcome {
    // ---- Recoverable refusals: the socket stays pristine through all of these.

    // `dangerous_into_kernel_connection` requires the opt-in that
    // `tls::enable_secret_extraction_for_ktls` applies at config build time.
    if !config.enable_secret_extraction {
        debug!("kTLS: secret extraction not enabled on this frontend TLS config, declining");
        return KtlsAcceptOutcome::Declined(stream);
    }

    if !ktls::is_ktls_available() {
        debug!("kTLS: kernel probe reports no usable cipher, declining");
        return KtlsAcceptOutcome::Declined(stream);
    }

    // The ClientHello is peeked, never consumed: declining below leaves the
    // buffered acceptor a byte-for-byte untouched stream.
    let Some(hello) = peek_client_hello(&stream, deadline).await else {
        debug!(
            peer = %peer.ip(),
            "kTLS: no complete ClientHello observable before the handshake deadline, declining"
        );
        return KtlsAcceptOutcome::Declined(stream);
    };

    let Some(facts) = crate::proxy::sni::client_hello_ktls_facts(&hello) else {
        debug!(
            peer = %peer.ip(),
            "kTLS: ClientHello could not be parsed for handoff eligibility, declining"
        );
        return KtlsAcceptOutcome::Declined(stream);
    };

    if !facts.ktls_eligible(
        cipher_handoff_usable(ktls::KtlsCipher::Aes128Gcm),
        cipher_handoff_usable(ktls::KtlsCipher::Aes256Gcm),
        cipher_handoff_usable(ktls::KtlsCipher::Chacha20Poly1305),
    ) {
        debug!(
            peer = %peer.ip(),
            offers_tls13 = facts.offers_tls13,
            "kTLS: ClientHello is not provably TLS 1.2 with a kernel-supported AEAD suite, \
             retaining the userspace rustls relay"
        );
        return KtlsAcceptOutcome::Declined(stream);
    }

    // Peer identity parity with the buffered accept. That path reports
    // `ServerConnection::server_name()`, the hostname rustls itself validated;
    // `UnbufferedServerConnection` exposes no equivalent accessor, so this path
    // re-parses the peeked hello. Ferrum's SNI validator is deliberately
    // stricter than rustls's `DnsName` rules (underscore labels and a trailing
    // root dot are refused here and accepted there), so a hello whose
    // `server_name` extension is present but unrepresentable would hand the
    // relay a `None` where the buffered accept reports a hostname — silently
    // changing what stream lifecycle plugins and transaction summaries see.
    // Decline while the socket is still pristine instead.
    let sni_hostname = crate::proxy::sni::extract_sni_from_client_hello(&hello);
    if !facts.sni_is_representable(sni_hostname.as_deref()) {
        debug!(
            peer = %peer.ip(),
            "kTLS: ClientHello SNI is not representable from the peeked hello, retaining the \
             userspace rustls relay so the connection reports rustls's own server name"
        );
        return KtlsAcceptOutcome::Declined(stream);
    }

    // Finite-limit AES-GCM suites are deliberately excluded above. Linux does
    // not expose a race-free bound for data admitted before SO_RCVBUF is
    // pinned: FIONREAD omits out-of-order skbs, so it cannot prove the receive
    // record budget. ChaCha20-Poly1305 has no finite confidentiality limit and
    // therefore needs neither a pinned window nor a receive ceiling.
    let stable_receive_ceiling = 0;

    let mut conn = match UnbufferedServerConnection::new(config.clone()) {
        Ok(conn) => conn,
        Err(e) => {
            debug!("kTLS: unbuffered server connection unavailable ({e}), declining");
            return KtlsAcceptOutcome::Declined(stream);
        }
    };

    // `TCP_ULP` is sticky on the fd, so install it while declining is still
    // possible. Before any key is installed the TLS ULP is the `TLS_BASE`
    // variant, which overrides only `setsockopt`/`getsockopt`/`close` — plain
    // reads and writes (including the userspace rustls relay taken on the
    // decline path) are unaffected.
    if let Err(e) = install_tcp_ulp(&stream) {
        debug!("kTLS: TCP_ULP install failed ({e}), declining");
        return KtlsAcceptOutcome::Declined(stream);
    }

    // ---- Point of no return: the handshake consumes socket bytes.

    let mut stream = stream;
    let handshake_result = match deadline {
        Some(d) => {
            let handshake = drive_unbuffered_handshake(&mut stream, &mut conn);
            match tokio::time::timeout_at(d, handshake).await {
                Ok(result) => result,
                Err(_) => {
                    record_frontend_tls_failure(record_mesh_mtls_metric, "timeout");
                    warn!(
                        "Frontend TLS handshake timed out from {} after {}s",
                        peer.ip(),
                        handshake_timeout_secs
                    );
                    return KtlsAcceptOutcome::Failed(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "frontend TLS handshake timed out",
                    ));
                }
            }
        }
        None => drive_unbuffered_handshake(&mut stream, &mut conn).await,
    };
    if let Err(e) = handshake_result {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        warn!("Frontend TLS handshake failed from {}: {}", peer.ip(), e);
        return KtlsAcceptOutcome::Failed(e);
    }

    // `WriteTraffic` proved the handshake completed with nothing buffered in
    // either direction. Re-read the negotiated parameters from the session
    // rather than trusting the pre-handshake ClientHello prediction.
    let Some(suite) = conn.negotiated_cipher_suite() else {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: no negotiated cipher suite after the handshake",
        ));
    };
    let Some(cipher) = ktls_cipher_for(suite.suite()) else {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: negotiated cipher suite is not installable in the kernel",
        ));
    };
    if !cipher_kernel_available(cipher) {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: negotiated cipher suite failed the kernel probe",
        ));
    }
    // The suite's own confidentiality limit, read from rustls rather than
    // hardcoded. Enforcing it is impossible without the kernel's record
    // sequence number, so a limited suite on a kernel that cannot report one
    // fails closed here. The pre-handshake eligibility gate above already
    // refuses that combination while the socket is pristine; this is the
    // defence-in-depth restatement for a suite rustls picked anyway.
    let limits = KtlsSessionLimits {
        cipher,
        tls_version: TLS_1_2_WIRE_VERSION,
        confidentiality_limit: suite_confidentiality_limit(suite),
    };
    if limits.requires_enforcement() && !ktls::is_ktls_record_seq_observable(cipher) {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: negotiated suite has a confidentiality limit but this kernel does not \
             report record sequence numbers",
        ));
    }
    // The pre-handshake ClientHello gate excludes every finite-limit suite.
    // Restate that invariant against the suite rustls actually chose before
    // consuming the session.
    if limits.requires_enforcement() && stable_receive_ceiling == 0 {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: negotiated suite requires a receive bound that was not established before \
             the handshake",
        ));
    }
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_2) {
        // Unreachable: rustls cannot negotiate TLS 1.3 without the
        // `supported_versions` extension the eligibility gate rejected.
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: negotiated TLS version is not TLS 1.2",
        ));
    }

    let peer_certificates: Option<Vec<Vec<u8>>> = conn
        .peer_certificates()
        .map(|certs| certs.iter().map(|cert| cert.to_vec()).collect());

    let secrets = match conn.dangerous_into_kernel_connection() {
        // The `KernelConnection` only exists to drive TLS 1.3 KeyUpdate and
        // client-side session tickets, neither of which applies to a TLS 1.2
        // server session. Dropping it releases the remaining key schedule.
        //
        // What it does NOT release is the confidentiality budget: rustls stops
        // counting protected messages here, so `limits` above plus the kernel
        // readback below take that over for the life of the connection.
        Ok((secrets, _kernel_conn)) => secrets,
        Err(e) => {
            record_frontend_tls_failure(record_mesh_mtls_metric, "error");
            warn!("kTLS: kernel handoff refused by rustls: {e}");
            return KtlsAcceptOutcome::Failed(io::Error::other(format!(
                "kTLS kernel handoff refused: {e}"
            )));
        }
    };

    // The sequence numbers the handshake already consumed. A TLS 1.2 server has
    // encrypted and decrypted at least its `Finished` record before handoff, so
    // a budget that started at zero would overstate the remaining headroom by
    // exactly those records.
    let tx_seq = secrets.tx.0;
    let rx_seq = secrets.rx.0;

    let Some(params) = build_ktls_params(TLS_1_2_WIRE_VERSION, &secrets) else {
        record_frontend_tls_failure(record_mesh_mtls_metric, "error");
        return KtlsAcceptOutcome::Failed(io::Error::other(
            "kTLS: extracted secrets are not mappable to kernel crypto info",
        ));
    };
    drop(secrets);

    let fd = stream.as_raw_fd();
    match ktls::enable_ktls(fd, &params) {
        Ok(true) => {
            drop(params);
            let seeded =
                seed_confidentiality_policy(fd, &limits, tx_seq, rx_seq, stable_receive_ceiling);
            let confidentiality = match seeded {
                Ok(policy) => policy,
                Err(e) => {
                    record_frontend_tls_failure(record_mesh_mtls_metric, "error");
                    warn!("kTLS: confidentiality budget could not be established: {e}");
                    return KtlsAcceptOutcome::Failed(e);
                }
            };
            if record_mesh_mtls_metric {
                record_hbone_handshake(NodeWaypointHboneHandshakePhase::InboundTls, true);
            }
            debug!(
                peer = %peer.ip(),
                "kTLS: kernel TLS installed from the unbuffered handshake; splicing TLS frontend"
            );
            KtlsAcceptOutcome::Installed(Box::new(KtlsAccepted {
                stream,
                sni_hostname,
                peer_certificates,
                confidentiality,
            }))
        }
        Ok(false) => {
            drop(params);
            record_frontend_tls_failure(record_mesh_mtls_metric, "error");
            warn!("kTLS: kernel returned ENOPROTOOPT after the handshake completed");
            KtlsAcceptOutcome::Failed(io::Error::other(
                "kTLS not supported by kernel after secret extraction",
            ))
        }
        Err(e) => {
            drop(params);
            record_frontend_tls_failure(record_mesh_mtls_metric, "error");
            warn!("kTLS: kernel key install failed after the handshake completed: {e}");
            KtlsAcceptOutcome::Failed(io::Error::other(format!("kTLS setsockopt failed: {e}")))
        }
    }
}

/// Wire code point for TLS 1.2, the only version handed to the kernel.
const TLS_1_2_WIRE_VERSION: u16 = 0x0303;

fn record_frontend_tls_failure(record_mesh_mtls_metric: bool, reason: &'static str) {
    if !record_mesh_mtls_metric {
        return;
    }
    crate::plugins::mesh::prometheus_helpers::increment_mesh_mtls_handshake_failure(reason);
    record_hbone_handshake(NodeWaypointHboneHandshakePhase::InboundTls, false);
}

/// Install the kernel TLS upper-layer protocol on the socket.
///
/// `EEXIST` means the ULP is already present (a retried accept on the same fd)
/// and is treated as success.
fn install_tcp_ulp(stream: &TcpStream) -> io::Result<()> {
    let ulp_name = b"tls\0";
    // SAFETY: `fd` is owned by the live `TcpStream` for the duration of the
    // call and `ulp_name` is a NUL-terminated buffer of the given length.
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_ULP,
            ulp_name.as_ptr() as *const libc::c_void,
            ulp_name.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Peek (never consume) until a complete ClientHello is buffered.
///
/// Returns `None` when the peer is not speaking TLS, the hello never
/// completes before the deadline, or it exceeds the hard peek bound. The
/// caller declines in every one of those cases, so the socket contents are
/// still whole for the buffered acceptor.
async fn peek_client_hello(stream: &TcpStream, deadline: Option<Instant>) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; crate::proxy::sni::initial_peek_capacity()];
    let hard_cap = crate::proxy::sni::no_deadline_peek_capacity();
    loop {
        let peeked = match deadline {
            Some(d) => tokio::time::timeout_at(d, stream.peek(&mut buf))
                .await
                .ok()?
                .ok()?,
            // With the handshake clock disabled there is no bound to loop
            // against, so take exactly one peek after readiness and decline if
            // the hello is not yet whole.
            None => {
                stream.readable().await.ok()?;
                stream.peek(&mut buf).await.ok()?
            }
        };
        if peeked == 0 {
            return None;
        }
        // Content type 0x16 (handshake): reject non-TLS prefixes on the first
        // visible byte instead of waiting out the handshake deadline.
        if buf[0] != 0x16 {
            return None;
        }
        if crate::proxy::sni::client_hello_ktls_facts(&buf[..peeked]).is_some() {
            buf.truncate(peeked);
            return Some(buf);
        }
        let d = deadline?;
        if peeked >= buf.len() {
            let want = crate::proxy::sni::next_peek_capacity(peeked);
            if want > buf.len() {
                // `peek()` always re-reads from byte 0 of the socket receive
                // queue, so growing between iterations is safe.
                buf.resize(want.min(hard_cap), 0);
                continue;
            }
            // Buffer is at the hard cap and the hello is still incomplete.
            return None;
        }
        let now = Instant::now();
        if now >= d {
            return None;
        }
        tokio::time::sleep_until((now + HELLO_PEEK_RETRY_INTERVAL).min(d)).await;
    }
}

/// Drive the unbuffered server handshake to `ConnectionState::WriteTraffic`.
///
/// Reads the socket one whole TLS record at a time and only when rustls
/// reports `BlockedHandshake`, so no byte beyond the handshake is ever pulled
/// out of the kernel receive queue and the caller-owned inbound buffer is
/// empty at the handoff point.
async fn drive_unbuffered_handshake(
    stream: &mut TcpStream,
    conn: &mut UnbufferedServerConnection,
) -> io::Result<()> {
    let mut incoming: Vec<u8> = Vec::new();
    let mut outgoing: Vec<u8> = vec![0u8; INITIAL_OUTBOUND_FLIGHT_BYTES];
    let mut outgoing_used = 0usize;

    loop {
        let mut needs_read = false;
        let mut reached_traffic = false;

        let discard = {
            let UnbufferedStatus { discard, state } = conn.process_tls_records(&mut incoming[..]);
            let state = state.map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("TLS handshake: {e}"))
            })?;
            match state {
                ConnectionState::EncodeTlsData(mut encoder) => loop {
                    match encoder.encode(&mut outgoing[outgoing_used..]) {
                        Ok(written) => {
                            outgoing_used += written;
                            break;
                        }
                        Err(EncodeError::InsufficientSize(need)) => {
                            let required = outgoing_used.saturating_add(need.required_size);
                            if required > MAX_OUTBOUND_FLIGHT_BYTES {
                                return Err(io::Error::other(
                                    "TLS handshake: outbound flight exceeds the bounded buffer",
                                ));
                            }
                            outgoing.resize(required, 0);
                        }
                        Err(e) => {
                            return Err(io::Error::other(format!(
                                "TLS handshake: record encode failed: {e}"
                            )));
                        }
                    }
                },
                ConnectionState::TransmitTlsData(transmit) => {
                    if outgoing_used > 0 {
                        stream.write_all(&outgoing[..outgoing_used]).await?;
                        outgoing_used = 0;
                    }
                    transmit.done();
                }
                ConnectionState::BlockedHandshake => needs_read = true,
                ConnectionState::WriteTraffic(_) => reached_traffic = true,
                // `ReadTraffic`/`ReadEarlyData` are unreachable: records are
                // only read while the handshake is blocked, so no application
                // record is ever pulled off the socket here. The remaining
                // states are peer-initiated closes during the handshake.
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("TLS handshake ended in state {other:?}"),
                    ));
                }
            }
            discard
        };

        if discard > 0 {
            if discard > incoming.len() {
                return Err(io::Error::other(
                    "TLS handshake: rustls discarded more bytes than were supplied",
                ));
            }
            incoming.drain(..discard);
        }

        if reached_traffic {
            if !incoming.is_empty() {
                // Unreachable with record-exact reads. Refusing here keeps the
                // "kernel resumes at a record boundary" invariant absolute.
                return Err(io::Error::other(
                    "kTLS: inbound handshake buffer not drained at handoff",
                ));
            }
            if outgoing_used > 0 {
                stream.write_all(&outgoing[..outgoing_used]).await?;
            }
            stream.flush().await?;
            return Ok(());
        }

        if needs_read {
            read_one_tls_record(stream, &mut incoming).await?;
        }
    }
}

/// Append exactly one whole TLS record to `buf`, reading nothing beyond it.
///
/// This is what makes the handoff provable: the socket is left positioned on a
/// record boundary, so any application data the client coalesced behind its
/// handshake tail stays in the kernel receive queue for the kTLS record layer.
async fn read_one_tls_record(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<()> {
    if buf.len().saturating_add(5) > MAX_INBOUND_HANDSHAKE_BYTES {
        return Err(io::Error::other(
            "TLS handshake: inbound record buffer exceeded its bound",
        ));
    }
    let header_at = buf.len();
    buf.resize(header_at + 5, 0);
    stream
        .read_exact(&mut buf[header_at..header_at + 5])
        .await?;

    let record_len = u16::from_be_bytes([buf[header_at + 3], buf[header_at + 4]]) as usize;
    if record_len > MAX_TLS_RECORD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS handshake: record length exceeds the protocol maximum",
        ));
    }
    let body_at = header_at + 5;
    if body_at.saturating_add(record_len) > MAX_INBOUND_HANDSHAKE_BYTES {
        return Err(io::Error::other(
            "TLS handshake: inbound record buffer exceeded its bound",
        ));
    }
    if record_len > 0 {
        buf.resize(body_at + record_len, 0);
        stream
            .read_exact(&mut buf[body_at..body_at + record_len])
            .await?;
    }
    Ok(())
}

/// Map a negotiated TLS 1.2 cipher suite to its kernel crypto family.
fn ktls_cipher_for(suite: rustls::CipherSuite) -> Option<ktls::KtlsCipher> {
    match suite {
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            Some(ktls::KtlsCipher::Aes128Gcm)
        }
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            Some(ktls::KtlsCipher::Aes256Gcm)
        }
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some(ktls::KtlsCipher::Chacha20Poly1305)
        }
        _ => None,
    }
}

/// Per-cipher kernel probe result. AES-GCM kTLS landed in Linux 4.13/4.17 and
/// ChaCha20-Poly1305 in 5.11, so a blanket availability answer is not enough.
fn cipher_kernel_available(cipher: ktls::KtlsCipher) -> bool {
    match cipher {
        ktls::KtlsCipher::Aes128Gcm => ktls::is_ktls_aes128gcm_available(),
        ktls::KtlsCipher::Aes256Gcm => ktls::is_ktls_aes256gcm_available(),
        ktls::KtlsCipher::Chacha20Poly1305 => ktls::is_ktls_chacha20_poly1305_available(),
    }
}

/// Whether a cipher may be offered to the handoff at all.
///
/// Installability is necessary but not sufficient. A suite with a finite
/// confidentiality limit also needs a sound upper bound on records already in
/// the receive queue. Linux's `FIONREAD` omits out-of-order skbs, so no such
/// bound is available when `SO_RCVBUF` is pinned after accept. Refuse those
/// suites here, before `UnbufferedServerConnection` reads a byte, so the
/// connection cleanly falls back to the buffered rustls relay.
///
/// ChaCha20-Poly1305 carries `confidentiality_limit: u64::MAX` in both pinned
/// providers, so it is deliberately *not* subject to the sequence-number
/// requirement: gating it there would disable a cipher that needs no budget.
fn cipher_handoff_usable(cipher: ktls::KtlsCipher) -> bool {
    if !cipher_kernel_available(cipher) {
        return false;
    }
    !cipher_has_confidentiality_limit(cipher)
}

/// Whether the TLS 1.2 suites that map to `cipher` carry a finite
/// confidentiality limit.
///
/// Cross-checked against the negotiated suite's real
/// `CipherSuiteCommon::confidentiality_limit` once the handshake completes
/// (`KtlsSessionLimits::requires_enforcement`), so this pre-handshake
/// approximation can only be conservative, never permissive.
fn cipher_has_confidentiality_limit(cipher: ktls::KtlsCipher) -> bool {
    match cipher {
        ktls::KtlsCipher::Aes128Gcm | ktls::KtlsCipher::Aes256Gcm => true,
        ktls::KtlsCipher::Chacha20Poly1305 => false,
    }
}

/// The negotiated suite's confidentiality limit, straight from rustls.
///
/// `u64::MAX` is rustls's encoding of "no limit applies". Reading the field
/// rather than hardcoding 2^24 means a provider or rustls upgrade that changes
/// the bound changes this enforcement with it.
fn suite_confidentiality_limit(suite: rustls::SupportedCipherSuite) -> u64 {
    match suite {
        rustls::SupportedCipherSuite::Tls12(inner) => inner.common.confidentiality_limit,
        rustls::SupportedCipherSuite::Tls13(inner) => inner.common.confidentiality_limit,
    }
}

/// Establish the per-connection confidentiality budget from the kernel's own
/// post-install state.
///
/// For an unlimited suite this is free. For a limited one it reads both
/// directions back through `getsockopt(SOL_TLS, ...)` and requires each to be
/// at least the sequence number rustls said the handshake had reached — a
/// kernel reporting *less* than what was just installed is not a counter this
/// budget can be built on, so it fails closed. The observed values (not the
/// requested ones) seed the policy, so the budget starts from what the kernel
/// will actually count from.
///
/// `stable_receive_ceiling` is the receive bound established before the rustls
/// session was consumed. The active handoff path always passes `0` today:
/// finite-limit suites are refused at the ClientHello gate, and unlimited
/// suites never pin a receive window. The argument is still threaded through so
/// a future finite-limit caller can supply a sound ceiling without re-deriving
/// one here — this function must not invent a fresh observation of a quantity
/// the budget needs to be immutable.
fn seed_confidentiality_policy(
    fd: std::os::unix::io::RawFd,
    limits: &KtlsSessionLimits,
    handshake_tx_seq: u64,
    handshake_rx_seq: u64,
    stable_receive_ceiling: u64,
) -> io::Result<KtlsConfidentialityPolicy> {
    if !limits.requires_enforcement() {
        let cipher = limits.cipher;
        let version = limits.tls_version;
        return Ok(KtlsConfidentialityPolicy::unlimited(cipher, version));
    }
    let tx = observe_record_seq(fd, limits, KtlsDirection::Transmit)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let rx = observe_record_seq(fd, limits, KtlsDirection::Receive)
        .map_err(|e| io::Error::other(e.to_string()))?;
    if tx.record_seq < handshake_tx_seq || rx.record_seq < handshake_rx_seq {
        return Err(io::Error::other(format!(
            "kTLS: kernel reports record sequences ({}, {}) below the handshake sequences \
             ({handshake_tx_seq}, {handshake_rx_seq})",
            tx.record_seq, rx.record_seq
        )));
    }
    let policy = KtlsConfidentialityPolicy {
        limits: *limits,
        initial_transmit_seq: tx.record_seq,
        initial_receive_seq: rx.record_seq,
        stable_receive_ceiling,
    };
    // Reject a session that is already out of budget rather than starting a
    // relay that would refuse on its first syscall.
    for direction in [KtlsDirection::Transmit, KtlsDirection::Receive] {
        let _guard = policy
            .guard(direction)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    Ok(policy)
}

/// Map rustls `ExtractedSecrets` to `KtlsParams` for the kernel TLS ULP.
///
/// Returns `None` if the cipher suite is not AES-128-GCM, AES-256-GCM, or
/// ChaCha20-Poly1305, or if the two directions disagree on the cipher.
///
/// Secret material is wrapped in `Zeroizing<Vec<u8>>` so the heap backing is
/// volatile-zeroed on drop. This applies to the intermediate allocations in
/// this function (they are `Zeroizing` from the moment they are created) as
/// well as any downstream storage inside `KtlsParams`.
fn build_ktls_params(
    tls_version: u16,
    secrets: &rustls::ExtractedSecrets,
) -> Option<ktls::KtlsParams> {
    use rustls::ConnectionTrafficSecrets;
    use zeroize::Zeroizing;

    let (tx_seq, ref tx_secrets) = secrets.tx;
    let (rx_seq, ref rx_secrets) = secrets.rx;

    let (cipher_suite, tx_key, tx_iv, rx_key, rx_iv) = match (tx_secrets, rx_secrets) {
        (
            ConnectionTrafficSecrets::Aes128Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes128Gcm { key: rk, iv: riv },
        ) => (
            ktls::KtlsCipher::Aes128Gcm,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        (
            ConnectionTrafficSecrets::Aes256Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes256Gcm { key: rk, iv: riv },
        ) => (
            ktls::KtlsCipher::Aes256Gcm,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        (
            ConnectionTrafficSecrets::Chacha20Poly1305 { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Chacha20Poly1305 { key: rk, iv: riv },
        ) => (
            ktls::KtlsCipher::Chacha20Poly1305,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        _ => return None,
    };

    Some(ktls::KtlsParams {
        tls_version,
        cipher_suite,
        tx_key,
        tx_iv,
        tx_seq: tx_seq.to_be_bytes(),
        rx_key,
        rx_iv,
        rx_seq: rx_seq.to_be_bytes(),
    })
}

#[cfg(test)]
mod ktls_param_tests {
    //! Tests for `build_ktls_params` — the rustls-ExtractedSecrets to
    //! KtlsParams mapping. These run inline (relocated with the function from
    //! `tcp_proxy.rs`) because `build_ktls_params` is private and the rustls
    //! types it consumes are not re-exported from the gateway crate.
    //!
    //! We use `AeadKey::from([u8; 32])` (the only stable public constructor)
    //! which yields a 32-byte key regardless of the cipher's real key length.
    //! That is harmless for this unit test since we are exercising the match
    //! arm selection and byte plumbing, not the kernel install path.

    use super::build_ktls_params;
    use crate::socket_opts::ktls::KtlsCipher;
    use rustls::ConnectionTrafficSecrets;
    use rustls::ExtractedSecrets;
    use rustls::crypto::cipher::{AeadKey, Iv};

    fn aead_key(byte: u8) -> AeadKey {
        AeadKey::from([byte; 32])
    }

    fn iv(byte: u8) -> Iv {
        Iv::new([byte; 12])
    }

    #[test]
    fn aes128_pair_maps_to_aes128_params() {
        let secrets = ExtractedSecrets {
            tx: (
                7,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x11),
                    iv: iv(0x21),
                },
            ),
            rx: (
                9,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x31),
                    iv: iv(0x41),
                },
            ),
        };

        let params = build_ktls_params(0x0303, &secrets).expect("AES-128 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Aes128Gcm));
        assert_eq!(params.tls_version, 0x0303);
        assert_eq!(params.tx_seq, 7u64.to_be_bytes());
        assert_eq!(params.rx_seq, 9u64.to_be_bytes());
        assert_eq!(params.tx_iv.as_slice(), &[0x21u8; 12]);
        assert_eq!(params.rx_iv.as_slice(), &[0x41u8; 12]);
    }

    #[test]
    fn mismatched_directions_do_not_map() {
        let secrets = ExtractedSecrets {
            tx: (
                0,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x11),
                    iv: iv(0x21),
                },
            ),
            rx: (
                0,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0x31),
                    iv: iv(0x41),
                },
            ),
        };

        assert!(build_ktls_params(0x0303, &secrets).is_none());
    }

    #[test]
    fn chacha20_pair_maps_to_chacha_params() {
        let secrets = ExtractedSecrets {
            tx: (
                1,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x51),
                    iv: iv(0x61),
                },
            ),
            rx: (
                2,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x71),
                    iv: iv(0x81),
                },
            ),
        };

        let params = build_ktls_params(0x0303, &secrets).expect("ChaCha20-Poly1305 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Chacha20Poly1305));
        assert_eq!(params.tx_iv.as_slice(), &[0x61u8; 12]);
    }
}
