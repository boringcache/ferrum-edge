//! kTLS control-record handling for the frontend-TLS TCP splice relay
//! (issue #3619).
//!
//! # Why this module exists
//!
//! Once a frontend-TLS TCP socket has been handed to the kernel TLS ULP
//! (`src/proxy/ktls_accept.rs`), the relay splices plaintext. `splice(2)` can
//! only move *application data*: when the record at the head of the kTLS
//! receive queue is any other content type, `tls_sw_splice_read` refuses with
//! `EINVAL` and **leaves the record queued**.
//!
//! `EINVAL` is therefore not a synonym for `close_notify`. It is the kernel's
//! answer for every non-application record — alerts of any severity,
//! renegotiation handshake records, ChangeCipherSpec — and `splice(2)` may
//! also return `EINVAL` for reasons that have nothing to do with TLS at all
//! (bad fd/flag combinations). Deciding "this was a graceful close" requires
//! actually reading the pending record and inspecting it.
//!
//! This module provides that: [`recv_ktls_record`] consumes exactly one record
//! with the `SOL_TLS` / `TLS_GET_RECORD_TYPE` `recvmsg(2)` ancillary contract,
//! and [`classify_ktls_control_record`] decides — as pure, testable logic —
//! whether it is the one thing that means clean EOF: an **authenticated TLS
//! 1.2 warning-level `close_notify`**. Everything else (fatal alerts, other
//! warning alerts, non-alert control records, malformed alert bodies) stays an
//! attributed relay error and is not swallowed.
//!
//! Authentication is the kernel's job and is already done by the time a record
//! surfaces here: the TLS ULP only delivers a record after its AEAD tag
//! verifies, so an attacker cannot inject a spoofed `close_notify` into an
//! established session.
//!
//! # Emitting `close_notify`
//!
//! The same ancillary contract runs in reverse for transmit:
//! [`send_close_notify`] issues one `sendmsg(2)` carrying a
//! `TLS_SET_RECORD_TYPE = alert` control message and the two-byte
//! `warning(1), close_notify(0)` body, so the peer sees a proper TLS shutdown
//! instead of a bare `shutdown(SHUT_WR)` (which a TLS client is required to
//! treat as a truncation attack).

/// TLS `ContentType` code points (RFC 5246 §6.2.1 / RFC 8446 §5.1).
pub const TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
/// TLS `alert` content type.
pub const TLS_RECORD_TYPE_ALERT: u8 = 21;
/// TLS `handshake` content type.
pub const TLS_RECORD_TYPE_HANDSHAKE: u8 = 22;
/// TLS `application_data` content type — the only one `splice(2)` can move.
pub const TLS_RECORD_TYPE_APPLICATION_DATA: u8 = 23;

/// `AlertLevel.warning` (RFC 5246 §7.2).
pub const TLS_ALERT_LEVEL_WARNING: u8 = 1;
/// `AlertLevel.fatal`.
pub const TLS_ALERT_LEVEL_FATAL: u8 = 2;
/// `AlertDescription.close_notify`.
pub const TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0;

/// The exact body of the only alert that means "clean EOF": `warning(1)`,
/// `close_notify(0)`. This is both what [`classify_ktls_control_record`]
/// accepts and what [`send_close_notify`] transmits.
pub const CLOSE_NOTIFY_ALERT_BODY: [u8; 2] =
    [TLS_ALERT_LEVEL_WARNING, TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY];

/// Maximum `TLSPlaintext.length` a peer may hand up after decryption
/// (`2^14`). Sizes the one-record scratch buffer used on the teardown path.
pub const MAX_TLS_PLAINTEXT_RECORD_LEN: usize = 16_384;

/// What the record pending on a kTLS receive queue actually was.
///
/// Only [`KtlsControlRecord::CloseNotify`] is a graceful end of stream. Every
/// other variant is reported as a relay failure rather than silently converted
/// into EOF, so a fatal alert or an unexpected renegotiation attempt cannot be
/// laundered into a successful-looking connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtlsControlRecord {
    /// Authenticated warning-level `close_notify`: the peer closed cleanly.
    CloseNotify,
    /// Any other alert, including every fatal alert and warning alerts that
    /// are not `close_notify`.
    Alert {
        /// `AlertLevel` byte as sent by the peer.
        level: u8,
        /// `AlertDescription` byte as sent by the peer.
        description: u8,
    },
    /// An alert record whose body is not exactly two bytes. A TLS 1.2 alert is
    /// fixed-width, so this is a malformed peer — fail closed.
    MalformedAlert {
        /// Observed body length.
        len: usize,
    },
    /// A well-formed record of some other content type (handshake /
    /// ChangeCipherSpec). Mid-stream renegotiation is not supported once the
    /// keys live in the kernel, so this ends the relay with an error.
    NonAlert {
        /// Observed `ContentType`.
        record_type: u8,
    },
}

impl KtlsControlRecord {
    /// Whether this record is the graceful end of the peer's write stream.
    #[inline]
    pub fn is_clean_eof(self) -> bool {
        matches!(self, KtlsControlRecord::CloseNotify)
    }
}

impl std::fmt::Display for KtlsControlRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KtlsControlRecord::CloseNotify => f.write_str("warning close_notify"),
            KtlsControlRecord::Alert { level, description } => {
                write!(f, "TLS alert level {level} description {description}")
            }
            KtlsControlRecord::MalformedAlert { len } => {
                write!(f, "malformed TLS alert record ({len} body bytes)")
            }
            KtlsControlRecord::NonAlert { record_type } => {
                write!(f, "unexpected TLS record type {record_type}")
            }
        }
    }
}

/// Classify one already-authenticated, already-decrypted control record.
///
/// Pure logic, deliberately separated from the syscall so the "only a
/// warning-level `close_notify` is EOF" rule can be pinned by tests on any
/// platform.
pub fn classify_ktls_control_record(record_type: u8, body: &[u8]) -> KtlsControlRecord {
    if record_type != TLS_RECORD_TYPE_ALERT {
        return KtlsControlRecord::NonAlert { record_type };
    }
    if body.len() != CLOSE_NOTIFY_ALERT_BODY.len() {
        return KtlsControlRecord::MalformedAlert { len: body.len() };
    }
    let level = body[0];
    let desc = body[1];
    if level == TLS_ALERT_LEVEL_WARNING && desc == TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY {
        KtlsControlRecord::CloseNotify
    } else {
        KtlsControlRecord::Alert {
            level,
            description: desc,
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::unix::io::RawFd;

    use crate::socket_opts::ktls::SOL_TLS;

    /// `cmsg_type` that sets the outgoing record's content type
    /// (`<linux/tls.h>`).
    pub const TLS_SET_RECORD_TYPE: libc::c_int = 1;
    /// `cmsg_type` the kernel attaches to a received non-application record.
    pub const TLS_GET_RECORD_TYPE: libc::c_int = 2;

    /// Inline capacity for a one-byte `SOL_TLS` control message. Linux's
    /// `CMSG_SPACE(1)` is 24 bytes on 64-bit and 16 on 32-bit; the constructor
    /// refuses rather than truncating if a platform ever exceeds this.
    pub(super) const RECORD_TYPE_CMSG_CAPACITY: usize = 32;

    /// The `SOL_TLS` / `TLS_SET_RECORD_TYPE` ancillary message that makes one
    /// `sendmsg(2)` emit a record of a chosen content type.
    ///
    /// Split out as its own value (rather than built inline in the syscall
    /// wrapper) so the wire layout can be constructed and read back in tests
    /// without opening a socket.
    pub struct TlsRecordTypeControl {
        buf: [u8; RECORD_TYPE_CMSG_CAPACITY],
        len: usize,
    }

    impl TlsRecordTypeControl {
        /// Build the control message for `record_type`.
        ///
        /// Returns `None` when this platform's `CMSG_SPACE(1)` does not fit the
        /// inline buffer. Failing closed matters: a truncated or absent control
        /// message would make the kernel emit the payload as ordinary
        /// **application data** instead of an alert.
        pub fn new(record_type: u8) -> Option<Self> {
            // SAFETY: `CMSG_SPACE` is a pure arithmetic macro over its length
            // argument and dereferences nothing.
            let space = unsafe { libc::CMSG_SPACE(1) } as usize;
            if space == 0 || space > RECORD_TYPE_CMSG_CAPACITY {
                return None;
            }
            let mut out = TlsRecordTypeControl {
                buf: [0u8; RECORD_TYPE_CMSG_CAPACITY],
                len: space,
            };
            // SAFETY: `msg` is zeroed and its only populated fields point at
            // `out.buf`, which lives for the whole block and is at least
            // `space` bytes. `CMSG_FIRSTHDR` therefore returns either null or a
            // correctly aligned `cmsghdr` inside that buffer, and
            // `CMSG_DATA(cmsg)` is the one payload byte `CMSG_LEN(1)` reserves.
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_control = out.buf.as_mut_ptr().cast::<libc::c_void>();
                msg.msg_controllen = space as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if cmsg.is_null() {
                    return None;
                }
                (*cmsg).cmsg_level = SOL_TLS;
                (*cmsg).cmsg_type = TLS_SET_RECORD_TYPE;
                (*cmsg).cmsg_len = libc::CMSG_LEN(1) as _;
                std::ptr::write(libc::CMSG_DATA(cmsg), record_type);
            }
            Some(out)
        }

        /// Raw ancillary bytes handed to `sendmsg(2)`.
        pub fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }

        /// Read the message back as `(cmsg_level, cmsg_type, record_type)`.
        ///
        /// Test seam: lets the ancillary contract be asserted without a socket.
        pub fn parsed(&self) -> Option<(libc::c_int, libc::c_int, u8)> {
            let mut scratch = self.buf;
            // SAFETY: same shape as `new` — a zeroed `msghdr` whose control
            // buffer is the local `scratch` array of `self.len` valid bytes.
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_control = scratch.as_mut_ptr().cast::<libc::c_void>();
                msg.msg_controllen = self.len as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if cmsg.is_null() {
                    return None;
                }
                Some((
                    (*cmsg).cmsg_level,
                    (*cmsg).cmsg_type,
                    std::ptr::read(libc::CMSG_DATA(cmsg)),
                ))
            }
        }
    }

    /// Outcome of consuming one record from a kTLS receive queue.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KtlsRecvOutcome {
        /// The peer's write side is at EOF with no record pending.
        Eof,
        /// A non-application record; `super::classify_ktls_control_record`
        /// decides what it means.
        Control {
            /// TLS `ContentType` reported by the kernel.
            record_type: u8,
            /// Length of the decrypted body written into the caller's buffer.
            len: usize,
        },
        /// Application data. The bytes were consumed from the socket, so the
        /// caller MUST forward them instead of dropping them.
        ApplicationData {
            /// Length written into the caller's buffer.
            len: usize,
        },
    }

    /// Consume exactly one decrypted record from a kTLS socket.
    ///
    /// Non-blocking (`MSG_DONTWAIT`): `WouldBlock` is surfaced to the caller so
    /// it can wait on readiness rather than parking a runtime worker.
    ///
    /// The kernel attaches a `SOL_TLS`/`TLS_GET_RECORD_TYPE` control message
    /// **only** for non-application records, so an absent control message is
    /// what identifies application data. A truncated control message
    /// (`MSG_CTRUNC`) is an error rather than a guess — misreading the content
    /// type is exactly the failure this module exists to prevent.
    pub fn recv_ktls_record(fd: RawFd, buf: &mut [u8]) -> io::Result<KtlsRecvOutcome> {
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "kTLS record buffer must be non-empty",
            ));
        }
        // SAFETY: `CMSG_SPACE` is pure arithmetic.
        let control_space = unsafe { libc::CMSG_SPACE(1) } as usize;
        if control_space == 0 || control_space > RECORD_TYPE_CMSG_CAPACITY {
            return Err(io::Error::other(
                "kTLS: platform CMSG_SPACE(1) does not fit the inline control buffer",
            ));
        }
        let mut control = [0u8; RECORD_TYPE_CMSG_CAPACITY];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };

        // SAFETY: `msg` is zeroed, `iov` describes the caller's buffer, and
        // `control` is a local array of at least `control_space` bytes. Both
        // outlive the `recvmsg` call. `fd` is borrowed from a live socket by
        // the caller for the duration of this function.
        let (n, msg_flags, control_len) = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
            msg.msg_controllen = control_space as _;
            let n = libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            (n as usize, msg.msg_flags, msg.msg_controllen as usize)
        };

        if msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::other(
                "kTLS: received record type control message was truncated",
            ));
        }

        let record_type = if control_len == 0 {
            None
        } else {
            // SAFETY: reconstruct a `msghdr` over the same control buffer with
            // the kernel-reported length so `CMSG_FIRSTHDR`/`CMSG_NXTHDR` walk
            // only initialized bytes.
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
                msg.msg_controllen = control_len as _;
                let mut found = None;
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == SOL_TLS && (*cmsg).cmsg_type == TLS_GET_RECORD_TYPE {
                        found = Some(std::ptr::read(libc::CMSG_DATA(cmsg)));
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
                found
            }
        };

        if let Some(record_type) = record_type
            && record_type != super::TLS_RECORD_TYPE_APPLICATION_DATA
        {
            return Ok(KtlsRecvOutcome::Control {
                record_type,
                len: n,
            });
        }
        if n == 0 {
            return Ok(KtlsRecvOutcome::Eof);
        }
        Ok(KtlsRecvOutcome::ApplicationData { len: n })
    }

    /// Send exactly one TLS 1.2 warning-level `close_notify` through kTLS TX.
    ///
    /// Non-blocking; `WouldBlock` is surfaced so the caller can await
    /// writability instead of blocking a runtime worker. `MSG_NOSIGNAL` keeps a
    /// peer that already reset the connection from raising `SIGPIPE`.
    pub fn send_close_notify(fd: RawFd) -> io::Result<usize> {
        let control = TlsRecordTypeControl::new(super::TLS_RECORD_TYPE_ALERT).ok_or_else(|| {
            io::Error::other("kTLS: cannot build the close_notify record-type control message")
        })?;
        let mut control_bytes = [0u8; RECORD_TYPE_CMSG_CAPACITY];
        let control_len = control.as_bytes().len();
        control_bytes[..control_len].copy_from_slice(control.as_bytes());
        let mut body = super::CLOSE_NOTIFY_ALERT_BODY;
        let mut iov = libc::iovec {
            iov_base: body.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: body.len(),
        };

        // SAFETY: `msg` is zeroed; `iov` and `control_bytes` are locals that
        // outlive the call and are sized by `body.len()` / `control_len`
        // respectively. `fd` is borrowed from a live socket by the caller.
        let n = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control_bytes.as_mut_ptr().cast::<libc::c_void>();
            msg.msg_controllen = control_len as _;
            libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    KtlsRecvOutcome, TLS_GET_RECORD_TYPE, TLS_SET_RECORD_TYPE, TlsRecordTypeControl,
    recv_ktls_record, send_close_notify,
};
