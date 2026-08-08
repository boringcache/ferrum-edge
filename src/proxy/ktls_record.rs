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
//! treat as a truncation attack). A TLS alert is an indivisible record, so
//! [`send_close_notify`] treats anything other than a full two-byte emission as
//! an error rather than a completed shutdown.
//!
//! # Ancillary buffers are aligned, not assumed
//!
//! Every `msg_control` in this module points at `AlignedCmsgBuf`, whose
//! storage is overlaid with a real `libc::cmsghdr` so it carries that type's
//! alignment. `CMSG_FIRSTHDR` / `CMSG_NXTHDR` hand back `*mut cmsghdr`
//! pointers into that storage and both the writer and the reader dereference
//! them; a plain `[u8; N]` has alignment
//! 1, which would make those dereferences undefined behaviour irrespective of
//! how a given stack frame happens to be laid out. Every read of `CMSG_DATA` is
//! additionally gated on the header having declared at least `CMSG_LEN(1)`, and
//! the walk length is clamped to this process's own buffer capacity.
//!
//! # A bare FIN is not a shutdown
//!
//! `KtlsRecvOutcome::Eof` means the peer closed TCP with no record pending.
//! Nothing authenticated said the stream ended, so it is a truncation for the
//! caller to attribute — never a clean EOF.

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
    /// `CMSG_SPACE(1)` is 24 bytes on 64-bit and 16 on 32-bit; every
    /// constructor refuses rather than truncating if a platform ever exceeds
    /// this.
    pub(super) const RECORD_TYPE_CMSG_CAPACITY: usize = 32;

    /// Alignment carrier for [`AlignedCmsgBuf`].
    ///
    /// `CMSG_FIRSTHDR`/`CMSG_NXTHDR` hand back `*mut cmsghdr` pointers *into*
    /// the control buffer, and both the writer and the reader dereference
    /// them. A plain `[u8; N]` local or field has alignment 1, so those
    /// dereferences are undefined behaviour regardless of how a particular
    /// stack frame happens to be laid out. Overlaying the bytes with a real
    /// `cmsghdr` raises the storage's alignment to `align_of::<cmsghdr>()`,
    /// which is exactly what the `CMSG_*` contract assumes.
    #[repr(C)]
    #[derive(Clone, Copy)]
    union CmsgStorage {
        /// Alignment only — never read or written through this field.
        #[allow(dead_code)]
        align: libc::cmsghdr,
        bytes: [u8; RECORD_TYPE_CMSG_CAPACITY],
    }

    /// A fixed-capacity ancillary-data buffer aligned for `libc::cmsghdr`.
    ///
    /// This is the only storage any `msg_control` in this module points at, so
    /// every `CMSG_*` walk in the module is alignment-correct by construction
    /// rather than by luck.
    #[derive(Clone, Copy)]
    pub struct AlignedCmsgBuf {
        storage: CmsgStorage,
    }

    /// `CMSG_FIRSTHDR` returns a header pointer whenever `msg_controllen` is at
    /// least one `cmsghdr`, so the capacity must be able to hold one — else a
    /// non-null header could describe storage past the end of the buffer.
    const _: () = assert!(RECORD_TYPE_CMSG_CAPACITY >= std::mem::size_of::<libc::cmsghdr>());

    impl AlignedCmsgBuf {
        /// Usable capacity in bytes.
        pub const CAPACITY: usize = RECORD_TYPE_CMSG_CAPACITY;

        /// A fully zeroed buffer. Every byte is initialized, which is what lets
        /// [`AlignedCmsgBuf::bytes`] hand out a slice of any prefix.
        pub fn zeroed() -> Self {
            Self {
                storage: CmsgStorage {
                    bytes: [0u8; RECORD_TYPE_CMSG_CAPACITY],
                },
            }
        }

        /// Pointer for `msghdr::msg_control`, aligned for `cmsghdr`.
        pub fn as_mut_ptr(&mut self) -> *mut u8 {
            std::ptr::addr_of_mut!(self.storage).cast::<u8>()
        }

        /// Byte view of the first `len` bytes, clamped to [`Self::CAPACITY`].
        pub fn bytes(&self, len: usize) -> &[u8] {
            let len = len.min(Self::CAPACITY);
            // SAFETY: the whole storage is initialized (`zeroed` writes every
            // byte and nothing ever leaves a hole), `len` is clamped to the
            // capacity, and `u8` has no invalid bit patterns.
            unsafe {
                std::slice::from_raw_parts(std::ptr::addr_of!(self.storage).cast::<u8>(), len)
            }
        }
    }

    /// Smallest `cmsg_len` that can carry the one-byte record type, i.e. the
    /// value below which `CMSG_DATA(cmsg)` would point past the message.
    fn min_record_type_cmsg_len() -> usize {
        // SAFETY: `CMSG_LEN` is a pure arithmetic macro and dereferences
        // nothing.
        unsafe { libc::CMSG_LEN(1) as usize }
    }

    /// `CMSG_SPACE(1)` for this platform, or `None` when it cannot be honoured
    /// inside [`AlignedCmsgBuf`].
    ///
    /// Failing closed matters on both sides: a truncated outbound control
    /// message would make the kernel emit the payload as ordinary
    /// **application data** instead of an alert, and a truncated inbound one
    /// would make a control record look like application data.
    fn record_type_cmsg_space() -> Option<usize> {
        // SAFETY: `CMSG_SPACE` is a pure arithmetic macro and dereferences
        // nothing.
        let space = unsafe { libc::CMSG_SPACE(1) } as usize;
        if space < min_record_type_cmsg_len() || space > AlignedCmsgBuf::CAPACITY {
            return None;
        }
        Some(space)
    }

    /// The `SOL_TLS` / `TLS_SET_RECORD_TYPE` ancillary message that makes one
    /// `sendmsg(2)` emit a record of a chosen content type.
    ///
    /// Split out as its own value (rather than built inline in the syscall
    /// wrapper) so the wire layout can be constructed and read back in tests
    /// without opening a socket.
    pub struct TlsRecordTypeControl {
        buf: AlignedCmsgBuf,
        len: usize,
    }

    impl TlsRecordTypeControl {
        /// Build the control message for `record_type`.
        ///
        /// Returns `None` when this platform's `CMSG_SPACE(1)` does not fit the
        /// inline buffer, or when the header `CMSG_FIRSTHDR` returns could not
        /// carry the one payload byte inside that space.
        pub fn new(record_type: u8) -> Option<Self> {
            let space = record_type_cmsg_space()?;
            let cmsg_len = min_record_type_cmsg_len();
            if cmsg_len > space {
                return None;
            }
            let mut out = TlsRecordTypeControl {
                buf: AlignedCmsgBuf::zeroed(),
                len: space,
            };
            // SAFETY: `msg` is zeroed and its only populated fields point at
            // `out.buf`, which lives for the whole block, is `cmsghdr`-aligned,
            // and is at least `space` bytes (checked above against
            // `AlignedCmsgBuf::CAPACITY`). `CMSG_FIRSTHDR` therefore returns
            // either null or a correctly aligned `cmsghdr` inside that buffer,
            // and `CMSG_DATA(cmsg)` is the one payload byte the checked
            // `CMSG_LEN(1)` reserves inside the same space.
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
                (*cmsg).cmsg_len = cmsg_len as _;
                std::ptr::write(libc::CMSG_DATA(cmsg), record_type);
            }
            Some(out)
        }

        /// Raw ancillary bytes handed to `sendmsg(2)`.
        pub fn as_bytes(&self) -> &[u8] {
            self.buf.bytes(self.len)
        }

        /// `(msg_control, msg_controllen)` for a `sendmsg(2)`.
        ///
        /// Handing out the buffer's own aligned storage is what keeps the
        /// transmit path from copying the message into a differently aligned
        /// scratch array on its way to the kernel.
        fn as_control(&mut self) -> (*mut libc::c_void, usize) {
            let len = self.len;
            (self.buf.as_mut_ptr().cast::<libc::c_void>(), len)
        }

        /// Read the message back as `(cmsg_level, cmsg_type, record_type)`.
        ///
        /// Test seam: lets the ancillary contract be asserted without a socket.
        pub fn parsed(&self) -> Option<(libc::c_int, libc::c_int, u8)> {
            // `AlignedCmsgBuf` is `Copy`, so the scratch copy keeps the
            // `cmsghdr` alignment the walk below depends on.
            let mut scratch = self.buf;
            // SAFETY: same shape as `new` — a zeroed `msghdr` whose control
            // buffer is the local `scratch`, aligned for `cmsghdr` and holding
            // `self.len` initialized bytes.
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_control = scratch.as_mut_ptr().cast::<libc::c_void>();
                msg.msg_controllen = self.len.min(AlignedCmsgBuf::CAPACITY) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if cmsg.is_null() {
                    return None;
                }
                if ((*cmsg).cmsg_len as usize) < min_record_type_cmsg_len() {
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
        /// The peer's write side is at EOF with **no record pending**.
        ///
        /// This is a bare TCP FIN, not a TLS shutdown: nothing authenticated
        /// said the stream ended. Callers must treat it as a truncation, never
        /// as the clean end of the relay direction — only
        /// [`KtlsControlRecord::CloseNotify`](super::KtlsControlRecord::CloseNotify)
        /// carries that meaning.
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
        let Some(control_space) = record_type_cmsg_space() else {
            return Err(io::Error::other(
                "kTLS: platform CMSG_SPACE(1) does not fit the inline control buffer",
            ));
        };
        let mut control = AlignedCmsgBuf::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };

        // SAFETY: `msg` is zeroed, `iov` describes the caller's buffer, and
        // `control` is a local `cmsghdr`-aligned buffer of at least
        // `control_space` bytes (`record_type_cmsg_space` bounds it by
        // `AlignedCmsgBuf::CAPACITY`). Both outlive the `recvmsg` call. `fd` is
        // borrowed from a live socket by the caller for the duration of this
        // function.
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

        // The kernel cannot report more control bytes than it was given, but
        // clamping makes the walk's bound depend on this process's own buffer
        // size rather than on a returned field.
        let control_len = control_len.min(control_space);
        let record_type = if control_len == 0 {
            None
        } else {
            let min_cmsg_len = min_record_type_cmsg_len();
            // SAFETY: reconstruct a `msghdr` over the same `cmsghdr`-aligned
            // control buffer with the (clamped) kernel-reported length, so
            // `CMSG_FIRSTHDR`/`CMSG_NXTHDR` walk only initialized bytes inside
            // it. `CMSG_DATA` is read only for a header that declared at least
            // `CMSG_LEN(1)`, so the payload byte is inside the same message.
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
                msg.msg_controllen = control_len as _;
                let mut found = None;
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_len as usize >= min_cmsg_len
                        && (*cmsg).cmsg_level == SOL_TLS
                        && (*cmsg).cmsg_type == TLS_GET_RECORD_TYPE
                    {
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
    ///
    /// **Only a full two-byte emission is success.** A TLS alert is an
    /// indivisible record: a zero-length or short `sendmsg` result means the
    /// peer did not receive a `close_notify`, and reporting that as a completed
    /// shutdown would be exactly the truncation this module exists to prevent.
    /// Any other count is an error too — the kernel cannot legitimately consume
    /// more than the two bytes offered, so an oversized result means the
    /// ancillary contract was not honoured as understood.
    pub fn send_close_notify(fd: RawFd) -> io::Result<usize> {
        let mut control = TlsRecordTypeControl::new(super::TLS_RECORD_TYPE_ALERT).ok_or_else(|| {
            io::Error::other("kTLS: cannot build the close_notify record-type control message")
        })?;
        let mut body = super::CLOSE_NOTIFY_ALERT_BODY;
        let mut iov = libc::iovec {
            iov_base: body.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: body.len(),
        };
        let (control_ptr, control_len) = control.as_control();

        // SAFETY: `msg` is zeroed; `iov` and the `cmsghdr`-aligned buffer owned
        // by `control` are locals that outlive the call and are sized by
        // `body.len()` / `control_len` respectively. `fd` is borrowed from a
        // live socket by the caller.
        let n = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control_ptr;
            msg.msg_controllen = control_len as _;
            libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let sent = n as usize;
        let expected = super::CLOSE_NOTIFY_ALERT_BODY.len();
        if sent != expected {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "kTLS: close_notify sendmsg reported {sent} of {expected} alert bytes; \
                     no complete close_notify record was emitted"
                ),
            ));
        }
        Ok(sent)
    }
}

#[cfg(target_os = "linux")]
pub use linux::AlignedCmsgBuf;
#[cfg(target_os = "linux")]
pub use linux::{
    KtlsRecvOutcome, TLS_GET_RECORD_TYPE, TLS_SET_RECORD_TYPE, TlsRecordTypeControl,
    recv_ktls_record, send_close_notify,
};
