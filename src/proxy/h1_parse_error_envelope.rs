//! HTTP/1.1 parse-error JSON envelopes for Hyper's automatic empty 400s.
//!
//! Hyper's HTTP/1 server writes an empty-bodied `400 Bad Request` on request
//! parse failures before Ferrum's service runs. This adapter intercepts that
//! wire shape on the outbound path and replaces it with the same JSON contract
//! `check_protocol_headers()` uses for handler-layer protocol rejects.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wire-hint values published by [`super::h1_framing_guard`] before Hyper parses.
pub(super) const PARSE_HINT_NONE: u8 = 0;
pub(super) const PARSE_HINT_CONFLICTING_CONTENT_LENGTH: u8 = 1;
pub(super) const PARSE_HINT_HTTP10_TRANSFER_ENCODING: u8 = 2;
pub(super) const PARSE_HINT_INVALID_REQUEST_TARGET_UTF8: u8 = 3;

pub(super) const X_GATEWAY_ERROR_PROTOCOL_REJECT: &str = "request_error";

const JSON_CONFLICTING_CONTENT_LENGTH: &str =
    r#"{"error":"Multiple Content-Length headers with conflicting values"}"#;
const JSON_HTTP10_TRANSFER_ENCODING: &str =
    r#"{"error":"HTTP/1.0 does not support Transfer-Encoding"}"#;
const JSON_MALFORMED_HTTP_REQUEST: &str = r#"{"error":"Malformed HTTP request"}"#;

/// Stable Hyper 1.x request-parse `Display` strings (see `hyper::error::Error`).
/// `hyper::Error::kind()` is crate-private, so sub-kinds are recovered from these
/// descriptions only when no public typed accessor exists.
const HYPER_DESC_INVALID_CONTENT_LENGTH: &str = "invalid content-length parsed";
const HYPER_DESC_UNEXPECTED_TRANSFER_ENCODING: &str = "unexpected transfer-encoding parsed";

const ENVELOPE_CONFLICTING_CONTENT_LENGTH: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 68\r\nconnection: close\r\nx-gateway-error: request_error\r\n\r\n{\"error\":\"Multiple Content-Length headers with conflicting values\"}";

const ENVELOPE_HTTP10_TRANSFER_ENCODING: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 58\r\nconnection: close\r\nx-gateway-error: request_error\r\n\r\n{\"error\":\"HTTP/1.0 does not support Transfer-Encoding\"}";

const ENVELOPE_MALFORMED_HTTP_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 35\r\nconnection: close\r\nx-gateway-error: request_error\r\n\r\n{\"error\":\"Malformed HTTP request\"}";

/// Connection-local hint set while observing raw HTTP/1 request heads.
#[derive(Default)]
pub(super) struct H1ParseRejectHint {
    hint: AtomicU8,
}

impl H1ParseRejectHint {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn store(&self, hint: u8) {
        self.hint.store(hint, Ordering::Release);
    }

    pub(super) fn load(&self) -> u8 {
        self.hint.load(Ordering::Acquire)
    }
}

/// Map a Hyper HTTP/1 request-parse failure to the JSON body Ferrum exposes.
pub(super) fn json_body_for_hyper_parse_error(err: &hyper::Error) -> &'static str {
    if !err.is_parse() || err.is_parse_too_large() {
        return JSON_MALFORMED_HTTP_REQUEST;
    }

    // Only `is_parse`, `is_parse_too_large`, `is_parse_status`, and
    // `is_parse_version_h2` are public; finer parse sub-kinds use the stable
    // descriptions below.
    match err.to_string().as_str() {
        HYPER_DESC_INVALID_CONTENT_LENGTH => JSON_CONFLICTING_CONTENT_LENGTH,
        HYPER_DESC_UNEXPECTED_TRANSFER_ENCODING => JSON_HTTP10_TRANSFER_ENCODING,
        _ => JSON_MALFORMED_HTTP_REQUEST,
    }
}

fn envelope_for_hint(hint: u8) -> &'static [u8] {
    match hint {
        PARSE_HINT_CONFLICTING_CONTENT_LENGTH => ENVELOPE_CONFLICTING_CONTENT_LENGTH,
        PARSE_HINT_HTTP10_TRANSFER_ENCODING => ENVELOPE_HTTP10_TRANSFER_ENCODING,
        _ => ENVELOPE_MALFORMED_HTTP_REQUEST,
    }
}

fn looks_like_hyper_empty_parse_400(headers_block: &[u8]) -> bool {
    if !headers_block.windows(12).any(|window| window == b" 400 ") {
        return false;
    }
    let lower = headers_block
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let lower = lower.as_slice();
    if lower.windows(12).any(|window| window == b"content-type") {
        return false;
    }
    lower.windows(14).any(|window| window == b"content-length")
        && lower.windows(4).any(|window| window == b": 0\r")
}

/// Transparent write adapter that rewrites Hyper's empty parse-error 400s.
pub(super) struct H1ParseErrorEnvelopeIo<T> {
    inner: T,
    hint: Arc<H1ParseRejectHint>,
    capture: Vec<u8>,
    pending_substitute: Option<&'static [u8]>,
    substitute_offset: usize,
}

impl<T> H1ParseErrorEnvelopeIo<T> {
    pub(super) fn new(inner: T, hint: Arc<H1ParseRejectHint>) -> Self {
        Self {
            inner,
            hint,
            capture: Vec::new(),
            pending_substitute: None,
            substitute_offset: 0,
        }
    }

    fn flush_pending_substitute(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(substitute) = this.pending_substitute else {
            return Poll::Ready(Ok(()));
        };
        while this.substitute_offset < substitute.len() {
            let wrote = ready!(
                Pin::new(&mut this.inner).poll_write(cx, &substitute[this.substitute_offset..],)?
            );
            if wrote == 0 {
                return Poll::Pending;
            }
            this.substitute_offset += wrote;
        }
        this.pending_substitute = None;
        this.substitute_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn maybe_begin_substitute(&mut self) {
        if self.pending_substitute.is_some() {
            return;
        }
        let Some(headers_end) = self
            .capture
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        else {
            return;
        };
        let headers_block = &self.capture[..headers_end + 4];
        if !looks_like_hyper_empty_parse_400(headers_block) {
            return;
        }
        self.pending_substitute = Some(envelope_for_hint(self.hint.load()));
        self.capture.clear();
    }

    fn write_capture_or_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_substitute.is_some() {
            ready!(self.as_mut().flush_pending_substitute(cx))?;
            return Poll::Ready(Ok(buf.len()));
        }

        if this.capture.is_empty() && !buf.starts_with(b"HTTP/1.") {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        this.capture.extend_from_slice(buf);
        this.maybe_begin_substitute();
        if this.pending_substitute.is_some() {
            ready!(self.as_mut().flush_pending_substitute(cx))?;
            return Poll::Ready(Ok(buf.len()));
        }

        if this.capture.len() > 16 * 1024 {
            let pending = std::mem::take(&mut this.capture);
            ready!(Pin::new(&mut this.inner).poll_write(cx, &pending))?;
        }
        Poll::Ready(Ok(buf.len()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for H1ParseErrorEnvelopeIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for H1ParseErrorEnvelopeIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_capture_or_inner(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.get_mut();
        if !this.capture.is_empty() {
            let pending = std::mem::take(&mut this.capture);
            ready!(Pin::new(&mut this.inner).poll_write(cx, &pending))?;
        }
        if this.pending_substitute.is_some() {
            drop(this);
            return self.flush_pending_substitute(cx);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total: usize = bufs.iter().map(|slice| slice.len()).sum();
        if total == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut merged = Vec::with_capacity(total);
        for slice in bufs {
            merged.extend_from_slice(slice);
        }
        self.write_capture_or_inner(cx, &merged)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Log-friendly classification for HTTP/1 connection errors.
pub(super) fn log_http1_connection_error(
    err: &hyper::Error,
    err_string: &str,
    remote_addr: &std::net::SocketAddr,
    listen_port: Option<u16>,
    tls: bool,
) {
    if err.is_parse() && !err.is_parse_too_large() {
        let body = json_body_for_hyper_parse_error(err);
        tracing::warn!(
            remote_addr = %remote_addr,
            listen_port = ?listen_port,
            tls,
            error = %err,
            gateway_error = X_GATEWAY_ERROR_PROTOCOL_REJECT,
            reject_body = body,
            "Rejected HTTP/1 request at parse time"
        );
        return;
    }

    tracing::error!(
        remote_addr = %remote_addr,
        listen_port = ?listen_port,
        tls,
        error = %err_string,
        "HTTP connection error"
    );
}

#[cfg(test)]
pub(crate) fn json_body_for_hyper_parse_error_for_test(err: &hyper::Error) -> &'static str {
    json_body_for_hyper_parse_error(err)
}

pub(super) fn envelope_for_hint_for_test(hint: u8) -> &'static [u8] {
    envelope_for_hint(hint)
}
