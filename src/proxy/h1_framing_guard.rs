//! Wire-level HTTP/1 framing observations that must survive Hyper parsing.
//!
//! Hyper applies `Transfer-Encoding` precedence while it builds the request
//! `HeaderMap`. In Hyper 1.9, a `Content-Length` field received after
//! `Transfer-Encoding` is deliberately omitted, so an application-level CL+TE
//! guard cannot distinguish that wire shape from a TE-only request.
//!
//! [`H1FramingGuardIo`] observes bytes in place before Hyper sees them and
//! publishes one bit per complete HTTP/1 request head. It does not retain a
//! head, allocate per request, or inspect body payloads. A small framing state
//! machine skips fixed and chunked bodies so keep-alive and pipelined requests
//! remain aligned. Reads that can contain request heads are capped at 8 KiB;
//! this hard-bounds the fixed signal ring's producer lead without limiting
//! body reads. The configured Hyper head-buffer limit bounds work on an
//! unterminated head.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const OBSERVED_READ_CAP: usize = 8 * 1024;
const SIGNAL_WORDS: usize = 16;
const SIGNAL_CAPACITY: u64 = (SIGNAL_WORDS * u64::BITS as usize) as u64;
const CHUNK_EXTENSION_LIMIT: usize = 16 * 1024;

/// Connection-local queue of wire-level CL+TE decisions.
///
/// A read that can contain request heads is capped at 8 KiB. Even the shortest
/// parseable HTTP/1 head is far larger than eight bytes, so 1,024 bits cannot
/// wrap before Hyper consumes the corresponding service entries. Overflow is
/// nevertheless fail-closed: all later H1 requests on that connection are
/// reported as conflicts.
pub(super) struct H1FramingSignals {
    produced: AtomicU64,
    consumed: AtomicU64,
    conflicts: [AtomicU64; SIGNAL_WORDS],
    overflowed: AtomicBool,
}

impl H1FramingSignals {
    fn new() -> Self {
        Self {
            produced: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
            conflicts: std::array::from_fn(|_| AtomicU64::new(0)),
            overflowed: AtomicBool::new(false),
        }
    }

    fn push(&self, conflict: bool) -> bool {
        let sequence = self.produced.load(Ordering::Relaxed);
        let consumed = self.consumed.load(Ordering::Acquire);
        if sequence.saturating_sub(consumed) >= SIGNAL_CAPACITY {
            self.overflowed.store(true, Ordering::Release);
            return false;
        }

        let slot = sequence % SIGNAL_CAPACITY;
        let Some(word) = self
            .conflicts
            .get((slot / u64::BITS as u64) as usize)
        else {
            self.overflowed.store(true, Ordering::Release);
            return false;
        };
        let mask = 1u64 << (slot % u64::BITS as u64);
        if conflict {
            word.fetch_or(mask, Ordering::Relaxed);
        } else {
            word.fetch_and(!mask, Ordering::Relaxed);
        }
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.overflowed.store(true, Ordering::Release);
            return false;
        };
        self.produced.store(next_sequence, Ordering::Release);
        true
    }

    pub(super) fn next_conflict(&self) -> bool {
        if self.overflowed.load(Ordering::Acquire) {
            return true;
        }

        let sequence = self.consumed.load(Ordering::Relaxed);
        if sequence >= self.produced.load(Ordering::Acquire) {
            return false;
        }

        let slot = sequence % SIGNAL_CAPACITY;
        let Some(word) = self
            .conflicts
            .get((slot / u64::BITS as u64) as usize)
        else {
            self.overflowed.store(true, Ordering::Release);
            return true;
        };
        let mask = 1u64 << (slot % u64::BITS as u64);
        let conflict = word.load(Ordering::Relaxed) & mask != 0;
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.overflowed.store(true, Ordering::Release);
            return true;
        };
        self.consumed.store(next_sequence, Ordering::Release);
        conflict
    }
}

/// Transparent I/O adapter that observes HTTP/1 request framing before Hyper.
pub(super) struct H1FramingGuardIo<T> {
    inner: T,
    scanner: WireScanner,
    signals: Arc<H1FramingSignals>,
}

impl<T> H1FramingGuardIo<T> {
    pub(super) fn new(inner: T, max_head_bytes: usize) -> (Self, Arc<H1FramingSignals>) {
        let signals = Arc::new(H1FramingSignals::new());
        (
            Self {
                inner,
                scanner: WireScanner::new(max_head_bytes),
                signals: Arc::clone(&signals),
            },
            signals,
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for H1FramingGuardIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let cap = this.scanner.read_cap(buf.remaining());

        let result = if cap < buf.remaining() {
            let (result, filled) = {
                let mut limited = buf.take(cap);
                let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
                (result, limited.filled().len())
            };
            if let Poll::Ready(Ok(())) = &result {
                // SAFETY: the inner AsyncRead initialized every byte it added to
                // `limited`; `limited` borrows this exact unfilled prefix.
                unsafe {
                    buf.assume_init(filled);
                }
                buf.advance(filled);
            }
            result
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        };

        if let Poll::Ready(Ok(())) = &result {
            this.scanner
                .observe(&buf.filled()[filled_before..], &this.signals);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for H1FramingGuardIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Detect,
    Http1,
    Http2,
    Disabled,
}

struct WireScanner {
    protocol: Protocol,
    preface: [u8; H2_PREFACE.len()],
    preface_len: usize,
    h1: H1StreamScanner,
}

impl WireScanner {
    fn new(max_head_bytes: usize) -> Self {
        Self {
            protocol: Protocol::Detect,
            preface: [0; H2_PREFACE.len()],
            preface_len: 0,
            h1: H1StreamScanner::new(max_head_bytes),
        }
    }

    fn read_cap(&self, requested: usize) -> usize {
        if requested == 0 {
            return 0;
        }
        match self.protocol {
            Protocol::Detect => requested.min(OBSERVED_READ_CAP),
            Protocol::Http1 => self.h1.read_cap(requested),
            Protocol::Http2 | Protocol::Disabled => requested,
        }
    }

    fn observe(&mut self, mut bytes: &[u8], signals: &H1FramingSignals) {
        if self.protocol == Protocol::Detect {
            let mut consumed = 0;
            while consumed < bytes.len() && self.protocol == Protocol::Detect {
                let byte = bytes[consumed];
                let Some(expected) = H2_PREFACE.get(self.preface_len).copied() else {
                    self.protocol = Protocol::Disabled;
                    return;
                };
                let Some(slot) = self.preface.get_mut(self.preface_len) else {
                    self.protocol = Protocol::Disabled;
                    return;
                };
                *slot = byte;
                self.preface_len += 1;
                consumed += 1;

                if byte != expected {
                    self.protocol = Protocol::Http1;
                    if !self.h1.observe(&self.preface[..self.preface_len], signals) {
                        self.protocol = Protocol::Disabled;
                        return;
                    }
                } else if self.preface_len == H2_PREFACE.len() {
                    self.protocol = Protocol::Http2;
                    return;
                }
            }
            bytes = &bytes[consumed..];
        }

        if self.protocol == Protocol::Http1 && !self.h1.observe(bytes, signals) {
            self.protocol = Protocol::Disabled;
        }
    }
}

enum H1State {
    Head(HeadScanner),
    FixedBody(u64),
    Chunked(ChunkedScanner),
    Disabled,
}

struct H1StreamScanner {
    state: H1State,
    max_head_bytes: usize,
}

impl H1StreamScanner {
    fn new(max_head_bytes: usize) -> Self {
        Self {
            state: H1State::Head(HeadScanner::new(max_head_bytes)),
            max_head_bytes,
        }
    }

    fn read_cap(&self, requested: usize) -> usize {
        match &self.state {
            H1State::FixedBody(remaining) => requested.min(u64_to_usize(*remaining)),
            H1State::Chunked(ChunkedScanner {
                state: ChunkState::Data(remaining),
                ..
            }) => requested.min(u64_to_usize(*remaining)),
            H1State::Head(_) | H1State::Chunked(_) => requested.min(OBSERVED_READ_CAP),
            H1State::Disabled => requested,
        }
    }

    fn observe(&mut self, bytes: &[u8], signals: &H1FramingSignals) -> bool {
        let mut offset = 0;
        while offset < bytes.len() {
            let transition = match &mut self.state {
                H1State::Head(head) => {
                    let step = head.observe(bytes[offset]);
                    offset += 1;
                    match step {
                        HeadStep::Continue => None,
                        HeadStep::Complete(outcome) => {
                            if !signals.push(outcome.conflict) {
                                Some(H1State::Disabled)
                            } else {
                                Some(match outcome.framing {
                                    BodyFraming::None => {
                                        H1State::Head(HeadScanner::new(self.max_head_bytes))
                                    }
                                    BodyFraming::Fixed(length) => H1State::FixedBody(length),
                                    BodyFraming::Chunked => H1State::Chunked(ChunkedScanner::new(
                                        self.max_head_bytes,
                                    )),
                                    BodyFraming::Invalid => H1State::Disabled,
                                })
                            }
                        }
                        HeadStep::Disable => Some(H1State::Disabled),
                    }
                }
                H1State::FixedBody(remaining) => {
                    let consumed = bytes
                        .len()
                        .saturating_sub(offset)
                        .min(u64_to_usize(*remaining));
                    *remaining -= consumed as u64;
                    offset += consumed;
                    if *remaining == 0 {
                        Some(H1State::Head(HeadScanner::new(self.max_head_bytes)))
                    } else {
                        None
                    }
                }
                H1State::Chunked(chunked) => {
                    let (consumed, step) = chunked.observe(&bytes[offset..]);
                    offset += consumed;
                    match step {
                        ChunkStep::Continue => None,
                        ChunkStep::Complete => {
                            Some(H1State::Head(HeadScanner::new(self.max_head_bytes)))
                        }
                        ChunkStep::Disable => Some(H1State::Disabled),
                    }
                }
                H1State::Disabled => return false,
            };

            if let Some(next) = transition {
                self.state = next;
            }
        }
        !matches!(&self.state, H1State::Disabled)
    }
}

fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[derive(Clone, Copy)]
enum CurrentHeader {
    Name,
    ContentLength,
    Other,
}

#[derive(Clone, Copy)]
enum ContentLengthPhase {
    LeadingOws,
    Digits,
    TrailingOws,
    Invalid,
}

struct ContentLengthScanner {
    phase: ContentLengthPhase,
    value: u64,
}

impl ContentLengthScanner {
    fn new() -> Self {
        Self {
            phase: ContentLengthPhase::LeadingOws,
            value: 0,
        }
    }

    fn observe(&mut self, byte: u8) {
        self.phase = match (self.phase, byte) {
            (ContentLengthPhase::LeadingOws, b' ' | b'\t') => {
                ContentLengthPhase::LeadingOws
            }
            (ContentLengthPhase::LeadingOws | ContentLengthPhase::Digits, b'0'..=b'9') => {
                match self
                    .value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                {
                    Some(value) => {
                        self.value = value;
                        ContentLengthPhase::Digits
                    }
                    None => ContentLengthPhase::Invalid,
                }
            }
            (ContentLengthPhase::Digits | ContentLengthPhase::TrailingOws, b' ' | b'\t') => {
                ContentLengthPhase::TrailingOws
            }
            _ => ContentLengthPhase::Invalid,
        };
    }

    fn finish(&self) -> Option<u64> {
        match self.phase {
            ContentLengthPhase::Digits | ContentLengthPhase::TrailingOws => Some(self.value),
            ContentLengthPhase::LeadingOws | ContentLengthPhase::Invalid => None,
        }
    }
}

struct HeadScanner {
    max_bytes: usize,
    bytes_seen: usize,
    request_line: bool,
    line_has_data: bool,
    pending_cr: bool,
    current_header: CurrentHeader,
    name_len: usize,
    content_length_candidate: bool,
    transfer_encoding_candidate: bool,
    content_length_value: ContentLengthScanner,
    canonical_content_length: Option<u64>,
    content_length_valid: bool,
    seen_content_length: bool,
    seen_transfer_encoding: bool,
    conflict: bool,
}

impl HeadScanner {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            bytes_seen: 0,
            request_line: true,
            line_has_data: false,
            pending_cr: false,
            current_header: CurrentHeader::Other,
            name_len: 0,
            content_length_candidate: false,
            transfer_encoding_candidate: false,
            content_length_value: ContentLengthScanner::new(),
            canonical_content_length: None,
            content_length_valid: true,
            seen_content_length: false,
            seen_transfer_encoding: false,
            conflict: false,
        }
    }

    fn observe(&mut self, byte: u8) -> HeadStep {
        self.bytes_seen = self.bytes_seen.saturating_add(1);
        if self.bytes_seen > self.max_bytes {
            return HeadStep::Disable;
        }

        if self.pending_cr {
            self.pending_cr = false;
            if byte == b'\n' {
                return self.finish_line();
            }
            self.observe_line_byte(b'\r');
        }

        match byte {
            b'\r' => {
                self.pending_cr = true;
                HeadStep::Continue
            }
            b'\n' => self.finish_line(),
            _ => {
                self.observe_line_byte(byte);
                HeadStep::Continue
            }
        }
    }

    fn observe_line_byte(&mut self, byte: u8) {
        self.line_has_data = true;
        if self.request_line || self.conflict {
            return;
        }

        match self.current_header {
            CurrentHeader::Name if byte == b':' => {
                if self.content_length_candidate && self.name_len == b"content-length".len() {
                    self.current_header = CurrentHeader::ContentLength;
                    self.content_length_value = ContentLengthScanner::new();
                    self.seen_content_length = true;
                } else {
                    self.current_header = CurrentHeader::Other;
                    if self.transfer_encoding_candidate
                        && self.name_len == b"transfer-encoding".len()
                    {
                        self.seen_transfer_encoding = true;
                    }
                }
                self.conflict = self.seen_content_length && self.seen_transfer_encoding;
            }
            CurrentHeader::Name => {
                self.content_length_candidate &=
                    pattern_byte_matches(b"content-length", self.name_len, byte);
                self.transfer_encoding_candidate &=
                    pattern_byte_matches(b"transfer-encoding", self.name_len, byte);
                self.name_len = self.name_len.saturating_add(1);
            }
            CurrentHeader::ContentLength => self.content_length_value.observe(byte),
            CurrentHeader::Other => {}
        }
    }

    fn finish_line(&mut self) -> HeadStep {
        if !self.line_has_data {
            let framing = if self.seen_transfer_encoding {
                BodyFraming::Chunked
            } else if !self.content_length_valid {
                BodyFraming::Invalid
            } else if let Some(length) = self.canonical_content_length {
                if length == 0 {
                    BodyFraming::None
                } else {
                    BodyFraming::Fixed(length)
                }
            } else {
                BodyFraming::None
            };
            return HeadStep::Complete(HeadOutcome {
                conflict: self.conflict,
                framing,
            });
        }

        if self.request_line {
            self.request_line = false;
        } else if matches!(self.current_header, CurrentHeader::ContentLength) && !self.conflict {
            match self.content_length_value.finish() {
                Some(value)
                    if self.canonical_content_length.is_none()
                        || self.canonical_content_length == Some(value) =>
                {
                    self.canonical_content_length = Some(value);
                }
                Some(_) | None => self.content_length_valid = false,
            }
        }

        self.line_has_data = false;
        self.current_header = CurrentHeader::Name;
        self.name_len = 0;
        self.content_length_candidate = true;
        self.transfer_encoding_candidate = true;
        HeadStep::Continue
    }
}

fn pattern_byte_matches(pattern: &[u8], index: usize, byte: u8) -> bool {
    pattern
        .get(index)
        .is_some_and(|expected| expected.eq_ignore_ascii_case(&byte))
}

enum HeadStep {
    Continue,
    Complete(HeadOutcome),
    Disable,
}

struct HeadOutcome {
    conflict: bool,
    framing: BodyFraming,
}

enum BodyFraming {
    None,
    Fixed(u64),
    Chunked,
    Invalid,
}

#[derive(Clone, Copy)]
enum ChunkState {
    SizeStart,
    Size,
    SizeLws,
    Extension,
    SizeLf,
    Data(u64),
    DataCr,
    DataLf,
    EndCr,
    Trailer,
    TrailerLf,
    EndLf,
}

struct ChunkedScanner {
    state: ChunkState,
    chunk_size: u64,
    extension_bytes: usize,
    trailer_bytes: usize,
    max_trailer_bytes: usize,
}

impl ChunkedScanner {
    fn new(max_trailer_bytes: usize) -> Self {
        Self {
            state: ChunkState::SizeStart,
            chunk_size: 0,
            extension_bytes: 0,
            trailer_bytes: 0,
            max_trailer_bytes,
        }
    }

    fn observe(&mut self, bytes: &[u8]) -> (usize, ChunkStep) {
        let mut offset = 0;
        while offset < bytes.len() {
            if let ChunkState::Data(remaining) = self.state {
                let consumed = bytes
                    .len()
                    .saturating_sub(offset)
                    .min(u64_to_usize(remaining));
                offset += consumed;
                let remaining = remaining - consumed as u64;
                self.state = if remaining == 0 {
                    ChunkState::DataCr
                } else {
                    ChunkState::Data(remaining)
                };
                continue;
            }

            let byte = bytes[offset];
            offset += 1;
            let next = match self.state {
                ChunkState::SizeStart => match hex_value(byte) {
                    Some(value) => {
                        self.chunk_size = u64::from(value);
                        Some(ChunkState::Size)
                    }
                    None => return (offset, ChunkStep::Disable),
                },
                ChunkState::Size => match byte {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        let Some(value) = hex_value(byte) else {
                            return (offset, ChunkStep::Disable);
                        };
                        let Some(size) = self
                            .chunk_size
                            .checked_mul(16)
                            .and_then(|size| size.checked_add(u64::from(value)))
                        else {
                            return (offset, ChunkStep::Disable);
                        };
                        self.chunk_size = size;
                        None
                    }
                    b' ' | b'\t' => Some(ChunkState::SizeLws),
                    b';' => Some(ChunkState::Extension),
                    b'\r' => Some(ChunkState::SizeLf),
                    _ => return (offset, ChunkStep::Disable),
                },
                ChunkState::SizeLws => match byte {
                    b' ' | b'\t' => None,
                    b';' => Some(ChunkState::Extension),
                    b'\r' => Some(ChunkState::SizeLf),
                    _ => return (offset, ChunkStep::Disable),
                },
                ChunkState::Extension => match byte {
                    b'\r' => Some(ChunkState::SizeLf),
                    b'\n' => return (offset, ChunkStep::Disable),
                    _ => {
                        self.extension_bytes = self.extension_bytes.saturating_add(1);
                        if self.extension_bytes >= CHUNK_EXTENSION_LIMIT {
                            return (offset, ChunkStep::Disable);
                        }
                        None
                    }
                },
                ChunkState::SizeLf => {
                    if byte != b'\n' {
                        return (offset, ChunkStep::Disable);
                    }
                    if self.chunk_size == 0 {
                        Some(ChunkState::EndCr)
                    } else {
                        Some(ChunkState::Data(self.chunk_size))
                    }
                }
                ChunkState::Data(_) => None,
                ChunkState::DataCr => {
                    if byte == b'\r' {
                        Some(ChunkState::DataLf)
                    } else {
                        return (offset, ChunkStep::Disable);
                    }
                }
                ChunkState::DataLf => {
                    if byte == b'\n' {
                        self.chunk_size = 0;
                        Some(ChunkState::SizeStart)
                    } else {
                        return (offset, ChunkStep::Disable);
                    }
                }
                ChunkState::EndCr => {
                    if byte == b'\r' {
                        Some(ChunkState::EndLf)
                    } else {
                        self.trailer_bytes = self.trailer_bytes.saturating_add(1);
                        Some(ChunkState::Trailer)
                    }
                }
                ChunkState::Trailer => {
                    self.trailer_bytes = self.trailer_bytes.saturating_add(1);
                    if self.trailer_bytes > self.max_trailer_bytes {
                        return (offset, ChunkStep::Disable);
                    }
                    if byte == b'\r' {
                        Some(ChunkState::TrailerLf)
                    } else {
                        None
                    }
                }
                ChunkState::TrailerLf => {
                    if byte == b'\n' {
                        Some(ChunkState::EndCr)
                    } else {
                        return (offset, ChunkStep::Disable);
                    }
                }
                ChunkState::EndLf => {
                    if byte == b'\n' {
                        return (offset, ChunkStep::Complete);
                    }
                    return (offset, ChunkStep::Disable);
                }
            };
            if let Some(next) = next {
                self.state = next;
            }
        }
        (offset, ChunkStep::Continue)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte + 10 - b'a'),
        b'A'..=b'F' => Some(byte + 10 - b'A'),
        _ => None,
    }
}

enum ChunkStep {
    Continue,
    Complete,
    Disable,
}
