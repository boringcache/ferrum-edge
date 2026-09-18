//! Passive client observations. TLS records are not socket writes or H1 chunks.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct Counters {
    tls_records: AtomicU64,
    tls_record_bytes: AtomicU64,
    tls_parse_errors: AtomicU64,
    body_data_frames: AtomicU64,
    body_data_bytes: AtomicU64,
    chunked_responses: AtomicU64,
    content_length_responses: AtomicU64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub tls_records: u64,
    pub tls_record_bytes: u64,
    pub tls_parse_errors: u64,
    pub body_data_frames: u64,
    pub body_data_bytes: u64,
    pub chunked_responses: u64,
    pub content_length_responses: u64,
}

impl Counters {
    pub fn data_frame(&self, bytes: usize) {
        self.body_data_frames.fetch_add(1, Ordering::Relaxed);
        self.body_data_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn response_headers(&self, headers: &http::HeaderMap) {
        if headers
            .get(http::header::TRANSFER_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"chunked"))
        {
            self.chunked_responses.fetch_add(1, Ordering::Relaxed);
        }
        if headers.contains_key(http::header::CONTENT_LENGTH) {
            self.content_length_responses.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Snapshot {
    pub fn capture(counters: &[Arc<Counters>]) -> Self {
        let mut result = Self::default();
        for counter in counters {
            result.tls_records += counter.tls_records.load(Ordering::Relaxed);
            result.tls_record_bytes += counter.tls_record_bytes.load(Ordering::Relaxed);
            result.tls_parse_errors += counter.tls_parse_errors.load(Ordering::Relaxed);
            result.body_data_frames += counter.body_data_frames.load(Ordering::Relaxed);
            result.body_data_bytes += counter.body_data_bytes.load(Ordering::Relaxed);
            result.chunked_responses += counter.chunked_responses.load(Ordering::Relaxed);
            result.content_length_responses +=
                counter.content_length_responses.load(Ordering::Relaxed);
        }
        result
    }

    pub fn delta(&self, start: &Self) -> Self {
        Self {
            tls_records: self.tls_records - start.tls_records,
            tls_record_bytes: self.tls_record_bytes - start.tls_record_bytes,
            tls_parse_errors: self.tls_parse_errors - start.tls_parse_errors,
            body_data_frames: self.body_data_frames - start.body_data_frames,
            body_data_bytes: self.body_data_bytes - start.body_data_bytes,
            chunked_responses: self.chunked_responses - start.chunked_responses,
            content_length_responses: self.content_length_responses - start.content_length_responses,
        }
    }
}

/// Incremental TLS wire framing below rustls; retain only the five-byte header.
/// Count complete records, including encrypted control messages. Never decrypt,
/// buffer payloads, infer application records, or change reads/writes/flushes.
#[derive(Default)]
pub struct RecordParser {
    header: [u8; 5],
    filled: usize,
    remaining: usize,
    failed: bool,
}

impl RecordParser {
    pub fn observe(&mut self, mut bytes: &[u8], counters: &Counters) {
        while !bytes.is_empty() && !self.failed {
            if self.filled < 5 {
                let length = (5 - self.filled).min(bytes.len());
                self.header[self.filled..self.filled + length].copy_from_slice(&bytes[..length]);
                self.filled += length;
                bytes = &bytes[length..];
                if self.filled != 5 {
                    continue;
                }
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if !(20..=24).contains(&self.header[0])
                    || self.header[1] != 3
                    || self.remaining > 18_432
                {
                    self.failed = true;
                    counters.tls_parse_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            let length = self.remaining.min(bytes.len());
            self.remaining -= length;
            bytes = &bytes[length..];
            if self.remaining == 0 {
                counters.tls_records.fetch_add(1, Ordering::Relaxed);
                let length = u16::from_be_bytes([self.header[3], self.header[4]]) as u64 + 5;
                counters.tls_record_bytes.fetch_add(length, Ordering::Relaxed);
                self.filled = 0;
            }
        }
    }
}

pub struct ObservedTls<S> {
    inner: S,
    parser: RecordParser,
    counters: Arc<Counters>,
}

impl<S> ObservedTls<S> {
    pub fn new(inner: S, counters: Arc<Counters>) -> Self {
        Self {
            inner,
            parser: RecordParser::default(),
            counters,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedTls<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.parser.observe(&buf.filled()[before..], &this.counters);
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedTls<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
