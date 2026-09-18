//! Transparent poll observation: logical writes are not Linux syscalls.
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Scope, count, in_scope, schema, store};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    ClearMixed = 0,
    TlsNonH2Plain = 1,
    TlsH2Plain = 2,
    TlsWireMixed = 3,
}

impl Layer {
    fn base(self) -> usize {
        schema::IO_BASE + self as usize * schema::IO_FIELDS
    }

    fn scope(self) -> Scope {
        if self == Self::TlsWireMixed {
            Scope::CipherWrite
        } else {
            Scope::PlainWrite
        }
    }
}

/// Same incremental five-byte-header framing as the benchmark client parser.
/// Only accepted prefixes enter here. No payload is retained or decrypted.
#[derive(Default)]
pub struct RecordParser {
    header: [u8; 5],
    filled: usize,
    remaining: usize,
    failed: bool,
}

impl RecordParser {
    pub fn observe(&mut self, mut bytes: &[u8]) {
        let base = Layer::TlsWireMixed.base();
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
                    count(base + 15, 1);
                    continue;
                }
            }
            let length = self.remaining.min(bytes.len());
            self.remaining -= length;
            bytes = &bytes[length..];
            if self.remaining == 0 {
                count(base + 13, 1);
                count(
                    base + 14,
                    u16::from_be_bytes([self.header[3], self.header[4]]) as usize + 5,
                );
                self.filled = 0;
            }
        }
    }

    pub fn incomplete(&self) -> bool {
        !self.failed && self.filled != 0
    }
}

pub struct ObservedIo<S> {
    inner: S,
    layer: Layer,
    parser: RecordParser,
}

impl<S> ObservedIo<S> {
    pub fn new(inner: S, layer: Layer) -> Self {
        Self {
            inner,
            layer,
            parser: RecordParser::default(),
        }
    }

    fn write_result(&self, vectored: bool, requested: usize, result: &Poll<io::Result<usize>>) {
        store::with_local(|local| {
            let base = self.layer.base();
            local.add(base + usize::from(vectored), 1);
            local.add(base + 2, requested as u64);
            match result {
                Poll::Pending => local.add(base + 5, 1),
                Poll::Ready(Err(_)) => local.add(base + 6, 1),
                Poll::Ready(Ok(accepted)) => {
                    local.add(base + 3, *accepted as u64);
                    if *accepted < requested {
                        local.add(base + 4, 1);
                    }
                    if *accepted > requested {
                        local.add(schema::OVERFLOW, 1);
                    }
                }
            }
        });
    }

    fn control_result(&self, offset: usize, result: &Poll<io::Result<()>>) {
        let base = self.layer.base() + offset;
        store::with_local(|local| {
            local.add(base, 1);
            match result {
                Poll::Pending => local.add(base + 1, 1),
                Poll::Ready(Err(_)) => local.add(base + 2, 1),
                Poll::Ready(Ok(())) => {}
            }
        });
    }
}

impl<S> Drop for ObservedIo<S> {
    fn drop(&mut self) {
        if self.layer == Layer::TlsWireMixed && self.parser.incomplete() {
            count(self.layer.base() + 16, 1);
        }
        super::publish_current_thread();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = in_scope(this.layer.scope(), || {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        });
        this.write_result(false, buf.len(), &result);
        if this.layer == Layer::TlsWireMixed
            && let Poll::Ready(Ok(accepted)) = &result
        {
            this.parser.observe(&buf[..(*accepted).min(buf.len())]);
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = in_scope(this.layer.scope(), || {
            Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
        });
        let mut requested = 0usize;
        for buf in bufs {
            if let Some(total) = requested.checked_add(buf.len()) {
                requested = total;
            } else {
                requested = usize::MAX;
                count(schema::OVERFLOW, 1);
            }
        }
        this.write_result(true, requested, &result);
        if this.layer == Layer::TlsWireMixed
            && let Poll::Ready(Ok(accepted)) = &result
        {
            let mut remaining = *accepted;
            for buf in bufs {
                let length = remaining.min(buf.len());
                this.parser.observe(&buf[..length]);
                remaining -= length;
                if remaining == 0 {
                    break;
                }
            }
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = in_scope(this.layer.scope(), || Pin::new(&mut this.inner).poll_flush(cx));
        this.control_result(7, &result);
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = in_scope(this.layer.scope(), || {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        });
        this.control_result(10, &result);
        result
    }
}
