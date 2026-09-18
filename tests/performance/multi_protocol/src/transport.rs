//! Observe client admission and physical socket lifetimes without changing load.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tonic::codegen::Service;

use crate::phases::{Admission, ConnectionGuard, Connections};

/// Bound offered TCP work to one full-duplex echo, including on split TLS I/O.
pub async fn echo_exchange<R, W>(
    read: &mut R,
    write: &mut W,
    payload: &[u8],
    response: &mut [u8],
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::try_join!(
        async {
            for chunk in payload.chunks(65_536) {
                write.write_all(chunk).await?;
                write.flush().await?;
                tokio::task::yield_now().await;
            }
            Ok::<_, std::io::Error>(())
        },
        async { read.read_exact(response).await.map(|_| ()) },
    )?;
    Ok(())
}

pub fn request_body(bytes: Bytes, admission: Option<Admission>) -> ObservedBody {
    ObservedBody {
        body: http_body_util::Full::new(bytes),
        admission,
    }
}

/// Keep the exact body size and avoid a new allocation on every H1/H2 request.
pub struct ObservedBody {
    body: http_body_util::Full<Bytes>,
    admission: Option<Admission>,
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if let Some(admission) = self.admission.take() {
            admission.admitted();
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

/// Tonic's buffer and H2 admission are observed at the first body frame poll,
/// not when the unary future is created or when response headers arrive.
#[derive(Clone)]
pub struct ObservedChannel {
    pub inner: tonic::transport::Channel,
    pub admission: Option<Admission>,
}

type GrpcRequest = http::Request<tonic::body::Body>;

impl Service<GrpcRequest> for ObservedChannel {
    type Response = <tonic::transport::Channel as Service<GrpcRequest>>::Response;
    type Error = <tonic::transport::Channel as Service<GrpcRequest>>::Error;
    type Future = <tonic::transport::Channel as Service<GrpcRequest>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: GrpcRequest) -> Self::Future {
        let admission = self.admission.clone();
        self.inner.call(request.map(|body| {
            tonic::body::Body::new(body.map_frame(move |frame| {
                if let Some(admission) = &admission {
                    admission.admitted();
                }
                frame
            }))
        }))
    }
}

pub struct CountedIo {
    stream: tokio::net::TcpStream,
    _connection: ConnectionGuard,
}

impl AsyncRead for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Service<http::Uri> for Connections {
    type Response = hyper_util::rt::TokioIo<CountedIo>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let connections = self.clone();
        Box::pin(async move {
            let host = uri.host().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing host")
            })?;
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
            let stream = tokio::net::TcpStream::connect((host, port)).await?;
            stream.set_nodelay(true)?;
            Ok(hyper_util::rt::TokioIo::new(CountedIo {
                stream,
                _connection: connections.opened(),
            }))
        })
    }
}
