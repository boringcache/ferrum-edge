# Summary

- implement `h3::quic::SendStreamStopped` for `SendStream` and `BidiStream`
- forward to Quinn's `&self` + `'static` `SendStream::stopped` without boxing
- map connection-lost / 0-RTT-rejected errors into `StreamErrorIncoming`

Fixes #NNN.

# Motivation

HTTP/3 servers that wait on a backend after request HEADERS need to observe
peer `STOP_SENDING` on the response direction without exclusive send-stream
access. Quinn already provides that watch; h3-quinn should expose it.

# Testing

- `cargo test -p h3-quinn`
