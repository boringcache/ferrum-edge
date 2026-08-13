# Summary

- add `quic::SendStreamStopped` so transports can expose peer `STOP_SENDING` as a `&self` + `'static` future
- forward the method through `BufRecvStream`, `FrameStream`, and `server::RequestStream`
- do not take exclusive send-stream access, so an unsplit bidi stream can still poll the receive half

Fixes #NNN.

# Motivation

A server that waits on a backend after request HEADERS is not polling H3 frames.
Clients can `STOP_SENDING` one response stream while keeping the multiplexed
QUIC connection open. Quinn already provides `SendStream::stopped(&self)` with a
`'static` future; h3 needs a trait so `RequestStream` can race that signal
without `&mut` on the send half.

# Testing

- `cargo test -p h3`
