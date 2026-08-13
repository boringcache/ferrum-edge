# h3-quinn: expose Quinn `SendStream::stopped` through the h3 transport traits

## Summary

Quinn's `SendStream::stopped(&self)` returns a `'static` future that completes
on peer `STOP_SENDING`. `h3-quinn` 0.0.10 does not forward that capability, so
an HTTP/3 server cannot observe cancellation of the response direction without
taking exclusive `&mut` access to the send stream.

## Details

A gateway waiting for backend response headers is not polling H3 frames. A
client can `STOP_SENDING` one stream and keep the multiplexed QUIC connection
open. Without `stopped()`, that cancellation is invisible until the backend
answers.

The send and receive halves of a bidi stream are independent. Polling
`stopped()` must not require `&mut SendStream` because the receive half may
already be borrowed for `poll_data`. Quinn already solved this: `stopped` is
`&self` and clones the connection ref into a `'static` future.

## Suggested fix

Implement `h3::quic::SendStreamStopped` for `h3_quinn::SendStream` and
`BidiStream` by forwarding to `quinn::SendStream::stopped` as a `'static`
return-position `impl Future` (no per-call `Box`, no associated-type
`impl Trait`). Map
`StoppedError::ConnectionLost` to `StreamErrorIncoming::ConnectionErrorIncoming`
and `ZeroRttRejected` to `Unknown`.
