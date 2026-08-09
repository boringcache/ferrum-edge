# `h3-quinn`: `RecvStream::stop_sending` panics while a `poll_data` is pending

## Summary

`h3_quinn::RecvStream::stop_sending` unwraps an `Option` that is `None` for the
entire duration of an in-flight read, so calling it after cancelling a
`recv_data()` aborts the process (or panics into the executor). That is exactly
when an HTTP/3 server needs it: to send `STOP_SENDING(H3_NO_ERROR)` once the
response is complete and the remaining request body is unwanted.

## Details

`RecvStream` moves the `quinn::RecvStream` into a `ReusableBoxFuture` on the
first poll of a read and only puts it back when the read resolves:

```rust
pub struct RecvStream {
    stream: Option<quinn::RecvStream>,
    read_chunk_fut: ReadChunkFuture,
}

fn poll_data(&mut self, cx: &mut task::Context<'_>) -> Poll<...> {
    if let Some(mut stream) = self.stream.take() {
        self.read_chunk_fut.set(async move {
            let chunk = stream.read_chunk(usize::MAX, true).await;
            (stream, chunk)
        })
    };
    let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
    self.stream = Some(stream);
    ...
}

fn stop_sending(&mut self, error_code: u64) {
    self.stream.as_mut().unwrap().stop(...).ok();   // <-- None while parked
}
```

`recv_id()` has the same `unwrap()`.

## Reproduction

1. Server accepts a request stream and `split()`s it.
2. A task polls `recv_data()` on the receive half; the client sends nothing, so
   the read parks and `RecvStream::stream` becomes `None`.
3. The server completes the response (trailers + FIN) and cancels that task's
   read (e.g. `tokio::select!` against a shutdown signal).
4. The server calls `RequestStream::stop_sending(Code::H3_NO_ERROR)` on the
   receive half.
5. Panic: `called Option::unwrap() on a None value`. Under
   `panic = "abort"` the process dies.

This is an ordinary bidirectional-streaming shape (gRPC over HTTP/3 where the
server answers before the client half-closes), not an exotic one.

## Why the obvious workarounds don't work

- `quinn::Connection` exposes no way to STOP_SENDING an existing stream by id,
  and `quinn::RecvStream::stop` needs `&mut self` — which is inside the boxed
  future.
- Skipping the call falls back to `quinn::RecvStream::drop`, which emits
  `STOP_SENDING(0)`. `0x0` is not an HTTP/3 error code (RFC 9114 §8.1 defines
  `H3_NO_ERROR = 0x0100`), so peers report a spurious reset.
- Waiting for the parked read to resolve first is unbounded: an idle peer may
  never send again.

## Suggested fix

Keep the `quinn::RecvStream` owned inline and construct the `read_chunk` future
per poll. `RecvStream::read_chunk` is documented cancel-safe and its future holds
no state beyond the borrow, so this is behaviourally identical while making
`stop_sending`/`recv_id` total. It also removes the `ReusableBoxFuture`
allocation. See the accompanying PR description.
