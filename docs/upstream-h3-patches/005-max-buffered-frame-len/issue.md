# `h3` buffers an unbounded non-`DATA` frame payload from a declared length

## Summary

`h3` 0.0.8 never bounds the **declared** payload length of a non-`DATA` frame.
A peer that completes the QUIC handshake can declare a `2^62 - 1` byte HEADERS
frame on one request stream and stream bytes until the process runs out of
memory. No protocol violation and no authentication are required.

## Details

`Frame::decode` (`src/proto/frame.rs`) returns
`FrameError::Incomplete(2 + len as usize)` for any non-`DATA` frame whose
payload has not fully arrived. `FrameDecoder::decode` (`src/frame.rs`) records
that as `self.expected`, and `FrameStream::poll_next` loops
`try_recv` -> `BufList::push_bytes` -> `continue` until
`src.remaining() >= expected`.

QUIC flow control does not bound this. `stream_receive_window` and
`receive_window` limit the bytes *in flight*; each poll here consumes from the
stream, which re-grants credit. `max_idle_timeout` does not fire either: the
peer is actively sending.

## Reproduction

1. Complete the QUIC handshake against an `h3::server::Connection`.
2. Open one bidirectional stream.
3. Write frame type `0x01` (HEADERS) followed by a varint length of
   `0x3FFF_FFFF_FFFF_FFFF`.
4. Stream arbitrary bytes.

`Connection::accept()` never returns and RSS grows linearly with the sender's
bandwidth.

## Variants

- **Unknown frame types.** The `buf.advance(len)` skip arm in `Frame::decode`
  is reached only *after* the full frame is buffered, so "endpoints MUST NOT
  consider these frames to have any meaning" still costs the full declared
  length in memory.
- **The unidirectional control stream.** SETTINGS and GOAWAY are decoded by an
  identically unbounded `FrameDecoder`, so the same shape works there.

`DATA` frames are not affected: their payload length is handed to the caller as
a streaming length and is never accumulated by the decoder.

## Suggested fix

Carry a receive-side ceiling on the declared payload length of a buffered
non-`DATA` frame, defaulting to today's unbounded behaviour so the change is
additive, and expose it on `server::builder()` / `client::builder()`. Refuse an
over-declared frame as soon as its type and length varints are decoded — before
any payload byte is stored and before `expected` is armed — with a connection
error of type `H3_EXCESSIVE_LOAD`.

Compare the ceiling against the raw `u64` varint before any `usize` conversion:
`len as usize` truncates on 32-bit targets, so a `2^32 + n` declaration would
otherwise present itself as a short frame.
