# frame: bound the declared payload length of a buffered non-`DATA` frame

Fixes #NNN.

## Problem

`Frame::decode` returns `Incomplete(2 + len)` for a non-`DATA` frame whose
declared payload has not fully arrived; `FrameDecoder` stores that as its
`expected` target and `FrameStream::poll_next` accumulates QUIC chunks into a
`BufList` until it is met. Because each poll consumes from the stream and so
re-grants flow-control credit, neither `stream_receive_window` nor
`receive_window` bounds the total, and `max_idle_timeout` never fires against an
actively sending peer. One unauthenticated stream declaring a `2^62 - 1` HEADERS
frame drives the process to OOM. The same holds for unknown frame types (the
skip arm runs only after the frame is buffered) and on the peer control stream.

## Change

- Add `Frame::decode_bounded(buf, max_buffered_frame_len)` and
  `FrameError::ExceedsMaxBufferedLen { ty, len, max }`. `Frame::decode`
  delegates with `u64::MAX`, so existing behaviour is unchanged.
- Refuse an over-declared non-`DATA` frame immediately after its type and length
  varints are decoded — before `buf.take(len)`, before any payload byte is
  stored, and before `FrameDecoder` arms `expected`.
- Compare against the raw `u64` varint before any `usize` conversion, and refuse
  a length the platform cannot address regardless of the configured ceiling, so
  32-bit truncation cannot bypass the bound. The remaining accumulation target
  uses `saturating_add`.
- Leave `DATA` unbounded: its payload is streamed to the caller, never
  accumulated, and request bodies legitimately exceed any header-sized ceiling.
- `FrameDecoder` carries the ceiling (`FrameDecoder::UNBOUNDED_FRAME_LEN` by
  default) and maps the refusal to
  `FrameProtocolError::ExceedsMaxBufferedFrameLen`, which becomes a connection
  error of type `H3_EXCESSIVE_LOAD` (RFC 9114 §8.1).
- Expose `max_buffered_frame_len(value)` on `server::builder()` and
  `client::builder()`, stored on `Config`, and thread it to every decoder the
  connection owns: accepted request streams, and CONTROL and PUSH
  unidirectional streams. `FrameStream::split` propagates it to both halves.

## Tests

New `src/frame.rs` unit tests cover: an oversized declared HEADERS frame
refused with nothing buffered and `expected` unarmed; the same for SETTINGS
(control stream) and for an unknown frame type; a payload exactly at the
ceiling accepted; one byte over refused; a `DATA` frame far above the ceiling
still decoded as a streaming length; a default decoder reproducing today's
unbounded behaviour; and the refusal surfacing through `FrameStream::poll_next`
while the peer keeps writing payload.
