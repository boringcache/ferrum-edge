//! External unit coverage for vendored `WebSocketConfig::auto_pong`.
//!
//! The gateway relay disables auto-Pong so Ping/Pong is end-to-end transparent
//! (issue #2963). These tests pin the vendored config contract independently of
//! the functional gateway suite. Matching regressions also live in
//! `vendor/tungstenite-0.29.0-ferrum-patched/src/protocol/mod.rs`.

use std::io::{self, Cursor, Read, Write};
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocket, WebSocketConfig};

struct CaptureIo {
    read: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Write for CaptureIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for CaptureIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(buf)
    }
}

#[test]
fn default_auto_pong_queues_local_reply() {
    let io = CaptureIo {
        read: Cursor::new(vec![0x89, 0x02, 0x01, 0x02]),
        written: Vec::new(),
    };
    let mut socket = WebSocket::from_raw_socket(io, Role::Client, None);
    assert_eq!(
        socket.read().expect("read Ping"),
        Message::Ping(vec![1, 2].into())
    );
    socket.flush().expect("flush auto-Pong");
    let stream = socket.into_inner();
    assert!(
        !stream.written.is_empty(),
        "default auto_pong must emit a local Pong"
    );
    assert_eq!(stream.written[0] & 0x0f, 0x0a);
}

#[test]
fn disabled_auto_pong_does_not_queue_local_reply() {
    let io = CaptureIo {
        read: Cursor::new(vec![0x89, 0x02, 0x01, 0x02]),
        written: Vec::new(),
    };
    let config = WebSocketConfig::default().auto_pong(false);
    let mut socket = WebSocket::from_raw_socket(io, Role::Client, Some(config));
    assert_eq!(
        socket.read().expect("read Ping"),
        Message::Ping(vec![1, 2].into())
    );
    socket.flush().expect("flush with auto_pong disabled");
    let stream = socket.into_inner();
    assert!(
        stream.written.is_empty(),
        "auto_pong=false must not emit a local Pong, wrote {:02x?}",
        stream.written
    );
}
