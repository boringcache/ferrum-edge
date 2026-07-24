//! Deterministic coverage for the rustls→kTLS handoff gate
//! ([issue #2955](https://github.com/ferrum-edge/ferrum-edge/issues/2955)).
//!
//! When a client coalesces post-handshake application data with its Finished
//! flight, rustls decrypts those bytes into `received_plaintext` during the
//! handshake. Installing kTLS and resuming from the raw socket would silently
//! discard them. A partial inbound TLS record in rustls's private deframer is
//! the second loss/desync case — and that state is **not** observable through
//! the public buffered `ServerConnection` API.
//!
//! These tests pin that:
//! - a clean buffered handshake is **not** treated as handoff-safe (alignment
//!   is not proven);
//! - complete buffered plaintext and abbreviated/coalesced cases refuse
//!   handoff while leaving the `ServerConnection` readable.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ferrum_edge::tls::NoVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

const OPENING: &[u8] = b"OPENING-CMD-2955";

fn load_test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/certs/server.crt");
    let key_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/certs/server.key");
    let cert_pem = std::fs::read(cert_path).expect("test cert");
    let key_pem = std::fs::read(key_path).expect("test key");
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse key")
        .expect("key present");
    (certs, key)
}

fn tls12_server_config() -> Arc<ServerConfig> {
    let (certs, key) = load_test_certs();
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert");
    config.session_storage = Arc::new(rustls::server::ServerSessionMemoryCache::new(128));
    Arc::new(config)
}

fn tls12_client_config() -> Arc<ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::in_memory_sessions(128);
    Arc::new(config)
}

fn write_tls(conn: &mut ClientConnection, sock: &mut TcpStream) -> std::io::Result<()> {
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    sock.flush()?;
    Ok(())
}

fn write_tls_server(conn: &mut ServerConnection, sock: &mut TcpStream) -> std::io::Result<()> {
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    sock.flush()?;
    Ok(())
}

fn read_tls(conn: &mut ClientConnection, sock: &mut TcpStream) -> std::io::Result<()> {
    if conn.wants_read() {
        conn.read_tls(sock)?;
        conn.process_new_packets()
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

fn read_tls_server(conn: &mut ServerConnection, sock: &mut TcpStream) -> std::io::Result<()> {
    if conn.wants_read() {
        conn.read_tls(sock)?;
        conn.process_new_packets()
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

fn set_timeouts(sock: &mut TcpStream) {
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
}

/// Block until rustls has at least `min_bytes` of decrypted plaintext, reading
/// from the socket as needed. Avoids races between the client writer thread and
/// the server handoff inspection.
fn wait_for_plaintext(
    server: &mut ServerConnection,
    sock: &mut TcpStream,
    min_bytes: usize,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let io = server
            .process_new_packets()
            .expect("process_new_packets while waiting for plaintext");
        if io.plaintext_bytes_to_read() >= min_bytes {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {min_bytes} plaintext bytes \
                 (have {})",
                io.plaintext_bytes_to_read()
            );
        }
        match server.read_tls(sock) {
            Ok(0) => panic!(
                "EOF before plaintext arrived (have {})",
                io.plaintext_bytes_to_read()
            ),
            Ok(_) => {
                server
                    .process_new_packets()
                    .expect("process after read_tls");
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read_tls while waiting for plaintext: {e}"),
        }
    }
}

fn assert_opening_bytes_still_readable(server: &mut ServerConnection) {
    let mut got = vec![0u8; OPENING.len()];
    server
        .reader()
        .read_exact(&mut got)
        .expect("opening bytes must remain readable after the handoff gate");
    assert_eq!(got, OPENING);
}

/// Drive a clean TLS 1.2 full handshake with no application data.
fn complete_tls12_handshake_clean(
) -> (ServerConnection, TcpStream, thread::JoinHandle<()>) {
    let server_config = tls12_server_config();
    let client_config = tls12_client_config();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let client_thread = thread::spawn(move || {
        let mut sock = TcpStream::connect(addr).expect("connect");
        set_timeouts(&mut sock);

        let server_name = ServerName::try_from("localhost").expect("dns name");
        let mut client =
            ClientConnection::new(client_config, server_name).expect("client connection");

        write_tls(&mut client, &mut sock).expect("client hello write");
        while client.is_handshaking() {
            read_tls(&mut client, &mut sock).expect("client read");
            write_tls(&mut client, &mut sock).expect("client write");
        }
        // Hold the socket open until the server finishes inspecting handoff state.
        thread::sleep(Duration::from_millis(250));
    });

    let (mut server_sock, _) = listener.accept().expect("accept");
    set_timeouts(&mut server_sock);

    let mut server = ServerConnection::new(server_config).expect("server connection");
    while server.is_handshaking() {
        read_tls_server(&mut server, &mut server_sock).expect("server read");
        write_tls_server(&mut server, &mut server_sock).expect("server write");
    }
    // Flush any post-handshake records (e.g. tickets) so the outbound buffer
    // is empty — matching a completed tokio-rustls accept() before kTLS handoff.
    write_tls_server(&mut server, &mut server_sock).expect("flush post-hs writes");

    (server, server_sock, client_thread)
}

/// Full TLS 1.2 handshake, then deliver opening application data so it sits in
/// rustls `received_plaintext` before any kTLS handoff decision — the buffer
/// state the gate must refuse. (True TCP coalescing with Finished is covered by
/// the abbreviated-handshake test below.)
fn complete_tls12_handshake_with_buffered_app(
    app_data: &'static [u8],
) -> (ServerConnection, TcpStream, thread::JoinHandle<()>) {
    let server_config = tls12_server_config();
    let client_config = tls12_client_config();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let client_thread = thread::spawn(move || {
        let mut sock = TcpStream::connect(addr).expect("connect");
        set_timeouts(&mut sock);

        let server_name = ServerName::try_from("localhost").expect("dns name");
        let mut client =
            ClientConnection::new(client_config, server_name).expect("client connection");

        write_tls(&mut client, &mut sock).expect("client hello write");
        while client.is_handshaking() {
            read_tls(&mut client, &mut sock).expect("client read");
            write_tls(&mut client, &mut sock).expect("client write");
        }
        client.writer().write_all(app_data).expect("stage app data");
        write_tls(&mut client, &mut sock).expect("write app data");
        thread::sleep(Duration::from_millis(250));
    });

    let (mut server_sock, _) = listener.accept().expect("accept");
    set_timeouts(&mut server_sock);

    let mut server = ServerConnection::new(server_config).expect("server connection");
    while server.is_handshaking() {
        read_tls_server(&mut server, &mut server_sock).expect("server read");
        write_tls_server(&mut server, &mut server_sock).expect("server write");
    }
    write_tls_server(&mut server, &mut server_sock).expect("flush post-hs writes");
    wait_for_plaintext(&mut server, &mut server_sock, app_data.len());

    (server, server_sock, client_thread)
}

/// Abbreviated TLS 1.2 handshake: warm the session cache, then resume and stage
/// Finished + application data into one client `write_tls` flush so the server
/// decrypts opening bytes during handshake processing.
fn complete_tls12_abbreviated_handshake_with_coalesced_app(
    app_data: &'static [u8],
) -> (ServerConnection, TcpStream, thread::JoinHandle<()>) {
    let server_config = tls12_server_config();
    let client_config = tls12_client_config();

    // ── Warmup (full handshake) to populate session caches ──────────────
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("warmup bind");
        let addr = listener.local_addr().expect("warmup addr");
        let client_config = Arc::clone(&client_config);
        let warmup_client = thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).expect("warmup connect");
            set_timeouts(&mut sock);
            let name = ServerName::try_from("localhost").expect("dns name");
            let mut client = ClientConnection::new(client_config, name).expect("warmup client");
            write_tls(&mut client, &mut sock).expect("warmup hello");
            while client.is_handshaking() {
                read_tls(&mut client, &mut sock).expect("warmup read");
                write_tls(&mut client, &mut sock).expect("warmup write");
            }
            let _ = client.send_close_notify();
            let _ = write_tls(&mut client, &mut sock);
        });
        let (mut server_sock, _) = listener.accept().expect("warmup accept");
        set_timeouts(&mut server_sock);
        let mut server =
            ServerConnection::new(Arc::clone(&server_config)).expect("warmup server");
        while server.is_handshaking() {
            read_tls_server(&mut server, &mut server_sock).expect("warmup server read");
            write_tls_server(&mut server, &mut server_sock).expect("warmup server write");
        }
        warmup_client.join().expect("warmup client");
    }

    // ── Resumed connection with coalesced opening bytes ─────────────────
    let listener = TcpListener::bind("127.0.0.1:0").expect("resume bind");
    let addr = listener.local_addr().expect("resume addr");
    let client_thread = thread::spawn(move || {
        let mut sock = TcpStream::connect(addr).expect("resume connect");
        set_timeouts(&mut sock);
        let name = ServerName::try_from("localhost").expect("dns name");
        let mut client = ClientConnection::new(client_config, name).expect("resume client");

        // ClientHello (with session id from warmup).
        write_tls(&mut client, &mut sock).expect("resume hello");

        let mut staged = false;
        while client.is_handshaking() {
            read_tls(&mut client, &mut sock).expect("resume read");
            // After ServerHello+CCS+Finished on an abbreviated handshake, the
            // client can emit CCS+Finished and application data together.
            // Stage app data before write_tls so they share one flush.
            if !staged {
                match client.writer().write_all(app_data) {
                    Ok(()) => staged = true,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("unexpected app-data stage error: {e}"),
                }
            }
            write_tls(&mut client, &mut sock).expect("resume write");
        }
        if !staged {
            client.writer().write_all(app_data).expect("post-hs stage");
            write_tls(&mut client, &mut sock).expect("post-hs app write");
        }
        thread::sleep(Duration::from_millis(250));
    });

    let (mut server_sock, _) = listener.accept().expect("resume accept");
    set_timeouts(&mut server_sock);
    let mut server = ServerConnection::new(server_config).expect("resume server");
    while server.is_handshaking() {
        read_tls_server(&mut server, &mut server_sock).expect("resume server read");
        write_tls_server(&mut server, &mut server_sock).expect("resume server write");
    }
    write_tls_server(&mut server, &mut server_sock).expect("flush post-hs writes");
    // Coalesced app data may already be plaintext after the handshake read;
    // otherwise wait for the client's post-handshake write.
    wait_for_plaintext(&mut server, &mut server_sock, app_data.len());

    (server, server_sock, client_thread)
}

#[test]
fn handoff_refused_for_buffered_api_even_when_no_plaintext_visible() {
    let (mut server, _sock, client) = complete_tls12_handshake_clean();
    let io = server.process_new_packets().expect("io state");
    assert_eq!(
        io.plaintext_bytes_to_read(),
        0,
        "clean handshake must not buffer application plaintext"
    );
    assert_eq!(
        io.tls_bytes_to_write(),
        0,
        "clean handshake flush must leave no outbound TLS records"
    );
    // A clean IoState is necessary but not sufficient: the buffered API
    // cannot prove the private inbound deframer is empty, so handoff must
    // stay refused until an unbuffered WriteTraffic path exists.
    assert!(
        !ferrum_edge::_test_support::ktls_rustls_buffers_safe_for_kernel_handoff(&mut server),
        "buffered ServerConnection must not be treated as kTLS-safe without \
         proven record alignment"
    );
    let _ = client.join();
}

#[test]
fn handoff_unsafe_when_post_handshake_app_data_buffered() {
    let (mut server, _sock, client) = complete_tls12_handshake_with_buffered_app(OPENING);

    let io = server.process_new_packets().expect("io state");
    assert!(
        io.plaintext_bytes_to_read() >= OPENING.len(),
        "test setup must leave decrypted opening bytes in rustls \
         (got plaintext_bytes_to_read = {})",
        io.plaintext_bytes_to_read()
    );

    assert!(
        !ferrum_edge::_test_support::ktls_rustls_buffers_safe_for_kernel_handoff(&mut server),
        "buffered plaintext must force userspace fallback"
    );

    assert_opening_bytes_still_readable(&mut server);
    let _ = client.join();
}

#[test]
fn handoff_unsafe_when_abbreviated_handshake_coalesces_app_data() {
    let (mut server, _sock, client) =
        complete_tls12_abbreviated_handshake_with_coalesced_app(OPENING);

    let io = server.process_new_packets().expect("io state");
    assert!(
        io.plaintext_bytes_to_read() >= OPENING.len(),
        "abbreviated handshake setup must leave coalesced plaintext buffered \
         (got plaintext_bytes_to_read = {})",
        io.plaintext_bytes_to_read()
    );
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    assert!(
        matches!(
            server.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        ),
        "expected TLS 1.2 session resumption, got {:?}",
        server.handshake_kind()
    );

    assert!(
        !ferrum_edge::_test_support::ktls_rustls_buffers_safe_for_kernel_handoff(&mut server),
        "resumed coalesced plaintext must force userspace fallback"
    );

    assert_opening_bytes_still_readable(&mut server);
    let _ = client.join();
}
