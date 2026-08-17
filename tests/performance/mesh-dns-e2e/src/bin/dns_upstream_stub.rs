//! Deterministic UDP + TCP DNS resolver used by the perf harness as the
//! gateway's `FERRUM_MESH_DNS_UPSTREAM_ADDR` target.
//!
//! Answers any A query with 192.0.2.1 (TEST-NET-1, RFC 5737 §3) and any
//! AAAA query with 2001:db8::1 (RFC 3849). Deterministic by design.

use std::net::SocketAddr;

use clap::Parser;
use mesh_dns_e2e_perf::upstream_stub::{run_tcp_accept_loop, run_udp_loop};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Parser, Debug)]
#[command(about = "Deterministic UDP+TCP DNS upstream stub for the mesh DNS perf harness")]
struct Args {
    /// Listen address (UDP and TCP bind the same host:port).
    #[arg(long, default_value = "127.0.0.1:17053")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let addr: SocketAddr = args.listen.parse()?;
    let udp = UdpSocket::bind(addr).await?;
    let tcp = TcpListener::bind(addr).await?;
    eprintln!("[dns_upstream_stub] UDP+TCP listening on {addr}");
    tokio::select! {
        _ = run_udp_loop(udp) => {}
        _ = run_tcp_accept_loop(tcp) => {}
    }
    Ok(())
}
