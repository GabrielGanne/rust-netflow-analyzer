//! Reference OS-socket integration (Phase 1).
//!
//! Binds a UDP socket, feeds every received datagram into the engine, prints
//! emitted flows from the background aging thread, and reports telemetry.
//!
//! Run with:
//!     cargo run -p netflow_analyzer_core --example udp_listener -- 0.0.0.0:2055
//!
//! Then point any NetFlow v9 / IPFIX exporter (or `nfreplay`) at that port.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::FlowContext;

fn format_ip(addr: &[u8; 16]) -> String {
    // Heuristic: if the first 12 bytes are zero, render as IPv4 (mapped layout).
    if addr[..12].iter().all(|&b| b == 0) {
        format!("{}.{}.{}.{}", addr[12], addr[13], addr[14], addr[15])
    } else {
        let mut groups = Vec::with_capacity(8);
        for chunk in addr.chunks(2) {
            groups.push(format!("{:02x}{:02x}", chunk[0], chunk[1]));
        }
        groups.join(":")
    }
}

fn print_flow(record: &FlowRecord) {
    println!(
        "[flow] {}:{} -> {}:{} proto={} bytes={} packets={}",
        format_ip(&record.src_ip),
        record.src_port,
        format_ip(&record.dst_ip),
        record.dst_port,
        record.proto,
        record.bytes,
        record.packets,
    );
}

fn main() -> std::io::Result<()> {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:2055".to_string());

    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    println!("netflow-analyzer listening on udp://{bind_addr}");

    let ctx = FlowContext::new();
    // Emitted flows (idle eviction / active rollover) are printed as they occur.
    ctx.start_aging(print_flow);

    // Reusable receive buffer. The parser borrows from it directly (zero-copy);
    // we never allocate per-packet on the heap.
    let mut buf = [0u8; 65_535];
    let mut last_report = Instant::now();

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _peer)) => {
                let _ = ctx.process_packet(&buf[..len]);
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }

        // Periodic telemetry dump every five seconds.
        if last_report.elapsed() >= Duration::from_secs(5) {
            let s = ctx.stats();
            println!(
                "[stats] parsed={} parse_errors={} templates={} records={} active={} output={} dropped={}",
                s.pkts_parsed,
                s.pkts_parse_error,
                s.templates_received,
                s.data_records_processed,
                s.active_flows,
                s.flows_output,
                s.flows_dropped,
            );
            last_report = Instant::now();
        }
    }
}
