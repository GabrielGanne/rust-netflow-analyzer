// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal usage example for `netflow_analyzer_core`.
//!
//! Run with:
//!     cargo run -p netflow_analyzer_core --example quickstart

use std::sync::Arc;
use std::time::Duration;

use netflow_analyzer_core::{AgingConfig, EngineConfig, FlowContext, FlowRecord};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure the engine with cache caps and aging timeouts
    let config = EngineConfig {
        max_flows: 100_000,
        max_templates: 10_000,
        aging: AgingConfig {
            idle_timeout: Duration::from_secs(30),
            active_timeout: Duration::from_secs(120),
            scan_interval: Duration::from_secs(5),
        },
        ..EngineConfig::default()
    };

    let ctx = Arc::new(FlowContext::with_config(config));

    // 2. Start the background aging worker with an emission callback
    ctx.start_aging(|record: &FlowRecord| {
        println!(
            "[aging emit] proto={} bytes={} packets={} (exporter={})",
            record.proto, record.bytes, record.packets, record.exporter
        );
    });

    // 3. Construct a synthetic NetFlow v5 packet (header + 1 record = 72 bytes)
    let mut packet = Vec::with_capacity(72);
    // NetFlow v5 Header (24 bytes)
    packet.extend_from_slice(&5u16.to_be_bytes()); // version = 5
    packet.extend_from_slice(&1u16.to_be_bytes()); // count = 1
    packet.extend_from_slice(&1000u32.to_be_bytes()); // sys_uptime = 1000ms
    packet.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // unix_secs
    packet.extend_from_slice(&0u32.to_be_bytes()); // unix_nanos
    packet.extend_from_slice(&1u32.to_be_bytes()); // flow_sequence
    packet.push(0); // engine_type
    packet.push(0); // engine_id
    packet.extend_from_slice(&0u16.to_be_bytes()); // sampling_interval

    // NetFlow v5 Record (48 bytes)
    packet.extend_from_slice(&[192, 168, 1, 10]); // src_ip
    packet.extend_from_slice(&[10, 0, 0, 1]); // dst_ip
    packet.extend_from_slice(&[0; 4]); // nexthop
    packet.extend_from_slice(&1u16.to_be_bytes()); // input iface
    packet.extend_from_slice(&2u16.to_be_bytes()); // output iface
    packet.extend_from_slice(&10u32.to_be_bytes()); // packets = 10
    packet.extend_from_slice(&1500u32.to_be_bytes()); // bytes = 1500
    packet.extend_from_slice(&100u32.to_be_bytes()); // first_uptime
    packet.extend_from_slice(&200u32.to_be_bytes()); // last_uptime
    packet.extend_from_slice(&12345u16.to_be_bytes()); // src_port
    packet.extend_from_slice(&80u16.to_be_bytes()); // dst_port
    packet.push(0); // pad1
    packet.push(0x10); // tcp_flags
    packet.push(6); // proto = TCP
    packet.push(0); // tos
    packet.extend_from_slice(&0u16.to_be_bytes()); // src_as
    packet.extend_from_slice(&0u16.to_be_bytes()); // dst_as
    packet.push(24); // src_mask
    packet.push(24); // dst_mask
    packet.extend_from_slice(&[0; 2]); // pad2

    // 4. Ingest the datagram with an explicit exporter key
    let exporter_key = 1;
    let count = ctx.process_packet_from(exporter_key, &packet)?;
    println!("Processed {count} flow record(s)");

    // 5. Query live telemetry
    let stats = ctx.stats();
    println!(
        "Stats: parsed={} active_flows={} parse_errors={}",
        stats.pkts_parsed, stats.active_flows, stats.pkts_parse_error
    );

    // 6. Flush cached flows synchronously and shut down
    ctx.stop_aging();
    ctx.flush(|record| {
        println!(
            "[flush emit] proto={} bytes={} packets={}",
            record.proto, record.bytes, record.packets
        );
    });

    Ok(())
}
