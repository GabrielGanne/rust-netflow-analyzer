// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Throughput benchmarks for the core ingestion path, [`FlowContext::process_packet`].
//!
//! Each benchmark reuses a single long-lived `FlowContext` (mirroring the
//! production model where one engine is shared across workers) and repeatedly
//! feeds it a pre-built datagram, so we measure the steady-state decode + cache
//! upsert cost rather than one-off allocation noise.
//!
//! Workload dimensions:
//! - `process_packet`: the original cases. Their v9/IPFIX packets carry the
//!   template, so every iteration also redefines it.
//! - `v9_records_per_packet`: records per datagram (and so datagram size), with
//!   the template either warm (sent once, data-only packets) or resent in
//!   every packet.
//! - `flow_cache`: cache hits (a pre-warmed pool of flows) versus misses
//!   (every record is a new flow).
//!
//! `tools/bench.sh` records the environment next to the Criterion results.

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use netflow_analyzer_core::FlowContext;

/// Length of the v9 header plus the template FlowSet built by [`v9_packet`].
const V9_TEMPLATE_PREFIX: usize = 20 + 36;
/// Length of one v9 data record built by [`v9_packet`].
const V9_RECORD_LEN: usize = 21;
/// Offset of the first record's source address within a data-only packet.
const V9_DATA_SRC_OFFSET: usize = 20 + 4 + 8;

/// Minimal big-endian writer used to assemble synthetic packets.
struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends `value` as a big-endian integer of `width` bytes.
    fn put(&mut self, value: u64, width: usize) -> &mut Self {
        for i in 0..width {
            self.buf.push((value >> (8 * (width - 1 - i))) as u8);
        }
        self
    }
}

/// A NetFlow v9 packet with a 7-field template (id 256) and `records` data records.
fn v9_packet(records: usize) -> Vec<u8> {
    let mut b = Builder::new();

    // Header.
    b.put(9, 2) // version
        .put((records + 1) as u64, 2) // count (template set + data records)
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(1, 4) // sequence
        .put(42, 4); // source id

    // Template FlowSet (id 256, 7 fields).
    b.put(0, 2) // flowset id (template)
        .put(36, 2) // length
        .put(256, 2) // template id
        .put(7, 2) // field count
        .put(1, 2)
        .put(4, 2) // IN_BYTES
        .put(2, 2)
        .put(4, 2) // IN_PKTS
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(7, 2)
        .put(2, 2) // SRC_PORT
        .put(11, 2)
        .put(2, 2) // DST_PORT
        .put(4, 2)
        .put(1, 2); // PROTOCOL

    // Data FlowSet: `records` records of 21 bytes each.
    let record_len = 21;
    b.put(256, 2) // flowset id = template id
        .put((4 + record_len * records) as u64, 2);
    for i in 0..records as u64 {
        b.put(1500 + i, 4) // bytes
            .put(10 + i, 4) // packets
            .put(0xC0A8_0100 + i, 4) // 192.168.1.x (distinct 5-tuples)
            .put(0x0A00_0005, 4) // 10.0.0.5
            .put(12345, 2) // src port
            .put(443, 2) // dst port
            .put(6, 1); // proto = TCP
    }

    b.buf
}

/// An IPFIX packet (version 10) with a Template Set (id 2) and one 9-byte data record.
fn ipfix_packet() -> Vec<u8> {
    let mut b = Builder::new();

    // IPFIX header (16 bytes).
    b.put(10, 2) // version
        .put(0, 2) // total length (patched below)
        .put(1_700_000_000, 4) // export time
        .put(5, 4) // sequence
        .put(7, 4); // observation domain id

    // Template Set (set id 2): one template (id 300) with 3 fields.
    b.put(2, 2)
        .put(20, 2)
        .put(300, 2)
        .put(3, 2)
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(4, 2)
        .put(1, 2); // PROTOCOL

    // Data Set (set id 300): one 9-byte record.
    b.put(300, 2)
        .put(13, 2)
        .put(0xC0A8_0001, 4) // 192.168.0.1
        .put(0x0808_0808, 4) // 8.8.8.8
        .put(17, 1); // proto = UDP

    // Patch the IPFIX header's total_length (bytes 2..4) to the real length.
    let total = b.buf.len() as u16;
    b.buf[2..4].copy_from_slice(&total.to_be_bytes());
    b.buf
}

/// A NetFlow v5 datagram: 24-byte header followed by `records` 48-byte records.
fn v5_packet(records: usize) -> Vec<u8> {
    let mut b = Builder::new();
    b.put(5, 2) // version
        .put(records as u64, 2) // count
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(0, 4) // unix nanos
        .put(1, 4) // flow sequence
        .put(0, 1) // engine type
        .put(0, 1) // engine id
        .put(0, 2); // sampling interval

    for i in 0..records as u32 {
        let mut rec = [0u8; 48];
        rec[0..4].copy_from_slice(&(0xC0A8_0000u32 + i).to_be_bytes()); // src
        rec[4..8].copy_from_slice(&[10, 0, 0, 1]); // dst
        rec[16..20].copy_from_slice(&(10u32).to_be_bytes()); // packets
        rec[20..24].copy_from_slice(&(1500u32).to_be_bytes()); // octets
        rec[32..34].copy_from_slice(&(12345u16).to_be_bytes()); // src port
        rec[34..36].copy_from_slice(&(443u16).to_be_bytes()); // dst port
        rec[38] = 6; // proto = TCP
        b.buf.extend_from_slice(&rec);
    }

    b.buf
}

fn bench_process_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_packet");

    // NetFlow v9: template set + a single data record, replayed on one
    // context. The template is redefined by every packet.
    {
        let packet = v9_packet(1);
        group.throughput(Throughput::Elements(1));
        group.bench_function("v9_single_record", |b| {
            let ctx = FlowContext::new();
            b.iter(|| {
                let n = ctx.process_packet(black_box(&packet)).expect("parse ok");
                black_box(n);
            });
        });
    }

    // NetFlow v9 with 30 distinct 5-tuples per datagram: exercises the data-set
    // walk and cache upsert path at a realistic record density.
    {
        let records = 30;
        let packet = v9_packet(records);
        group.throughput(Throughput::Elements(records as u64));
        group.bench_function("v9_thirty_records", |b| {
            let ctx = FlowContext::new();
            b.iter(|| {
                let n = ctx.process_packet(black_box(&packet)).expect("parse ok");
                black_box(n);
            });
        });
    }

    // IPFIX: template set + one data record; the template is redefined by
    // every packet.
    {
        let packet = ipfix_packet();
        group.throughput(Throughput::Elements(1));
        group.bench_function("ipfix_single_record", |b| {
            let ctx = FlowContext::new();
            b.iter(|| {
                let n = ctx.process_packet(black_box(&packet)).expect("parse ok");
                black_box(n);
            });
        });
    }

    // NetFlow v5: template-less fixed-format decode of 30 records per datagram.
    {
        let records = 30;
        let packet = v5_packet(records);
        group.throughput(Throughput::Elements(records as u64));
        group.bench_function("v5_thirty_records", |b| {
            let ctx = FlowContext::new();
            b.iter(|| {
                let n = ctx.process_packet(black_box(&packet)).expect("parse ok");
                black_box(n);
            });
        });
    }

    // Cold-cache cost: build a fresh context for every iteration so we also
    // capture allocation of the sharded caches, not just the steady state.
    {
        let packet = v9_packet(30);
        group.throughput(Throughput::Elements(30));
        group.bench_function("v9_cold_context", |b| {
            b.iter_batched(
                FlowContext::new,
                |ctx| {
                    let n = ctx.process_packet(black_box(&packet)).expect("parse ok");
                    black_box(n);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// `v9_packet(records)` without its template FlowSet: header + data FlowSet.
fn v9_data_only_packet(records: usize) -> Vec<u8> {
    let full = v9_packet(records);
    [&full[..20], &full[V9_TEMPLATE_PREFIX..]].concat()
}

/// Rewrites every record's source address so the packet carries the
/// `records` flows starting at `first_flow`.
fn set_flows(packet: &mut [u8], records: usize, first_flow: u32) {
    for i in 0..records {
        let at = V9_DATA_SRC_OFFSET + i * V9_RECORD_LEN;
        let src = first_flow.wrapping_add(i as u32);
        packet[at..at + 4].copy_from_slice(&src.to_be_bytes());
    }
}

fn bench_records_per_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("v9_records_per_packet");
    // 60 records of 21 bytes fill a 1500-byte MTU datagram.
    for records in [1usize, 10, 30, 60] {
        group.throughput(Throughput::Elements(records as u64));

        let data = v9_data_only_packet(records);
        group.bench_function(format!("warm_template/{records}r_{}B", data.len()), |b| {
            let ctx = FlowContext::new();
            ctx.process_packet(&v9_packet(0)).expect("template ok");
            b.iter(|| {
                let n = ctx.process_packet(black_box(&data)).expect("parse ok");
                assert_eq!(n, records);
            });
        });

        let full = v9_packet(records);
        group.bench_function(format!("template_resent/{records}r_{}B", full.len()), |b| {
            let ctx = FlowContext::new();
            b.iter(|| {
                let n = ctx.process_packet(black_box(&full)).expect("parse ok");
                assert_eq!(n, records);
            });
        });
    }
    group.finish();
}

fn bench_flow_cache(c: &mut Criterion) {
    const RECORDS: usize = 30;
    /// Distinct flows cycled through by the hit case (all resident).
    const HIT_POOL: u32 = 64 * 1024;
    /// Packets timed between untimed flushes in the miss case, bounding the
    /// cache to `MISS_CHUNK * RECORDS` flows.
    const MISS_CHUNK: u64 = 4096;

    let mut group = c.benchmark_group("flow_cache");
    group.throughput(Throughput::Elements(RECORDS as u64));

    group.bench_function("hit_64k_resident", |b| {
        let ctx = FlowContext::new();
        let mut packet = v9_data_only_packet(RECORDS);
        ctx.process_packet(&v9_packet(0)).expect("template ok");
        for first in (0..HIT_POOL).step_by(RECORDS) {
            set_flows(&mut packet, RECORDS, first);
            ctx.process_packet(&packet).expect("parse ok");
        }
        let resident = ctx.active_flows();
        let mut first = 0u32;
        b.iter(|| {
            set_flows(&mut packet, RECORDS, first);
            first = (first + RECORDS as u32) % HIT_POOL;
            black_box(ctx.process_packet(black_box(&packet)).expect("parse ok"));
        });
        assert_eq!(ctx.active_flows(), resident, "every record was a hit");
    });

    group.bench_function("miss_new_flow", |b| {
        let ctx = FlowContext::new();
        let mut packet = v9_data_only_packet(RECORDS);
        ctx.process_packet(&v9_packet(0)).expect("template ok");
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            let mut first = 0u32;
            let mut done = 0u64;
            while done < iters {
                let chunk = MISS_CHUNK.min(iters - done);
                let start = Instant::now();
                for _ in 0..chunk {
                    set_flows(&mut packet, RECORDS, first);
                    first = first.wrapping_add(RECORDS as u32);
                    black_box(ctx.process_packet(black_box(&packet)).expect("parse ok"));
                }
                elapsed += start.elapsed();
                done += chunk;
                ctx.flush(|_| {});
            }
            assert_eq!(ctx.stats().flows_dropped, 0, "misses were admitted");
            elapsed
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_process_packet,
    bench_records_per_packet,
    bench_flow_cache
);
criterion_main!(benches);
