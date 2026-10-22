// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Deterministic aging driven by caller timestamps (`*_at` + `age_at`),
//! aging-thread lifecycle, and concurrent ingestion, flushing, and aging
//! against the bounded caches.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use common::{sample_v5_packet, sample_v9_packet, V5Flow};
use netflow_analyzer_core::cache::AgingConfig;
use netflow_analyzer_core::{EngineConfig, FlowContext};

const T0: u64 = 1_700_000_000_000_000_000;
const SECOND: u64 = 1_000_000_000;

fn aging(idle_secs: u64, active_secs: u64) -> EngineConfig {
    EngineConfig {
        aging: AgingConfig {
            idle_timeout: Duration::from_secs(idle_secs),
            active_timeout: Duration::from_secs(active_secs),
            scan_interval: Duration::from_secs(3600),
        },
        ..EngineConfig::default()
    }
}

/// A v5 flow whose source address encodes `id`, carrying `octets` bytes.
fn flow(id: u32, octets: u32) -> V5Flow {
    (id.to_be_bytes(), [10, 0, 0, 1], 1, octets, 1000, 80, 6)
}

#[test]
fn idle_timeout_boundaries_follow_receipt_time() {
    // (case, seconds after the last packet at which age_at runs, evicted?)
    let cases = [
        ("same instant", 0, false),
        ("just before idle timeout", 29, false),
        ("at idle timeout", 30, true),
        ("long after", 3600, true),
    ];
    for (name, after, evicted) in cases {
        let ctx = FlowContext::with_config(aging(30, 3600));
        let packet = sample_v5_packet(&[flow(1, 100)]);
        ctx.process_packet_at(&packet, T0).expect("parse ok");
        // A later packet for the same flow refreshes its idle clock.
        ctx.process_packet_at(&packet, T0 + 10 * SECOND)
            .expect("parse ok");

        let emitted = ctx.age_at(T0 + (10 + after) * SECOND, |record| {
            assert_eq!(record.bytes, 200, "{name}");
        });
        assert_eq!(emitted, evicted as usize, "{name}");
        assert_eq!(ctx.active_flows(), !evicted as usize, "{name}");
    }
}

#[test]
fn active_timeout_rolls_over_and_restarts_the_window() {
    let ctx = FlowContext::with_config(aging(3600, 60));
    let packet = sample_v5_packet(&[flow(1, 100)]);
    for second in [0, 20, 40] {
        ctx.process_packet_at(&packet, T0 + second * SECOND)
            .expect("parse ok");
    }

    assert_eq!(ctx.age_at(T0 + 59 * SECOND, |_| panic!("not yet due")), 0);
    let bytes = Mutex::new(Vec::new());
    assert_eq!(
        ctx.age_at(T0 + 60 * SECOND, |r| bytes.lock().unwrap().push(r.bytes)),
        1
    );
    assert_eq!(*bytes.lock().unwrap(), [300]);
    assert_eq!(ctx.active_flows(), 1, "rollover keeps the flow resident");

    // The next window starts at the rollover time, not the first packet.
    assert_eq!(ctx.age_at(T0 + 119 * SECOND, |_| panic!("not yet due")), 0);
    assert_eq!(ctx.age_at(T0 + 120 * SECOND, |r| assert_eq!(r.bytes, 0)), 1);
}

#[test]
fn time_moving_backwards_never_ages_early() {
    let ctx = FlowContext::with_config(aging(30, 60));
    let packet = sample_v5_packet(&[flow(1, 100)]);
    ctx.process_packet_at(&packet, T0).expect("parse ok");
    // An out-of-order older packet must not pull the observation time back.
    ctx.process_packet_at(&packet, T0 - 3600 * SECOND)
        .expect("parse ok");

    assert_eq!(ctx.age_at(0, |_| panic!("no flow is due")), 0);
    assert_eq!(
        ctx.age_at(T0 + 29 * SECOND, |_| panic!("no flow is due")),
        0
    );
    assert_eq!(ctx.age_at(T0 + 30 * SECOND, |_| {}), 1);
}

#[test]
fn templates_expire_on_receipt_time() {
    let lifetime = 30 * 60 * SECOND;
    let packet = sample_v9_packet();
    let template_only = &packet[..20 + 36];
    let data_only = [&packet[..20], &packet[20 + 36..]].concat();

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet_at(template_only, T0), Ok(0));
    assert_eq!(ctx.process_packet_at(&data_only, T0 + lifetime - 1), Ok(1));
    assert_eq!(
        ctx.process_packet_at(&data_only, T0 + lifetime),
        Ok(0),
        "expired template no longer decodes"
    );
    assert_eq!(ctx.active_templates(), 0);

    // An out-of-order older refresh must not shorten the newer definition.
    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet_at(template_only, T0), Ok(0));
    assert_eq!(
        ctx.process_packet_at(template_only, T0 - 3600 * SECOND),
        Ok(0)
    );
    assert_eq!(ctx.process_packet_at(&data_only, T0 + SECOND), Ok(1));

    // age_at also reclaims an expired template without any data traffic.
    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet_at(template_only, T0), Ok(0));
    ctx.age_at(T0 + lifetime - 1, |_| {});
    assert_eq!(ctx.active_templates(), 1);
    ctx.age_at(T0 + lifetime, |_| {});
    assert_eq!(ctx.active_templates(), 0);
}

#[test]
fn repeated_aging_start_stop_is_prompt_and_leak_free() {
    let ctx = FlowContext::with_config(aging(3600, 3600));
    ctx.process_packet(&sample_v9_packet()).expect("parse ok");
    let emitted = Arc::new(AtomicU64::new(0));
    for _ in 0..100 {
        let sink = emitted.clone();
        ctx.start_aging(move |_| {
            sink.fetch_add(1, Ordering::Relaxed);
        });
        // Restarting replaces the running worker.
        let sink = emitted.clone();
        ctx.start_aging(move |_| {
            sink.fetch_add(1, Ordering::Relaxed);
        });
        // The hour-long scan interval would block here if stop did not wake
        // the worker.
        ctx.stop_aging();
    }
    ctx.stop_aging();
    assert_eq!(emitted.load(Ordering::Relaxed), 0, "no sweep was due");
    assert_eq!(ctx.active_flows(), 1);
}

/// Runs `threads` workers, each sending `packets` one-byte single-record
/// packets over `flows_per_thread` distinct flows, while the calling thread
/// runs `drain` `packets / 10` times.
fn ingest_concurrently(
    ctx: &FlowContext,
    threads: u32,
    packets: u32,
    flows_per_thread: u32,
    drain: impl Fn(u32) + Sync,
) {
    let barrier = Barrier::new(threads as usize + 1);
    thread::scope(|scope| {
        for worker in 0..threads {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for i in 0..packets {
                    let id = worker * flows_per_thread + i % flows_per_thread;
                    let packet = sample_v5_packet(&[flow(id, 1)]);
                    ctx.process_packet_at(&packet, T0 + u64::from(i))
                        .expect("parse ok");
                }
            });
        }
        barrier.wait();
        for round in 0..packets / 10 {
            drain(round);
        }
    });
}

#[test]
fn concurrent_ingestion_and_flushing_conserve_bytes() {
    let ctx = FlowContext::new();
    let flushed = AtomicU64::new(0);
    let add = |record: &netflow_analyzer_core::FlowRecord| {
        flushed.fetch_add(record.bytes, Ordering::Relaxed);
    };
    ingest_concurrently(&ctx, 8, 2_000, 50, |_| ctx.flush(add));
    ctx.flush(add);

    assert_eq!(flushed.load(Ordering::Relaxed), 8 * 2_000);
    assert_eq!(ctx.active_flows(), 0);
    let stats = ctx.stats();
    assert_eq!(stats.data_records_processed, 8 * 2_000);
    assert_eq!(stats.flows_dropped, 0);
}

#[test]
fn concurrent_ingestion_and_age_at_conserve_bytes() {
    let ctx = FlowContext::with_config(aging(0, 3600));
    let aged = AtomicU64::new(0);
    let add = |record: &netflow_analyzer_core::FlowRecord| {
        aged.fetch_add(record.bytes, Ordering::Relaxed);
    };
    ingest_concurrently(&ctx, 8, 2_000, 50, |round| {
        ctx.age_at(T0 + u64::from(round) * 10, add);
    });
    ctx.age_at(u64::MAX, add);

    assert_eq!(aged.load(Ordering::Relaxed), 8 * 2_000);
    assert_eq!(ctx.active_flows(), 0);
}

#[test]
fn flow_cap_holds_under_concurrent_load() {
    let cfg = EngineConfig {
        max_flows: 100,
        ..aging(3600, 3600)
    };
    let ctx = FlowContext::with_config(cfg);
    let peak = AtomicU64::new(0);
    ingest_concurrently(&ctx, 8, 1_000, 1_000, |_| {
        peak.fetch_max(ctx.active_flows() as u64, Ordering::Relaxed);
    });

    assert!(peak.load(Ordering::Relaxed) <= 100);
    assert_eq!(
        ctx.active_flows(),
        100,
        "the cache fills exactly to its cap"
    );
    let stats = ctx.stats();
    assert_eq!(stats.flows_dropped, 8 * 1_000 - 100);

    // Flushing frees every slot, so new flows are admitted again.
    ctx.flush(|_| {});
    ctx.process_packet_at(&sample_v5_packet(&[flow(u32::MAX, 1)]), T0)
        .expect("parse ok");
    assert_eq!(ctx.active_flows(), 1);
    assert_eq!(ctx.stats().flows_dropped, stats.flows_dropped);
}
