// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Protocol-agnostic engine behaviour: configuration, capacity limits,
//! background aging, and malformed-input handling.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{sample_v5_packet, sample_v9_packet, Builder, V5Flow};
use netflow_analyzer_core::cache::AgingConfig;
use netflow_analyzer_core::clock::ClockConfig;
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::scope::{Scope, SINGLE_EXPORTER};
use netflow_analyzer_core::{EngineConfig, FlowContext};

#[test]
fn rejects_unknown_version() {
    let ctx = FlowContext::new();
    let mut bogus = vec![0xFF, 0xFF];
    bogus.extend_from_slice(&[0u8; 20]);

    assert!(ctx.process_packet(&bogus).is_err());
    assert_eq!(ctx.stats().pkts_parse_error, 1);
    assert_eq!(ctx.stats().pkts_parsed, 0);
}

#[test]
fn empty_input_is_malformed() {
    let ctx = FlowContext::new();
    assert!(ctx.process_packet(&[]).is_err());
    assert_eq!(ctx.stats().pkts_parse_error, 1);
    assert_eq!(ctx.stats().pkts_parsed, 0);
}

#[test]
fn default_context_matches_new() {
    let ctx = FlowContext::default();
    assert_eq!(ctx.flows.len(), 0);
    assert_eq!(ctx.templates.len(), 0);
}

#[test]
fn cache_cap_drops_excess_flows() {
    // A 2-field template producing distinct flows, with a flow cap of 1.
    let cfg = EngineConfig {
        max_flows: 1,
        ..EngineConfig::default()
    };
    let ctx = FlowContext::with_config(cfg);

    // Template (id 270): SRC_PORT (distinguishes flows) + PROTOCOL.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(3, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4)
        .put(0, 2)
        .put(16, 2) // 4 + 4 + 2*4
        .put(270, 2)
        .put(2, 2)
        .put(7, 2)
        .put(2, 2) // SRC_PORT
        .put(4, 2)
        .put(1, 2); // PROTOCOL

    // Two data records with different source ports => two distinct keys.
    let record_len = 3; // 2 + 1
    b.put(270, 2).put((4 + record_len * 2) as u64, 2);
    b.put(1111, 2).put(6, 1);
    b.put(2222, 2).put(6, 1);

    let processed = ctx.process_packet(&b.buf).expect("parse ok");
    assert_eq!(processed, 2, "both records decoded");
    assert_eq!(ctx.flows.len(), 1, "cap keeps only one flow");
    assert_eq!(ctx.stats().flows_dropped, 1);
}

/// End-to-end proof that the flow cap bounds heap growth when a hostile or
/// high-volume exporter floods the engine with unique flows through the real
/// `process_packet` path. This is the meaningful OOM-tolerance property: the
/// only structure that grows over the process lifetime is hard-capped.
#[test]
fn flow_cap_bounds_growth_under_flood() {
    const CAP: usize = 100;
    const FLOOD: usize = 1000;

    let cfg = EngineConfig {
        max_flows: CAP,
        ..EngineConfig::default()
    };
    let ctx = FlowContext::with_config(cfg);

    // Each record carries a distinct source IP, so every one is a new flow key.
    let records: Vec<V5Flow> = (0..FLOOD)
        .map(|i| {
            let ip = (i as u32).to_be_bytes();
            (ip, [10, 0, 0, 1], 1, 100, 1234, 80, 6)
        })
        .collect();
    let packet = sample_v5_packet(&records);

    let processed = ctx.process_packet(&packet).expect("parse ok");

    assert_eq!(processed, FLOOD, "every record decodes");
    assert_eq!(ctx.flows.len(), CAP, "cache never exceeds the hard cap");
    assert_eq!(
        ctx.stats().flows_dropped as usize,
        FLOOD - CAP,
        "every flow beyond the cap is dropped and counted"
    );
}

/// Same guarantee for the template cache: a flood of unique template ids in a
/// single packet cannot grow the template map beyond `max_templates`.
#[test]
fn template_cap_bounds_growth_under_flood() {
    const CAP: usize = 100;
    const FLOOD: usize = 1000;

    let cfg = EngineConfig {
        max_templates: CAP,
        ..EngineConfig::default()
    };
    let ctx = FlowContext::with_config(cfg);

    let mut b = Builder::new();
    // NetFlow v9 header.
    b.put(9, 2) // version
        .put(FLOOD as u64, 2) // count (informational)
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(1, 4) // sequence
        .put(42, 4); // source id

    // One template FlowSet packed with FLOOD single-field templates. Each
    // template record is 8 bytes: id(2) + field_count(2) + one specifier(4).
    let set_len = 4 + FLOOD * 8;
    b.put(0, 2) // flowset id = template
        .put(set_len as u64, 2);
    for id in 0..FLOOD {
        let template_id = 256 + id as u64; // distinct, >= FIRST_DATA_SET_ID range
        b.put(template_id, 2) // template id
            .put(1, 2) // field count
            .put(8, 2) // IPV4_SRC
            .put(4, 2); // length
    }

    ctx.process_packet(&b.buf).expect("parse ok");

    assert_eq!(ctx.stats().templates_received, FLOOD as u64);
    assert_eq!(
        ctx.templates.len(),
        CAP,
        "template cache never exceeds the hard cap"
    );
}

#[test]
fn background_aging_evicts_and_emits() {
    let cfg = EngineConfig {
        aging: AgingConfig {
            idle_timeout: Duration::ZERO,
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_millis(10),
        },
        ..EngineConfig::default()
    };
    let ctx = FlowContext::with_config(cfg);

    let emitted: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = emitted.clone();
    ctx.start_aging(move |rec| sink.lock().unwrap().push(rec.clone()));

    ctx.process_packet(&sample_v9_packet()).expect("parse ok");

    // Wait for the aging thread to sweep the idle flow.
    std::thread::sleep(Duration::from_millis(300));
    ctx.stop_aging();

    assert_eq!(ctx.flows.len(), 0, "idle flow evicted");
    assert!(
        !emitted.lock().unwrap().is_empty(),
        "eviction emitted a record"
    );
    assert!(ctx.stats().flows_output >= 1);
}

#[test]
fn clock_check_drops_skewed_packet_and_tracks_domain() {
    let cfg = EngineConfig {
        clock: ClockConfig {
            sync_check_enabled: true,
            max_skew: Duration::from_nanos(10),
            fallback_to_receipt_time: false,
        },
        ..EngineConfig::default()
    };
    let ctx = FlowContext::with_config(cfg);
    let export_ns = 1_700_000_000_000_000_000;

    let result = ctx.process_packet_at(&sample_v9_packet(), export_ns + 11);
    assert!(result.is_err());
    assert_eq!(ctx.stats().clock_dropped_packets, 1);
    assert_eq!(ctx.stats().clock_fallback_packets, 0);
    assert_eq!(ctx.templates.len(), 0, "the entire packet is rejected");

    let state = ctx
        .clocks
        .get(SINGLE_EXPORTER, Scope::V9Domain(42))
        .expect("domain clock state");
    assert_eq!(state.last_skew_ns, 11);
    assert_eq!(state.clock_issues, 1);
    assert!(!state.last_was_usable);
}

#[test]
fn clock_fallback_preserves_original_and_rebases_effective_times() {
    let cfg = EngineConfig {
        clock: ClockConfig {
            sync_check_enabled: true,
            max_skew: Duration::from_nanos(10),
            fallback_to_receipt_time: true,
        },
        ..EngineConfig::default()
    };
    let ctx = FlowContext::with_config(cfg);
    let export_ns = 1_700_000_000_000_000_000;
    let receipt_ns = export_ns + 1_000_000_000;

    assert_eq!(
        ctx.process_packet_at(&sample_v9_packet(), receipt_ns),
        Ok(1)
    );
    assert_eq!(ctx.stats().clock_dropped_packets, 0);
    assert_eq!(ctx.stats().clock_fallback_packets, 1);

    let emitted: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = emitted.clone();
    ctx.flush(move |record| sink.lock().unwrap().push(record.clone()));
    let records = emitted.lock().unwrap();
    assert_eq!(records[0].original_start_time_ns, export_ns);
    assert_eq!(records[0].original_end_time_ns, export_ns);
    assert_eq!(records[0].start_time_ns, receipt_ns);
    assert_eq!(records[0].end_time_ns, receipt_ns);
}

#[test]
fn clock_state_is_independent_per_domain() {
    let ctx = FlowContext::new();
    let first = sample_v9_packet();
    let mut second = sample_v9_packet();
    second[16..20].copy_from_slice(&43_u32.to_be_bytes());

    ctx.process_packet_at(&first, 1_700_000_001_000_000_000)
        .unwrap();
    ctx.process_packet_at(&second, 1_700_000_002_000_000_000)
        .unwrap();

    assert_eq!(ctx.clocks.len(), 2);
    assert_eq!(
        ctx.clocks
            .get(SINGLE_EXPORTER, Scope::V9Domain(42))
            .unwrap()
            .last_receipt_time_ns,
        1_700_000_001_000_000_000
    );
    assert_eq!(
        ctx.clocks
            .get(SINGLE_EXPORTER, Scope::V9Domain(43))
            .unwrap()
            .last_receipt_time_ns,
        1_700_000_002_000_000_000
    );
}

#[test]
fn distinct_exporters_do_not_share_state() {
    // The very same datagram (same domain, template id, and 5-tuple) fed under
    // two different exporter keys must not collide: separate templates, clocks,
    // and flows, and emitted records tagged with their exporter.
    let ctx = FlowContext::new();
    let packet = sample_v9_packet();

    assert_eq!(ctx.process_packet_from(1, &packet), Ok(1));
    assert_eq!(ctx.process_packet_from(2, &packet), Ok(1));

    assert_eq!(ctx.templates.len(), 2, "templates are per-exporter");
    assert_eq!(ctx.clocks.len(), 2, "clocks are per-exporter");
    assert_eq!(ctx.flows.len(), 2, "flows are per-exporter");
    assert!(ctx.clocks.get(1, Scope::V9Domain(42)).is_some());
    assert!(ctx.clocks.get(2, Scope::V9Domain(42)).is_some());

    let emitted: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = emitted.clone();
    ctx.flush(move |record| sink.lock().unwrap().push(record.clone()));

    let mut keys: Vec<u64> = emitted.lock().unwrap().iter().map(|r| r.exporter).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![1, 2],
        "each emitted flow carries its exporter key"
    );
}
