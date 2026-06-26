//! Protocol-agnostic engine behaviour: configuration, capacity limits,
//! background aging, and malformed-input handling.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{sample_v9_packet, Builder};
use netflow_analyzer_core::cache::AgingConfig;
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::{EngineConfig, FlowContext};

#[test]
fn rejects_unknown_version() {
    let ctx = FlowContext::new();
    let mut bogus = vec![0xFF, 0xFF];
    bogus.extend_from_slice(&[0u8; 20]);

    assert!(ctx.process_packet(&bogus).is_err());
    assert_eq!(ctx.stats().malformed_packets, 1);
}

#[test]
fn empty_input_is_malformed() {
    let ctx = FlowContext::new();
    assert!(ctx.process_packet(&[]).is_err());
    assert_eq!(ctx.stats().malformed_packets, 1);
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
        .put(7, 2).put(2, 2) // SRC_PORT
        .put(4, 2).put(1, 2); // PROTOCOL

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
    assert!(!emitted.lock().unwrap().is_empty(), "eviction emitted a record");
    assert!(ctx.stats().flows_evicted >= 1);
}
