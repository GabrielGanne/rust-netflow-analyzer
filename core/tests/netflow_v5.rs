//! End-to-end tests for NetFlow v5: the fixed-format, template-less protocol.

mod common;

use std::sync::{Arc, Mutex};

use common::sample_v5_packet;
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::FlowContext;

#[test]
fn decodes_v5_packet_with_multiple_records() {
    let ctx = FlowContext::new();
    let packet = sample_v5_packet(&[
        ([192, 168, 0, 1], [10, 0, 0, 1], 5, 500, 1234, 80, 6),
        ([192, 168, 0, 2], [10, 0, 0, 2], 9, 900, 4321, 443, 6),
    ]);

    let processed = ctx.process_packet(&packet).expect("parse ok");
    assert_eq!(processed, 2);
    assert_eq!(ctx.flows.len(), 2);

    let stats = ctx.stats();
    assert_eq!(stats.data_records_processed, 2);
    assert_eq!(stats.pkts_parse_error, 0);

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));
    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 2);
    let total_bytes: u64 = flows.iter().map(|f| f.bytes).sum();
    assert_eq!(total_bytes, 1400);
    assert!(flows
        .iter()
        .all(|f| f.start_time_ns == 1_699_999_999_000_000_000));
    assert!(flows
        .iter()
        .all(|f| f.end_time_ns == 1_699_999_999_000_000_000));
}

#[test]
fn v5_count_is_bounded_by_buffer() {
    // Header claims 5 records but only one is present; decoding must not read
    // past the buffer and must report a single record.
    let ctx = FlowContext::new();
    let mut packet = sample_v5_packet(&[([1, 1, 1, 1], [2, 2, 2, 2], 1, 100, 1, 2, 6)]);
    // Overwrite the count field (bytes 2..4) with an inflated value.
    packet[2..4].copy_from_slice(&5u16.to_be_bytes());

    let processed = ctx.process_packet(&packet).expect("parse ok");
    assert_eq!(processed, 1);
    assert_eq!(ctx.flows.len(), 1);
}
