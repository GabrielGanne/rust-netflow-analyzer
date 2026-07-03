//! End-to-end tests for NetFlow v9 (RFC 3954): template FlowSets, data
//! records, options handling, truncation, and variable-length fields.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use common::{sample_v9_packet, Builder};
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::FlowContext;

#[test]
fn decodes_v9_data_record_into_cache() {
    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&sample_v9_packet()).expect("parse ok");

    assert_eq!(processed, 1, "one data record expected");
    assert_eq!(ctx.flows.len(), 1, "one flow cached");

    let stats = ctx.stats();
    assert_eq!(stats.pkts_parsed, 1);
    assert_eq!(stats.templates_received, 1);
    assert_eq!(stats.data_records_processed, 1);
    assert_eq!(stats.active_flows, 1);
    assert_eq!(stats.pkts_parse_error, 0);
}

#[test]
fn flush_emits_decoded_fields() {
    let ctx = FlowContext::new();
    ctx.process_packet(&sample_v9_packet()).expect("parse ok");

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));

    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);

    let f = &flows[0];
    assert_eq!(&f.src_ip[12..16], &[192, 168, 1, 10]);
    assert_eq!(&f.dst_ip[12..16], &[10, 0, 0, 5]);
    assert_eq!(f.src_port, 12345);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.proto, 6);
    assert_eq!(f.bytes, 1500);
    assert_eq!(f.packets, 10);
    assert_eq!(f.start_time_ns, 1_700_000_000_000_000_000);
    assert_eq!(f.end_time_ns, 1_700_000_000_000_000_000);

    // The cache is emptied by flush.
    assert_eq!(ctx.flows.len(), 0);
    assert_eq!(ctx.stats().flows_output, 1);
    assert_eq!(ctx.stats().flows_dropped, 0);
}

#[test]
fn repeated_records_accumulate_counters() {
    let ctx = FlowContext::new();
    let packet = sample_v9_packet();

    // First packet installs the template + one record; second reuses both.
    ctx.process_packet(&packet).expect("parse ok");
    ctx.process_packet(&packet).expect("parse ok");

    assert_eq!(ctx.flows.len(), 1, "same 5-tuple stays a single flow");

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));

    let flows = collected.lock().unwrap();
    assert_eq!(flows[0].bytes, 3000, "byte counters accumulate");
    assert_eq!(flows[0].packets, 20, "packet counters accumulate");
}

#[test]
fn data_without_template_is_skipped() {
    // A data FlowSet whose template has not been seen yet must not panic and
    // must not create any flows.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4)
        // Data set for an unknown template id.
        .put(256, 2)
        .put(8, 2)
        .put(0xDEAD_BEEF, 4);

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("parse ok");
    assert_eq!(processed, 0);
    assert_eq!(ctx.flows.len(), 0);
}

#[test]
fn malformed_options_template_is_handled_gracefully() {
    // A v9 options template (flowset id 1) whose declared field lengths run
    // past the buffer must be rejected without error and store nothing.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4)
        // Options template flowset (id 1) with a nonsensical 8-byte body.
        .put(1, 2)
        .put(12, 2)
        .put(0xABCD, 4)
        .put(0x1234, 4);

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("parse ok");
    assert_eq!(processed, 0);
    assert_eq!(ctx.stats().templates_received, 0);
    assert_eq!(ctx.counters.options_templates_received.load(Ordering::Relaxed), 0);
}

#[test]
fn options_template_and_data_are_decoded_but_not_flows() {
    // A well-formed v9 options template (1 scope field + 1 option field)
    // followed by one options data record. The template must be stored and the
    // record decoded and counted, but it must never enter the flow cache.
    let mut b = Builder::new();
    b.put(9, 2) // version
        .put(2, 2) // count
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(1, 4) // sequence
        .put(42, 4); // source id

    // Options Template FlowSet (id 1). Record: template id 260, scope length 4
    // bytes (one field), option length 4 bytes (one field).
    b.put(1, 2) // flowset id = options template
        .put(18, 2) // length = 4 header + 14 record
        .put(260, 2) // template id
        .put(4, 2) // option scope length (bytes)
        .put(4, 2) // option length (bytes)
        .put(1, 2) // scope field: SYSTEM
        .put(4, 2) // scope field length
        .put(34, 2) // option field: samplingInterval
        .put(4, 2); // option field length

    // Options Data FlowSet (id 260): one 8-byte record (scope + option value).
    b.put(260, 2) // set id = options template id
        .put(12, 2) // length = 4 + 8
        .put(0x0000_0001, 4) // scope value (system)
        .put(1000, 4); // samplingInterval value

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("parse ok");

    // Options records are not flows: nothing is returned or cached as a flow.
    assert_eq!(processed, 0);
    assert_eq!(ctx.flows.len(), 0);
    assert_eq!(ctx.stats().templates_received, 0, "options are not regular templates");
    assert_eq!(ctx.counters.options_templates_received.load(Ordering::Relaxed), 1);
    assert_eq!(ctx.counters.options_records_processed.load(Ordering::Relaxed), 1);
}

#[test]
fn unknown_reserved_set_id_is_skipped() {
    // Set id 100 (reserved, < 256, not a template/options id) is ignored.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4)
        .put(100, 2)
        .put(8, 2)
        .put(0xDEAD_BEEF, 4);

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&b.buf).expect("parse ok"), 0);
}

#[test]
fn truncated_flowset_stops_gracefully() {
    // The flowset claims length 100 but only a few body bytes follow; the walk
    // must stop without panicking or fabricating records.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4)
        .put(0, 2) // template flowset
        .put(100, 2) // bogus length, far beyond the buffer
        .put(0x0102, 2);

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("header parse ok");
    assert_eq!(processed, 0);
    assert_eq!(ctx.stats().templates_received, 0);
}

#[test]
fn variable_length_records_via_process_packet() {
    // v9 template with a single variable-length IPv6 source field, two records.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(2, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4)
        // Template (id 260): one variable-length field (IPV6_SRC, len 0xffff).
        .put(0, 2)
        .put(12, 2) // length = 4 + 4 + 1*4
        .put(260, 2)
        .put(1, 2)
        .put(27, 2)
        .put(0xFFFF, 2);

    // Two variable-length records (short form), each 1 + 16 bytes.
    let addr_a: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A];
    let addr_b: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0B];
    let body_len = (1 + 16) * 2;
    b.put(260, 2).put((4 + body_len) as u64, 2);
    b.put(16, 1);
    b.buf.extend_from_slice(&addr_a);
    b.put(16, 1);
    b.buf.extend_from_slice(&addr_b);

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("parse ok");
    assert_eq!(processed, 2);
    assert_eq!(ctx.flows.len(), 2);
}
