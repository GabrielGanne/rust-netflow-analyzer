//! End-to-end tests for IPFIX (RFC 7011): Template Sets and Data Sets.

mod common;

use std::sync::{Arc, Mutex};

use common::sample_ipfix_packet;
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::FlowContext;

#[test]
fn decodes_ipfix_packet() {
    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&sample_ipfix_packet()).expect("parse ok");
    assert_eq!(processed, 1);

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));

    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(&flows[0].src_ip[12..16], &[192, 168, 0, 1]);
    assert_eq!(&flows[0].dst_ip[12..16], &[8, 8, 8, 8]);
    assert_eq!(flows[0].proto, 17);
    assert_eq!(flows[0].start_time_ns, 1_700_000_000_000_000_000);
    assert_eq!(flows[0].end_time_ns, 1_700_000_000_000_000_000);
}
