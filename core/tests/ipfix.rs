// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end tests for IPFIX (RFC 7011): Template Sets and Data Sets.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use common::{sample_ipfix_packet, Builder};
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::FlowContext;

#[test]
fn decodes_ipfix_packet() {
    let ctx = FlowContext::new();
    let processed = ctx
        .process_packet(&sample_ipfix_packet())
        .expect("parse ok");
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

#[test]
fn options_template_and_data_are_decoded_but_not_flows() {
    // IPFIX Options Template Set (set id 3) with 2 fields, 1 of which is scope,
    // followed by one options data record. The template must be stored and the
    // record counted, but it must never enter the flow cache.
    let mut b = Builder::new();
    // IPFIX header (16 bytes).
    b.put(10, 2) // version
        .put(0, 2) // total length (ignored by the parser)
        .put(1_700_000_000, 4) // export time
        .put(5, 4) // sequence
        .put(7, 4); // observation domain id

    // Options Template Set (set id 3): template 260, field count 2, scope 1.
    b.put(3, 2) // set id = IPFIX options template
        .put(18, 2) // set length = 4 + 14
        .put(260, 2) // template id
        .put(2, 2) // total field count (incl. scope)
        .put(1, 2) // scope field count
        .put(149, 2) // scope field: observationDomainId
        .put(4, 2) // scope field length
        .put(34, 2) // option field: samplingInterval
        .put(4, 2); // option field length

    // Options Data Set (set id 260): one 8-byte record.
    b.put(260, 2) // set id = options template id
        .put(12, 2) // set length = 4 + 8
        .put(7, 4) // observationDomainId value
        .put(1000, 4); // samplingInterval value

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("parse ok");

    assert_eq!(processed, 0);
    assert_eq!(ctx.flows.len(), 0);
    assert_eq!(ctx.stats().templates_received, 0, "options are not regular templates");
    assert_eq!(ctx.counters.options_templates_received.load(Ordering::Relaxed), 1);
    assert_eq!(ctx.counters.options_records_processed.load(Ordering::Relaxed), 1);
}
