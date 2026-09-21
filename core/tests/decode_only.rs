// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests for the decode-only path (`decode_packet` / `decode_packet_at`), which
//! emits one record per decoded data record through a sink and never touches the
//! flow cache. This is the split that lets the parser drive an external
//! aggregator.

mod common;

use std::sync::atomic::Ordering;

use common::{sample_v5_packet, sample_v9_packet, Builder};
use netflow_analyzer_core::records::FlowFields;
use netflow_analyzer_core::FlowContext;

#[test]
fn decode_emits_per_record_without_caching() {
    let ctx = FlowContext::new();

    let mut collected: Vec<(u32, FlowFields)> = Vec::new();
    let processed = ctx
        .decode_packet(&sample_v9_packet(), &mut |domain, fields| {
            collected.push((domain, *fields));
        })
        .expect("parse ok");

    assert_eq!(processed, 1, "one data record decoded");
    assert_eq!(collected.len(), 1, "sink invoked once");
    // Crucially: nothing is aggregated into the flow cache.
    assert_eq!(ctx.flows.len(), 0, "decode-only must not cache flows");

    let (domain, fields) = &collected[0];
    assert_eq!(*domain, 42, "v9 source id is the observation domain");
    assert_eq!(&fields.src_ip[12..16], &[192, 168, 1, 10]);
    assert_eq!(&fields.dst_ip[12..16], &[10, 0, 0, 5]);
    assert_eq!(fields.src_port, 12345);
    assert_eq!(fields.dst_port, 443);
    assert_eq!(fields.proto, 6);
    assert_eq!(fields.bytes, 1500);
    assert_eq!(fields.packets, 10);

    // Parse/template counters still advance; flow gauges stay at zero.
    let stats = ctx.stats();
    assert_eq!(stats.pkts_parsed, 1);
    assert_eq!(stats.templates_received, 1);
    assert_eq!(stats.data_records_processed, 1);
    assert_eq!(stats.active_flows, 0);
    assert_eq!(stats.flows_output, 0);
}

#[test]
fn decode_does_not_accumulate_across_calls() {
    // The fused path would fold repeated 5-tuples into one accumulating flow.
    // The decode-only path must instead surface each record independently.
    let ctx = FlowContext::new();
    let packet = sample_v9_packet();

    let mut count = 0usize;
    let mut last = FlowFields::default();
    let mut sink = |_domain: u32, fields: &FlowFields| {
        count += 1;
        last = *fields;
    };
    ctx.decode_packet(&packet, &mut sink).expect("parse ok");
    ctx.decode_packet(&packet, &mut sink).expect("parse ok");

    assert_eq!(count, 2, "each record surfaced separately");
    assert_eq!(last.bytes, 1500, "no accumulation on the decode path");
    assert_eq!(ctx.flows.len(), 0);
}

#[test]
fn decode_v5_reports_zero_domain() {
    let ctx = FlowContext::new();
    let packet = sample_v5_packet(&[([192, 168, 0, 1], [8, 8, 8, 8], 3, 400, 1111, 53, 17)]);

    let mut domains = Vec::new();
    let processed = ctx
        .decode_packet(&packet, &mut |domain, _fields| domains.push(domain))
        .expect("parse ok");

    assert_eq!(processed, 1);
    assert_eq!(domains, vec![0], "v5 is template-less and domain-less");
    assert_eq!(ctx.flows.len(), 0);
}

#[test]
fn decode_counts_options_records_but_never_emits_them() {
    // A well-formed v9 options template + one options data record. Options data
    // is exporter metadata, not a flow, so the sink must never see it.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(2, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);
    b.put(1, 2)
        .put(18, 2)
        .put(260, 2)
        .put(4, 2)
        .put(4, 2)
        .put(1, 2)
        .put(4, 2)
        .put(34, 2)
        .put(4, 2);
    b.put(260, 2).put(12, 2).put(0x0000_0001, 4).put(1000, 4);

    let ctx = FlowContext::new();
    let mut emitted = 0usize;
    let processed = ctx
        .decode_packet(&b.buf, &mut |_d, _f| emitted += 1)
        .expect("parse ok");

    assert_eq!(processed, 0, "options records are not flows");
    assert_eq!(emitted, 0, "sink is never called for options data");
    assert_eq!(
        ctx.counters
            .options_records_processed
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(ctx.flows.len(), 0);
}
