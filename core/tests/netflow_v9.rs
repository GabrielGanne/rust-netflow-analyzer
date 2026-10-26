// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end tests for NetFlow v9 (RFC 3954): template FlowSets, data
//! records, options handling, truncation, and variable-length fields.

mod common;

use std::sync::{Arc, Mutex};

use common::{flowset, packet, sample_v9_packet, template_record, v9_header, Builder};
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::sampling::{SamplerSelector, SamplingRatio};
use netflow_analyzer_core::scope::{Scope, SINGLE_EXPORTER};
use netflow_analyzer_core::FlowContext;

#[test]
fn decodes_v9_data_record_into_cache() {
    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&sample_v9_packet()).expect("parse ok");

    assert_eq!(processed, 1, "one data record expected");
    assert_eq!(ctx.active_flows(), 1, "one flow cached");

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
    assert_eq!(ctx.active_flows(), 0);
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

    assert_eq!(ctx.active_flows(), 1, "same 5-tuple stays a single flow");

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
    assert_eq!(ctx.active_flows(), 0);
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
    assert_eq!(ctx.stats().options_templates_received, 0);
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
    assert_eq!(ctx.active_flows(), 0);
    assert_eq!(
        ctx.stats().templates_received,
        0,
        "options are not regular templates"
    );
    assert_eq!(ctx.stats().options_templates_received, 1);
    assert_eq!(ctx.stats().options_records_processed, 1);
    // The samplingInterval (IE 34) carried by the options record is learned as a
    // 1000/1 ratio for this exporter and observation domain (source id 42). The
    // record carries no flowSamplerId/selectorId, so it is the domain sampler.
    assert_eq!(ctx.active_samplers(), 1);
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::V9Domain(42),
            SamplerSelector::Domain
        ),
        Some(SamplingRatio {
            numerator: 1000,
            denominator: 1
        })
    );
}

#[test]
fn domain_wide_sampling_scales_flow_counters() {
    let ctx = FlowContext::new();

    // 1) Learn a domain-wide 1-in-1000 sampler for domain 42 via an options
    //    record with no flowSamplerId/selectorId.
    let mut opts = Builder::new();
    opts.put(9, 2) // version
        .put(1, 2) // count (ignored for v9)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4); // source id / domain
    opts.put(1, 2) // options template flowset
        .put(18, 2) // length
        .put(260, 2) // template id
        .put(4, 2) // scope length (bytes)
        .put(4, 2) // option length (bytes)
        .put(1, 2) // scope: SYSTEM (IE 1)
        .put(4, 2)
        .put(34, 2) // option: samplingInterval
        .put(4, 2);
    opts.put(260, 2) // options data set
        .put(12, 2)
        .put(0x0000_0001, 4) // scope value
        .put(1000, 4); // samplingInterval
    assert_eq!(ctx.process_packet(&opts.buf).expect("parse ok"), 0);

    // 2) A normal data record (1500 bytes / 10 packets, domain 42, no selector)
    //    is scaled by the learned 1000x ratio before it is cached.
    assert_eq!(
        ctx.process_packet(&sample_v9_packet()).expect("parse ok"),
        1
    );

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));
    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].bytes, 1_500_000);
    assert_eq!(flows[0].packets, 10_000);
}

#[test]
fn per_sampler_ratio_scales_by_the_flows_own_selector() {
    // One packet that advertises a sampler keyed by flowSamplerId=7 (1-in-100)
    // and carries a data record tagged with that same flowSamplerId.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(100, 4); // domain 100

    // Options template 260: scope observationDomainId (IE 149), options
    // flowSamplerId (IE 48) + samplingInterval (IE 34).
    b.put(1, 2) // options template flowset
        .put(22, 2) // length = 4 + 6 + 3*4
        .put(260, 2) // template id
        .put(4, 2) // scope length (one 4-byte specifier)
        .put(8, 2) // option length (two 4-byte specifiers)
        .put(149, 2) // scope: observationDomainId
        .put(4, 2)
        .put(48, 2) // option: flowSamplerId
        .put(1, 2)
        .put(34, 2) // option: samplingInterval
        .put(4, 2);
    b.put(260, 2) // options data set
        .put(13, 2) // length = 4 + 9
        .put(100, 4) // observationDomainId value
        .put(7, 1) // flowSamplerId
        .put(100, 4); // samplingInterval

    // Flow template 300: octets, packets, flowSamplerId.
    b.put(0, 2) // template flowset
        .put(20, 2) // length = 4 + 4 + 3*4
        .put(300, 2)
        .put(3, 2)
        .put(1, 2) // IN_BYTES
        .put(4, 2)
        .put(2, 2) // IN_PKTS
        .put(4, 2)
        .put(48, 2) // flowSamplerId
        .put(1, 2);
    b.put(300, 2) // data set
        .put(13, 2) // length = 4 + 9
        .put(50, 4) // bytes
        .put(2, 4) // packets
        .put(7, 1); // flowSamplerId = 7

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&b.buf).expect("parse ok"), 1);
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::V9Domain(100),
            SamplerSelector::FlowSampler(7)
        ),
        Some(SamplingRatio {
            numerator: 100,
            denominator: 1
        })
    );

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));
    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].bytes, 5_000); // 50 * 100
    assert_eq!(flows[0].packets, 200); // 2 * 100
}

#[test]
fn count_based_options_sampling_scales_flow_counters() {
    // A sampler advertised with the count-based pair samplingPacketInterval (IE
    // 305) = 1 and samplingPacketSpace (IE 306) = 99 is a 1-in-100 rate.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);

    // Options template 260: scope SYSTEM (IE 1), options IE 305 + IE 306.
    b.put(1, 2)
        .put(22, 2) // length = 4 + 6 + 3*4
        .put(260, 2)
        .put(4, 2) // scope length (one specifier)
        .put(8, 2) // option length (two specifiers)
        .put(1, 2) // scope: SYSTEM
        .put(4, 2)
        .put(305, 2) // samplingPacketInterval
        .put(4, 2)
        .put(306, 2) // samplingPacketSpace
        .put(4, 2);
    b.put(260, 2)
        .put(16, 2) // length = 4 + 12
        .put(1, 4) // scope value
        .put(1, 4) // samplingPacketInterval
        .put(99, 4); // samplingPacketSpace

    // Flow template 300 + one data record (50 bytes / 2 packets).
    b.put(0, 2)
        .put(16, 2) // length = 4 + 4 + 2*4
        .put(300, 2)
        .put(2, 2)
        .put(1, 2) // IN_BYTES
        .put(4, 2)
        .put(2, 2) // IN_PKTS
        .put(4, 2);
    b.put(300, 2).put(12, 2).put(50, 4).put(2, 4);

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&b.buf).expect("parse ok"), 1);
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::V9Domain(42),
            SamplerSelector::Domain
        ),
        Some(SamplingRatio {
            numerator: 100,
            denominator: 1
        })
    );

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));
    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].bytes, 5_000); // 50 * 100
    assert_eq!(flows[0].packets, 200); // 2 * 100
}

#[test]
fn conflicting_domain_sampling_leaves_the_flow_unscaled() {
    // Two options records for the same domain with no selector advertise
    // different rates, so the domain sampler is ambiguous and the flow is left
    // unscaled rather than mis-scaled.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);

    // Options template 260: scope SYSTEM (IE 1), option samplingInterval (IE 34).
    b.put(1, 2)
        .put(18, 2)
        .put(260, 2)
        .put(4, 2)
        .put(4, 2)
        .put(1, 2)
        .put(4, 2)
        .put(34, 2)
        .put(4, 2);
    // Options data set 260: two 8-byte records with conflicting rates.
    b.put(260, 2)
        .put(20, 2) // length = 4 + 2*8
        .put(1, 4) // scope value
        .put(100, 4) // samplingInterval
        .put(1, 4) // scope value
        .put(200, 4); // samplingInterval (conflict)

    // Flow template 300 + one data record.
    b.put(0, 2)
        .put(16, 2)
        .put(300, 2)
        .put(2, 2)
        .put(1, 2)
        .put(4, 2)
        .put(2, 2)
        .put(4, 2);
    b.put(300, 2).put(12, 2).put(50, 4).put(2, 4);

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&b.buf).expect("parse ok"), 1);
    // The conflicting advertisements poisoned the domain bucket.
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::V9Domain(42),
            SamplerSelector::Domain
        ),
        None
    );

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));
    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    // Left unscaled (factor 1), not mis-scaled by either rate.
    assert_eq!(flows[0].bytes, 50);
    assert_eq!(flows[0].packets, 2);
}

#[test]
fn flow_with_an_unadvertised_sampler_is_not_scaled() {
    // A sampler is advertised for flowSamplerId 7, but the flow tags itself with
    // flowSamplerId 9, which has no known rate, so its counters are unscaled.
    let mut b = Builder::new();
    b.put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);

    // Options template 260: scope observationDomainId (IE 149), options
    // flowSamplerId (IE 48) + samplingInterval (IE 34).
    b.put(1, 2)
        .put(22, 2)
        .put(260, 2)
        .put(4, 2)
        .put(8, 2)
        .put(149, 2)
        .put(4, 2)
        .put(48, 2)
        .put(1, 2)
        .put(34, 2)
        .put(4, 2);
    b.put(260, 2).put(13, 2).put(42, 4).put(7, 1).put(100, 4);

    // Flow template 300: IN_BYTES, IN_PKTS, flowSamplerId.
    b.put(0, 2)
        .put(20, 2)
        .put(300, 2)
        .put(3, 2)
        .put(1, 2)
        .put(4, 2)
        .put(2, 2)
        .put(4, 2)
        .put(48, 2)
        .put(1, 2);
    // Data record tagged with the *unadvertised* flowSamplerId 9.
    b.put(300, 2).put(13, 2).put(50, 4).put(2, 4).put(9, 1);

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&b.buf).expect("parse ok"), 1);
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::V9Domain(42),
            SamplerSelector::FlowSampler(9)
        ),
        None
    );

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));
    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].bytes, 50);
    assert_eq!(flows[0].packets, 2);
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
fn ipfix_template_set_ids_are_ignored() {
    // NetFlow v9 does not use the IPFIX Set IDs 2 and 3. Neither may install a
    // template nor replace the one defined through FlowSet ID 0.
    let ipfix_options = [
        0x01, 0x04, 0x00, 0x02, 0x00, 0x01, // 260: 2 fields, 1 scope
        0x00, 0x95, 0x00, 0x04, // observationDomainId/4
        0x00, 0x22, 0x00, 0x04, // samplingInterval/4
    ];
    let ctx = FlowContext::new();
    let pkt = packet(
        v9_header(42),
        &[
            flowset(2, &template_record(256, &[(1, 8)])),
            flowset(256, &[0; 8]),
            flowset(3, &ipfix_options),
            flowset(260, &[0, 0, 0, 7, 0, 0, 0x03, 0xE8]),
        ],
    );
    assert_eq!(ctx.process_packet(&pkt), Ok(0));
    assert_eq!(ctx.active_templates(), 0);

    let pkt = packet(
        v9_header(42),
        &[
            flowset(0, &template_record(256, &[(1, 8)])),
            flowset(2, &template_record(256, &[(4, 4)])),
            flowset(256, &1500u64.to_be_bytes()),
        ],
    );
    assert_eq!(ctx.process_packet(&pkt), Ok(1));

    let stats = ctx.stats();
    assert_eq!(ctx.active_templates(), 1);
    assert_eq!(stats.templates_received, 1);
    assert_eq!(stats.options_templates_received, 0);
    assert_eq!(stats.options_records_processed, 0);
    assert_eq!(stats.malformed_packets, 0);
}

#[test]
fn truncated_flowset_stops_gracefully() {
    // The flowset claims length 100 but only a few body bytes follow; the walk
    // must stop without panicking or fabricating records, and the datagram must
    // be counted as malformed rather than silently succeeding.
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
    // Header was valid, so it counts as parsed, but the body was malformed.
    assert_eq!(ctx.stats().pkts_parsed, 1);
    assert_eq!(ctx.stats().malformed_packets, 1);
}

#[test]
fn partial_decode_keeps_records_before_a_malformed_set() {
    // A valid template + one valid data record, then a second data FlowSet whose
    // declared length overruns the datagram. Partial decoding keeps the good
    // record and flags the datagram as malformed instead of dropping everything.
    let mut b = Builder::new();
    b.put(9, 2) // version
        .put(3, 2) // count
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(1, 4) // sequence
        .put(42, 4); // source id

    // Template FlowSet: template 256 with SRC/DST/PROTO. Set length =
    // 4 (header) + 2 (template id) + 2 (field count) + 3 * 4 (field specs) = 20.
    b.put(0, 2) // template flowset id
        .put(20, 2) // length
        .put(256, 2) // template id
        .put(3, 2) // field count
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(4, 2)
        .put(1, 2); // PROTOCOL (1 byte)

    // Valid data FlowSet: one 9-byte record (4 + 9 = 13).
    b.put(256, 2)
        .put(13, 2)
        .put(0xC0A8_0001, 4) // 192.168.0.1
        .put(0x0808_0808, 4) // 8.8.8.8
        .put(6, 1); // proto = TCP

    // Second data FlowSet claims length 40 but only its 4-byte header follows.
    b.put(256, 2).put(40, 2);

    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("header parse ok");
    assert_eq!(processed, 1, "the record before the bad set is kept");
    assert_eq!(ctx.active_flows(), 1);
    assert_eq!(ctx.stats().malformed_packets, 1);
}

#[test]
fn resent_template_replaces_the_previous_definition() {
    // An exporter may redefine a template id with a new layout. Later data
    // records must be decoded against the new definition, not the old one.
    let ctx = FlowContext::new();

    // First definition: template 256 = SRC, DST, PROTO (9-byte record).
    let mut first = Builder::new();
    first
        .put(9, 2)
        .put(2, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);
    first
        .put(0, 2) // template flowset
        .put(20, 2) // length
        .put(256, 2)
        .put(3, 2)
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(4, 2)
        .put(1, 2); // PROTOCOL
    first
        .put(256, 2)
        .put(13, 2) // 4 + 9
        .put(0xC0A8_0001, 4)
        .put(0x0808_0808, 4)
        .put(6, 1);
    assert_eq!(ctx.process_packet(&first.buf), Ok(1));

    // Redefinition: template 256 = SRC, SRC_PORT (6-byte record). If the old
    // 9-byte definition were still used, the 6-byte data record would not decode.
    let mut second = Builder::new();
    second
        .put(9, 2)
        .put(2, 2)
        .put(1000, 4)
        .put(1_700_000_001, 4)
        .put(2, 4)
        .put(42, 4);
    second
        .put(0, 2) // template flowset
        .put(16, 2) // length = 4 + 2 + 2 + 2*4
        .put(256, 2)
        .put(2, 2)
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(7, 2)
        .put(2, 2); // SRC_PORT
    second
        .put(256, 2)
        .put(10, 2) // 4 + 6
        .put(0xC0A8_0002, 4)
        .put(1234, 2);

    assert_eq!(
        ctx.process_packet(&second.buf),
        Ok(1),
        "the new 6-byte template layout is used after redefinition"
    );
}

#[test]
fn rejected_template_set_stops_decoding_and_keeps_old_template() {
    // Regression: a template set that validly redefines a cached template but is
    // followed by an invalid record is rejected wholesale (template parsing is
    // transactional). Decoding must then STOP for the rest of the packet, or a
    // following data set gets decoded against the stale cached layout — e.g. an
    // old 4-byte template splitting one new 8-byte record into two bogus flows.
    let ctx = FlowContext::new();

    // Packet 1: cache template 256 as a single 4-byte IPV4_SRC field and send
    // one matching data record.
    let mut first = Builder::new();
    first
        .put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);
    first
        .put(0, 2) // template flowset
        .put(12, 2) // length = 4 + 2 + 2 + 4
        .put(256, 2)
        .put(1, 2)
        .put(8, 2)
        .put(4, 2); // IPV4_SRC (4 bytes)
    first
        .put(256, 2)
        .put(8, 2) // length = 4 + 4
        .put(0xC0A8_0001, 4);
    assert_eq!(ctx.process_packet(&first.buf), Ok(1));
    assert_eq!(ctx.active_flows(), 1);

    // Packet 2: a template set validly redefining 256 as an 8-byte layout, then
    // an invalid record (reserved id 100 defining a field). The whole set is
    // rejected, so 256 keeps its old 4-byte layout. A data set for 256 with one
    // new 8-byte record follows; the stale template must NOT decode it as two.
    let mut second = Builder::new();
    second
        .put(9, 2)
        .put(2, 2)
        .put(1000, 4)
        .put(1_700_000_001, 4)
        .put(2, 4)
        .put(42, 4);
    second
        .put(0, 2) // template flowset
        .put(24, 2) // length = 4 + 12 + 8
        .put(256, 2) // valid: redefine 256 with two 4-byte fields
        .put(2, 2)
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(100, 2) // invalid: reserved id (< 256) defining a field
        .put(1, 2)
        .put(8, 2)
        .put(4, 2);
    second
        .put(256, 2)
        .put(12, 2) // length = 4 + 8
        .put(0xC0A8_0002, 4)
        .put(0x0808_0808, 4);
    assert_eq!(
        ctx.process_packet(&second.buf),
        Ok(0),
        "decoding stops at the rejected template set; the stale 4-byte template \
         must not split the following 8-byte record into two"
    );
    assert_eq!(
        ctx.active_flows(),
        1,
        "no flow fabricated from the stale layout"
    );
    assert_eq!(ctx.stats().malformed_packets, 1);

    // Packet 3: the original 4-byte template is still usable, proving the
    // rejected set left the cached definition intact.
    let mut third = Builder::new();
    third
        .put(9, 2)
        .put(1, 2)
        .put(1000, 4)
        .put(1_700_000_002, 4)
        .put(3, 4)
        .put(42, 4);
    third.put(256, 2).put(8, 2).put(0xC0A8_0003, 4);
    assert_eq!(ctx.process_packet(&third.buf), Ok(1));
    assert_eq!(ctx.active_flows(), 2);
}

#[test]
fn trailing_truncated_flowset_header_is_counted_malformed() {
    // A well-formed datagram with 2 stray trailing bytes (an incomplete FlowSet
    // header) still decodes its records, but is flagged malformed rather than
    // silently succeeding.
    let mut packet = sample_v9_packet();
    packet.extend_from_slice(&[0x00, 0x01]);

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&packet), Ok(1));
    assert_eq!(ctx.stats().pkts_parsed, 1);
    assert_eq!(ctx.stats().malformed_packets, 1);
}

/// A v9 packet whose template (id 256) carries L2/QoS/ICMP metadata plus the
/// 5-tuple and counters. `include_dscp` toggles the ipClassOfService field so a
/// second packet can omit it, exercising the cache metadata merge.
fn metadata_v9_packet(include_dscp: bool) -> Vec<u8> {
    let mut b = Builder::new();
    b.put(9, 2)
        .put(2, 2)
        .put(1000, 4)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(42, 4);

    // Fields: bytes, packets, src, dst, sport, dport, proto, ingress, egress,
    // srcMac, dstMac, tcpFlags, vlan, [ipClassOfService].
    let mut fields: Vec<(u16, u16)> = vec![
        (1, 4),
        (2, 4),
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (10, 4),
        (14, 4),
        (56, 6),
        (80, 6),
        (6, 2),
        (58, 2),
    ];
    if include_dscp {
        fields.push((5, 1)); // ipClassOfService
    }
    let field_count = fields.len() as u64;
    let record_len: u64 = fields.iter().map(|(_, l)| *l as u64).sum();

    // Template FlowSet.
    b.put(0, 2)
        .put(4 + 4 + field_count * 4, 2)
        .put(256, 2)
        .put(field_count, 2);
    for (id, len) in &fields {
        b.put(*id as u64, 2).put(*len as u64, 2);
    }

    // Data FlowSet.
    b.put(256, 2).put(4 + record_len, 2);
    b.put(1500, 4) // bytes
        .put(10, 4) // packets
        .put(0xC0A8_010A, 4) // src
        .put(0x0A00_0005, 4) // dst
        .put(12345, 2) // sport
        .put(443, 2) // dport
        .put(6, 1) // proto
        .put(3, 4) // ingress
        .put(4, 4); // egress
    b.buf
        .extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src mac
    b.buf
        .extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst mac
    b.put(0x0018, 2) // tcp flags PSH+ACK
        .put(100, 2); // vlan
    if include_dscp {
        b.put(0b1011_1000, 1); // ToS 0xB8 -> DSCP 46
    }
    b.buf
}

#[test]
fn metadata_fields_survive_aggregation_and_flush() {
    use netflow_analyzer_core::records::presence;

    let ctx = FlowContext::new();
    // First packet carries DSCP, second omits it: the merge must retain DSCP.
    ctx.process_packet(&metadata_v9_packet(true)).expect("ok");
    ctx.process_packet(&metadata_v9_packet(false)).expect("ok");
    assert_eq!(ctx.active_flows(), 1, "same 5-tuple stays one flow");

    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    ctx.flush(move |rec| sink.lock().unwrap().push(rec.clone()));

    let flows = collected.lock().unwrap();
    assert_eq!(flows.len(), 1);
    let f = &flows[0];

    assert_eq!(f.bytes, 3000, "counters still accumulate");
    assert_eq!(f.packets, 20);
    assert_eq!(f.iface_in, 3);
    assert_eq!(f.iface_out, 4);
    assert_eq!(f.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(f.dst_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(f.tcp_flags, 0x18);
    assert_eq!(f.vlan_tag, 100);
    assert_eq!(f.dscp, 46, "DSCP from the first packet is retained");
    assert_eq!(f.ip_version, 4);

    let want = presence::IFACE_IN
        | presence::IFACE_OUT
        | presence::SRC_MAC
        | presence::DST_MAC
        | presence::TCP_FLAGS
        | presence::VLAN_TAG
        | presence::DSCP
        | presence::IP_VERSION;
    assert_eq!(f.present & want, want);

    let ffi = f.to_ffi();
    assert_eq!(ffi.dscp, 46);
    assert_eq!(ffi.iface_in, 3);
    assert_eq!(ffi.present, f.present);
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
    assert_eq!(ctx.active_flows(), 2);
}
