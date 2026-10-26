// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end tests for IPFIX (RFC 7011): Template Sets and Data Sets.

mod common;

use std::sync::{Arc, Mutex};

use common::{sample_ipfix_packet, set_ipfix_total_length, Builder};
use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::sampling::{SamplerSelector, SamplingRatio};
use netflow_analyzer_core::scope::{Scope, SINGLE_EXPORTER};
use netflow_analyzer_core::{FlowContext, PacketError};

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
        .put(0, 2) // total length (patched below)
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

    set_ipfix_total_length(&mut b.buf);
    let ctx = FlowContext::new();
    let processed = ctx.process_packet(&b.buf).expect("parse ok");

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
    // 1000/1 ratio for this exporter and observation domain (id 7). The record
    // carries no flowSamplerId/selectorId, so it is the domain-wide sampler.
    assert_eq!(ctx.active_samplers(), 1);
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::IpfixDomain(7),
            SamplerSelector::Domain
        ),
        Some(SamplingRatio {
            numerator: 1000,
            denominator: 1
        })
    );
}

#[test]
fn options_sampling_scales_ipfix_flow_counters() {
    // One IPFIX message that advertises a domain-wide 1-in-100 sampler (via an
    // options record) and then a flow whose byte/packet counters must be scaled
    // by that rate before it is cached.
    let mut b = Builder::new();
    b.put(10, 2) // version
        .put(0, 2) // total length (patched below)
        .put(1_700_000_000, 4) // export time
        .put(5, 4) // sequence
        .put(7, 4); // observation domain id

    // Options Template Set (set id 3): template 260, scope observationDomainId
    // (IE 149), option samplingInterval (IE 34).
    b.put(3, 2)
        .put(18, 2) // set length = 4 + 14
        .put(260, 2) // template id
        .put(2, 2) // total field count
        .put(1, 2) // scope field count
        .put(149, 2) // scope: observationDomainId
        .put(4, 2)
        .put(34, 2) // option: samplingInterval
        .put(4, 2);
    // Options Data Set (set id 260): domain 7, samplingInterval 100.
    b.put(260, 2).put(12, 2).put(7, 4).put(100, 4);

    // Flow Template Set (set id 2): template 300 with IN_BYTES, IN_PKTS, PROTOCOL.
    b.put(2, 2)
        .put(20, 2) // set length = 4 + 16
        .put(300, 2)
        .put(3, 2)
        .put(1, 2) // IN_BYTES
        .put(4, 2)
        .put(2, 2) // IN_PKTS
        .put(4, 2)
        .put(4, 2) // PROTOCOL
        .put(1, 2);
    // Flow Data Set (set id 300): 1500 bytes / 10 packets, proto 6.
    b.put(300, 2)
        .put(13, 2) // set length = 4 + 9
        .put(1500, 4)
        .put(10, 4)
        .put(6, 1);

    set_ipfix_total_length(&mut b.buf);
    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&b.buf).expect("parse ok"), 1);
    assert_eq!(
        ctx.sampler_ratio(
            SINGLE_EXPORTER,
            Scope::IpfixDomain(7),
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
    assert_eq!(flows[0].bytes, 150_000); // 1500 * 100
    assert_eq!(flows[0].packets, 1_000); // 10 * 100
    assert_eq!(flows[0].proto, 6);
}

/// An IPFIX message for domain 7 made of the given `(set id, body)` Sets.
fn ipfix_message(sets: &[(u16, &[u8])]) -> Vec<u8> {
    let mut b = Builder::new();
    b.put(10, 2)
        .put(0, 2)
        .put(1_700_000_000, 4)
        .put(1, 4)
        .put(7, 4);
    for &(set_id, body) in sets {
        b.put(set_id as u64, 2).put(4 + body.len() as u64, 2);
        b.buf.extend_from_slice(body);
    }
    set_ipfix_total_length(&mut b.buf);
    b.buf
}

#[test]
fn udp_template_withdrawals_are_ignored() {
    // RFC 7011 §8.4: a UDP collector must ignore Template Withdrawals. Both a
    // specific withdrawal and the "withdraw all" id (2) leave the cached
    // definition in place without consuming another slot.
    let template = [0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x08]; // 256: octetDeltaCount/8
    let data = 1500u64.to_be_bytes();
    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&ipfix_message(&[(2, &template)])), Ok(0));

    let withdrawals: [&[u8]; 2] = [&[0x01, 0x00, 0x00, 0x00], &[0x00, 0x02, 0x00, 0x00]];
    for withdrawal in withdrawals {
        let msg = ipfix_message(&[(2, withdrawal), (256, &data)]);
        assert_eq!(ctx.process_packet(&msg), Ok(1));
    }
    let stats = ctx.stats();
    assert_eq!(ctx.active_templates(), 1);
    assert_eq!(
        stats.templates_received, 1,
        "withdrawals are not definitions"
    );
    assert_eq!(stats.malformed_packets, 0);
}

#[test]
fn udp_options_template_withdrawals_are_ignored() {
    let template = [
        0x01, 0x04, 0x00, 0x02, 0x00, 0x01, // 260: 2 fields, 1 scope
        0x00, 0x95, 0x00, 0x04, // observationDomainId/4
        0x00, 0x22, 0x00, 0x04, // samplingInterval/4
    ];
    let data = [0, 0, 0, 7, 0, 0, 0x03, 0xE8];
    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&ipfix_message(&[(3, &template)])), Ok(0));

    // Options withdrawals are 4 bytes (RFC 7011 §8.1); several in one Set must
    // stay aligned rather than being misread as a 6-byte options header.
    let withdrawals = [
        0x01, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00,
    ];
    let msg = ipfix_message(&[(3, &withdrawals), (260, &data)]);
    assert_eq!(ctx.process_packet(&msg), Ok(0));

    let stats = ctx.stats();
    assert_eq!(ctx.active_templates(), 1);
    assert_eq!(stats.options_templates_received, 1);
    assert_eq!(stats.options_records_processed, 1);
    assert_eq!(stats.malformed_packets, 0);
}

#[test]
fn netflow_v9_template_set_ids_are_ignored() {
    // RFC 7011 §3.3.2: Set IDs 0 and 1 are not used by IPFIX. Neither may
    // install a template nor replace the one defined through Set ID 2.
    let template = [0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x08]; // 256: octetDeltaCount/8
    let v9_options = [
        0x01, 0x04, 0x00, 0x04, 0x00, 0x04, // 260: 4-byte scope, 4-byte options
        0x00, 0x01, 0x00, 0x04, // scope: System/4
        0x00, 0x22, 0x00, 0x04, // samplingInterval/4
    ];
    let options_data = [0, 0, 0, 7, 0, 0, 0x03, 0xE8];
    let ctx = FlowContext::new();
    let msg = ipfix_message(&[
        (0, &template),
        (256, &[0; 8]),
        (1, &v9_options),
        (260, &options_data),
    ]);
    assert_eq!(ctx.process_packet(&msg), Ok(0));
    assert_eq!(ctx.active_templates(), 0);

    let replacement = [0x01, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x04]; // 256: protocolIdentifier/4
    let msg = ipfix_message(&[
        (2, &template),
        (0, &replacement),
        (256, &1500u64.to_be_bytes()),
    ]);
    assert_eq!(ctx.process_packet(&msg), Ok(1));

    let stats = ctx.stats();
    assert_eq!(ctx.active_templates(), 1);
    assert_eq!(stats.templates_received, 1);
    assert_eq!(stats.options_templates_received, 0);
    assert_eq!(stats.options_records_processed, 0);
    assert_eq!(stats.malformed_packets, 0);
}

#[test]
fn trailing_bytes_beyond_total_length_are_ignored() {
    // Bytes past the declared message length must not be walked: appending
    // garbage after `total_length` leaves decoding unchanged.
    let mut packet = sample_ipfix_packet();
    packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]);

    let ctx = FlowContext::new();
    assert_eq!(ctx.process_packet(&packet), Ok(1));
    assert_eq!(ctx.stats().pkts_parsed, 1);
    assert_eq!(ctx.stats().pkts_parse_error, 0);
    assert_eq!(ctx.active_flows(), 1);
}

#[test]
fn total_length_claiming_more_than_datagram_is_rejected() {
    // A message whose declared `total_length` exceeds the received datagram is
    // truncated/inconsistent and must be rejected, not partially parsed.
    let mut packet = sample_ipfix_packet();
    let overstated = (packet.len() as u16) + 8;
    packet[2..4].copy_from_slice(&overstated.to_be_bytes());

    let ctx = FlowContext::new();
    assert_eq!(
        ctx.process_packet(&packet),
        Err(PacketError::InconsistentIpfixLength)
    );
    assert_eq!(
        ctx.stats().pkts_parsed,
        0,
        "an inconsistent message is not counted as parsed"
    );
    assert_eq!(ctx.stats().pkts_parse_error, 1);
    assert_eq!(ctx.active_flows(), 0);
}

#[test]
fn total_length_below_header_is_rejected() {
    // `total_length` smaller than the 16-byte IPFIX header is impossible.
    let mut packet = sample_ipfix_packet();
    packet[2..4].copy_from_slice(&8u16.to_be_bytes());

    let ctx = FlowContext::new();
    assert_eq!(
        ctx.process_packet(&packet),
        Err(PacketError::InconsistentIpfixLength)
    );
    assert_eq!(ctx.stats().pkts_parse_error, 1);
    assert_eq!(ctx.active_flows(), 0);
}

#[test]
fn total_length_that_truncates_a_set_is_rejected() {
    // total_length = 40 covers the template set (20) plus only the 4-byte data
    // Set header, cutting off the data Set body. That Set overruns the declared
    // message, so the whole message is rejected.
    let mut packet = sample_ipfix_packet();
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());

    let ctx = FlowContext::new();
    assert_eq!(
        ctx.process_packet(&packet),
        Err(PacketError::InconsistentIpfixLength)
    );
    assert_eq!(ctx.stats().pkts_parsed, 0);
    assert_eq!(ctx.stats().pkts_parse_error, 1);
    assert_eq!(ctx.active_flows(), 0);
}

#[test]
fn total_length_can_shorten_the_walk() {
    // A declared length shorter than the datagram must bound the walk: here it
    // covers only the template set (header 16 + template 20 = 36), so the data
    // set that follows is not decoded.
    let mut packet = sample_ipfix_packet();
    packet[2..4].copy_from_slice(&36u16.to_be_bytes());

    let ctx = FlowContext::new();
    assert_eq!(
        ctx.process_packet(&packet),
        Ok(0),
        "data set is beyond total_length"
    );
    assert_eq!(ctx.stats().pkts_parsed, 1);
    assert_eq!(ctx.active_flows(), 0);
}
