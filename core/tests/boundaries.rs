// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Table-driven boundary tests: header and FlowSet/Set length limits,
//! truncation, padding, unknown fields, multiple observation domains, and the
//! documented `PacketError` paths with their telemetry counters.

mod common;

use common::{
    flowset, ipfix_header, packet, sample_ipfix_packet, sample_v5_packet, sample_v9_packet,
    set_ipfix_total_length, template_record, v9_header, Builder,
};
use netflow_analyzer_core::records::FlowFields;
use netflow_analyzer_core::{FlowContext, PacketError};

/// IPV4_SRC, IPV4_DST, PROTOCOL: a 9-byte record layout.
const FIELDS: &[(u16, u16)] = &[(8, 4), (12, 4), (4, 1)];

fn record(src: u32, dst: u32, proto: u8) -> Vec<u8> {
    let mut b = Builder::new();
    b.put(src as u64, 4).put(dst as u64, 4).put(proto as u64, 1);
    b.buf
}

fn decode(ctx: &FlowContext, buf: &[u8]) -> (Result<usize, PacketError>, Vec<FlowFields>) {
    let mut out = Vec::new();
    let result = ctx.decode_packet(buf, &mut |_, fields| out.push(*fields));
    (result, out)
}

#[test]
fn v9_high_bit_field_ids_do_not_consume_enterprise_numbers() {
    let body = [vec![0; 12], vec![6]].concat();
    let buf = packet(
        v9_header(7),
        &[
            flowset(0, &template_record(256, &[(33000, 12), (4, 1)])),
            flowset(256, &body),
        ],
    );
    let ctx = FlowContext::new();
    let (result, records) = decode(&ctx, &buf);
    assert_eq!(result, Ok(1));
    assert_eq!(records[0].proto, 6);
    assert_eq!(ctx.stats().malformed_packets, 0);
}

#[test]
fn v9_record_count_distinguishes_short_records_from_padding() {
    for width in 1..=3 {
        for count in 1..=4 {
            let mut header = v9_header(7);
            header[2..4].copy_from_slice(&((count + 1) as u16).to_be_bytes());
            let mut body = vec![0; width * count];
            body[0] = 6;
            body.resize((body.len() + 3) & !3, 0);
            let mut fields = vec![(4, 1)];
            if width > 1 {
                fields.push((999, (width - 1) as u16));
            }
            let buf = packet(
                header,
                &[
                    flowset(0, &template_record(256, &fields)),
                    flowset(256, &body),
                ],
            );
            let ctx = FlowContext::new();
            let (result, records) = decode(&ctx, &buf);
            assert_eq!(result, Ok(count), "width {width}, count {count}");
            assert_eq!(records.len(), count);
            assert_eq!(ctx.stats().malformed_packets, 0);
        }
    }
}

#[test]
fn v9_short_sets_use_the_remaining_packet_record_count() {
    for (count, expected, malformed) in [(3u16, 2, 0), (4, 0, 1)] {
        let mut header = v9_header(7);
        header[2..4].copy_from_slice(&count.to_be_bytes());
        let buf = packet(
            header,
            &[
                flowset(0, &template_record(256, &[(4, 1)])),
                flowset(256, &[6, 0, 0, 0]),
                flowset(256, &[17, 0, 0, 0]),
            ],
        );
        let ctx = FlowContext::new();
        let (result, records) = decode(&ctx, &buf);
        assert_eq!(result, Ok(expected));
        assert_eq!(ctx.stats().malformed_packets, malformed);
        if malformed == 0 {
            assert_eq!(records.iter().map(|r| r.proto).collect::<Vec<_>>(), [6, 17]);
        }
    }
}

#[test]
fn v9_many_padded_short_sets_decode_once_each() {
    let mut header = v9_header(7);
    header[2..4].copy_from_slice(&8001u16.to_be_bytes());
    let mut sets = vec![flowset(0, &template_record(256, &[(4, 1)]))];
    sets.extend((0..8000).map(|_| flowset(256, &[6, 0, 0, 0])));
    let ctx = FlowContext::new();
    let (result, records) = decode(&ctx, &packet(header, &sets));
    assert_eq!(result, Ok(8000));
    assert!(records.iter().all(|r| r.proto == 6));
    assert_eq!(ctx.stats().malformed_packets, 0);
}

#[test]
fn v9_short_set_before_template_change_remains_ambiguous() {
    let mut header = v9_header(7);
    header[2..4].copy_from_slice(&4u16.to_be_bytes());
    let buf = packet(
        header,
        &[
            flowset(0, &template_record(256, &[(4, 1)])),
            flowset(256, &[6, 0, 0, 0]),
            flowset(0, &template_record(256, &[(4, 1)])),
            flowset(256, &[17, 0, 0, 0]),
        ],
    );
    let ctx = FlowContext::new();
    let (result, records) = decode(&ctx, &buf);
    assert_eq!(result, Ok(0));
    assert!(records.is_empty());
    assert_eq!(ctx.stats().malformed_packets, 1);
}

#[test]
fn v9_options_records_are_included_in_the_padding_budget() {
    let mut header = v9_header(7);
    header[2..4].copy_from_slice(&4u16.to_be_bytes());
    let options = [260, 4, 4, 1, 4, 34, 4]
        .iter()
        .flat_map(|v| (*v as u16).to_be_bytes())
        .collect::<Vec<_>>();
    let buf = packet(
        header,
        &[
            flowset(1, &options),
            flowset(260, &[0, 0, 0, 1, 0, 0, 0, 1]),
            flowset(0, &template_record(256, &[(4, 1)])),
            flowset(256, &[6, 0, 0, 0]),
        ],
    );
    let ctx = FlowContext::new();
    let (result, records) = decode(&ctx, &buf);
    assert_eq!(result, Ok(1));
    assert_eq!(records[0].proto, 6);
    assert_eq!(ctx.stats().options_records_processed, 1);
}

#[test]
fn every_truncated_header_is_rejected() {
    let cases: [(&str, Vec<u8>, usize); 3] = [
        ("v5", sample_v5_packet(&[]), 24),
        ("v9", sample_v9_packet(), 20),
        ("ipfix", sample_ipfix_packet(), 16),
    ];
    for (name, buf, header_len) in cases {
        for len in 0..header_len {
            let ctx = FlowContext::new();
            assert_eq!(
                ctx.process_packet(&buf[..len]),
                Err(PacketError::InvalidHeader),
                "{name} header truncated to {len} bytes"
            );
            let stats = ctx.stats();
            assert_eq!(stats.pkts_parse_error, 1, "{name} len {len}");
            assert_eq!(stats.pkts_parsed, 0, "{name} len {len}");
        }
    }
}

#[test]
fn header_only_packets_are_accepted_and_empty() {
    let mut ipfix = ipfix_header(1);
    set_ipfix_total_length(&mut ipfix);
    let cases = [
        ("v5", sample_v5_packet(&[])),
        ("v9", v9_header(1)),
        ("ipfix", ipfix),
    ];
    for (name, buf) in cases {
        let ctx = FlowContext::new();
        assert_eq!(ctx.process_packet(&buf), Ok(0), "{name}");
        let stats = ctx.stats();
        assert_eq!(stats.pkts_parsed, 1, "{name}");
        assert_eq!(stats.malformed_packets, 0, "{name}");
    }
}

#[test]
fn unsupported_versions_are_rejected() {
    for version in [0u16, 1, 4, 6, 7, 8, 11, 0xffff] {
        let mut buf = sample_v9_packet();
        buf[0..2].copy_from_slice(&version.to_be_bytes());
        let ctx = FlowContext::new();
        assert_eq!(
            ctx.process_packet(&buf),
            Err(PacketError::InvalidHeader),
            "version {version}"
        );
        assert_eq!(ctx.stats().pkts_parse_error, 1, "version {version}");
    }
}

#[test]
fn v9_flowset_length_boundaries() {
    let template = flowset(0, &template_record(256, FIELDS));
    let data = flowset(256, &record(0x0A00_0001, 0x0A00_0002, 6));

    // (case, trailing bytes after a valid template + data set, malformed?)
    let cases: [(&str, Vec<u8>, bool); 9] = [
        ("nothing", vec![], false),
        ("empty set", vec![0x01, 0x00, 0x00, 0x04], false),
        ("length 0", vec![0x01, 0x00, 0x00, 0x00], true),
        ("length 3", vec![0x01, 0x00, 0x00, 0x03], true),
        ("length overruns", vec![0x01, 0x00, 0x00, 0x09, 0xAA], true),
        ("1 stray byte", vec![0x00], true),
        ("3 stray bytes", vec![0x00, 0x00, 0x00], true),
        ("reserved id", flowset(4, &[1, 2, 3, 4]), false),
        ("max reserved id", flowset(255, &[]), false),
    ];
    for (name, trailer, malformed) in cases {
        let mut buf = packet(v9_header(1), &[template.clone(), data.clone()]);
        buf.extend_from_slice(&trailer);
        let ctx = FlowContext::new();
        let (result, records) = decode(&ctx, &buf);
        assert_eq!(result, Ok(1), "{name}: records before the trailer survive");
        assert_eq!(records.len(), 1, "{name}");
        assert_eq!(
            ctx.stats().malformed_packets,
            malformed as u64,
            "{name}: malformed flag"
        );
    }
}

#[test]
fn ipfix_total_length_boundaries() {
    let base = packet(
        ipfix_header(1),
        &[
            flowset(2, &template_record(300, FIELDS)),
            flowset(300, &record(1, 2, 17)),
        ],
    );
    let len = base.len() as u16;

    // (case, declared total_length, extra datagram bytes, expected result)
    type Expected = Result<usize, PacketError>;
    const BAD: Expected = Err(PacketError::InconsistentIpfixLength);
    let cases: [(&str, u16, &[u8], Expected); 8] = [
        ("exact", len, &[], Ok(1)),
        ("trailing ignored", len, &[0xFF; 5], Ok(1)),
        ("zero", 0, &[], BAD),
        ("below header", 15, &[], BAD),
        ("header only", 16, &[], Ok(0)),
        ("one past datagram", len + 1, &[], BAD),
        ("splits data set", len - 1, &[], BAD),
        ("short of one set", len - 13, &[0; 13], Ok(0)),
    ];
    for (name, total_length, extra, expected) in cases {
        let mut buf = base.clone();
        buf[2..4].copy_from_slice(&total_length.to_be_bytes());
        buf.extend_from_slice(extra);
        let ctx = FlowContext::new();
        assert_eq!(ctx.process_packet(&buf), expected, "{name}");
        let errors = expected.is_err() as u64;
        assert_eq!(ctx.stats().pkts_parse_error, errors, "{name}");
    }
}

#[test]
fn ipfix_set_length_below_header_is_inconsistent() {
    for set_len in 0u16..4 {
        let mut buf = packet(ipfix_header(1), &[vec![0, 4, 0, 0]]);
        buf[18..20].copy_from_slice(&set_len.to_be_bytes());
        let ctx = FlowContext::new();
        assert_eq!(
            ctx.process_packet(&buf),
            Err(PacketError::InconsistentIpfixLength),
            "set length {set_len}"
        );
    }
}

#[test]
fn padding_after_records_and_templates_is_ignored() {
    for pad in 0..4usize {
        let mut template_body = template_record(256, FIELDS);
        template_body.extend(std::iter::repeat_n(0, pad));
        let mut data_body = [record(1, 2, 6), record(3, 4, 17)].concat();
        // Padding shorter than one 9-byte record.
        data_body.extend(std::iter::repeat_n(0, pad * 2));

        let buf = packet(
            v9_header(1),
            &[flowset(0, &template_body), flowset(256, &data_body)],
        );
        let ctx = FlowContext::new();
        let (result, records) = decode(&ctx, &buf);
        assert_eq!(result, Ok(2), "pad {pad}");
        assert_eq!(records[1].proto, 17, "pad {pad}");
        let stats = ctx.stats();
        assert_eq!(stats.templates_received, 1, "pad {pad}");
        assert_eq!(stats.malformed_packets, 0, "pad {pad}");
    }
}

#[test]
fn unknown_fields_are_skipped_without_shifting_known_ones() {
    // Unknown standard IE 999 (3 bytes) between known fields.
    let v9_fields: &[(u16, u16)] = &[(8, 4), (999, 3), (12, 4), (4, 1)];
    let mut v9_data = record(0x0A00_0001, 0, 6);
    v9_data.splice(4..4, [0xEE; 3]);
    v9_data[7..11].copy_from_slice(&0x0A00_0002u32.to_be_bytes());
    let v9 = packet(
        v9_header(1),
        &[
            flowset(0, &template_record(256, v9_fields)),
            flowset(256, &v9_data),
        ],
    );

    // IPFIX enterprise-specific element (PEN 9) of length 2 before IPV4_SRC.
    let mut ipfix_template = Builder::new();
    ipfix_template
        .put(300, 2)
        .put(4, 2)
        .put(0x8000 | 1, 2)
        .put(2, 2)
        .put(9, 4);
    for &(type_id, length) in FIELDS {
        ipfix_template.put(type_id as u64, 2).put(length as u64, 2);
    }
    let ipfix_data = [vec![0xEE, 0xEE], record(0x0A00_0001, 0x0A00_0002, 6)].concat();
    let ipfix = packet(
        ipfix_header(1),
        &[flowset(2, &ipfix_template.buf), flowset(300, &ipfix_data)],
    );

    for (name, buf) in [("v9", v9), ("ipfix", ipfix)] {
        let ctx = FlowContext::new();
        let (result, records) = decode(&ctx, &buf);
        assert_eq!(result, Ok(1), "{name}");
        let fields = &records[0];
        assert_eq!(&fields.src_ip[12..16], &[10, 0, 0, 1], "{name}");
        assert_eq!(&fields.dst_ip[12..16], &[10, 0, 0, 2], "{name}");
        assert_eq!(fields.proto, 6, "{name}");
    }
}

#[test]
fn templates_are_scoped_to_their_observation_domain() {
    let ctx = FlowContext::new();
    let narrow: &[(u16, u16)] = &[(4, 1)];

    // Same template id 256, different layouts in v9 domains 1 and 2.
    let define = |domain, fields| {
        packet(
            v9_header(domain),
            &[flowset(0, &template_record(256, fields))],
        )
    };
    assert_eq!(ctx.process_packet(&define(1, FIELDS)), Ok(0));
    assert_eq!(ctx.process_packet(&define(2, narrow)), Ok(0));

    let data = |header: Vec<u8>, id| packet(header, &[flowset(id, &record(1, 2, 17))]);
    let cases: [(&str, Vec<u8>, usize, u8); 4] = [
        (
            "v9 domain 1 uses the 9-byte layout",
            data(v9_header(1), 256),
            1,
            17,
        ),
        (
            "v9 domain 2 uses the 1-byte layout",
            data(v9_header(2), 256),
            9,
            0,
        ),
        ("v9 domain 3 has no template", data(v9_header(3), 256), 0, 0),
        (
            "ipfix domain 1 is a distinct scope",
            data(ipfix_header(1), 256),
            0,
            0,
        ),
    ];
    for (name, buf, expected, first_proto) in cases {
        let (result, records) = decode(&ctx, &buf);
        assert_eq!(result, Ok(expected), "{name}");
        if let Some(first) = records.first() {
            assert_eq!(first.proto, first_proto, "{name}");
        }
    }
}

#[test]
fn rejected_template_sets_flag_the_packet_malformed() {
    let mut options_bad_scope = Builder::new();
    options_bad_scope
        .put(300, 2)
        .put(1, 2)
        .put(0, 2)
        .put(8, 2)
        .put(4, 2);
    let mut v9_options_odd = Builder::new();
    v9_options_odd.put(300, 2).put(3, 2).put(4, 2);
    v9_options_odd.buf.extend_from_slice(&[0; 7]);

    let cases: [(&str, Vec<u8>); 5] = [
        (
            "v9 reserved template id",
            packet(v9_header(1), &[flowset(0, &template_record(255, FIELDS))]),
        ),
        (
            "v9 fields overrun set",
            packet(v9_header(1), &[flowset(0, &[1, 0, 0, 9, 0, 8, 0, 4])]),
        ),
        (
            "v9 options odd scope length",
            packet(v9_header(1), &[flowset(1, &v9_options_odd.buf)]),
        ),
        (
            "ipfix reserved template id",
            packet(ipfix_header(1), &[flowset(2, &template_record(3, FIELDS))]),
        ),
        (
            "ipfix options zero scope",
            packet(ipfix_header(1), &[flowset(3, &options_bad_scope.buf)]),
        ),
    ];
    for (name, buf) in cases {
        let ctx = FlowContext::new();
        assert_eq!(ctx.process_packet(&buf), Ok(0), "{name}");
        let stats = ctx.stats();
        assert_eq!(stats.malformed_packets, 1, "{name}");
        assert_eq!(stats.templates_received, 0, "{name}");
        assert_eq!(stats.options_templates_received, 0, "{name}");
        assert_eq!(ctx.active_templates(), 0, "{name}");
    }
}

#[test]
fn packet_error_display_is_stable() {
    let cases = [
        (
            PacketError::InvalidHeader,
            "Failed to parse NetFlow header packet structure",
        ),
        (
            PacketError::InconsistentIpfixLength,
            "IPFIX message total_length is inconsistent with the datagram",
        ),
        (
            PacketError::ClockSkewExceeded,
            "Packet dropped because exporter clock skew exceeds limit",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}
