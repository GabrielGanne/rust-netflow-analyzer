// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use crate::parser::{TemplateField, TemplateRecord};
use crate::scope::SINGLE_EXPORTER;

fn field(type_id: u16, length: u16) -> TemplateField {
    TemplateField {
        type_id,
        length,
        enterprise_number: None,
    }
}

fn tuple_template() -> TemplateRecord {
    TemplateRecord::from_fields(
        256,
        vec![
            field(IE_OCTET_DELTA_COUNT, 4),
            field(IE_PACKET_DELTA_COUNT, 4),
            field(IE_SOURCE_IPV4_ADDRESS, 4),
            field(IE_DESTINATION_IPV4_ADDRESS, 4),
            field(IE_SOURCE_TRANSPORT_PORT, 2),
            field(IE_DESTINATION_TRANSPORT_PORT, 2),
            field(IE_PROTOCOL_IDENTIFIER, 1),
        ],
    )
}

#[test]
fn read_be_uint_handles_reduced_sizes() {
    assert_eq!(read_be_uint(&[]), 0);
    assert_eq!(read_be_uint(&[0x05]), 5);
    assert_eq!(read_be_uint(&[0x01, 0x00]), 256);
    assert_eq!(read_be_uint(&[0x00, 0x00, 0x05, 0xDC]), 1500);
    // More than 8 bytes is truncated to the first 8.
    assert_eq!(
        read_be_uint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        u64::MAX
    );
}

#[test]
fn read_be_u16_handles_short_input() {
    assert_eq!(read_be_u16(&[]), 0);
    assert_eq!(read_be_u16(&[0x01]), 1);
    assert_eq!(read_be_u16(&[0x01, 0x02]), 0x0102);
}

#[test]
fn copy_ipv4_uses_mapped_layout() {
    let mut dst = [0u8; 16];
    copy_ipv4(&mut dst, &[192, 168, 0, 1]);
    assert_eq!(&dst[12..16], &[192, 168, 0, 1]);
    assert!(dst[..12].iter().all(|&b| b == 0));
}

#[test]
fn copy_ipv6_fills_all_bytes() {
    let mut dst = [0u8; 16];
    let addr: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    copy_ipv6(&mut dst, &addr);
    assert_eq!(dst, addr);
}

#[test]
fn copy_helpers_ignore_short_input() {
    let mut dst = [7u8; 16];
    copy_ipv4(&mut dst, &[1, 2, 3]); // too short, unchanged
    copy_ipv6(&mut dst, &[1, 2, 3]); // too short, unchanged
    assert_eq!(dst, [7u8; 16]);
}

#[test]
fn from_record_decodes_full_tuple() {
    let tmpl = tuple_template();
    let mut rec = Vec::new();
    rec.extend_from_slice(&[0x00, 0x00, 0x05, 0xDC]); // bytes 1500
    rec.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]); // packets 10
    rec.extend_from_slice(&[192, 168, 1, 10]); // src
    rec.extend_from_slice(&[10, 0, 0, 5]); // dst
    rec.extend_from_slice(&[0x30, 0x39]); // 12345
    rec.extend_from_slice(&[0x01, 0xBB]); // 443
    rec.push(6); // proto

    let (fields, consumed) = FlowFields::from_record_sized(&tmpl, &rec).unwrap();
    assert_eq!(consumed, 21);
    assert_eq!(fields.bytes, 1500);
    assert_eq!(fields.packets, 10);
    assert_eq!(&fields.src_ip[12..16], &[192, 168, 1, 10]);
    assert_eq!(&fields.dst_ip[12..16], &[10, 0, 0, 5]);
    assert_eq!(fields.src_port, 12345);
    assert_eq!(fields.dst_port, 443);
    assert_eq!(fields.proto, 6);
    assert!(matches!(
        fields.key(SINGLE_EXPORTER, Scope::V9Domain(0)).identity,
        FlowIdentity::FiveTuple { proto: 6, .. }
    ));
}

#[test]
fn from_record_prefers_flow_id_for_identity() {
    let tmpl = TemplateRecord::from_fields(
        257,
        vec![
            field(IE_FLOW_ID, 8),
            field(IE_SOURCE_IPV4_ADDRESS, 4),
            field(IE_DESTINATION_IPV4_ADDRESS, 4),
        ],
    );
    let mut rec = 0x0102_0304_0506_0708_u64.to_be_bytes().to_vec();
    rec.extend_from_slice(&[192, 0, 2, 1]);
    rec.extend_from_slice(&[198, 51, 100, 2]);

    let fields = FlowFields::from_record(&tmpl, &rec).unwrap();
    assert_eq!(fields.flow_id, Some(0x0102_0304_0506_0708));
    assert_eq!(
        fields.key(SINGLE_EXPORTER, Scope::V9Domain(42)),
        FlowKey {
            exporter: SINGLE_EXPORTER,
            scope: Scope::V9Domain(42),
            identity: FlowIdentity::FlowId(0x0102_0304_0506_0708),
        }
    );
}

#[test]
fn zero_flow_id_is_present_and_used_as_identity() {
    let tmpl = TemplateRecord::from_fields(258, vec![field(IE_FLOW_ID, 8)]);
    let fields = FlowFields::from_record(&tmpl, &[0; 8]).unwrap();

    assert_eq!(fields.flow_id, Some(0));
    assert!(matches!(
        fields.key(SINGLE_EXPORTER, Scope::V9Domain(0)).identity,
        FlowIdentity::FlowId(0)
    ));
}

#[test]
fn from_record_rejects_truncated_input() {
    let tmpl = tuple_template();
    let short = [0u8; 10]; // template needs 21 bytes
    assert!(FlowFields::from_record(&tmpl, &short).is_none());
}

#[test]
fn from_record_skips_unknown_and_enterprise_elements() {
    let tmpl = TemplateRecord::from_fields(
        300,
        vec![
            field(9999, 2), // unknown element -> skipped
            TemplateField {
                type_id: IE_PROTOCOL_IDENTIFIER,
                length: 1,
                enterprise_number: Some(42), // enterprise -> not interpreted
            },
            field(IE_SOURCE_TRANSPORT_PORT, 2),
        ],
    );
    let rec = [0xAA, 0xBB, 0x11, 0x04, 0xD2];
    let fields = FlowFields::from_record(&tmpl, &rec).unwrap();
    assert_eq!(fields.proto, 0, "enterprise proto must be ignored");
    assert_eq!(fields.src_port, 1234);
}

#[test]
fn from_record_handles_variable_length_short_form() {
    // One variable-length field (len prefix < 255) followed by a port.
    let tmpl = TemplateRecord::from_fields(
        400,
        vec![
            field(IE_SOURCE_IPV6_ADDRESS, VARIABLE_LENGTH),
            field(IE_SOURCE_TRANSPORT_PORT, 2),
        ],
    );
    let mut rec = vec![16]; // length prefix = 16
    let addr: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
    ];
    rec.extend_from_slice(&addr);
    rec.extend_from_slice(&[0x00, 0x50]); // port 80

    let (fields, consumed) = FlowFields::from_record_sized(&tmpl, &rec).unwrap();
    assert_eq!(consumed, 1 + 16 + 2);
    assert_eq!(fields.src_ip, addr);
    assert_eq!(fields.src_port, 80);
}

#[test]
fn from_record_handles_variable_length_long_form() {
    // 3-byte length form: 0xFF, then u16 length.
    let tmpl =
        TemplateRecord::from_fields(401, vec![field(IE_SOURCE_IPV6_ADDRESS, VARIABLE_LENGTH)]);
    let mut rec = vec![0xFF, 0x00, 16]; // long form, length = 16
    let addr: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    rec.extend_from_slice(&addr);

    let (fields, consumed) = FlowFields::from_record_sized(&tmpl, &rec).unwrap();
    assert_eq!(consumed, 3 + 16);
    assert_eq!(fields.src_ip, addr);
}

#[test]
fn total_counters_are_recognized() {
    let tmpl = TemplateRecord::from_fields(
        500,
        vec![
            field(IE_OCTET_TOTAL_COUNT, 4),
            field(IE_PACKET_TOTAL_COUNT, 4),
        ],
    );
    let rec = [0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02];
    let fields = FlowFields::from_record(&tmpl, &rec).unwrap();
    assert_eq!(fields.bytes, 100);
    assert_eq!(fields.packets, 2);
}

/// Builds a single 48-byte NetFlow v5 record with the given 5-tuple.
fn v5_record(
    src: [u8; 4],
    dst: [u8; 4],
    packets: u32,
    octets: u32,
    sport: u16,
    dport: u16,
    proto: u8,
) -> [u8; 48] {
    let mut r = [0u8; 48];
    r[0..4].copy_from_slice(&src);
    r[4..8].copy_from_slice(&dst);
    r[16..20].copy_from_slice(&packets.to_be_bytes());
    r[20..24].copy_from_slice(&octets.to_be_bytes());
    r[32..34].copy_from_slice(&sport.to_be_bytes());
    r[34..36].copy_from_slice(&dport.to_be_bytes());
    r[38] = proto;
    r
}

#[test]
fn from_v5_record_decodes_fields() {
    let rec = v5_record([192, 168, 1, 1], [8, 8, 4, 4], 7, 980, 53, 5353, 17);
    let fields = FlowFields::from_v5_record(&rec).unwrap();
    assert_eq!(&fields.src_ip[12..16], &[192, 168, 1, 1]);
    assert_eq!(&fields.dst_ip[12..16], &[8, 8, 4, 4]);
    assert_eq!(fields.packets, 7);
    assert_eq!(fields.bytes, 980);
    assert_eq!(fields.src_port, 53);
    assert_eq!(fields.dst_port, 5353);
    assert_eq!(fields.proto, 17);
}

#[test]
fn from_v5_record_rejects_short_input() {
    assert!(FlowFields::from_v5_record(&[0u8; 47]).is_none());
}

#[test]
fn flow_record_round_trips_to_ffi() {
    let fields = FlowFields {
        flow_id: Some(42),
        src_ip: [1u8; 16],
        dst_ip: [2u8; 16],
        src_port: 1,
        dst_port: 2,
        proto: 17,
        bytes: 9,
        packets: 3,
        start_time_ns: 1_700_000_000_123_456_789,
        end_time_ns: 1_700_000_001_987_654_321,
        original_start_time_ns: 1_700_000_000_123_456_789,
        original_end_time_ns: 1_700_000_001_987_654_321,
        iface_in: 7,
        iface_out: 8,
        src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        icmp_type: 3,
        icmp_code: 1,
        tcp_flags: 0x18,
        dscp: 46,
        vlan_tag: 100,
        ip_version: 4,
        present: presence::FLOW_ID | presence::IFACE_IN | presence::DSCP,
        sampler: SamplerSelector::Domain,
        total_bytes: None,
        total_packets: None,
    };
    let record = FlowRecord::from_fields(&fields, SINGLE_EXPORTER, Scope::IpfixDomain(9), 0);
    assert_eq!(record.fields, fields);
    assert_eq!(record.flow_id, Some(42));
    let ffi = record.to_ffi();
    assert_eq!(ffi.exporter_key, 0);
    assert_eq!(ffi.exporter_key_hi, 0);
    assert_eq!(ffi.scope_protocol, crate::scope::SCOPE_PROTOCOL_IPFIX);
    assert_eq!(ffi.observation_domain, 9);
    assert_eq!(ffi.src_ip, [1u8; 16]);
    assert_eq!(ffi.dst_ip, [2u8; 16]);
    assert_eq!(ffi.proto, 17);
    assert_eq!(ffi.bytes, 9);
    assert_eq!(ffi.packets, 3);
    assert_eq!(ffi.start_time_ns, 1_700_000_000_123_456_789);
    assert_eq!(ffi.end_time_ns, 1_700_000_001_987_654_321);
    assert_eq!(ffi.original_start_time_ns, 1_700_000_000_123_456_789);
    assert_eq!(ffi.original_end_time_ns, 1_700_000_001_987_654_321);
    assert_eq!(ffi.flow_id, 42);
    assert_eq!(ffi.iface_in, 7);
    assert_eq!(ffi.iface_out, 8);
    assert_eq!(ffi.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(ffi.dst_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(ffi.icmp_type, 3);
    assert_eq!(ffi.icmp_code, 1);
    assert_eq!(ffi.tcp_flags, 0x18);
    assert_eq!(ffi.dscp, 46);
    assert_eq!(ffi.vlan_tag, 100);
    assert_eq!(ffi.ip_version, 4);
    assert_eq!(ffi.present, fields.present);
}

#[test]
fn from_record_decodes_l2_qos_and_icmp_metadata() {
    let tmpl = TemplateRecord::from_fields(
        700,
        vec![
            field(IE_INGRESS_INTERFACE, 4),
            field(IE_EGRESS_INTERFACE, 4),
            field(IE_SOURCE_MAC_ADDRESS, 6),
            field(IE_DESTINATION_MAC_ADDRESS, 6),
            field(IE_IP_CLASS_OF_SERVICE, 1),
            field(IE_TCP_CONTROL_BITS, 2),
            field(IE_VLAN_ID, 2),
            field(IE_ICMP_TYPE_CODE_IPV4, 2),
            field(IE_SOURCE_IPV4_ADDRESS, 4),
        ],
    );
    let mut rec = Vec::new();
    rec.extend_from_slice(&5u32.to_be_bytes()); // ingress
    rec.extend_from_slice(&9u32.to_be_bytes()); // egress
    rec.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src mac
    rec.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst mac
    rec.push(0b1011_1000); // ToS 0xB8 -> DSCP 46 (EF)
    rec.extend_from_slice(&0x0018u16.to_be_bytes()); // tcp flags PSH+ACK
    rec.extend_from_slice(&100u16.to_be_bytes()); // vlan
    rec.extend_from_slice(&0x0301u16.to_be_bytes()); // icmp type 3, code 1
    rec.extend_from_slice(&[192, 0, 2, 1]); // src ipv4

    let fields = FlowFields::from_record(&tmpl, &rec).unwrap();
    assert_eq!(fields.iface_in, 5);
    assert_eq!(fields.iface_out, 9);
    assert_eq!(fields.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(fields.dst_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(fields.dscp, 46);
    assert_eq!(fields.tcp_flags, 0x18);
    assert_eq!(fields.vlan_tag, 100);
    assert_eq!(fields.icmp_type, 3);
    assert_eq!(fields.icmp_code, 1);
    assert_eq!(fields.ip_version, 4);

    let expected = presence::IFACE_IN
        | presence::IFACE_OUT
        | presence::SRC_MAC
        | presence::DST_MAC
        | presence::DSCP
        | presence::TCP_FLAGS
        | presence::VLAN_TAG
        | presence::ICMP_TYPE
        | presence::ICMP_CODE
        | presence::IP_VERSION
        | presence::SRC_IP;
    assert_eq!(fields.present, expected);
}

#[test]
fn ip_class_of_service_takes_precedence_over_post_variant() {
    // Regardless of field order, ipClassOfService wins over postIpClassOfService.
    let tmpl = TemplateRecord::from_fields(
        701,
        vec![
            field(IE_POST_IP_CLASS_OF_SERVICE, 1),
            field(IE_IP_CLASS_OF_SERVICE, 1),
        ],
    );
    let rec = [0b0001_0000, 0b1011_1000]; // post -> DSCP 4, real -> DSCP 46
    let fields = FlowFields::from_record(&tmpl, &rec).unwrap();
    assert_eq!(fields.dscp, 46);
    assert_eq!(fields.present & presence::DSCP, presence::DSCP);
}

#[test]
fn diffserv_code_points_are_decoded_unshifted() {
    // ipDiffServCodePoint (195) carries the 6-bit DSCP directly and wins over
    // postIpDiffServCodePoint (98) regardless of field order.
    let tmpl = TemplateRecord::from_fields(
        702,
        vec![
            field(IE_POST_IP_DIFF_SERV_CODE_POINT, 1),
            field(IE_IP_DIFF_SERV_CODE_POINT, 1),
        ],
    );
    let fields = FlowFields::from_record(&tmpl, &[46, 20]).unwrap();
    assert_eq!(fields.dscp, 20);

    // Alone, the post code point is taken as-is (not shifted like a ToS byte).
    let tmpl = TemplateRecord::from_fields(703, vec![field(IE_POST_IP_DIFF_SERV_CODE_POINT, 1)]);
    let fields = FlowFields::from_record(&tmpl, &[46]).unwrap();
    assert_eq!(fields.dscp, 46);
    assert_eq!(fields.present & presence::DSCP, presence::DSCP);
}

#[test]
fn resolves_delta_microsecond_timestamps_before_export_time() {
    let tmpl = TemplateRecord::from_fields(
        704,
        vec![
            field(IE_FLOW_START_DELTA_MICROSECONDS, 4),
            field(IE_FLOW_END_DELTA_MICROSECONDS, 4),
        ],
    );
    let mut rec = Vec::new();
    rec.extend_from_slice(&2_000_u32.to_be_bytes());
    rec.extend_from_slice(&1_000_u32.to_be_bytes());
    let ctx = RecordTimeContext {
        original_export_time_ns: 1_700_000_000_000_000_000,
        effective_export_time_ns: 1_700_000_000_000_000_000,
        system_uptime_ms: None,
    };
    let (fields, _) = FlowFields::from_record_sized_at(&tmpl, &rec, Some(ctx)).unwrap();
    assert_eq!(fields.start_time_ns, 1_699_999_999_998_000_000);
    assert_eq!(fields.end_time_ns, 1_699_999_999_999_000_000);
    let both = presence::START_TIME | presence::END_TIME;
    assert_eq!(fields.present & both, both);
}

#[test]
fn absent_metadata_leaves_presence_bits_clear() {
    // The plain 5-tuple template exports none of the optional metadata.
    let fields = FlowFields::from_record(&tuple_template(), &{
        let mut rec = Vec::new();
        rec.extend_from_slice(&1500u32.to_be_bytes());
        rec.extend_from_slice(&10u32.to_be_bytes());
        rec.extend_from_slice(&[192, 168, 1, 10]);
        rec.extend_from_slice(&[10, 0, 0, 5]);
        rec.extend_from_slice(&12345u16.to_be_bytes());
        rec.extend_from_slice(&443u16.to_be_bytes());
        rec.push(6);
        rec
    })
    .unwrap();

    // Only the 5-tuple and IP-version bits are set; no metadata, no timestamps.
    assert_eq!(
        fields.present,
        presence::IP_VERSION
            | presence::SRC_IP
            | presence::DST_IP
            | presence::SRC_PORT
            | presence::DST_PORT
            | presence::PROTO
    );
    assert_eq!(fields.tcp_flags, 0);
    assert_eq!(fields.present & presence::TCP_FLAGS, 0, "zero != present");
}

#[test]
fn v5_record_populates_structural_metadata() {
    let mut rec = v5_record([192, 168, 1, 1], [8, 8, 4, 4], 7, 980, 53, 5353, 6);
    rec[12..14].copy_from_slice(&3u16.to_be_bytes()); // input iface
    rec[14..16].copy_from_slice(&4u16.to_be_bytes()); // output iface
    rec[37] = 0x12; // tcp flags SYN+ACK
    rec[39] = 0b1011_1000; // ToS 0xB8 -> DSCP 46

    let fields = FlowFields::from_v5_record(&rec).unwrap();
    assert_eq!(fields.iface_in, 3);
    assert_eq!(fields.iface_out, 4);
    assert_eq!(fields.tcp_flags, 0x12);
    assert_eq!(fields.dscp, 46);
    assert_eq!(fields.ip_version, 4);
    let expected = presence::IFACE_IN
        | presence::IFACE_OUT
        | presence::TCP_FLAGS
        | presence::DSCP
        | presence::IP_VERSION
        | presence::SRC_IP
        | presence::DST_IP
        | presence::PROTO
        | presence::SRC_PORT
        | presence::DST_PORT;
    assert_eq!(fields.present, expected);
}

#[test]
fn resolves_uptime_timestamps_to_unix_nanoseconds() {
    let tmpl = TemplateRecord::from_fields(
        600,
        vec![
            field(IE_FLOW_START_SYS_UP_TIME, 4),
            field(IE_FLOW_END_SYS_UP_TIME, 4),
        ],
    );
    let mut rec = Vec::new();
    rec.extend_from_slice(&9_000_u32.to_be_bytes());
    rec.extend_from_slice(&9_750_u32.to_be_bytes());
    let context = RecordTimeContext {
        original_export_time_ns: 1_700_000_000_123_456_789,
        effective_export_time_ns: 1_700_000_000_123_456_789,
        system_uptime_ms: Some(10_000),
    };

    let (fields, _) = FlowFields::from_record_sized_at(&tmpl, &rec, Some(context)).unwrap();
    assert_eq!(fields.start_time_ns, 1_699_999_999_123_456_789);
    assert_eq!(fields.end_time_ns, 1_699_999_999_873_456_789);
}

#[test]
fn normalizes_all_ipfix_absolute_time_units() {
    let seconds = 1_700_000_000_u64;
    let unix_ns = seconds * NS_PER_SECOND + 123_456_788;
    let ntp_seconds = seconds + NTP_UNIX_EPOCH_OFFSET;
    let fraction = ((123_456_789_u128 << 32) / NS_PER_SECOND as u128) as u64;
    let ntp = (ntp_seconds << 32) | fraction;

    let tmpl = TemplateRecord::from_fields(
        601,
        vec![
            field(IE_FLOW_START_SECONDS, 4),
            field(IE_FLOW_END_MILLISECONDS, 8),
            field(IE_FLOW_START_NANOSECONDS, 8),
            field(IE_FLOW_END_MICROSECONDS, 8),
        ],
    );
    let mut rec = Vec::new();
    rec.extend_from_slice(&(seconds as u32).to_be_bytes());
    rec.extend_from_slice(&(seconds * 1_000 + 987).to_be_bytes());
    rec.extend_from_slice(&ntp.to_be_bytes());
    rec.extend_from_slice(&ntp.to_be_bytes());
    let context = RecordTimeContext {
        original_export_time_ns: seconds * NS_PER_SECOND,
        effective_export_time_ns: seconds * NS_PER_SECOND,
        system_uptime_ms: None,
    };

    let (fields, _) = FlowFields::from_record_sized_at(&tmpl, &rec, Some(context)).unwrap();
    // The later elements win; binary NTP fractions are rounded down to ns.
    assert_eq!(fields.start_time_ns, unix_ns);
    assert_eq!(fields.end_time_ns, unix_ns);
}

#[test]
fn v5_timestamps_preserve_header_nanoseconds() {
    let mut rec = v5_record([1, 2, 3, 4], [5, 6, 7, 8], 1, 2, 3, 4, 6);
    rec[24..28].copy_from_slice(&4_000_u32.to_be_bytes());
    rec[28..32].copy_from_slice(&4_999_u32.to_be_bytes());
    let context = RecordTimeContext {
        original_export_time_ns: 1_700_000_000_987_654_321,
        effective_export_time_ns: 1_700_000_000_987_654_321,
        system_uptime_ms: Some(5_000),
    };

    let fields = FlowFields::from_v5_record_at(&rec, Some(context)).unwrap();
    assert_eq!(fields.start_time_ns, 1_699_999_999_987_654_321);
    assert_eq!(fields.end_time_ns, 1_700_000_000_986_654_321);
}

/// An options template with one 4-byte scope field (`observationDomainId`, IE
/// 149) followed by `options`.
fn options_template(options: &[TemplateField]) -> TemplateRecord {
    let mut fields = vec![field(149, 4)];
    fields.extend_from_slice(options);
    TemplateRecord::from_options_fields(260, 1, fields)
}

fn ratio(numerator: u64, denominator: u64) -> SamplingRatio {
    SamplingRatio {
        numerator,
        denominator,
    }
}

#[test]
fn sampling_prefers_ie34_over_ie50_and_305() {
    // Scope + samplingPacketInterval/Space (305/306) + samplerRandomInterval (50)
    // + samplingInterval (34); IE 34 wins.
    let template = options_template(&[
        field(IE_SAMPLING_PACKET_INTERVAL, 4),
        field(IE_SAMPLING_PACKET_SPACE, 4),
        field(IE_SAMPLER_RANDOM_INTERVAL, 4),
        field(IE_SAMPLING_INTERVAL, 4),
    ]);
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes()); // scope value (observationDomainId)
    record.extend_from_slice(&1u32.to_be_bytes()); // samplingPacketInterval
    record.extend_from_slice(&99u32.to_be_bytes()); // samplingPacketSpace
    record.extend_from_slice(&512u32.to_be_bytes()); // samplerRandomInterval
    record.extend_from_slice(&1000u32.to_be_bytes()); // samplingInterval

    let observation = sampling_from_options_record(&template, &record).unwrap();
    assert_eq!(observation.ratio, ratio(1000, 1));
    // The record carries no flowSamplerId/selectorId, so it is the domain sampler.
    assert_eq!(observation.selector, SamplerSelector::Domain);
}

#[test]
fn sampler_random_interval_is_ie50() {
    let template = options_template(&[field(IE_SAMPLER_RANDOM_INTERVAL, 2)]);
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes());
    record.extend_from_slice(&256u16.to_be_bytes());
    assert_eq!(
        sampling_from_options_record(&template, &record).map(|o| o.ratio),
        Some(ratio(256, 1))
    );
}

#[test]
fn count_based_sampling_ratio_keeps_interval_and_space() {
    // 1 packet kept then 999 skipped per cycle => 1000/1.
    let template = options_template(&[
        field(IE_SAMPLING_PACKET_INTERVAL, 4),
        field(IE_SAMPLING_PACKET_SPACE, 4),
    ]);
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes());
    record.extend_from_slice(&1u32.to_be_bytes());
    record.extend_from_slice(&999u32.to_be_bytes());
    assert_eq!(
        sampling_from_options_record(&template, &record).map(|o| o.ratio),
        Some(ratio(1000, 1))
    );

    // 2 kept then 9 skipped per cycle => 11/2 (kept exact rather than truncated).
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes());
    record.extend_from_slice(&2u32.to_be_bytes());
    record.extend_from_slice(&9u32.to_be_bytes());
    assert_eq!(
        sampling_from_options_record(&template, &record).map(|o| o.ratio),
        Some(ratio(11, 2))
    );
}

#[test]
fn count_based_sampling_requires_both_interval_and_space() {
    // samplingPacketInterval (IE 305) alone is ambiguous without the space, so
    // it is not treated as a sampling advertisement.
    let template = options_template(&[field(IE_SAMPLING_PACKET_INTERVAL, 4)]);
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes());
    record.extend_from_slice(&2u32.to_be_bytes());
    assert_eq!(sampling_from_options_record(&template, &record), None);
}

#[test]
fn sampler_id_option_field_disambiguates_a_shared_scope() {
    // Two records under the same (observationDomainId) scope but different
    // flowSamplerId (IE 48) values must select distinct samplers.
    let template =
        options_template(&[field(IE_FLOW_SAMPLER_ID, 1), field(IE_SAMPLING_INTERVAL, 4)]);
    let build = |sampler_id: u8, interval: u32| {
        let mut record = 7u32.to_be_bytes().to_vec();
        record.push(sampler_id);
        record.extend_from_slice(&interval.to_be_bytes());
        sampling_from_options_record(&template, &record).unwrap()
    };

    let first = build(1, 100);
    let second = build(2, 200);
    assert_eq!(first.selector, SamplerSelector::FlowSampler(1));
    assert_eq!(second.selector, SamplerSelector::FlowSampler(2));
    assert_ne!(first.selector, second.selector);
    assert_eq!(first.ratio, ratio(100, 1));
    assert_eq!(second.ratio, ratio(200, 1));
}

#[test]
fn selector_id_takes_precedence_over_flow_sampler_id() {
    // A record carrying both IE 302 and IE 48 resolves to the selectorId, and a
    // flow decoded the same way (below) agrees, so the two match.
    let template = options_template(&[
        field(IE_FLOW_SAMPLER_ID, 4),
        field(IE_SELECTOR_ID, 4),
        field(IE_SAMPLING_INTERVAL, 4),
    ]);
    let mut record = 7u32.to_be_bytes().to_vec();
    record.extend_from_slice(&5u32.to_be_bytes()); // flowSamplerId
    record.extend_from_slice(&9u32.to_be_bytes()); // selectorId
    record.extend_from_slice(&1000u32.to_be_bytes());
    let observation = sampling_from_options_record(&template, &record).unwrap();
    assert_eq!(observation.selector, SamplerSelector::Selector(9));
}

#[test]
fn unmatched_scoped_rate_is_rejected() {
    // An interface-scoped rate (IPFIX ingressInterface, IE 10; NetFlow v9
    // scope type 2) without a selector cannot be matched to a flow, so it must
    // not be treated as the domain-wide rate.
    for scope_type in [10u16, 2] {
        let template = TemplateRecord::from_options_fields(
            260,
            1,
            vec![field(scope_type, 4), field(IE_SAMPLING_INTERVAL, 4)],
        );
        let mut record = 3u32.to_be_bytes().to_vec();
        record.extend_from_slice(&1000u32.to_be_bytes());
        assert_eq!(sampling_from_options_record(&template, &record), None);
    }
}

#[test]
fn domain_level_scopes_yield_the_domain_sampler() {
    // NetFlow v9 System scope (type 1) and IPFIX process/exporter scopes are
    // domain-wide.
    for scope_type in [1u16, 130, 143, 144, 149] {
        let template = TemplateRecord::from_options_fields(
            260,
            1,
            vec![field(scope_type, 4), field(IE_SAMPLING_INTERVAL, 4)],
        );
        let mut record = 3u32.to_be_bytes().to_vec();
        record.extend_from_slice(&1000u32.to_be_bytes());
        let observation = sampling_from_options_record(&template, &record).unwrap();
        assert_eq!(observation.selector, SamplerSelector::Domain);
    }
}

#[test]
fn selector_makes_a_finer_scope_attributable() {
    // An interface-scoped record that also carries a flowSamplerId is matched
    // by that sampler, so it is kept.
    let template = TemplateRecord::from_options_fields(
        260,
        1,
        vec![
            field(10, 4),
            field(IE_FLOW_SAMPLER_ID, 1),
            field(IE_SAMPLING_INTERVAL, 4),
        ],
    );
    let mut record = 3u32.to_be_bytes().to_vec();
    record.push(5);
    record.extend_from_slice(&1000u32.to_be_bytes());
    let observation = sampling_from_options_record(&template, &record).unwrap();
    assert_eq!(observation.selector, SamplerSelector::FlowSampler(5));
}

#[test]
fn flow_record_decodes_its_sampler_selector() {
    // A flow record's flowSamplerId (IE 48) is captured so it can be matched to
    // its sampler; selectorId (IE 302) wins when both are present.
    let sampled = TemplateRecord::from_fields(
        256,
        vec![field(IE_OCTET_DELTA_COUNT, 4), field(IE_FLOW_SAMPLER_ID, 1)],
    );
    let mut record = 1500u32.to_be_bytes().to_vec();
    record.push(3);
    let (fields, _) = FlowFields::from_record_sized(&sampled, &record).unwrap();
    assert_eq!(fields.sampler, SamplerSelector::FlowSampler(3));

    let both = TemplateRecord::from_fields(
        256,
        vec![field(IE_FLOW_SAMPLER_ID, 1), field(IE_SELECTOR_ID, 2)],
    );
    let (fields, _) = FlowFields::from_record_sized(&both, &[3, 0, 9]).unwrap();
    assert_eq!(fields.sampler, SamplerSelector::Selector(9));
}

#[test]
fn sampling_ignores_enterprise_zero_and_short_records() {
    // A zero interval carries no scaling information and is rejected.
    let zero = options_template(&[field(IE_SAMPLING_INTERVAL, 4)]);
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes());
    record.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(sampling_from_options_record(&zero, &record), None);

    // An enterprise-specific element that merely reuses id 34 is not IANA IE 34.
    let enterprise_field = TemplateField {
        type_id: IE_SAMPLING_INTERVAL,
        length: 4,
        enterprise_number: Some(9),
    };
    let enterprise = options_template(&[enterprise_field]);
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_be_bytes());
    record.extend_from_slice(&1000u32.to_be_bytes());
    assert_eq!(sampling_from_options_record(&enterprise, &record), None);

    // A record shorter than the template requires yields nothing.
    let template = options_template(&[field(IE_SAMPLING_INTERVAL, 4)]);
    assert_eq!(
        sampling_from_options_record(&template, &[0, 0, 0, 7, 0, 0]),
        None
    );
}
