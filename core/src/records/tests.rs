use super::*;
use crate::parser::{TemplateField, TemplateRecord};

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
    assert!(matches!(fields.key(), FlowKey::FiveTuple { proto: 6, .. }));
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
        fields.key_in_domain(42),
        FlowKey::FlowId {
            observation_domain_id: 42,
            flow_id: 0x0102_0304_0506_0708,
        }
    );
}

#[test]
fn zero_flow_id_is_present_and_used_as_identity() {
    let tmpl = TemplateRecord::from_fields(258, vec![field(IE_FLOW_ID, 8)]);
    let fields = FlowFields::from_record(&tmpl, &[0; 8]).unwrap();

    assert_eq!(fields.flow_id, Some(0));
    assert!(matches!(fields.key(), FlowKey::FlowId { flow_id: 0, .. }));
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
    use std::time::Instant;
    let fields = FlowFields {
        flow_id: None,
        src_ip: [1u8; 16],
        dst_ip: [2u8; 16],
        src_port: 1,
        dst_port: 2,
        proto: 17,
        bytes: 9,
        packets: 3,
    };
    let record = FlowRecord::from_fields(&fields, Instant::now());
    let ffi = record.to_ffi();
    assert_eq!(ffi.src_ip, [1u8; 16]);
    assert_eq!(ffi.dst_ip, [2u8; 16]);
    assert_eq!(ffi.proto, 17);
    assert_eq!(ffi.bytes, 9);
    assert_eq!(ffi.packets, 3);
}
