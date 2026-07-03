// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

#[test]
fn parses_v9_header_and_routes() {
    // version=9, count=1, uptime, secs, seq, source_id, then 2 trailing bytes
    let mut input = vec![0x00, 0x09, 0x00, 0x01];
    input.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // uptime 1000
    input.extend_from_slice(&[0x65, 0x00, 0x00, 0x00]); // secs
    input.extend_from_slice(&[0x00, 0x00, 0x00, 0x07]); // seq 7
    input.extend_from_slice(&[0x00, 0x00, 0x00, 0x2A]); // source id 42
    input.extend_from_slice(&[0xAA, 0xBB]); // payload remainder

    let (payload, header) = parse_packet_header(&input).unwrap();
    assert_eq!(payload, &[0xAA, 0xBB]);
    match &header {
        ParsedHeader::V9(h) => {
            assert_eq!(h.count, 1);
            assert_eq!(h.system_uptime, 1000);
            assert_eq!(h.sequence_number, 7);
            assert_eq!(h.source_id, 42);
        }
        other => panic!("expected v9, got {other:?}"),
    }
    assert_eq!(header.domain_id(), 42);
}

#[test]
fn parses_v5_header_and_routes() {
    let mut input = vec![0x00, 0x05, 0x00, 0x02]; // version 5, count 2
    input.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // uptime
    input.extend_from_slice(&[0x65, 0x00, 0x00, 0x00]); // unix secs
    input.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // unix nanos
    input.extend_from_slice(&[0x00, 0x00, 0x00, 0x0B]); // flow sequence
    input.push(0x01); // engine type
    input.push(0x02); // engine id
    input.extend_from_slice(&[0x00, 0x40]); // sampling interval
    input.extend_from_slice(&[0xAA]); // payload remainder

    let (payload, header) = parse_packet_header(&input).unwrap();
    assert_eq!(payload, &[0xAA]);
    match &header {
        ParsedHeader::V5(h) => {
            assert_eq!(h.count, 2);
            assert_eq!(h.flow_sequence, 11);
            assert_eq!(h.engine_type, 1);
            assert_eq!(h.engine_id, 2);
            assert_eq!(h.sampling_interval, 64);
            assert_eq!(header.export_time_ns(), 0x6500_0000_u64 * 1_000_000_000 + 1);
        }
        other => panic!("expected v5, got {other:?}"),
    }
    assert_eq!(header.domain_id(), 0);
}

#[test]
fn parses_ipfix_header_and_domain() {
    let mut input = vec![0x00, 0x0A]; // version 10
    input.extend_from_slice(&[0x00, 0x20]); // total length 32
    input.extend_from_slice(&[0x65, 0x00, 0x00, 0x00]); // export time
    input.extend_from_slice(&[0x00, 0x00, 0x00, 0x09]); // seq 9
    input.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // domain 256

    let (_payload, header) = parse_packet_header(&input).unwrap();
    match &header {
        ParsedHeader::Ipfix(h) => {
            assert_eq!(h.total_length, 32);
            assert_eq!(h.sequence_number, 9);
            assert_eq!(h.observation_domain_id, 256);
        }
        other => panic!("expected ipfix, got {other:?}"),
    }
    assert_eq!(header.domain_id(), 256);
}

#[test]
fn rejects_unknown_version() {
    let input = [0x00, 0x05, 0x00, 0x00];
    assert!(parse_packet_header(&input).is_err());
}

#[test]
fn truncated_header_errors() {
    // Only the version is present; the v9 body cannot be read.
    let input = [0x00, 0x09];
    assert!(parse_packet_header(&input).is_err());
}

#[test]
fn parses_flowset_header() {
    let input = [0x01, 0x00, 0x00, 0x18, 0xFF];
    let (rest, fs) = parse_flowset_header(&input).unwrap();
    assert_eq!(fs.set_id, 256);
    assert_eq!(fs.length, 24);
    assert_eq!(rest, &[0xFF]);
}

#[test]
fn field_specifier_handles_enterprise_bit() {
    // type 0x8001 (enterprise), length 4, PEN 9
    let input = [0x80, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09];
    let (rest, field) = parse_field_specifier(&input).unwrap();
    assert_eq!(field.type_id, 1); // enterprise bit stripped
    assert_eq!(field.length, 4);
    assert_eq!(field.enterprise_number, Some(9));
    assert!(rest.is_empty());
}

#[test]
fn field_specifier_standard_element() {
    let input = [0x00, 0x08, 0x00, 0x04];
    let (_rest, field) = parse_field_specifier(&input).unwrap();
    assert_eq!(field.type_id, 8);
    assert_eq!(field.length, 4);
    assert_eq!(field.enterprise_number, None);
}

#[test]
fn template_set_with_two_records() {
    let mut body = Vec::new();
    // template 256, 1 field
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04]);
    // template 257, 1 field
    body.extend_from_slice(&[0x01, 0x01, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x04]);

    let (_rest, templates) = parse_template_set(&body).unwrap();
    assert_eq!(templates.len(), 2);
    assert_eq!(templates[0].template_id, 256);
    assert_eq!(templates[0].fixed_length, Some(4));
    assert_eq!(templates[1].template_id, 257);
}

#[test]
fn variable_length_template_has_no_fixed_length() {
    let fields = vec![
        TemplateField {
            type_id: 8,
            length: 4,
            enterprise_number: None,
        },
        TemplateField {
            type_id: 12,
            length: VARIABLE_LENGTH,
            enterprise_number: None,
        },
    ];
    let tmpl = TemplateRecord::from_fields(900, fields);
    assert_eq!(tmpl.fixed_length, None);
}

#[test]
fn split_fixed_records_discards_padding() {
    let body = [1u8, 2, 3, 4, 5, 6, 7]; // 7 bytes, record_len 3 -> 2 records + 1 pad
    let records = split_fixed_records(&body, 3);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0], &[1, 2, 3]);
    assert_eq!(records[1], &[4, 5, 6]);
}

#[test]
fn split_fixed_records_zero_len_is_empty() {
    assert!(split_fixed_records(&[1, 2, 3], 0).is_empty());
}
