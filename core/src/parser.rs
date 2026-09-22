// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use nom::{
    number::complete::{be_u16, be_u32},
    IResult,
};

use crate::scope::Scope;

/// Supported versions of the NetFlow/IPFIX protocol
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    NetflowV5,
    NetflowV9,
    Ipfix,
}

/// Normalized structure for NetFlow v5 Headers (fixed-format, RFC-less legacy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetflowV5Header {
    /// Number of fixed-size flow records that follow the header.
    pub count: u16,
    pub system_uptime: u32,
    pub unix_seconds: u32,
    pub unix_nanos: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u16,
}

/// Normalized structure for NetFlow v9 Headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetflowV9Header {
    pub count: u16,
    pub system_uptime: u32,
    pub unix_seconds: u32,
    pub sequence_number: u32,
    pub source_id: u32,
}

/// Normalized structure for IPFIX Headers (RFC 7011)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfixHeader {
    pub total_length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
}

/// Unified Header Enum representing a parsed network packet header
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedHeader {
    V5(NetflowV5Header),
    V9(NetflowV9Header),
    Ipfix(IpfixHeader),
}

// --- Low-Level Nom Parsers ---

/// Parses a NetFlow v5 Header (22 bytes following the 2-byte version field).
fn parse_v5_header(input: &[u8]) -> IResult<&[u8], NetflowV5Header> {
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) = be_u32(input)?;
    let (input, unix_seconds) = be_u32(input)?;
    let (input, unix_nanos) = be_u32(input)?;
    let (input, flow_sequence) = be_u32(input)?;
    let (input, engine_type) = nom::number::complete::be_u8(input)?;
    let (input, engine_id) = nom::number::complete::be_u8(input)?;
    let (input, sampling_interval) = be_u16(input)?;

    Ok((
        input,
        NetflowV5Header {
            count,
            system_uptime,
            unix_seconds,
            unix_nanos,
            flow_sequence,
            engine_type,
            engine_id,
            sampling_interval,
        },
    ))
}

/// Parses a NetFlow v9 Header (20 bytes total, excluding version)
fn parse_v9_header(input: &[u8]) -> IResult<&[u8], NetflowV9Header> {
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) = be_u32(input)?;
    let (input, unix_seconds) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    Ok((
        input,
        NetflowV9Header {
            count,
            system_uptime,
            unix_seconds,
            sequence_number,
            source_id,
        },
    ))
}

/// Parses an IPFIX Header (16 bytes total, excluding version)
fn parse_ipfix_header(input: &[u8]) -> IResult<&[u8], IpfixHeader> {
    let (input, total_length) = be_u16(input)?;
    let (input, export_time) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, observation_domain_id) = be_u32(input)?;

    Ok((
        input,
        IpfixHeader {
            total_length,
            export_time,
            sequence_number,
            observation_domain_id,
        },
    ))
}

/// Master parser function that inspects the version string and routes processing
pub fn parse_packet_header(input: &[u8]) -> IResult<&[u8], ParsedHeader> {
    let (remaining_input, version) = be_u16(input)?;

    match version {
        5 => {
            let (payload, header) = parse_v5_header(remaining_input)?;
            Ok((payload, ParsedHeader::V5(header)))
        }
        9 => {
            let (payload, header) = parse_v9_header(remaining_input)?;
            Ok((payload, ParsedHeader::V9(header)))
        }
        10 => {
            let (payload, header) = parse_ipfix_header(remaining_input)?;
            Ok((payload, ParsedHeader::Ipfix(header)))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

impl ParsedHeader {
    /// Returns the observation domain identifier used to scope template lookups.
    /// NetFlow v9 uses the `source_id`; IPFIX uses the `observation_domain_id`.
    /// NetFlow v5 is template-less and has no domain, so it reports `0`.
    pub fn domain_id(&self) -> u32 {
        match self {
            ParsedHeader::V5(_) => 0,
            ParsedHeader::V9(h) => h.source_id,
            ParsedHeader::Ipfix(h) => h.observation_domain_id,
        }
    }

    /// Returns the protocol-tagged [`Scope`] used to key per-exporter state.
    ///
    /// Unlike [`Self::domain_id`], this keeps NetFlow v9, IPFIX, and NetFlow v5
    /// engine namespaces distinct so their identically numbered domains cannot
    /// collide within a single exporter. See `docs/exporter-identity.md`.
    pub fn scope(&self) -> Scope {
        match self {
            ParsedHeader::V5(h) => Scope::V5Engine {
                engine_type: h.engine_type,
                engine_id: h.engine_id,
            },
            ParsedHeader::V9(h) => Scope::V9Domain(h.source_id),
            ParsedHeader::Ipfix(h) => Scope::IpfixDomain(h.observation_domain_id),
        }
    }

    /// Export time normalized to nanoseconds since the Unix epoch.
    ///
    /// NetFlow v5 supplies a nanosecond remainder. NetFlow v9 and IPFIX only
    /// carry whole seconds in their headers, so their sub-second part is zero.
    pub fn export_time_ns(&self) -> u64 {
        const NS_PER_SECOND: u64 = 1_000_000_000;
        match self {
            ParsedHeader::V5(h) => (h.unix_seconds as u64)
                .saturating_mul(NS_PER_SECOND)
                .saturating_add(h.unix_nanos as u64),
            ParsedHeader::V9(h) => (h.unix_seconds as u64).saturating_mul(NS_PER_SECOND),
            ParsedHeader::Ipfix(h) => (h.export_time as u64).saturating_mul(NS_PER_SECOND),
        }
    }

    /// Exporter uptime in milliseconds, when the protocol header provides it.
    pub fn system_uptime_ms(&self) -> Option<u32> {
        match self {
            ParsedHeader::V5(h) => Some(h.system_uptime),
            ParsedHeader::V9(h) => Some(h.system_uptime),
            ParsedHeader::Ipfix(_) => None,
        }
    }
}

// --- FlowSet / Set Identifiers (RFC 3954 & RFC 7011) ---

/// NetFlow v9 Template FlowSet identifier.
pub const FLOWSET_ID_V9_TEMPLATE: u16 = 0;
/// NetFlow v9 Options Template FlowSet identifier.
pub const FLOWSET_ID_V9_OPTIONS: u16 = 1;
/// IPFIX Template Set identifier.
pub const SET_ID_IPFIX_TEMPLATE: u16 = 2;
/// IPFIX Options Template Set identifier.
pub const SET_ID_IPFIX_OPTIONS: u16 = 3;
/// Set identifiers at or above this value carry data records keyed by template id.
pub const FIRST_DATA_SET_ID: u16 = 256;

/// Fixed length, in bytes, of a single NetFlow v5 flow record.
pub const V5_RECORD_LEN: usize = 48;

/// Total IPFIX message header length in bytes (version, length, export time,
/// sequence number, observation domain id), per RFC 7011 §3.1. The message's
/// declared `total_length` includes this header.
pub const IPFIX_HEADER_LEN: usize = 16;

/// Sentinel field length signalling an IPFIX variable-length element.
pub const VARIABLE_LENGTH: u16 = 0xffff;

/// A single field specifier inside a template definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateField {
    /// Information element identifier (enterprise bit already stripped).
    pub type_id: u16,
    /// Declared field length in bytes, or `VARIABLE_LENGTH` for variable fields.
    pub length: u16,
    /// Private Enterprise Number when this is an enterprise-specific element.
    pub enterprise_number: Option<u32>,
}

/// A decoded template describing the layout of subsequent data records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub fields: Vec<TemplateField>,
    /// Sum of all fixed field lengths. `None` if the template contains any
    /// variable-length field (record size must then be computed per record).
    pub fixed_length: Option<usize>,
    /// `true` when this is an Options Template. Its data records carry exporter
    /// metadata (scoped options) rather than observed flows.
    pub is_options: bool,
    /// Number of leading fields that form the option scope. Zero for ordinary
    /// (non-options) templates.
    pub scope_field_count: u16,
}

impl TemplateRecord {
    fn fixed_length_of(fields: &[TemplateField]) -> Option<usize> {
        if fields.iter().any(|f| f.length == VARIABLE_LENGTH) {
            None
        } else {
            Some(fields.iter().map(|f| f.length as usize).sum())
        }
    }

    pub(crate) fn from_fields(template_id: u16, fields: Vec<TemplateField>) -> Self {
        let fixed_length = Self::fixed_length_of(&fields);
        Self {
            template_id,
            fields,
            fixed_length,
            is_options: false,
            scope_field_count: 0,
        }
    }

    /// Builds an Options Template. `scope_field_count` is the number of leading
    /// `fields` that form the scope; the remainder are the option fields. Both
    /// share the same on-wire layout, so decoding walks them uniformly.
    pub(crate) fn from_options_fields(
        template_id: u16,
        scope_field_count: u16,
        fields: Vec<TemplateField>,
    ) -> Self {
        let fixed_length = Self::fixed_length_of(&fields);
        Self {
            template_id,
            fields,
            fixed_length,
            is_options: true,
            scope_field_count,
        }
    }
}

/// Header that prefixes every FlowSet / Set in the packet payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowSetHeader {
    pub set_id: u16,
    pub length: u16,
}

/// Parses a 4-byte FlowSet header (set id + total length including the header).
pub fn parse_flowset_header(input: &[u8]) -> IResult<&[u8], FlowSetHeader> {
    let (input, set_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    Ok((input, FlowSetHeader { set_id, length }))
}

/// Parses a single field specifier, transparently handling the IPFIX
/// enterprise bit (`0x8000`) which prefixes a 4-byte Private Enterprise Number.
fn parse_field_specifier(input: &[u8]) -> IResult<&[u8], TemplateField> {
    let (input, raw_type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    if raw_type & 0x8000 != 0 {
        let (input, enterprise) = be_u32(input)?;
        Ok((
            input,
            TemplateField {
                type_id: raw_type & 0x7fff,
                length,
                enterprise_number: Some(enterprise),
            },
        ))
    } else {
        Ok((
            input,
            TemplateField {
                type_id: raw_type,
                length,
                enterprise_number: None,
            },
        ))
    }
}

/// Parses a single template record (template id, field count, field specifiers).
fn parse_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) = parse_field_specifiers(input, field_count as usize)?;
    Ok((input, TemplateRecord::from_fields(template_id, fields)))
}

/// Parses every template record contained within a template FlowSet body.
pub fn parse_template_set(mut body: &[u8]) -> IResult<&[u8], Vec<TemplateRecord>> {
    let mut templates = Vec::new();

    // Template sets may carry several template records back to back. Trailing
    // padding bytes (fewer than 4) are ignored.
    while body.len() >= 4 {
        let (rest, template) = parse_template_record(body)?;
        body = rest;
        templates.push(template);
    }

    Ok((body, templates))
}

/// Minimum on-wire size of a field specifier (2-byte type + 2-byte length).
/// Enterprise specifiers are larger (they add a 4-byte PEN), so this is only a
/// lower bound, used to reject an impossible `count` before allocating.
const FIELD_SPECIFIER_MIN_LEN: usize = 4;

/// Conservative upper bound on the number of field specifiers in a single
/// template. Real templates carry at most a few dozen fields; this caps the
/// per-template allocation from a hostile `field_count` far below what the
/// datagram size alone would permit.
pub const MAX_TEMPLATE_FIELDS: usize = 1024;

/// Reads `count` field specifiers into a fallibly pre-allocated vector.
///
/// The declared `count` is validated against a conservative cap *and* against
/// the bytes that actually remain **before** any allocation, so a hostile
/// `field_count` cannot drive a large reservation (or a chain of them across
/// many template records) before the fields are ever read.
fn parse_field_specifiers(mut input: &[u8], count: usize) -> IResult<&[u8], Vec<TemplateField>> {
    let too_large = count > MAX_TEMPLATE_FIELDS
        || count
            .checked_mul(FIELD_SPECIFIER_MIN_LEN)
            .is_none_or(|min_bytes| min_bytes > input.len());
    if too_large {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }

    let mut fields = Vec::new();
    if fields.try_reserve_exact(count).is_err() {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    for _ in 0..count {
        let (rest, field) = parse_field_specifier(input)?;
        input = rest;
        fields.push(field);
    }
    Ok((input, fields))
}

/// Parses a single NetFlow v9 Options Template record (RFC 3954 §6.1).
///
/// Layout: template id, option scope length (bytes), option length (bytes),
/// then the scope field specifiers followed by the option field specifiers.
/// The two length fields are byte counts; every v9 field specifier is 4 bytes.
fn parse_v9_options_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, scope_len_bytes) = be_u16(input)?;
    let (input, option_len_bytes) = be_u16(input)?;

    let scope_field_count = scope_len_bytes / 4;
    let option_field_count = option_len_bytes / 4;
    let total = scope_field_count as usize + option_field_count as usize;

    let (input, fields) = parse_field_specifiers(input, total)?;
    Ok((
        input,
        TemplateRecord::from_options_fields(template_id, scope_field_count, fields),
    ))
}

/// Parses every options-template record in a NetFlow v9 Options Template
/// FlowSet body (set id 1). Trailing alignment padding is ignored.
pub fn parse_v9_options_template_set(mut body: &[u8]) -> IResult<&[u8], Vec<TemplateRecord>> {
    let mut templates = Vec::new();
    // Minimum record is the 6-byte header (id + two length fields).
    while body.len() >= 6 {
        let (rest, template) = parse_v9_options_template_record(body)?;
        body = rest;
        templates.push(template);
    }
    Ok((body, templates))
}

/// Parses a single IPFIX Options Template record (RFC 7011 §3.4.2.2).
///
/// Layout: template id, total field count, scope field count, then that many
/// field specifiers (scope fields first). `field_count` includes the scope
/// fields, so exactly `field_count` specifiers follow.
fn parse_ipfix_options_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, scope_field_count) = be_u16(input)?;

    let (input, fields) = parse_field_specifiers(input, field_count as usize)?;
    Ok((
        input,
        TemplateRecord::from_options_fields(template_id, scope_field_count, fields),
    ))
}

/// Parses every options-template record in an IPFIX Options Template Set body
/// (set id 3). Trailing alignment padding is ignored.
pub fn parse_ipfix_options_template_set(mut body: &[u8]) -> IResult<&[u8], Vec<TemplateRecord>> {
    let mut templates = Vec::new();
    // Minimum record is the 6-byte header (id + two count fields).
    while body.len() >= 6 {
        let (rest, template) = parse_ipfix_options_template_record(body)?;
        body = rest;
        templates.push(template);
    }
    Ok((body, templates))
}

/// Splits a data FlowSet body into individual fixed-width record slices.
///
/// This is the zero-copy hot path: each returned element borrows directly from
/// the original packet buffer rather than copying record bytes onto the heap.
pub fn split_fixed_records(body: &[u8], record_len: usize) -> Vec<&[u8]> {
    if record_len == 0 {
        return Vec::new();
    }
    // `chunks_exact` discards trailing padding shorter than a full record.
    body.chunks_exact(record_len).collect()
}

#[cfg(test)]
mod tests;
