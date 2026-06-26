use nom::{
    number::complete::{be_u16, be_u32},
    IResult,
};

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
}

impl TemplateRecord {
    pub(crate) fn from_fields(template_id: u16, fields: Vec<TemplateField>) -> Self {
        let fixed_length = if fields.iter().any(|f| f.length == VARIABLE_LENGTH) {
            None
        } else {
            Some(fields.iter().map(|f| f.length as usize).sum())
        };
        Self {
            template_id,
            fields,
            fixed_length,
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
    let (mut input, template_id) = be_u16(input)?;
    let (rest, field_count) = be_u16(input)?;
    input = rest;

    let mut fields = Vec::new();
    // Bounded pre-allocation: avoid an implicit grow for the common case while
    // refusing to honour an absurd field count from a malicious exporter.
    let _ = fields.try_reserve(field_count as usize);

    for _ in 0..field_count {
        let (rest, field) = parse_field_specifier(input)?;
        input = rest;
        fields.push(field);
    }

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
