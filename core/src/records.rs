use std::time::Instant;

use crate::parser::{TemplateRecord, V5_RECORD_LEN, VARIABLE_LENGTH};

// --- IANA Information Element identifiers we normalize into the FlowRecord ---
// Reference: https://www.iana.org/assignments/ipfix/ipfix.xhtml
const IE_OCTET_DELTA_COUNT: u16 = 1;
const IE_PACKET_DELTA_COUNT: u16 = 2;
const IE_PROTOCOL_IDENTIFIER: u16 = 4;
const IE_SOURCE_TRANSPORT_PORT: u16 = 7;
const IE_SOURCE_IPV4_ADDRESS: u16 = 8;
const IE_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IE_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IE_SOURCE_IPV6_ADDRESS: u16 = 27;
const IE_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IE_OCTET_TOTAL_COUNT: u16 = 85;
const IE_PACKET_TOTAL_COUNT: u16 = 86;

/// Identity 5-tuple used to key the flow state cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Volatile values decoded from a single data record before they are folded
/// into the persistent `FlowRecord` state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowFields {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
}

impl FlowFields {
    pub fn key(&self) -> FlowKey {
        FlowKey {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            proto: self.proto,
        }
    }

    /// Decodes the relevant information elements from a single data-record
    /// slice using the supplied template layout.
    ///
    /// Returns `None` if the record is shorter than the template requires.
    /// Unknown elements are skipped, keeping the walk fully bounds-checked.
    pub fn from_record(template: &TemplateRecord, record: &[u8]) -> Option<Self> {
        Self::from_record_sized(template, record).map(|(fields, _)| fields)
    }

    /// Like [`from_record`], but also returns the number of bytes consumed.
    ///
    /// This is required when walking variable-length records back to back,
    /// where the record boundary is only known after decoding the layout.
    pub fn from_record_sized(template: &TemplateRecord, record: &[u8]) -> Option<(Self, usize)> {
        let mut fields = FlowFields::default();
        let mut offset: usize = 0;

        for field in &template.fields {
            // Resolve the on-wire length, honouring IPFIX variable-length encoding.
            let (value_offset, value_len) = if field.length == VARIABLE_LENGTH {
                let first = *record.get(offset)? as usize;
                if first < 255 {
                    (offset + 1, first)
                } else {
                    // 3-byte length form: 0xFF followed by a u16 length.
                    let hi = *record.get(offset + 1)? as usize;
                    let lo = *record.get(offset + 2)? as usize;
                    (offset + 3, (hi << 8) | lo)
                }
            } else {
                (offset, field.length as usize)
            };

            let end = value_offset.checked_add(value_len)?;
            let raw = record.get(value_offset..end)?;

            // Enterprise-specific elements share numeric ids with IANA ones, so
            // only interpret elements from the standard registry.
            if field.enterprise_number.is_none() {
                fields.apply_element(field.type_id, raw);
            }

            offset = end;
        }

        Some((fields, offset))
    }

    /// Decodes a single fixed-format NetFlow v5 flow record (48 bytes).
    ///
    /// Unlike v9/IPFIX, v5 has no templates: the field layout is hard-coded by
    /// the protocol. Returns `None` if the slice is shorter than one record.
    pub fn from_v5_record(record: &[u8]) -> Option<Self> {
        let record = record.get(..V5_RECORD_LEN)?;

        let mut fields = FlowFields::default();
        copy_ipv4(&mut fields.src_ip, &record[0..4]); // srcaddr
        copy_ipv4(&mut fields.dst_ip, &record[4..8]); // dstaddr
        fields.packets = read_be_uint(&record[16..20]); // dPkts
        fields.bytes = read_be_uint(&record[20..24]); // dOctets
        fields.src_port = read_be_u16(&record[32..34]); // srcport
        fields.dst_port = read_be_u16(&record[34..36]); // dstport
        fields.proto = record[38]; // prot
        Some(fields)
    }

    fn apply_element(&mut self, type_id: u16, raw: &[u8]) {
        match type_id {
            IE_SOURCE_IPV4_ADDRESS => copy_ipv4(&mut self.src_ip, raw),
            IE_DESTINATION_IPV4_ADDRESS => copy_ipv4(&mut self.dst_ip, raw),
            IE_SOURCE_IPV6_ADDRESS => copy_ipv6(&mut self.src_ip, raw),
            IE_DESTINATION_IPV6_ADDRESS => copy_ipv6(&mut self.dst_ip, raw),
            IE_SOURCE_TRANSPORT_PORT => self.src_port = read_be_u16(raw),
            IE_DESTINATION_TRANSPORT_PORT => self.dst_port = read_be_u16(raw),
            IE_PROTOCOL_IDENTIFIER => self.proto = raw.first().copied().unwrap_or(0),
            IE_OCTET_DELTA_COUNT | IE_OCTET_TOTAL_COUNT => self.bytes = read_be_uint(raw),
            IE_PACKET_DELTA_COUNT | IE_PACKET_TOTAL_COUNT => self.packets = read_be_uint(raw),
            _ => {}
        }
    }
}

/// Persistent per-flow state held in the cache between exported records.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
    pub first_switched: Instant,
    pub last_switched: Instant,
}

impl FlowRecord {
    pub fn from_fields(fields: &FlowFields, now: Instant) -> Self {
        Self {
            src_ip: fields.src_ip,
            dst_ip: fields.dst_ip,
            src_port: fields.src_port,
            dst_port: fields.dst_port,
            proto: fields.proto,
            bytes: fields.bytes,
            packets: fields.packets,
            first_switched: now,
            last_switched: now,
        }
    }
}

// A C-compatible representation to safely pass over the FFI boundary
#[repr(C)]
pub struct FlowRecordFFI {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
}

impl FlowRecord {
    pub fn to_ffi(&self) -> FlowRecordFFI {
        FlowRecordFFI {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            proto: self.proto,
            bytes: self.bytes,
            packets: self.packets,
        }
    }
}

// --- Bounds-checked big-endian readers ---

fn copy_ipv4(dst: &mut [u8; 16], raw: &[u8]) {
    if raw.len() >= 4 {
        // IPv4-mapped layout: store the 4 octets in the trailing slot.
        dst[12..16].copy_from_slice(&raw[..4]);
    }
}

fn copy_ipv6(dst: &mut [u8; 16], raw: &[u8]) {
    if raw.len() >= 16 {
        dst.copy_from_slice(&raw[..16]);
    }
}

fn read_be_u16(raw: &[u8]) -> u16 {
    match raw.len() {
        0 => 0,
        1 => raw[0] as u16,
        _ => u16::from_be_bytes([raw[0], raw[1]]),
    }
}

/// Reads a big-endian unsigned integer of 1..=8 bytes (IPFIX reduced-size encoding).
fn read_be_uint(raw: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for &byte in raw.iter().take(8) {
        value = (value << 8) | byte as u64;
    }
    value
}

#[cfg(test)]
mod tests;
