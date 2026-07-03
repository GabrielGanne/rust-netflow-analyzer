// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};
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
const IE_FLOW_ID: u16 = 148;
const IE_FLOW_END_SYS_UP_TIME: u16 = 21;
const IE_FLOW_START_SYS_UP_TIME: u16 = 22;
const IE_FLOW_START_SECONDS: u16 = 150;
const IE_FLOW_END_SECONDS: u16 = 151;
const IE_FLOW_START_MILLISECONDS: u16 = 152;
const IE_FLOW_END_MILLISECONDS: u16 = 153;
const IE_FLOW_START_MICROSECONDS: u16 = 154;
const IE_FLOW_END_MICROSECONDS: u16 = 155;
const IE_FLOW_START_NANOSECONDS: u16 = 156;
const IE_FLOW_END_NANOSECONDS: u16 = 157;

const NS_PER_SECOND: u64 = 1_000_000_000;
const NS_PER_MILLISECOND: u64 = 1_000_000;
const NTP_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;
const NTP_ERA_SECONDS: u64 = 1_u64 << 32;

/// Packet-level clock values used to resolve relative exporter timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordTimeContext {
    /// Unmodified timestamp supplied by the exporter.
    pub original_export_time_ns: u64,
    /// Export timestamp after optional receipt-time fallback.
    pub effective_export_time_ns: u64,
    pub system_uptime_ms: Option<u32>,
}

impl RecordTimeContext {
    fn adjust_to_effective_clock(self, timestamp_ns: u64) -> u64 {
        if self.effective_export_time_ns >= self.original_export_time_ns {
            timestamp_ns
                .saturating_add(self.effective_export_time_ns - self.original_export_time_ns)
        } else {
            timestamp_ns
                .saturating_sub(self.original_export_time_ns - self.effective_export_time_ns)
        }
    }
}

/// Identity used to key the flow state cache.
///
/// An exported IPFIX `flowId` takes precedence over the 5-tuple. Flow IDs are
/// scoped to their observation domain, as required by the IPFIX registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKey {
    FlowId {
        observation_domain_id: u32,
        flow_id: u64,
    },
    FiveTuple {
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        proto: u8,
    },
}

/// Normalized values decoded from a single exported data record.
///
/// A copy of these fields is retained by [`FlowRecord`] while the flow is in
/// the cache. Keeping the normalized data in one type avoids maintaining two
/// parallel representations of the addresses, ports, protocol, and counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowFields {
    /// Exporter-assigned flow identity (IPFIX information element 148).
    pub flow_id: Option<u64>,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
    /// Effective flow start time in Unix nanoseconds, corrected when fallback is used.
    pub start_time_ns: u64,
    /// Effective flow end time in Unix nanoseconds, corrected when fallback is used.
    pub end_time_ns: u64,
    /// Unmodified exporter-derived flow start time.
    pub original_start_time_ns: u64,
    /// Unmodified exporter-derived flow end time.
    pub original_end_time_ns: u64,
}

impl FlowFields {
    /// Builds a cache key for callers without an observation domain (notably
    /// NetFlow v5). Prefer [`Self::key_in_domain`] for v9/IPFIX records.
    pub fn key(&self) -> FlowKey {
        self.key_in_domain(0)
    }

    /// Builds the flow identity, preferring `flowId` when the exporter supplied
    /// it and falling back to the traditional 5-tuple otherwise.
    pub fn key_in_domain(&self, observation_domain_id: u32) -> FlowKey {
        match self.flow_id {
            Some(flow_id) => FlowKey::FlowId {
                observation_domain_id,
                flow_id,
            },
            None => FlowKey::FiveTuple {
                src_ip: self.src_ip,
                dst_ip: self.dst_ip,
                src_port: self.src_port,
                dst_port: self.dst_port,
                proto: self.proto,
            },
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
        Self::from_record_sized_at(template, record, None)
    }

    /// Decodes a record and resolves all supported timestamp encodings to Unix
    /// nanoseconds. Missing flow timestamps fall back to the packet export time.
    pub fn from_record_sized_at(
        template: &TemplateRecord,
        record: &[u8],
        time_context: Option<RecordTimeContext>,
    ) -> Option<(Self, usize)> {
        let mut fields = FlowFields::default();
        let mut timestamps = DecodedTimestamps::default();
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
            if field.enterprise_number.is_none() && !timestamps.apply_element(field.type_id, raw) {
                fields.apply_element(field.type_id, raw);
            }

            offset = end;
        }

        let fallback = time_context
            .map(|ctx| ctx.original_export_time_ns)
            .unwrap_or(0);
        fields.original_start_time_ns = timestamps.resolve_start(time_context).unwrap_or(fallback);
        fields.original_end_time_ns = timestamps.resolve_end(time_context).unwrap_or(fallback);
        fields.start_time_ns = time_context
            .map(|ctx| ctx.adjust_to_effective_clock(fields.original_start_time_ns))
            .unwrap_or(fields.original_start_time_ns);
        fields.end_time_ns = time_context
            .map(|ctx| ctx.adjust_to_effective_clock(fields.original_end_time_ns))
            .unwrap_or(fields.original_end_time_ns);

        Some((fields, offset))
    }

    /// Decodes a single fixed-format NetFlow v5 flow record (48 bytes).
    ///
    /// Unlike v9/IPFIX, v5 has no templates: the field layout is hard-coded by
    /// the protocol. Returns `None` if the slice is shorter than one record.
    pub fn from_v5_record(record: &[u8]) -> Option<Self> {
        Self::from_v5_record_at(record, None)
    }

    /// Decodes a NetFlow v5 record and converts its millisecond uptime stamps
    /// to Unix nanoseconds using the packet header clock.
    pub fn from_v5_record_at(
        record: &[u8],
        time_context: Option<RecordTimeContext>,
    ) -> Option<Self> {
        let record = record.get(..V5_RECORD_LEN)?;

        let mut fields = FlowFields::default();
        copy_ipv4(&mut fields.src_ip, &record[0..4]); // srcaddr
        copy_ipv4(&mut fields.dst_ip, &record[4..8]); // dstaddr
        fields.packets = read_be_uint(&record[16..20]); // dPkts
        fields.bytes = read_be_uint(&record[20..24]); // dOctets
        let first_ms = u32::from_be_bytes(record[24..28].try_into().ok()?);
        let last_ms = u32::from_be_bytes(record[28..32].try_into().ok()?);
        fields.src_port = read_be_u16(&record[32..34]); // srcport
        fields.dst_port = read_be_u16(&record[34..36]); // dstport
        fields.proto = record[38]; // prot
        if let Some(ctx) = time_context {
            fields.original_start_time_ns = uptime_timestamp_ns(ctx, first_ms);
            fields.original_end_time_ns = uptime_timestamp_ns(ctx, last_ms);
            fields.start_time_ns = ctx.adjust_to_effective_clock(fields.original_start_time_ns);
            fields.end_time_ns = ctx.adjust_to_effective_clock(fields.original_end_time_ns);
        }
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
            IE_FLOW_ID => self.flow_id = Some(read_be_uint(raw)),
            _ => {}
        }
    }
}

/// Persistent per-flow state held in the cache between exported records.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// The normalized flow data accumulated by the cache.
    pub fields: FlowFields,
    pub(crate) first_observed: Instant,
    pub(crate) last_observed: Instant,
}

impl FlowRecord {
    pub fn from_fields(fields: &FlowFields, now: Instant) -> Self {
        Self {
            fields: *fields,
            first_observed: now,
            last_observed: now,
        }
    }
}

/// Preserve the convenient `record.src_ip` / `record.bytes` API while storing
/// the normalized flow values in a single shared representation.
impl Deref for FlowRecord {
    type Target = FlowFields;

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl DerefMut for FlowRecord {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.fields
    }
}

// A C-compatible representation to safely pass over the FFI boundary
#[repr(C)]
pub struct NetflowAnalyzerFlowRecord {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
    /// Effective flow start time as Unix epoch nanoseconds.
    pub start_time_ns: u64,
    /// Effective flow end time as Unix epoch nanoseconds.
    pub end_time_ns: u64,
    /// Unmodified exporter-derived flow start time.
    pub original_start_time_ns: u64,
    /// Unmodified exporter-derived flow end time.
    pub original_end_time_ns: u64,
}

impl FlowFields {
    /// Projects the normalized flow values into the C-compatible record shape.
    pub fn to_ffi(&self) -> NetflowAnalyzerFlowRecord {
        NetflowAnalyzerFlowRecord {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            proto: self.proto,
            bytes: self.bytes,
            packets: self.packets,
            start_time_ns: self.start_time_ns,
            end_time_ns: self.end_time_ns,
            original_start_time_ns: self.original_start_time_ns,
            original_end_time_ns: self.original_end_time_ns,
        }
    }
}

impl FlowRecord {
    pub fn to_ffi(&self) -> NetflowAnalyzerFlowRecord {
        self.fields.to_ffi()
    }
}

#[derive(Default)]
struct DecodedTimestamps {
    start_absolute_ns: Option<u64>,
    end_absolute_ns: Option<u64>,
    start_precision: u8,
    end_precision: u8,
    start_uptime_ms: Option<u32>,
    end_uptime_ms: Option<u32>,
    start_ntp: Option<u64>,
    end_ntp: Option<u64>,
}

impl DecodedTimestamps {
    fn apply_element(&mut self, type_id: u16, raw: &[u8]) -> bool {
        let value = read_be_uint(raw);
        match type_id {
            IE_FLOW_START_SYS_UP_TIME => self.start_uptime_ms = Some(value as u32),
            IE_FLOW_END_SYS_UP_TIME => self.end_uptime_ms = Some(value as u32),
            IE_FLOW_START_SECONDS => self.set_start(value.saturating_mul(NS_PER_SECOND), 1),
            IE_FLOW_END_SECONDS => self.set_end(value.saturating_mul(NS_PER_SECOND), 1),
            IE_FLOW_START_MILLISECONDS => {
                self.set_start(value.saturating_mul(NS_PER_MILLISECOND), 2)
            }
            IE_FLOW_END_MILLISECONDS => self.set_end(value.saturating_mul(NS_PER_MILLISECOND), 2),
            IE_FLOW_START_MICROSECONDS => self.start_ntp = Some(value),
            IE_FLOW_END_MICROSECONDS => self.end_ntp = Some(value),
            IE_FLOW_START_NANOSECONDS => self.start_ntp = Some(value),
            IE_FLOW_END_NANOSECONDS => self.end_ntp = Some(value),
            _ => return false,
        }
        true
    }

    fn set_start(&mut self, value: u64, precision: u8) {
        if precision >= self.start_precision {
            self.start_absolute_ns = Some(value);
            self.start_precision = precision;
        }
    }

    fn set_end(&mut self, value: u64, precision: u8) {
        if precision >= self.end_precision {
            self.end_absolute_ns = Some(value);
            self.end_precision = precision;
        }
    }

    fn resolve_start(&self, context: Option<RecordTimeContext>) -> Option<u64> {
        // Prefer the sub-second NTP representation when exporters include
        // multiple time elements for the same boundary.
        self.start_ntp
            .map(|v| ntp_to_unix_ns(v, context))
            .or(self.start_absolute_ns)
            .or_else(|| {
                self.start_uptime_ms
                    .zip(context)
                    .map(|(v, ctx)| uptime_timestamp_ns(ctx, v))
            })
    }

    fn resolve_end(&self, context: Option<RecordTimeContext>) -> Option<u64> {
        self.end_ntp
            .map(|v| ntp_to_unix_ns(v, context))
            .or(self.end_absolute_ns)
            .or_else(|| {
                self.end_uptime_ms
                    .zip(context)
                    .map(|(v, ctx)| uptime_timestamp_ns(ctx, v))
            })
    }
}

fn uptime_timestamp_ns(context: RecordTimeContext, switched_ms: u32) -> u64 {
    let Some(uptime_ms) = context.system_uptime_ms else {
        return context.original_export_time_ns;
    };
    let elapsed_ms = uptime_ms.wrapping_sub(switched_ms) as u64;
    context
        .original_export_time_ns
        .saturating_sub(elapsed_ms.saturating_mul(NS_PER_MILLISECOND))
}

/// IPFIX dateTimeMicroseconds/dateTimeNanoseconds use the 64-bit NTP format:
/// 32 seconds bits followed by a 32-bit binary fraction. Pick the NTP era
/// closest to the packet export time so dates after the 2036 rollover work.
fn ntp_to_unix_ns(value: u64, context: Option<RecordTimeContext>) -> u64 {
    let seconds_low = value >> 32;
    let fraction = value as u32 as u64;
    let reference_unix_seconds = context.map(|ctx| ctx.original_export_time_ns / NS_PER_SECOND);
    let era = reference_unix_seconds
        .map(|reference| {
            let reference_ntp = reference.saturating_add(NTP_UNIX_EPOCH_OFFSET);
            let base_era = reference_ntp / NTP_ERA_SECONDS;
            let candidates = [
                base_era.saturating_sub(1),
                base_era,
                base_era.saturating_add(1),
            ];
            candidates
                .into_iter()
                .min_by_key(|candidate| {
                    let seconds = candidate
                        .saturating_mul(NTP_ERA_SECONDS)
                        .saturating_add(seconds_low);
                    seconds.abs_diff(reference_ntp)
                })
                .unwrap_or(base_era)
        })
        .unwrap_or(0);
    let ntp_seconds = era
        .saturating_mul(NTP_ERA_SECONDS)
        .saturating_add(seconds_low);
    let unix_seconds = ntp_seconds.saturating_sub(NTP_UNIX_EPOCH_OFFSET);
    let nanos = ((fraction as u128 * NS_PER_SECOND as u128) >> 32) as u64;
    unix_seconds
        .saturating_mul(NS_PER_SECOND)
        .saturating_add(nanos)
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
