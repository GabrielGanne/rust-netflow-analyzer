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
const IE_IP_CLASS_OF_SERVICE: u16 = 5;
const IE_TCP_CONTROL_BITS: u16 = 6;
const IE_SOURCE_TRANSPORT_PORT: u16 = 7;
const IE_SOURCE_IPV4_ADDRESS: u16 = 8;
const IE_INGRESS_INTERFACE: u16 = 10;
const IE_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IE_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IE_EGRESS_INTERFACE: u16 = 14;
const IE_SOURCE_IPV6_ADDRESS: u16 = 27;
const IE_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IE_ICMP_TYPE_CODE_IPV4: u16 = 32;
const IE_SOURCE_MAC_ADDRESS: u16 = 56;
const IE_VLAN_ID: u16 = 58;
const IE_DESTINATION_MAC_ADDRESS: u16 = 80;
const IE_OCTET_TOTAL_COUNT: u16 = 85;
const IE_PACKET_TOTAL_COUNT: u16 = 86;
const IE_POST_IP_CLASS_OF_SERVICE: u16 = 98;
const IE_ICMP_TYPE_CODE_IPV6: u16 = 139;
const IE_FLOW_ID: u16 = 148;
const IE_ICMP_TYPE_IPV4: u16 = 176;
const IE_ICMP_CODE_IPV4: u16 = 177;
const IE_ICMP_TYPE_IPV6: u16 = 178;
const IE_ICMP_CODE_IPV6: u16 = 179;
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

/// Presence bits for the optional metadata carried by [`FlowFields`].
///
/// Exporters advertise different information elements per template, so a field
/// value of `0` is ambiguous: it may be a genuine zero or simply "not exported".
/// Each bit here is set only when the corresponding field was actually decoded,
/// letting downstream formatters reproduce the empty-vs-zero distinction.
pub mod presence {
    pub const FLOW_ID: u32 = 1 << 0;
    pub const IFACE_IN: u32 = 1 << 1;
    pub const IFACE_OUT: u32 = 1 << 2;
    pub const SRC_MAC: u32 = 1 << 3;
    pub const DST_MAC: u32 = 1 << 4;
    pub const ICMP_TYPE: u32 = 1 << 5;
    pub const ICMP_CODE: u32 = 1 << 6;
    pub const TCP_FLAGS: u32 = 1 << 7;
    pub const DSCP: u32 = 1 << 8;
    pub const VLAN_TAG: u32 = 1 << 9;
    pub const IP_VERSION: u32 = 1 << 10;
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
    /// Ingress interface index (`ingressInterface`, IE 10; v5 `input`).
    pub iface_in: u64,
    /// Egress interface index (`egressInterface`, IE 14; v5 `output`).
    pub iface_out: u64,
    /// Source L2 address (`sourceMacAddress`, IE 56).
    pub src_mac: [u8; 6],
    /// Destination L2 address (`destinationMacAddress`, IE 80).
    pub dst_mac: [u8; 6],
    /// ICMP message type (from `icmpTypeCode*` or `icmpType*`).
    pub icmp_type: u8,
    /// ICMP message code (from `icmpTypeCode*` or `icmpCode*`).
    pub icmp_code: u8,
    /// TCP control bits (`tcpControlBits`, IE 6; v5 `tcp_flags`).
    pub tcp_flags: u16,
    /// Differentiated-services code point (6 bits), derived from the ToS byte.
    pub dscp: u8,
    /// Source VLAN identifier (`vlanId`, IE 58). `postVlanId` is intentionally dropped.
    pub vlan_tag: u16,
    /// IP version marker: 4, 6, or 0 when unknown.
    pub ip_version: u8,
    /// Bitmask of the metadata fields above that were actually decoded. See
    /// [`presence`] for the individual bits.
    pub present: u32,
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
        fields.iface_in = read_be_u16(&record[12..14]) as u64; // input SNMP ifIndex
        fields.iface_out = read_be_u16(&record[14..16]) as u64; // output SNMP ifIndex
        fields.packets = read_be_uint(&record[16..20]); // dPkts
        fields.bytes = read_be_uint(&record[20..24]); // dOctets
        let first_ms = u32::from_be_bytes(record[24..28].try_into().ok()?);
        let last_ms = u32::from_be_bytes(record[28..32].try_into().ok()?);
        fields.src_port = read_be_u16(&record[32..34]); // srcport
        fields.dst_port = read_be_u16(&record[34..36]); // dstport
        fields.tcp_flags = record[37] as u16; // tcp_flags
        fields.proto = record[38]; // prot
        fields.dscp = record[39] >> 2; // tos byte -> DSCP
                                       // Every v5 record structurally carries these fields, so mark them present.
        fields.ip_version = 4;
        fields.present |= presence::IFACE_IN
            | presence::IFACE_OUT
            | presence::TCP_FLAGS
            | presence::DSCP
            | presence::IP_VERSION;
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
            IE_SOURCE_IPV4_ADDRESS => {
                copy_ipv4(&mut self.src_ip, raw);
                self.set_ip_version(4);
            }
            IE_DESTINATION_IPV4_ADDRESS => {
                copy_ipv4(&mut self.dst_ip, raw);
                self.set_ip_version(4);
            }
            IE_SOURCE_IPV6_ADDRESS => {
                copy_ipv6(&mut self.src_ip, raw);
                self.set_ip_version(6);
            }
            IE_DESTINATION_IPV6_ADDRESS => {
                copy_ipv6(&mut self.dst_ip, raw);
                self.set_ip_version(6);
            }
            IE_SOURCE_TRANSPORT_PORT => self.src_port = read_be_u16(raw),
            IE_DESTINATION_TRANSPORT_PORT => self.dst_port = read_be_u16(raw),
            IE_PROTOCOL_IDENTIFIER => self.proto = raw.first().copied().unwrap_or(0),
            IE_OCTET_DELTA_COUNT | IE_OCTET_TOTAL_COUNT => self.bytes = read_be_uint(raw),
            IE_PACKET_DELTA_COUNT | IE_PACKET_TOTAL_COUNT => self.packets = read_be_uint(raw),
            IE_FLOW_ID => {
                self.flow_id = Some(read_be_uint(raw));
                self.present |= presence::FLOW_ID;
            }
            IE_INGRESS_INTERFACE => {
                self.iface_in = read_be_uint(raw);
                self.present |= presence::IFACE_IN;
            }
            IE_EGRESS_INTERFACE => {
                self.iface_out = read_be_uint(raw);
                self.present |= presence::IFACE_OUT;
            }
            IE_SOURCE_MAC_ADDRESS if copy_mac(&mut self.src_mac, raw) => {
                self.present |= presence::SRC_MAC;
            }
            IE_DESTINATION_MAC_ADDRESS if copy_mac(&mut self.dst_mac, raw) => {
                self.present |= presence::DST_MAC;
            }
            IE_TCP_CONTROL_BITS => {
                self.tcp_flags = read_be_uint(raw) as u16;
                self.present |= presence::TCP_FLAGS;
            }
            IE_VLAN_ID => {
                self.vlan_tag = read_be_u16(raw);
                self.present |= presence::VLAN_TAG;
            }
            // The full ToS byte carries the DSCP in its high 6 bits. It takes
            // precedence over the post-middlebox variant regardless of field
            // order (the post value only fills in if none was seen yet).
            IE_IP_CLASS_OF_SERVICE => {
                self.dscp = raw.first().copied().unwrap_or(0) >> 2;
                self.present |= presence::DSCP;
            }
            IE_POST_IP_CLASS_OF_SERVICE if self.present & presence::DSCP == 0 => {
                self.dscp = raw.first().copied().unwrap_or(0) >> 2;
                self.present |= presence::DSCP;
            }
            // Combined type/code elements pack the type in the high byte.
            IE_ICMP_TYPE_CODE_IPV4 | IE_ICMP_TYPE_CODE_IPV6 => {
                let value = read_be_u16(raw);
                self.icmp_type = (value >> 8) as u8;
                self.icmp_code = value as u8;
                self.present |= presence::ICMP_TYPE | presence::ICMP_CODE;
            }
            IE_ICMP_TYPE_IPV4 | IE_ICMP_TYPE_IPV6 => {
                self.icmp_type = raw.first().copied().unwrap_or(0);
                self.present |= presence::ICMP_TYPE;
            }
            IE_ICMP_CODE_IPV4 | IE_ICMP_CODE_IPV6 => {
                self.icmp_code = raw.first().copied().unwrap_or(0);
                self.present |= presence::ICMP_CODE;
            }
            _ => {}
        }
    }

    /// Records the observed IP address family. The first family wins so a mixed
    /// v4/v6 record (which the protocols forbid) keeps a stable marker.
    fn set_ip_version(&mut self, version: u8) {
        if self.present & presence::IP_VERSION == 0 {
            self.ip_version = version;
            self.present |= presence::IP_VERSION;
        }
    }

    /// Fills in any metadata field this flow has not yet observed from a later
    /// record of the same flow. Counters and timestamps are handled separately
    /// by the cache; this only carries the descriptive metadata forward so a
    /// field exported on a subsequent record is not lost.
    pub(crate) fn merge_metadata_from(&mut self, other: &FlowFields) {
        if self.flow_id.is_none() {
            self.flow_id = other.flow_id;
        }
        let missing = other.present & !self.present;
        if missing & presence::IFACE_IN != 0 {
            self.iface_in = other.iface_in;
        }
        if missing & presence::IFACE_OUT != 0 {
            self.iface_out = other.iface_out;
        }
        if missing & presence::SRC_MAC != 0 {
            self.src_mac = other.src_mac;
        }
        if missing & presence::DST_MAC != 0 {
            self.dst_mac = other.dst_mac;
        }
        if missing & presence::ICMP_TYPE != 0 {
            self.icmp_type = other.icmp_type;
        }
        if missing & presence::ICMP_CODE != 0 {
            self.icmp_code = other.icmp_code;
        }
        if missing & presence::TCP_FLAGS != 0 {
            self.tcp_flags = other.tcp_flags;
        }
        if missing & presence::DSCP != 0 {
            self.dscp = other.dscp;
        }
        if missing & presence::VLAN_TAG != 0 {
            self.vlan_tag = other.vlan_tag;
        }
        if missing & presence::IP_VERSION != 0 {
            self.ip_version = other.ip_version;
        }
        self.present |= other.present;
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
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan_tag: u16,
    pub tcp_flags: u16,
    pub proto: u8,
    pub dscp: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// IP version marker: 4, 6, or 0 when unknown.
    pub ip_version: u8,
    pub bytes: u64,
    pub packets: u64,
    /// Ingress interface index (`ingressInterface`; v5 `input`).
    pub iface_in: u64,
    /// Egress interface index (`egressInterface`; v5 `output`).
    pub iface_out: u64,
    /// Exporter-assigned flow identity; `0` when absent (see `present`).
    pub flow_id: u64,
    /// Effective flow start time as Unix epoch nanoseconds.
    pub start_time_ns: u64,
    /// Effective flow end time as Unix epoch nanoseconds.
    pub end_time_ns: u64,
    /// Unmodified exporter-derived flow start time.
    pub original_start_time_ns: u64,
    /// Unmodified exporter-derived flow end time.
    pub original_end_time_ns: u64,
    /// Bitmask of which optional fields were actually exported. A field whose
    /// bit is clear was not present in the source records; its value is `0` and
    /// should be rendered as empty rather than a real zero. See the `presence`
    /// constants for the individual bit positions.
    pub present: u32,
}

impl FlowFields {
    /// Projects the normalized flow values into the C-compatible record shape.
    pub fn to_ffi(&self) -> NetflowAnalyzerFlowRecord {
        NetflowAnalyzerFlowRecord {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_mac: self.src_mac,
            dst_mac: self.dst_mac,
            src_port: self.src_port,
            dst_port: self.dst_port,
            vlan_tag: self.vlan_tag,
            tcp_flags: self.tcp_flags,
            proto: self.proto,
            dscp: self.dscp,
            icmp_type: self.icmp_type,
            icmp_code: self.icmp_code,
            ip_version: self.ip_version,
            bytes: self.bytes,
            packets: self.packets,
            iface_in: self.iface_in,
            iface_out: self.iface_out,
            flow_id: self.flow_id.unwrap_or(0),
            start_time_ns: self.start_time_ns,
            end_time_ns: self.end_time_ns,
            original_start_time_ns: self.original_start_time_ns,
            original_end_time_ns: self.original_end_time_ns,
            present: self.present,
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

/// Copies a 6-byte MAC address, returning whether the source was long enough.
fn copy_mac(dst: &mut [u8; 6], raw: &[u8]) -> bool {
    if raw.len() >= 6 {
        dst.copy_from_slice(&raw[..6]);
        true
    } else {
        false
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
