// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};
use std::time::Instant;

use crate::parser::{TemplateRecord, V5_RECORD_LEN, VARIABLE_LENGTH};
use crate::sampling::{SamplerSelector, SamplingRatio};
use crate::scope::{ExporterKey, Scope};

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

// --- Sampling information elements carried by options data records ---
// Interpreted from options records rather than flow records (see
// `crate::sampling`). Reference: RFC 7270 (34/50) and RFC 5477/PSAMP (305/306).
//
// The deprecated `samplingInterval` (IE 34) and `samplerRandomInterval` (IE 50)
// each express "1 packet in N was sampled" directly, so the value *is* the
// rate. The modern count-based pair `samplingPacketInterval` (IE 305, packets
// selected per cycle) and `samplingPacketSpace` (IE 306, packets skipped per
// cycle) yield the rate `(interval + space) / interval`.
//
// `flowSamplerId` (IE 48) and `selectorId` (IE 302) identify *which* sampler an
// options record configures when the option scope itself is shared (e.g. a
// system- or domain-wide scope); they are folded into the sampler identity.
const IE_SAMPLING_INTERVAL: u16 = 34;
const IE_FLOW_SAMPLER_ID: u16 = 48;
const IE_SAMPLER_RANDOM_INTERVAL: u16 = 50;
const IE_SAMPLING_PACKET_INTERVAL: u16 = 305;
const IE_SAMPLING_PACKET_SPACE: u16 = 306;
const IE_SELECTOR_ID: u16 = 302;

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
    /// Exporter system uptime in milliseconds, when provided by the packet header.
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

/// The within-scope identity of a flow.
///
/// An exported IPFIX `flowId` takes precedence over the 5-tuple. Both are only
/// unique within a single `(exporter, scope)`, which is why [`FlowKey`] carries
/// that context alongside the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowIdentity {
    /// Exporter-assigned flow identifier (IPFIX element `flowId`, IE 148).
    FlowId(u64),
    /// Traditional 5-tuple flow identity.
    FiveTuple {
        /// Source IP address in IPv4-mapped IPv6 representation.
        src_ip: [u8; 16],
        /// Destination IP address in IPv4-mapped IPv6 representation.
        dst_ip: [u8; 16],
        /// Transport source port.
        src_port: u16,
        /// Transport destination port.
        dst_port: u16,
        /// IP protocol number (e.g. 6 for TCP, 17 for UDP).
        proto: u8,
    },
}

/// Identity used to key the flow state cache.
///
/// Flows are scoped by the exporter/transport session and the protocol-tagged
/// observation [`Scope`], so unrelated exporters, protocol versions, or domains
/// that happen to share a `flowId` or 5-tuple are never aggregated together.
/// See `docs/exporter-identity.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Exporter/transport-session key.
    pub exporter: ExporterKey,
    /// Protocol-tagged observation scope.
    pub scope: Scope,
    /// Within-scope identity (either explicit flow ID or 5-tuple).
    pub identity: FlowIdentity,
}

/// Presence bits for the optional metadata carried by [`FlowFields`].
///
/// Exporters advertise different information elements per template, so a field
/// value of `0` is ambiguous: it may be a genuine zero or simply "not exported".
/// Each bit here is set only when the corresponding field was actually decoded,
/// letting downstream formatters reproduce the empty-vs-zero distinction.
pub mod presence {
    /// Flow ID was present in the record.
    pub const FLOW_ID: u32 = 1 << 0;
    /// Ingress interface index was present in the record.
    pub const IFACE_IN: u32 = 1 << 1;
    /// Egress interface index was present in the record.
    pub const IFACE_OUT: u32 = 1 << 2;
    /// Source MAC address was present in the record.
    pub const SRC_MAC: u32 = 1 << 3;
    /// Destination MAC address was present in the record.
    pub const DST_MAC: u32 = 1 << 4;
    /// ICMP type was present in the record.
    pub const ICMP_TYPE: u32 = 1 << 5;
    /// ICMP code was present in the record.
    pub const ICMP_CODE: u32 = 1 << 6;
    /// Cumulative TCP control flags were present in the record.
    pub const TCP_FLAGS: u32 = 1 << 7;
    /// Differentiated Services Code Point (DSCP) was present in the record.
    pub const DSCP: u32 = 1 << 8;
    /// VLAN identifier was present in the record.
    pub const VLAN_TAG: u32 = 1 << 9;
    /// IP version marker was present in the record.
    pub const IP_VERSION: u32 = 1 << 10;
    /// Source IP address was present in the record.
    pub const SRC_IP: u32 = 1 << 11;
    /// Destination IP address was present in the record.
    pub const DST_IP: u32 = 1 << 12;
    /// IP protocol number was present in the record.
    pub const PROTO: u32 = 1 << 13;
    /// Transport source port was present in the record.
    pub const SRC_PORT: u32 = 1 << 14;
    /// Transport destination port was present in the record.
    pub const DST_PORT: u32 = 1 << 15;
    /// Flow start time was exported (otherwise it is the packet export time).
    pub const START_TIME: u32 = 1 << 16;
    /// Flow end time was exported (otherwise it is the packet export time).
    pub const END_TIME: u32 = 1 << 17;
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
    /// Source IP address in IPv4-mapped IPv6 format.
    pub src_ip: [u8; 16],
    /// Destination IP address in IPv4-mapped IPv6 format.
    pub dst_ip: [u8; 16],
    /// Transport source port (or 0 if not present).
    pub src_port: u16,
    /// Transport destination port (or 0 if not present).
    pub dst_port: u16,
    /// IP protocol number (e.g. 6 for TCP, 17 for UDP).
    pub proto: u8,
    /// Flow byte count (scaled by any configured sampling ratio).
    pub bytes: u64,
    /// Flow packet count (scaled by any configured sampling ratio).
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
    /// Which sampler *this record* was produced by (`flowSamplerId` IE 48 /
    /// `selectorId` IE 302), used only during decoding to look up the sampling
    /// ratio to scale the counters by. It is internal and transient: after a
    /// record is folded into an aggregate flow it is not meaningful (records
    /// with the same key but different selectors are summed), so it is not part
    /// of the emitted `FlowRecord`/FFI identity.
    pub(crate) sampler: SamplerSelector,
}

impl FlowFields {
    /// Builds the flow cache key for this record within `(exporter, scope)`,
    /// preferring the exported `flowId` when present and falling back to the
    /// traditional 5-tuple otherwise.
    pub fn key(&self, exporter: ExporterKey, scope: Scope) -> FlowKey {
        let identity = match self.flow_id {
            Some(flow_id) => FlowIdentity::FlowId(flow_id),
            None => FlowIdentity::FiveTuple {
                src_ip: self.src_ip,
                dst_ip: self.dst_ip,
                src_port: self.src_port,
                dst_port: self.dst_port,
                proto: self.proto,
            },
        };
        FlowKey {
            exporter,
            scope,
            identity,
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

    /// Like [`Self::from_record`], but also returns the number of bytes consumed.
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

        let offset = walk_record_fields(template, record, |type_id, enterprise_number, raw| {
            // Enterprise-specific elements share numeric ids with IANA ones, so
            // only interpret elements from the standard registry.
            if enterprise_number.is_none() && !timestamps.apply_element(type_id, raw) {
                fields.apply_element(type_id, raw);
            }
        })?;

        let fallback = time_context
            .map(|ctx| ctx.original_export_time_ns)
            .unwrap_or(0);
        let start = timestamps.resolve_start(time_context);
        let end = timestamps.resolve_end(time_context);
        if start.is_some() {
            fields.present |= presence::START_TIME;
        }
        if end.is_some() {
            fields.present |= presence::END_TIME;
        }
        fields.original_start_time_ns = start.unwrap_or(fallback);
        fields.original_end_time_ns = end.unwrap_or(fallback);
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
            | presence::IP_VERSION
            | presence::SRC_IP
            | presence::DST_IP
            | presence::PROTO
            | presence::SRC_PORT
            | presence::DST_PORT;
        if let Some(ctx) = time_context {
            fields.present |= presence::START_TIME | presence::END_TIME;
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
                self.present |= presence::SRC_IP;
            }
            IE_DESTINATION_IPV4_ADDRESS => {
                copy_ipv4(&mut self.dst_ip, raw);
                self.set_ip_version(4);
                self.present |= presence::DST_IP;
            }
            IE_SOURCE_IPV6_ADDRESS => {
                copy_ipv6(&mut self.src_ip, raw);
                self.set_ip_version(6);
                self.present |= presence::SRC_IP;
            }
            IE_DESTINATION_IPV6_ADDRESS => {
                copy_ipv6(&mut self.dst_ip, raw);
                self.set_ip_version(6);
                self.present |= presence::DST_IP;
            }
            IE_SOURCE_TRANSPORT_PORT => {
                self.src_port = read_be_u16(raw);
                self.present |= presence::SRC_PORT;
            }
            IE_DESTINATION_TRANSPORT_PORT => {
                self.dst_port = read_be_u16(raw);
                self.present |= presence::DST_PORT;
            }
            IE_PROTOCOL_IDENTIFIER => {
                self.proto = raw.first().copied().unwrap_or(0);
                self.present |= presence::PROTO;
            }
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
            // Sampler selector: `selectorId` (302) takes precedence over
            // `flowSamplerId` (48), matching the sampling cache's resolution, so
            // this flow is scaled by the sampler that produced it.
            IE_SELECTOR_ID => self.sampler = SamplerSelector::Selector(read_be_uint(raw)),
            IE_FLOW_SAMPLER_ID if self.sampler == SamplerSelector::Domain => {
                self.sampler = SamplerSelector::FlowSampler(read_be_uint(raw));
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
        // Only reachable for `flowId`-keyed flows, whose records need not all
        // carry the 5-tuple.
        if missing & presence::SRC_IP != 0 {
            self.src_ip = other.src_ip;
        }
        if missing & presence::DST_IP != 0 {
            self.dst_ip = other.dst_ip;
        }
        if missing & presence::PROTO != 0 {
            self.proto = other.proto;
        }
        if missing & presence::SRC_PORT != 0 {
            self.src_port = other.src_port;
        }
        if missing & presence::DST_PORT != 0 {
            self.dst_port = other.dst_port;
        }
        self.present |= other.present;
    }
}

/// Persistent per-flow state held in the cache between exported records.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// The normalized flow data accumulated by the cache.
    pub fields: FlowFields,
    /// Exporter/transport session this flow belongs to (see the identity model).
    pub exporter: ExporterKey,
    /// Protocol-tagged observation scope this flow belongs to.
    pub scope: Scope,
    pub(crate) first_observed: Instant,
    pub(crate) last_observed: Instant,
}

impl FlowRecord {
    /// Constructs an initial cached record from decoded fields and scope identity.
    pub fn from_fields(
        fields: &FlowFields,
        exporter: ExporterKey,
        scope: Scope,
        now: Instant,
    ) -> Self {
        Self {
            fields: *fields,
            exporter,
            scope,
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

/// A C-compatible representation to safely pass over the FFI boundary.
///
/// `#[non_exhaustive]` is a deliberate ABI decision: consumers must not assume
/// this layout is frozen and must not exhaustively construct or match it, so
/// future additions (coordinated with an ABI version/size mechanism) do not break
/// callers. See `docs/exporter-identity.md`.
#[repr(C)]
#[non_exhaustive]
pub struct NetflowAnalyzerFlowRecord {
    /// Source IP address in IPv4-mapped IPv6 representation.
    pub src_ip: [u8; 16],
    /// Destination IP address in IPv4-mapped IPv6 representation.
    pub dst_ip: [u8; 16],
    /// Source MAC address (or zero if absent).
    pub src_mac: [u8; 6],
    /// Destination MAC address (or zero if absent).
    pub dst_mac: [u8; 6],
    /// Transport layer source port.
    pub src_port: u16,
    /// Transport layer destination port.
    pub dst_port: u16,
    /// 802.1Q VLAN identifier.
    pub vlan_tag: u16,
    /// Cumulative TCP control flags.
    pub tcp_flags: u16,
    /// IP protocol number.
    pub proto: u8,
    /// Differentiated Services Code Point (DSCP).
    pub dscp: u8,
    /// ICMP type value.
    pub icmp_type: u8,
    /// ICMP code value.
    pub icmp_code: u8,
    /// IP version marker: 4, 6, or 0 when unknown.
    pub ip_version: u8,
    /// Protocol discriminator for the scope fields (`NETFLOW_ANALYZER_SCOPE_*`):
    /// `0` v9, `1` IPFIX, `2` v5.
    pub scope_protocol: u8,
    /// NetFlow v5 switching-engine type; `0` for v9/IPFIX.
    pub scope_engine_type: u8,
    /// NetFlow v5 switching-engine id; `0` for v9/IPFIX.
    pub scope_engine_id: u8,
    /// Observation domain (v9 `source_id` / IPFIX domain); `0` for v5.
    pub observation_domain: u32,
    /// Accumulated byte count.
    pub bytes: u64,
    /// Accumulated packet count.
    pub packets: u64,
    /// Ingress interface index (`ingressInterface`; v5 `input`).
    pub iface_in: u64,
    /// Egress interface index (`egressInterface`; v5 `output`).
    pub iface_out: u64,
    /// Exporter-assigned flow identity; `0` when absent (see `present`).
    pub flow_id: u64,
    /// Caller-supplied exporter/transport-session key this flow belongs to
    /// (low 64 bits; see `exporter_key_hi`).
    pub exporter_key: u64,
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
    /// High 64 bits of the 128-bit exporter key; `0` for keys supplied through
    /// the 64-bit `_from` entry points. Added in ABI version 3 (took the first
    /// reserved slot).
    pub exporter_key_hi: u64,
    /// Reserved for future fields. Always zero today; kept so new fields can be
    /// added within this space without changing the struct size or ABI. Which
    /// slots carry meaning is tied to the FFI `netflow_analyzer_abi_version`.
    pub reserved: [u64; 7],
}

impl FlowFields {
    /// Projects the normalized flow values into the C-compatible record shape,
    /// stamping the emitted record with its `(exporter, scope)` identity.
    pub fn to_ffi(&self, exporter: ExporterKey, scope: Scope) -> NetflowAnalyzerFlowRecord {
        let (engine_type, engine_id) = scope.engine();
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
            scope_protocol: scope.protocol_tag(),
            scope_engine_type: engine_type,
            scope_engine_id: engine_id,
            observation_domain: scope.observation_domain(),
            bytes: self.bytes,
            packets: self.packets,
            iface_in: self.iface_in,
            iface_out: self.iface_out,
            flow_id: self.flow_id.unwrap_or(0),
            exporter_key: exporter as u64,
            start_time_ns: self.start_time_ns,
            end_time_ns: self.end_time_ns,
            original_start_time_ns: self.original_start_time_ns,
            original_end_time_ns: self.original_end_time_ns,
            present: self.present,
            exporter_key_hi: (exporter >> 64) as u64,
            reserved: [0; 7],
        }
    }
}

impl FlowRecord {
    /// Converts this record to the C-compatible [`NetflowAnalyzerFlowRecord`] representation.
    pub fn to_ffi(&self) -> NetflowAnalyzerFlowRecord {
        self.fields.to_ffi(self.exporter, self.scope)
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

/// Walks every field of `template` across `record`, invoking `visit` with each
/// element's `(type_id, enterprise_number, raw_bytes)`. Honours IPFIX
/// variable-length encoding and stays fully bounds-checked: it returns `None`
/// (visiting no further fields) as soon as the record is shorter than the
/// template requires, otherwise the total number of bytes consumed.
///
/// Both flow decoding ([`FlowFields::from_record_sized_at`]) and options-record
/// interpretation ([`sampling_interval_from_options_record`]) share this walk so
/// the on-wire framing is parsed in exactly one place.
fn walk_record_fields(
    template: &TemplateRecord,
    record: &[u8],
    mut visit: impl FnMut(u16, Option<u32>, &[u8]),
) -> Option<usize> {
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
        visit(field.type_id, field.enterprise_number, raw);
        offset = end;
    }
    Some(offset)
}

/// A packet-sampling configuration interpreted from one options data record.
///
/// A single observation domain can advertise several samplers (one per
/// interface, per `flowSamplerId`, etc.). `selector` identifies which one — the
/// `selectorId` (IE 302) or `flowSamplerId` (IE 48) the record carries, whether
/// as a scope or an option field, or [`SamplerSelector::Domain`] when it carries
/// neither. It is derived exactly as a flow record's selector, so decoded flows
/// match the sampler that produced them (see `docs/exporter-identity.md`).
/// `ratio` is the fraction of real traffic that was captured, kept exact so a
/// fractional rate is not truncated early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplingObservation {
    /// Sampler identity extracted from options scope or options data fields.
    pub selector: SamplerSelector,
    /// Extracted packet-sampling ratio.
    pub ratio: SamplingRatio,
}

/// Interprets the packet-sampling configuration carried by a single options
/// data record, decoded against its options `template`.
///
/// Returns `None` unless the record actually carries a sampling rate: the
/// deprecated `samplingInterval` (IE 34) or `samplerRandomInterval` (IE 50),
/// each a direct "1 in N" value, or the modern `samplingPacketInterval` (IE
/// 305) with `samplingPacketSpace` (IE 306), whose rate is
/// `(interval + space) / interval`. IE 34 is preferred over IE 50 over the
/// 305/306 pair when more than one is present. Sampling and selector elements
/// are read only from the IANA registry (enterprise-specific elements merely
/// reuse the numeric ids), and a record shorter than its template requires
/// yields `None`.
pub fn sampling_from_options_record(
    template: &TemplateRecord,
    record: &[u8],
) -> Option<SamplingObservation> {
    let scope_field_count = template.scope_field_count as usize;
    let mut selector = SamplerSelector::Domain;
    let mut sampling_interval: Option<u64> = None;
    let mut random_interval: Option<u64> = None;
    let mut packet_interval: Option<u64> = None;
    let mut packet_space: Option<u64> = None;
    let mut index = 0usize;

    walk_record_fields(template, record, |type_id, enterprise_number, raw| {
        let field_index = index;
        index += 1;
        if enterprise_number.is_some() {
            return;
        }
        // A selector identifies which sampler the record configures whether it
        // sits in the scope or the option fields. The *rate* elements are only
        // meaningful as option fields — as a scope field their value identifies
        // what the options apply to, not an advertised rate — so they are read
        // only past the scope fields.
        let is_option_field = field_index >= scope_field_count;
        match type_id {
            // `selectorId` (302) wins over `flowSamplerId` (48); this must match
            // the precedence in `FlowFields::apply_element` so the two agree.
            IE_SELECTOR_ID => selector = SamplerSelector::Selector(read_be_uint(raw)),
            IE_FLOW_SAMPLER_ID if selector == SamplerSelector::Domain => {
                selector = SamplerSelector::FlowSampler(read_be_uint(raw));
            }
            IE_SAMPLING_INTERVAL if is_option_field => sampling_interval = Some(read_be_uint(raw)),
            IE_SAMPLER_RANDOM_INTERVAL if is_option_field => {
                random_interval = Some(read_be_uint(raw))
            }
            IE_SAMPLING_PACKET_INTERVAL if is_option_field => {
                packet_interval = Some(read_be_uint(raw))
            }
            IE_SAMPLING_PACKET_SPACE if is_option_field => packet_space = Some(read_be_uint(raw)),
            _ => {}
        }
    })?;

    let ratio = resolve_sampling_ratio(
        sampling_interval,
        random_interval,
        packet_interval,
        packet_space,
    )?;
    Some(SamplingObservation { selector, ratio })
}

/// Resolves the decoded sampling elements into an exact [`SamplingRatio`], or
/// `None` when none of them describe a usable rate. See
/// [`sampling_from_options_record`] for the element precedence.
fn resolve_sampling_ratio(
    sampling_interval: Option<u64>,
    random_interval: Option<u64>,
    packet_interval: Option<u64>,
    packet_space: Option<u64>,
) -> Option<SamplingRatio> {
    // IE 34 / IE 50 carry the "1 in N" rate directly: N in the population per
    // 1 captured, i.e. numerator N over denominator 1.
    for value in [sampling_interval, random_interval].into_iter().flatten() {
        if value >= 1 {
            return Some(SamplingRatio {
                numerator: value,
                denominator: 1,
            });
        }
    }

    // IE 305 / IE 306 describe a selection cycle: `interval` packets kept then
    // `space` skipped, so the rate is `(interval + space) / interval`. Both are
    // required to determine the cycle — an interval alone is ambiguous, so it is
    // not treated as an advertisement (which would wrongly manufacture a 1:1
    // rate and could overwrite a real one). Both terms are kept exact so a
    // non-integral rate is not truncated here.
    if let (Some(interval), Some(space)) = (packet_interval, packet_space) {
        if interval >= 1 {
            return Some(SamplingRatio {
                numerator: interval.saturating_add(space),
                denominator: interval,
            });
        }
    }

    None
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
