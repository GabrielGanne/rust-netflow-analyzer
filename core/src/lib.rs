// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # netflow_analyzer_core
//!
//! A high-performance, zero-copy NetFlow v5, NetFlow v9, and IPFIX decoding and
//! flow aggregation engine in Rust.
//!
//! `netflow_analyzer_core` parses exported datagrams directly from caller-provided
//! byte buffers without heap allocations for packet framing. It manages template
//! definitions, tracks exporter clock skew, and folds decoded flow records into an
//! internally sharded, size-bounded cache supporting concurrent ingestion, flushing,
//! and background timeout aging.
//!
//! ## Quick Start
//!
//! ```rust
//! use netflow_analyzer_core::FlowContext;
//!
//! let ctx = FlowContext::new();
//!
//! // Fused decode + aggregation path
//! let packet: &[u8] = &[]; // Raw NetFlow or IPFIX packet bytes
//! if !packet.is_empty() {
//!     let count = ctx.process_packet(packet).unwrap();
//!     println!("Decoded and cached {count} records");
//! }
//!
//! // Read diagnostic counters and active flow count
//! let stats = ctx.stats();
//! println!("Active flows in cache: {}", stats.active_flows);
//! ```
//!
//! ## Decode-Only Mode
//!
//! To bypass cache aggregation and receive decoded records directly:
//!
//! ```rust
//! use netflow_analyzer_core::FlowContext;
//!
//! let ctx = FlowContext::new();
//! let packet: &[u8] = &[];
//! if !packet.is_empty() {
//!     ctx.decode_packet(packet, &mut |domain_id, fields| {
//!         println!("Observed domain {domain_id}, bytes: {}", fields.bytes);
//!     }).unwrap();
//! }
//! ```

/// Cache configurations and hard caps for flows and templates.
pub mod cache;
/// Exporter clock tracking and skew validation.
pub mod clock;
/// Template definitions and protocol versions.
pub mod parser;
/// Flow record representation, field bitmasks, and metadata.
pub mod records;
/// Packet sampling factors and options-template tracking.
pub mod sampling;
/// Exporter keys and protocol-tagged observation domain scopes.
pub mod scope;
/// Telemetry snapshots and diagnostic counters.
pub mod stats;

pub use cache::AgingConfig;
pub use clock::ClockConfig;
pub use records::{FlowFields, FlowRecord, NetflowAnalyzerFlowRecord};
pub use scope::{ExporterKey, Scope, SINGLE_EXPORTER};
pub use stats::NetflowAnalyzerStats;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cache::{AgingHandle, FlowCache, TemplateCache, DEFAULT_MAX_FLOWS, DEFAULT_MAX_TEMPLATES};
use clock::{ClockDecision, ClockTracker};
use parser::{
    NetflowV5Header, ParsedHeader, FIRST_DATA_SET_ID, FLOWSET_ID_V9_OPTIONS,
    FLOWSET_ID_V9_TEMPLATE, IPFIX_HEADER_LEN, SET_ID_IPFIX_OPTIONS, SET_ID_IPFIX_TEMPLATE,
    V5_RECORD_LEN,
};
use records::RecordTimeContext;
use sampling::{SamplingRatio, SamplingTracker};
use stats::InternalCounters;

/// Errors that can occur when processing or decoding a NetFlow/IPFIX packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// The NetFlow/IPFIX packet header was structurally invalid, unsupported, or truncated.
    InvalidHeader,
    /// The IPFIX message `total_length` was inconsistent with the received datagram
    /// or its Sets.
    InconsistentIpfixLength,
    /// The packet was dropped because the exporter's clock skew exceeded the configured
    /// limit (and timestamp fallback was not enabled).
    ClockSkewExceeded,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader => write!(f, "Failed to parse NetFlow header packet structure"),
            Self::InconsistentIpfixLength => {
                write!(
                    f,
                    "IPFIX message total_length is inconsistent with the datagram"
                )
            }
            Self::ClockSkewExceeded => {
                write!(
                    f,
                    "Packet dropped because exporter clock skew exceeds limit"
                )
            }
        }
    }
}

impl std::error::Error for PacketError {}

/// Legacy error string returned when clock validation rejects an otherwise parseable packet.
#[deprecated(note = "use PacketError::ClockSkewExceeded instead")]
pub const CLOCK_SKEW_ERROR: &str = "Packet dropped because exporter clock skew exceeds limit";

/// Returns true if `body` is tiled exactly by IPFIX Sets: every Set has a valid
/// length (at least the 4-byte Set header) that fits, and the Sets consume the
/// whole slice with nothing left over. A Set that overruns the declared message,
/// or stray trailing bytes, means the declared `total_length` is inconsistent.
fn ipfix_sets_tile_exactly(mut body: &[u8]) -> bool {
    while !body.is_empty() {
        // A full 4-byte Set header (set id + length) must be present.
        if body.len() < 4 {
            return false;
        }
        let set_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        if set_len < 4 || set_len > body.len() {
            return false;
        }
        body = &body[set_len..];
    }
    true
}

/// Sampling ratio advertised by a NetFlow v5 header `sampling_interval`: the
/// top 2 bits are the sampling mode and the low 14 bits the "1 in N" interval.
/// The interval is honoured whatever the mode, since exporters commonly leave
/// the mode bits clear; `0` and `1` both mean unsampled.
fn v5_sampling_ratio(sampling_interval: u16) -> SamplingRatio {
    match u64::from(sampling_interval & 0x3FFF) {
        0 | 1 => SamplingRatio::NONE,
        interval => SamplingRatio {
            numerator: interval,
            denominator: 1,
        },
    }
}

/// Returns false for a Template Withdrawal (a zero-field record, RFC 7011 §8.1).
///
/// Withdrawals are ignored for every transport: RFC 7011 §8.4 requires UDP
/// collectors to ignore them, and the transport-agnostic core cannot tell a
/// reliable session apart. Templates instead age out via the template lifetime
/// or are dropped by an explicit exporter purge.
fn is_definition(template: &parser::TemplateRecord) -> bool {
    !template.fields.is_empty()
}

/// Current wall-clock time as Unix nanoseconds, saturating at `u64::MAX`.
pub(crate) fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// Top-level engine configuration combining cache caps and aging timings.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    /// Maximum number of active flows retained in the flow cache before dropping new flows.
    pub max_flows: usize,
    /// Maximum number of templates retained in the template cache.
    pub max_templates: usize,
    /// Timeout and scan interval parameters for the background aging thread.
    pub aging: AgingConfig,
    /// Clock synchronization and skew tolerance settings.
    pub clock: ClockConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            max_templates: DEFAULT_MAX_TEMPLATES,
            aging: AgingConfig::default(),
            clock: ClockConfig::default(),
        }
    }
}

/// The core ingestion and state-tracking engine.
///
/// A single `FlowContext` is shared (via `Arc`) across all worker threads. Its
/// caches are internally sharded, so concurrent `process_packet` calls update
/// flow records without a cache-wide lock. Template definitions, template
/// capacity reclamation, and template expiry sweeps share one
/// template-cache-wide mutex across all exporters.
///
/// # Time domains
///
/// Flow aging and template expiry run on the receipt time of each packet. The
/// entry points without an `_at` suffix, and the background worker started by
/// [`Self::start_aging`], read the wall clock. The `_at` entry points use the
/// caller's timestamp instead, which lets a capture replay or a test age state
/// deterministically through [`Self::age_at`].
///
/// Use **one** time domain per context: either the wall-clock entry points with
/// [`Self::start_aging`], or the `_at` entry points with [`Self::age_at`].
/// Mixing them, for example feeding capture timestamps while the background
/// worker sweeps at wall-clock time, ages flows and templates against
/// unrelated clocks. Time moving backwards never ages state early: elapsed
/// time saturates at zero.
pub struct FlowContext {
    counters: Arc<InternalCounters>,
    templates: Arc<TemplateCache>,
    flows: Arc<FlowCache>,
    clocks: Arc<ClockTracker>,
    sampling: Arc<SamplingTracker>,
    aging_cfg: AgingConfig,
    clock_cfg: ClockConfig,
    aging: Mutex<Option<AgingHandle>>,
}

impl FlowContext {
    /// Creates an engine using the default configuration.
    pub fn new() -> Self {
        Self::with_config(EngineConfig::default())
    }

    /// Creates an engine with explicit cache caps and aging timings.
    pub fn with_config(cfg: EngineConfig) -> Self {
        Self {
            counters: Arc::new(InternalCounters::default()),
            templates: Arc::new(TemplateCache::new(cfg.max_templates)),
            flows: Arc::new(FlowCache::new(cfg.max_flows)),
            clocks: Arc::new(ClockTracker::new(cfg.max_templates)),
            sampling: Arc::new(SamplingTracker::new(cfg.max_templates)),
            aging_cfg: cfg.aging,
            clock_cfg: cfg.clock,
            aging: Mutex::new(None),
        }
    }

    /// Decodes a single exported datagram, updating template and flow state.
    ///
    /// Returns the number of data records successfully folded into the cache.
    /// The input is borrowed and never copied: parsing operates directly on the
    /// caller's buffer.
    pub fn process_packet(&self, raw_bytes: &[u8]) -> Result<usize, PacketError> {
        self.process_packet_at(raw_bytes, now_unix_ns())
    }

    /// Like [`Self::process_packet`], with an explicit Unix-nanosecond receipt
    /// timestamp. Capture readers should pass the packet's capture timestamp.
    ///
    /// The timestamp also drives flow aging and template expiry; see the
    /// [time domains](Self#time-domains) note before combining it with
    /// [`Self::start_aging`].
    ///
    /// This is the fused decode + aggregate entry point for the reserved
    /// single-exporter key. It is a thin wrapper over
    /// [`Self::process_packet_from_at`].
    pub fn process_packet_at(
        &self,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
    ) -> Result<usize, PacketError> {
        self.process_packet_from_at(SINGLE_EXPORTER, raw_bytes, receipt_time_ns)
    }

    /// Fused decode + aggregate for a specific exporter/transport session.
    ///
    /// `exporter` scopes all template, clock, and flow state and is stamped onto
    /// every emitted record, so one [`FlowContext`] can serve many exporters
    /// without their state colliding. See `docs/exporter-identity.md` for the
    /// caller contract governing how keys must be allocated and never reused.
    pub fn process_packet_from(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
    ) -> Result<usize, PacketError> {
        self.process_packet_from_at(exporter, raw_bytes, now_unix_ns())
    }

    /// Like [`Self::process_packet_from`], with an explicit Unix-nanosecond
    /// receipt timestamp.
    pub fn process_packet_from_at(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
    ) -> Result<usize, PacketError> {
        self.decode_at(
            exporter,
            raw_bytes,
            receipt_time_ns,
            &mut |exporter, scope, fields| {
                self.flows
                    .upsert(exporter, scope, fields, &self.counters, receipt_time_ns);
            },
        )
    }

    /// Decode-only counterpart of [`Self::process_packet`]: parses a datagram and
    /// emits each decoded data record through `sink` **without** touching the flow
    /// cache. Template, options-template, clock, and sampling state is still
    /// updated and retained per exporter (it is required to decode later
    /// packets), but no flow aggregation, timeouts, or eviction take place.
    ///
    /// The receipt timestamp defaults to the current wall clock. Use
    /// [`Self::decode_packet_at`] to supply a capture timestamp explicitly.
    ///
    /// This is a **lossy legacy sink**: it reports only the observation domain
    /// (`0` for NetFlow v5) and cannot distinguish protocol-tagged scopes or
    /// exporters. Use [`Self::decode_packet_scoped`] to receive the full
    /// `(ExporterKey, Scope)` identity.
    pub fn decode_packet(
        &self,
        raw_bytes: &[u8],
        sink: &mut dyn FnMut(u32, &FlowFields),
    ) -> Result<usize, PacketError> {
        let receipt_time_ns = now_unix_ns();
        self.decode_packet_at(raw_bytes, receipt_time_ns, sink)
    }

    /// Decode-only entry point with an explicit Unix-nanosecond receipt timestamp.
    ///
    /// Each decoded data record is delivered to `sink` as `(observation_domain_id,
    /// &FlowFields)`. NetFlow v5 records report domain `0`. Options data records
    /// are counted but not emitted, mirroring the fused path. The flow cache is
    /// never consulted or mutated, so this can drive an external aggregator.
    ///
    /// See [`Self::decode_packet`] for the lossy-domain caveat.
    pub fn decode_packet_at(
        &self,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
        sink: &mut dyn FnMut(u32, &FlowFields),
    ) -> Result<usize, PacketError> {
        self.decode_at(
            SINGLE_EXPORTER,
            raw_bytes,
            receipt_time_ns,
            &mut |_exporter, scope, fields| sink(scope.observation_domain(), fields),
        )
    }

    /// Scope-aware decode-only entry point for the reserved single-exporter key:
    /// like [`Self::decode_packet`], but each record is delivered as
    /// `(exporter_key, scope, &FlowFields)` so a consumer can attribute it to its
    /// exporter, protocol, and domain. Thin wrapper over
    /// [`Self::decode_packet_from`].
    pub fn decode_packet_scoped(
        &self,
        raw_bytes: &[u8],
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, PacketError> {
        self.decode_packet_from(SINGLE_EXPORTER, raw_bytes, sink)
    }

    /// Scope-aware decode-only entry point with an explicit receipt timestamp.
    /// See [`Self::decode_packet_scoped`].
    pub fn decode_packet_scoped_at(
        &self,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, PacketError> {
        self.decode_packet_from_at(SINGLE_EXPORTER, raw_bytes, receipt_time_ns, sink)
    }

    /// Decode-only entry point for a specific exporter/transport session. Each
    /// record is delivered as `(exporter_key, scope, &FlowFields)` without
    /// touching the flow cache. See [`Self::process_packet_from`] for the
    /// exporter-key contract.
    pub fn decode_packet_from(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, PacketError> {
        self.decode_packet_from_at(exporter, raw_bytes, now_unix_ns(), sink)
    }

    /// Like [`Self::decode_packet_from`], with an explicit receipt timestamp.
    pub fn decode_packet_from_at(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, PacketError> {
        self.decode_at(exporter, raw_bytes, receipt_time_ns, sink)
    }

    /// Core decode routine shared by every entry point. Decodes the datagram
    /// under `exporter` and the packet's protocol-tagged [`Scope`], updating
    /// template and clock state and delivering each data record to `sink`.
    fn decode_at(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, PacketError> {
        let (mut payload, header) = match parser::parse_packet_header(raw_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.counters
                    .pkts_parse_error
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PacketError::InvalidHeader);
            }
        };

        // Enforce the IPFIX declared message length (RFC 7011 §3.1): the message
        // is exactly `total_length` bytes including the 16-byte header. Reject a
        // message whose declared length is impossible or exceeds the datagram,
        // and never walk trailing bytes beyond it.
        if let ParsedHeader::Ipfix(ref h) = header {
            let consistent = match (h.total_length as usize).checked_sub(IPFIX_HEADER_LEN) {
                // The declared body must fit in the datagram and be tiled exactly
                // by its Sets (no Set overrunning it, no stray trailing bytes).
                Some(body_len) if body_len <= payload.len() => {
                    payload = &payload[..body_len];
                    ipfix_sets_tile_exactly(payload)
                }
                _ => false,
            };
            if !consistent {
                self.counters
                    .pkts_parse_error
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PacketError::InconsistentIpfixLength);
            }
        }

        self.counters.pkts_parsed.fetch_add(1, Ordering::Relaxed);

        // Per-exporter, protocol-tagged scope used to key template, clock, and
        // flow state and to stamp emitted records (see docs/exporter-identity.md).
        let scope = header.scope();
        let original_export_time_ns = header.export_time_ns();
        let effective_export_time_ns = match self.clocks.observe(
            exporter,
            scope,
            original_export_time_ns,
            receipt_time_ns,
            self.clock_cfg,
        ) {
            ClockDecision::Accept {
                effective_export_time_ns,
            } => effective_export_time_ns,
            ClockDecision::Fallback {
                effective_export_time_ns,
            } => {
                self.counters
                    .clock_fallback_packets
                    .fetch_add(1, Ordering::Relaxed);
                effective_export_time_ns
            }
            ClockDecision::Drop => {
                self.counters
                    .clock_dropped_packets
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PacketError::ClockSkewExceeded);
            }
        };
        let time_context = RecordTimeContext {
            original_export_time_ns,
            effective_export_time_ns,
            system_uptime_ms: header.system_uptime_ms(),
        };

        // NetFlow v5 is template-less: the payload is simply `count` fixed-size
        // records, so it takes a dedicated decode path instead of a set walk.
        if let ParsedHeader::V5(ref h) = header {
            return Ok(self.process_v5_records(exporter, scope, payload, h, time_context, sink));
        }

        let mut data_records = 0usize;
        // Set when a template/options set fails to parse or validate. Template
        // sets are transactional (see `parse_template_set`), so a rejected set
        // applies none of its templates and the previously cached definition is
        // retained. Decoding must then stop for the rest of this packet: any
        // following data set could otherwise be decoded against a *stale* layout
        // (e.g. an old 4-byte template splitting one new 8-byte record into two),
        // silently corrupting flows.
        let mut rejected_template = false;
        // Template Set IDs are protocol-specific: NetFlow v9 uses 0 and 1, IPFIX
        // uses 2 and 3. An inapplicable ID is reserved for that protocol and
        // skipped like any other reserved Set, so it never installs a template.
        let (template_set_id, options_set_id) = match header {
            ParsedHeader::Ipfix(_) => (SET_ID_IPFIX_TEMPLATE, SET_ID_IPFIX_OPTIONS),
            _ => (FLOWSET_ID_V9_TEMPLATE, FLOWSET_ID_V9_OPTIONS),
        };

        // Walk each FlowSet/Set in the payload. A structural inconsistency stops
        // the walk without panicking; the unconsumed remainder is detected after
        // the loop and counted as malformed.
        while payload.len() >= 4 {
            let (rest, fs) = match parser::parse_flowset_header(payload) {
                Ok(parsed) => parsed,
                Err(_) => break,
            };

            // FlowSet length includes the 4-byte header. A length below that or
            // beyond the remaining buffer signals truncation/corruption.
            let body_len = match (fs.length as usize).checked_sub(4) {
                Some(len) if len <= rest.len() => len,
                _ => break,
            };

            let (body, remainder) = rest.split_at(body_len);
            payload = remainder;

            match fs.set_id {
                id if id == template_set_id => match parser::parse_template_set(body) {
                    Ok((_, templates)) => {
                        for template in templates.into_iter().filter(is_definition) {
                            self.counters
                                .templates_received
                                .fetch_add(1, Ordering::Relaxed);
                            self.templates
                                .insert(exporter, scope, template, receipt_time_ns);
                        }
                    }
                    Err(_) => {
                        rejected_template = true;
                        break;
                    }
                },
                // Options templates describe the layout of options data records
                // (exporter metadata). Decode and store them so their data sets
                // can later be interpreted rather than silently dropped.
                id if id == options_set_id && id == FLOWSET_ID_V9_OPTIONS => {
                    match parser::parse_v9_options_template_set(body) {
                        Ok((_, templates)) => self.store_options_templates(
                            exporter,
                            scope,
                            templates,
                            receipt_time_ns,
                        ),
                        Err(_) => {
                            rejected_template = true;
                            break;
                        }
                    }
                }
                id if id == options_set_id && id == SET_ID_IPFIX_OPTIONS => {
                    match parser::parse_ipfix_options_template_set(body) {
                        Ok((_, templates)) => self.store_options_templates(
                            exporter,
                            scope,
                            templates,
                            receipt_time_ns,
                        ),
                        Err(_) => {
                            rejected_template = true;
                            break;
                        }
                    }
                }
                // Without the template we cannot interpret the records yet; the
                // exporter will resend it periodically, so we skip until then.
                id if id >= FIRST_DATA_SET_ID => {
                    if let Some(template) = self.templates.get(exporter, scope, id, receipt_time_ns)
                    {
                        data_records += self.process_data_set(
                            exporter,
                            scope,
                            &template,
                            body,
                            time_context,
                            sink,
                        );
                    }
                }
                // Reserved/unknown set ids (e.g. 4..=255) are ignored.
                _ => {}
            }
        }

        // Partial decoding: a rejected template set, any unconsumed bytes (a
        // FlowSet/Set length that overran or truncated the message), or a
        // trailing truncated Set header all mean the body could not be fully and
        // consistently walked. A cleanly framed message ends with the payload
        // fully consumed and no rejection. Keep the records decoded so far but
        // flag the datagram as malformed rather than silently succeeding. (IPFIX
        // messages are already validated to tile exactly above, so unconsumed
        // bytes only arise for NetFlow v9.)
        if rejected_template || !payload.is_empty() {
            self.counters
                .malformed_packets
                .fetch_add(1, Ordering::Relaxed);
        }

        self.counters
            .data_records_processed
            .fetch_add(data_records as u64, Ordering::Relaxed);

        Ok(data_records)
    }

    /// Records every decoded options template under `(exporter, scope)`,
    /// counting each one.
    fn store_options_templates(
        &self,
        exporter: scope::ExporterKey,
        scope: Scope,
        templates: Vec<parser::TemplateRecord>,
        now_ns: u64,
    ) {
        for template in templates.into_iter().filter(is_definition) {
            self.counters
                .options_templates_received
                .fetch_add(1, Ordering::Relaxed);
            self.templates.insert(exporter, scope, template, now_ns);
        }
    }

    /// Decodes up to the header's `count` fixed-format NetFlow v5 records from
    /// the payload, scaling counters by the header's sampling interval.
    fn process_v5_records(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        payload: &[u8],
        header: &NetflowV5Header,
        time_context: RecordTimeContext,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> usize {
        let count = header.count as usize;
        let ratio = v5_sampling_ratio(header.sampling_interval);
        let mut decoded = 0usize;
        // Trust the header count but never read past the buffer.
        for record in parser::split_fixed_records(payload, V5_RECORD_LEN).take(count) {
            if let Some(mut fields) = FlowFields::from_v5_record_at(record, Some(time_context)) {
                fields.bytes = ratio.expand(fields.bytes);
                fields.packets = ratio.expand(fields.packets);
                sink(exporter, scope, &fields);
                decoded += 1;
            }
        }
        self.counters
            .data_records_processed
            .fetch_add(decoded as u64, Ordering::Relaxed);
        decoded
    }

    /// Decodes every data record in a data FlowSet body against its template.
    ///
    /// `(exporter, scope)` keys the sampling lookup and is forwarded to `sink`.
    fn process_data_set(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template: &parser::TemplateRecord,
        body: &[u8],
        time_context: RecordTimeContext,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> usize {
        // Options data records carry exporter metadata, not observed flows, so
        // they are decoded and interpreted separately without polluting the flow
        // cache. `count` therefore tracks only flow records for the return value.
        let is_options = template.is_options;
        let mut count = 0usize;

        match template.fixed_length {
            Some(record_len) if record_len > 0 => {
                for record in parser::split_fixed_records(body, record_len) {
                    if let Some((mut fields, _)) =
                        FlowFields::from_record_sized_at(template, record, Some(time_context))
                    {
                        if is_options {
                            self.consume_options_record(exporter, scope, template, record);
                        } else {
                            self.apply_sampling(exporter, scope, &mut fields);
                            sink(exporter, scope, &fields);
                            count += 1;
                        }
                    }
                }
            }
            // Variable-length template: boundaries are only known after decoding.
            None => {
                let mut cursor = body;
                while !cursor.is_empty() {
                    match FlowFields::from_record_sized_at(template, cursor, Some(time_context)) {
                        Some((mut fields, consumed))
                            if consumed > 0 && consumed <= cursor.len() =>
                        {
                            if is_options {
                                self.consume_options_record(
                                    exporter,
                                    scope,
                                    template,
                                    &cursor[..consumed],
                                );
                            } else {
                                self.apply_sampling(exporter, scope, &mut fields);
                                sink(exporter, scope, &fields);
                                count += 1;
                            }
                            cursor = &cursor[consumed..];
                        }
                        _ => break,
                    }
                }
            }
            // A zero-length fixed template is degenerate; nothing to do.
            _ => {}
        }

        count
    }

    /// Counts one decoded options data record and interprets the exporter
    /// metadata it carries. Currently that means learning the packet-sampling
    /// ratio (from `samplingInterval` IE 34, `samplerRandomInterval` IE 50, or
    /// the `samplingPacketInterval` / `samplingPacketSpace` pair IE 305/306) for
    /// the sampler this record configures, so flow counters can later be scaled
    /// by it.
    fn consume_options_record(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template: &parser::TemplateRecord,
        record: &[u8],
    ) {
        self.counters
            .options_records_processed
            .fetch_add(1, Ordering::Relaxed);
        if let Some(observation) = records::sampling_from_options_record(template, record) {
            self.sampling
                .observe(exporter, scope, observation.selector, observation.ratio);
        }
    }

    /// Scales a decoded flow record's byte and packet counters up to their
    /// estimated real values using the sampling ratio advertised for the
    /// record's sampler, matching it by the same `(exporter, scope, selector)`
    /// the options record was stored under. This runs per record, **before**
    /// aggregation, so records sampled at different rates are each normalized
    /// before they are summed or (later) stitched/deduplicated.
    ///
    /// The common unsampled case is free: when no sampling has been advertised
    /// at all, the whole cache is empty and the lookup is skipped.
    fn apply_sampling(&self, exporter: ExporterKey, scope: Scope, fields: &mut FlowFields) {
        if self.sampling.is_empty() {
            return;
        }
        let ratio = self.sampling.ratio(exporter, scope, fields.sampler);
        fields.bytes = ratio.expand(fields.bytes);
        fields.packets = ratio.expand(fields.packets);
    }

    /// Starts the background aging thread. Idle flows are evicted and long-lived
    /// flows are rolled over; both events are delivered through `on_emit`.
    ///
    /// The worker sweeps every `scan_interval` at wall-clock time. Contexts fed
    /// through the `_at` entry points should call [`Self::age_at`] instead (see
    /// the [time domains](Self#time-domains) note).
    ///
    /// Calling this again first stops any previously running aging thread.
    ///
    /// Aging lifecycle control — [`Self::start_aging`], [`Self::stop_aging`], and
    /// (over the FFI) `netflow_analyzer_create` / `netflow_analyzer_destroy` — is
    /// expected to be driven by a **single controlling thread**; these methods
    /// are not designed to be invoked concurrently with one another.
    ///
    /// Panics if the background worker thread cannot be spawned. Use
    /// [`Self::try_start_aging`] to handle that failure instead of unwinding
    /// (the C ABI does).
    pub fn start_aging<F>(&self, on_emit: F)
    where
        F: Fn(&FlowRecord) + Send + Sync + 'static,
    {
        self.try_start_aging(on_emit)
            .expect("failed to spawn the netflow aging thread");
    }

    /// Fallible form of [`Self::start_aging`]: returns the OS error instead of
    /// panicking when the background worker thread cannot be created. On success
    /// any previously running aging thread is stopped.
    pub fn try_start_aging<F>(&self, on_emit: F) -> std::io::Result<()>
    where
        F: Fn(&FlowRecord) + Send + Sync + 'static,
    {
        let handle = AgingHandle::spawn(
            self.flows.clone(),
            self.templates.clone(),
            self.counters.clone(),
            self.aging_cfg,
            now_unix_ns,
            on_emit,
        )?;
        // Swap the new handle in under the lock, then drop the previous one only
        // after the lock is released: dropping it joins its worker, and holding
        // `aging` across that join would deadlock a callback that locks `aging`.
        // A poisoned lock is recovered rather than propagated as a panic: the
        // guarded `Option<AgingHandle>` is always in a valid state.
        let previous = {
            let mut guard = self.aging.lock().unwrap_or_else(|e| e.into_inner());
            guard.replace(handle)
        };
        drop(previous);
        Ok(())
    }

    /// Stops the background aging thread, if running. When called by the single
    /// controlling thread (see [`Self::start_aging`]) it blocks until the worker
    /// has exited.
    ///
    /// Calling it re-entrantly from within an emission callback (on the aging
    /// thread itself) is **unsupported**, but is made non-deadlocking as a safety
    /// net so a misbehaving callback — or a `netflow_analyzer_destroy` mistakenly
    /// issued from one — cannot hang the process: a thread cannot join itself, so
    /// the handle is detached and this returns without waiting. In that case the
    /// worker is not guaranteed to have stopped when this returns, so do not rely
    /// on callback-invoked stop for shutdown.
    pub fn stop_aging(&self) {
        // Take the handle out under the lock, then stop/join it only after the
        // lock is released. Joining while holding `aging` would deadlock if the
        // worker's callback tries to lock `aging` (e.g. a re-entrant stop_aging).
        let handle = {
            let mut guard = self.aging.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        if let Some(mut handle) = handle {
            handle.stop();
        }
    }

    /// Runs one aging pass at `now_ns` (Unix nanoseconds) on the calling thread:
    /// evicts idle flows and rolls over active ones through `on_emit`, exactly
    /// as one background sweep would, and drops templates expired by `now_ns`.
    ///
    /// This is the deterministic counterpart of [`Self::start_aging`] for
    /// contexts fed through the `_at` entry points, such as capture replay.
    /// `on_emit` runs with no cache lock held. Returns the number of records
    /// emitted.
    pub fn age_at<F>(&self, now_ns: u64, on_emit: F) -> usize
    where
        F: Fn(&FlowRecord),
    {
        let emitted = std::cell::Cell::new(0usize);
        let counting = |record: &FlowRecord| {
            on_emit(record);
            emitted.set(emitted.get() + 1);
        };
        self.flows
            .sweep(&self.aging_cfg, &self.counters, &counting, now_ns);
        self.templates.sweep_due(now_ns);
        emitted.get()
    }

    /// Whether a background aging thread started by [`Self::start_aging`] is
    /// currently installed.
    pub fn is_aging(&self) -> bool {
        self.aging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Emits and clears every flow still resident in the cache.
    pub fn flush<F>(&self, on_emit: F)
    where
        F: Fn(&FlowRecord),
    {
        self.flows.flush_all(&self.counters, &on_emit);
    }

    /// Purges all cached state for one exporter/transport session, reclaiming
    /// its slots in every cache. Returns the number of flows emitted.
    ///
    /// This is the transport-session reset primitive. Its resident flows are
    /// emitted through `on_emit` **first** (so traffic accumulated since the
    /// last aging sweep is not lost), then its templates, clock, and sampling
    /// state are dropped. Call it before a key is retired — for example when an
    /// exporter restarts — so the bounded caches do not fill permanently with
    /// the stale state of gone sessions. See `docs/exporter-identity.md` for the key
    /// contract and listener key-rotation rules.
    ///
    /// Purge reclaims *local* cache capacity; it does not retract a key that
    /// was already emitted as identity (see the identity model). It also does
    /// not stop the background aging thread, so a concurrent sweep of the same
    /// exporter's flows may interleave; callers needing a strict boundary must
    /// coordinate with the aging worker as the identity model describes.
    ///
    /// Purge is **not** atomic against other cache access for `exporter`. While
    /// it runs, the caller must ensure nothing else ingests or decodes packets
    /// for this key — this covers `process_packet[_from][_at]`, the decode-only
    /// `decode_packet*` entry points (which still update template and clock
    /// state), and the key-`0` convenience wrappers — whether from another
    /// thread or re-entrantly from within `on_emit`. The flow cache is drained
    /// *before* the templates and clock state are dropped, so state added for
    /// this key mid-purge can be left behind inconsistently (a flow with no
    /// matching template, say) and could contaminate a reused session. This is
    /// the same dispatch fencing the identity model requires for listener key
    /// rotation.
    ///
    /// Emission callbacks (aging sweep, [`Self::flush`], and purge itself) run
    /// with no cache lock held, so calling purge from within one does not
    /// deadlock. Be aware it re-enters the emission callback for each flow it
    /// drains, and the non-atomicity above still applies.
    pub fn purge_exporter<F>(&self, exporter: ExporterKey, on_emit: F) -> usize
    where
        F: Fn(&FlowRecord),
    {
        let emitted = self
            .flows
            .purge_exporter(exporter, &self.counters, &on_emit);
        self.templates.purge_exporter(exporter);
        self.clocks.purge_exporter(exporter);
        self.sampling.purge_exporter(exporter);
        emitted
    }

    /// Non-blocking telemetry snapshot, including the live active-flow gauge.
    pub fn stats(&self) -> NetflowAnalyzerStats {
        self.counters.get_ffi_snapshot(self.flows.len() as u64)
    }

    /// Number of active flows currently resident in the state cache.
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    /// Number of templates currently resident in the template cache.
    pub fn active_templates(&self) -> usize {
        self.templates.len()
    }

    /// Looks up a cached template for `(exporter, scope, template_id)`.
    pub fn template(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template_id: u16,
    ) -> Option<Arc<parser::TemplateRecord>> {
        self.templates.get_latest(exporter, scope, template_id)
    }

    /// Number of clock states currently tracked across all exporters and scopes.
    pub fn active_clocks(&self) -> usize {
        self.clocks.len()
    }

    /// Looks up the clock observation state for `(exporter, scope)`.
    pub fn clock_state(&self, exporter: ExporterKey, scope: Scope) -> Option<clock::ClockState> {
        self.clocks.get(exporter, scope)
    }

    /// Number of samplers currently tracked across all exporters and scopes.
    pub fn active_samplers(&self) -> usize {
        self.sampling.len()
    }

    /// Looks up the sampling ratio learned for a specific sampler.
    pub fn sampler_ratio(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        selector: sampling::SamplerSelector,
    ) -> Option<sampling::SamplingRatio> {
        self.sampling.get(exporter, scope, selector)
    }
}

impl Default for FlowContext {
    fn default() -> Self {
        Self::new()
    }
}
