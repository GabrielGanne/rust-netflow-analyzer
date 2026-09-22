// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cache;
pub mod clock;
pub mod parser;
pub mod records;
pub mod scope;
pub mod stats;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cache::{
    AgingConfig, AgingHandle, FlowCache, TemplateCache, DEFAULT_MAX_FLOWS, DEFAULT_MAX_TEMPLATES,
};
use clock::{ClockConfig, ClockDecision, ClockTracker};
use parser::{
    ParsedHeader, FIRST_DATA_SET_ID, FLOWSET_ID_V9_OPTIONS, FLOWSET_ID_V9_TEMPLATE,
    IPFIX_HEADER_LEN, SET_ID_IPFIX_OPTIONS, SET_ID_IPFIX_TEMPLATE, V5_RECORD_LEN,
};
use records::{FlowFields, FlowRecord, RecordTimeContext};
use scope::{ExporterKey, Scope, SINGLE_EXPORTER};
use stats::{InternalCounters, NetflowAnalyzerStats};

/// Error returned when clock validation rejects an otherwise parseable packet.
pub const CLOCK_SKEW_ERROR: &str = "Packet dropped because exporter clock skew exceeds limit";

/// Error returned when an IPFIX message's declared `total_length` is impossible
/// or exceeds the received datagram.
const IPFIX_LENGTH_ERROR: &str = "IPFIX message total_length is inconsistent with the datagram";

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

/// Current wall-clock time as Unix nanoseconds, saturating at `u64::MAX`.
fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// Top-level engine configuration combining cache caps and aging timings.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub max_flows: usize,
    pub max_templates: usize,
    pub aging: AgingConfig,
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
/// caches are internally sharded, so concurrent `process_packet` calls do not
/// contend on a global lock.
pub struct FlowContext {
    pub counters: Arc<InternalCounters>,
    pub templates: Arc<TemplateCache>,
    pub flows: Arc<FlowCache>,
    pub clocks: Arc<ClockTracker>,
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
    pub fn process_packet(&self, raw_bytes: &[u8]) -> Result<usize, &'static str> {
        self.process_packet_at(raw_bytes, now_unix_ns())
    }

    /// Like [`Self::process_packet`], with an explicit Unix-nanosecond receipt
    /// timestamp. Capture readers should pass the packet's capture timestamp.
    ///
    /// This is the fused decode + aggregate entry point for the reserved
    /// single-exporter key. It is a thin wrapper over
    /// [`Self::process_packet_from_at`].
    pub fn process_packet_at(
        &self,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
    ) -> Result<usize, &'static str> {
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
    ) -> Result<usize, &'static str> {
        self.process_packet_from_at(exporter, raw_bytes, now_unix_ns())
    }

    /// Like [`Self::process_packet_from`], with an explicit Unix-nanosecond
    /// receipt timestamp.
    pub fn process_packet_from_at(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
    ) -> Result<usize, &'static str> {
        self.decode_at(
            exporter,
            raw_bytes,
            receipt_time_ns,
            &mut |exporter, scope, fields| {
                self.flows.upsert(exporter, scope, fields, &self.counters);
            },
        )
    }

    /// Decode-only counterpart of [`Self::process_packet`]: parses a datagram and
    /// emits each decoded data record through `sink` **without** touching the flow
    /// cache. Template and options-template state is still updated (it is required
    /// to decode), but no aggregation, timeouts, or eviction take place.
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
    ) -> Result<usize, &'static str> {
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
    ) -> Result<usize, &'static str> {
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
    ) -> Result<usize, &'static str> {
        self.decode_packet_from(SINGLE_EXPORTER, raw_bytes, sink)
    }

    /// Scope-aware decode-only entry point with an explicit receipt timestamp.
    /// See [`Self::decode_packet_scoped`].
    pub fn decode_packet_scoped_at(
        &self,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, &'static str> {
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
    ) -> Result<usize, &'static str> {
        self.decode_packet_from_at(exporter, raw_bytes, now_unix_ns(), sink)
    }

    /// Like [`Self::decode_packet_from`], with an explicit receipt timestamp.
    pub fn decode_packet_from_at(
        &self,
        exporter: ExporterKey,
        raw_bytes: &[u8],
        receipt_time_ns: u64,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> Result<usize, &'static str> {
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
    ) -> Result<usize, &'static str> {
        let (mut payload, header) = match parser::parse_packet_header(raw_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.counters
                    .pkts_parse_error
                    .fetch_add(1, Ordering::Relaxed);
                return Err("Failed to parse NetFlow header packet structure");
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
                return Err(IPFIX_LENGTH_ERROR);
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
                return Err(CLOCK_SKEW_ERROR);
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
            return Ok(self.process_v5_records(
                exporter,
                scope,
                payload,
                h.count as usize,
                time_context,
                sink,
            ));
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
                id if id == FLOWSET_ID_V9_TEMPLATE || id == SET_ID_IPFIX_TEMPLATE => {
                    match parser::parse_template_set(body) {
                        Ok((_, templates)) => {
                            for template in templates {
                                self.counters
                                    .templates_received
                                    .fetch_add(1, Ordering::Relaxed);
                                self.templates.insert(exporter, scope, template);
                            }
                        }
                        Err(_) => {
                            rejected_template = true;
                            break;
                        }
                    }
                }
                // Options templates describe the layout of options data records
                // (exporter metadata). Decode and store them so their data sets
                // can later be interpreted rather than silently dropped.
                id if id == FLOWSET_ID_V9_OPTIONS => {
                    match parser::parse_v9_options_template_set(body) {
                        Ok((_, templates)) => {
                            self.store_options_templates(exporter, scope, templates)
                        }
                        Err(_) => {
                            rejected_template = true;
                            break;
                        }
                    }
                }
                id if id == SET_ID_IPFIX_OPTIONS => {
                    match parser::parse_ipfix_options_template_set(body) {
                        Ok((_, templates)) => {
                            self.store_options_templates(exporter, scope, templates)
                        }
                        Err(_) => {
                            rejected_template = true;
                            break;
                        }
                    }
                }
                id if id >= FIRST_DATA_SET_ID => {
                    data_records +=
                        self.process_data_set(exporter, scope, id, body, time_context, sink);
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
    ) {
        for template in templates {
            self.counters
                .options_templates_received
                .fetch_add(1, Ordering::Relaxed);
            self.templates.insert(exporter, scope, template);
        }
    }

    /// Decodes up to `count` fixed-format NetFlow v5 records from the payload.
    fn process_v5_records(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        payload: &[u8],
        count: usize,
        time_context: RecordTimeContext,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> usize {
        let mut decoded = 0usize;
        // Trust the header count but never read past the buffer.
        let available = payload.len() / V5_RECORD_LEN;
        for record in parser::split_fixed_records(payload, V5_RECORD_LEN)
            .into_iter()
            .take(count.min(available))
        {
            if let Some(fields) = FlowFields::from_v5_record_at(record, Some(time_context)) {
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
    /// `(exporter, scope)` keys the template lookup and is forwarded to `sink`.
    fn process_data_set(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template_id: u16,
        body: &[u8],
        time_context: RecordTimeContext,
        sink: &mut dyn FnMut(ExporterKey, Scope, &FlowFields),
    ) -> usize {
        // Without the template we cannot interpret the records yet; the exporter
        // will resend it periodically, so we simply skip until then.
        let Some(template) = self.templates.get(exporter, scope, template_id) else {
            return 0;
        };

        // Options data records carry exporter metadata, not observed flows, so
        // they are decoded and counted separately without polluting the flow
        // cache. `count` therefore tracks only flow records for the return value.
        let is_options = template.is_options;
        let mut count = 0usize;

        let mut consume = |fields: &FlowFields| {
            if is_options {
                self.counters
                    .options_records_processed
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                sink(exporter, scope, fields);
                count += 1;
            }
        };

        match template.fixed_length {
            Some(record_len) if record_len > 0 => {
                for record in parser::split_fixed_records(body, record_len) {
                    if let Some((fields, _)) =
                        FlowFields::from_record_sized_at(&template, record, Some(time_context))
                    {
                        consume(&fields);
                    }
                }
            }
            // Variable-length template: boundaries are only known after decoding.
            None => {
                let mut cursor = body;
                while !cursor.is_empty() {
                    match FlowFields::from_record_sized_at(&template, cursor, Some(time_context)) {
                        Some((fields, consumed)) if consumed > 0 && consumed <= cursor.len() => {
                            consume(&fields);
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

    /// Starts the background aging thread. Idle flows are evicted and long-lived
    /// flows are rolled over; both events are delivered through `on_emit`.
    ///
    /// Calling this again first stops any previously running aging thread.
    pub fn start_aging<F>(&self, on_emit: F)
    where
        F: Fn(&FlowRecord) + Send + Sync + 'static,
    {
        let handle = AgingHandle::spawn(
            self.flows.clone(),
            self.counters.clone(),
            self.aging_cfg,
            on_emit,
        );
        let mut guard = self.aging.lock().expect("aging mutex poisoned");
        *guard = Some(handle); // dropping the old handle joins its thread
    }

    /// Stops the background aging thread, if running.
    pub fn stop_aging(&self) {
        let mut guard = self.aging.lock().expect("aging mutex poisoned");
        if let Some(mut handle) = guard.take() {
            handle.stop();
        }
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
    /// last aging sweep is not lost), then its templates and clock state are
    /// dropped. Call it before a key is retired — for example when an exporter
    /// restarts — so the bounded caches do not fill permanently with the stale
    /// state of gone sessions. See `docs/exporter-identity.md` for the key
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
    /// Like [`Self::flush`], purge acquires cache locks, so it must not be
    /// called from within an emission callback (a background aging sweep, a
    /// `flush`, or another purge) that is still holding those locks, or it will
    /// deadlock. Moving emission callbacks outside the cache locks is tracked
    /// separately as FFI-safety work.
    pub fn purge_exporter<F>(&self, exporter: ExporterKey, on_emit: F) -> usize
    where
        F: Fn(&FlowRecord),
    {
        let emitted = self
            .flows
            .purge_exporter(exporter, &self.counters, &on_emit);
        self.templates.purge_exporter(exporter);
        self.clocks.purge_exporter(exporter);
        emitted
    }

    /// Non-blocking telemetry snapshot, including the live active-flow gauge.
    pub fn stats(&self) -> NetflowAnalyzerStats {
        self.counters.get_ffi_snapshot(self.flows.len() as u64)
    }
}

impl Default for FlowContext {
    fn default() -> Self {
        Self::new()
    }
}
