pub mod cache;
pub mod parser;
pub mod records;
pub mod stats;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use cache::{
    AgingConfig, AgingHandle, FlowCache, TemplateCache, DEFAULT_MAX_FLOWS, DEFAULT_MAX_TEMPLATES,
};
use parser::{
    ParsedHeader, FIRST_DATA_SET_ID, FLOWSET_ID_V9_OPTIONS, FLOWSET_ID_V9_TEMPLATE,
    SET_ID_IPFIX_OPTIONS, SET_ID_IPFIX_TEMPLATE, V5_RECORD_LEN,
};
use records::{FlowFields, FlowRecord, RecordTimeContext};
use stats::{InternalCounters, LibraryStatsFFI};

/// Top-level engine configuration combining cache caps and aging timings.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub max_flows: usize,
    pub max_templates: usize,
    pub aging: AgingConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            max_templates: DEFAULT_MAX_TEMPLATES,
            aging: AgingConfig::default(),
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
    aging_cfg: AgingConfig,
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
            aging_cfg: cfg.aging,
            aging: Mutex::new(None),
        }
    }

    /// Decodes a single exported datagram, updating template and flow state.
    ///
    /// Returns the number of data records successfully folded into the cache.
    /// The input is borrowed and never copied: parsing operates directly on the
    /// caller's buffer.
    pub fn process_packet(&self, raw_bytes: &[u8]) -> Result<usize, &'static str> {
        let (mut payload, header) = match parser::parse_packet_header(raw_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.counters
                    .malformed_packets
                    .fetch_add(1, Ordering::Relaxed);
                return Err("Failed to parse NetFlow header packet structure");
            }
        };

        self.counters
            .packets_processed
            .fetch_add(1, Ordering::Relaxed);

        // NetFlow v5 is template-less: the payload is simply `count` fixed-size
        // records, so it takes a dedicated decode path instead of a set walk.
        if let ParsedHeader::V5(ref h) = header {
            let time_context = RecordTimeContext {
                export_time_ns: header.export_time_ns(),
                system_uptime_ms: header.system_uptime_ms(),
            };
            return Ok(self.process_v5_records(payload, h.count as usize, time_context));
        }

        let domain = header.domain_id();
        let time_context = RecordTimeContext {
            export_time_ns: header.export_time_ns(),
            system_uptime_ms: header.system_uptime_ms(),
        };
        let mut data_records = 0usize;

        // Walk each FlowSet/Set in the payload. Any structural inconsistency
        // stops the walk gracefully rather than panicking.
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
                    if let Ok((_, templates)) = parser::parse_template_set(body) {
                        for template in templates {
                            self.counters
                                .templates_received
                                .fetch_add(1, Ordering::Relaxed);
                            self.templates.insert(domain, template);
                        }
                    }
                }
                // Options templates carry metadata, not flow records; skip them.
                id if id == FLOWSET_ID_V9_OPTIONS || id == SET_ID_IPFIX_OPTIONS => {}
                id if id >= FIRST_DATA_SET_ID => {
                    data_records += self.process_data_set(domain, id, body, time_context);
                }
                // Reserved/unknown set ids (e.g. 4..=255) are ignored.
                _ => {}
            }
        }

        self.counters
            .data_records_processed
            .fetch_add(data_records as u64, Ordering::Relaxed);

        Ok(data_records)
    }

    /// Decodes up to `count` fixed-format NetFlow v5 records from the payload.
    fn process_v5_records(
        &self,
        payload: &[u8],
        count: usize,
        time_context: RecordTimeContext,
    ) -> usize {
        let mut decoded = 0usize;
        // Trust the header count but never read past the buffer.
        let available = payload.len() / V5_RECORD_LEN;
        for record in parser::split_fixed_records(payload, V5_RECORD_LEN)
            .into_iter()
            .take(count.min(available))
        {
            if let Some(fields) = FlowFields::from_v5_record_at(record, Some(time_context)) {
                self.flows.upsert(&fields, &self.counters);
                decoded += 1;
            }
        }
        self.counters
            .data_records_processed
            .fetch_add(decoded as u64, Ordering::Relaxed);
        decoded
    }

    /// Decodes every data record in a data FlowSet body against its template.
    fn process_data_set(
        &self,
        domain: u32,
        template_id: u16,
        body: &[u8],
        time_context: RecordTimeContext,
    ) -> usize {
        // Without the template we cannot interpret the records yet; the exporter
        // will resend it periodically, so we simply skip until then.
        let Some(template) = self.templates.get(domain, template_id) else {
            return 0;
        };

        let mut count = 0usize;

        match template.fixed_length {
            Some(record_len) if record_len > 0 => {
                for record in parser::split_fixed_records(body, record_len) {
                    if let Some((fields, _)) =
                        FlowFields::from_record_sized_at(&template, record, Some(time_context))
                    {
                        self.flows.upsert_in_domain(domain, &fields, &self.counters);
                        count += 1;
                    }
                }
            }
            // Variable-length template: boundaries are only known after decoding.
            None => {
                let mut cursor = body;
                while !cursor.is_empty() {
                    match FlowFields::from_record_sized_at(&template, cursor, Some(time_context)) {
                        Some((fields, consumed)) if consumed > 0 && consumed <= cursor.len() => {
                            self.flows.upsert_in_domain(domain, &fields, &self.counters);
                            count += 1;
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

    /// Non-blocking telemetry snapshot, including the live active-flow gauge.
    pub fn stats(&self) -> LibraryStatsFFI {
        self.counters.get_ffi_snapshot(self.flows.len() as u64)
    }
}

impl Default for FlowContext {
    fn default() -> Self {
        Self::new()
    }
}
