use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::parser::TemplateRecord;
use crate::records::{FlowFields, FlowKey, FlowRecord};
use crate::stats::InternalCounters;
use std::sync::atomic::AtomicBool;

/// Template lookup key: templates are scoped to the exporter's observation
/// domain so that identical template ids from different domains never collide.
pub type TemplateKey = (u32, u16);

/// Default hard caps. These bound heap growth even under a hostile exporter
/// that floods the engine with unique templates or flows.
pub const DEFAULT_MAX_TEMPLATES: usize = 65_536;
pub const DEFAULT_MAX_FLOWS: usize = 1_000_000;

/// Concurrent, size-bounded cache of decoded templates.
pub struct TemplateCache {
    map: DashMap<TemplateKey, Arc<TemplateRecord>>,
    max_templates: usize,
}

impl TemplateCache {
    pub fn new(max_templates: usize) -> Self {
        Self {
            map: DashMap::new(),
            max_templates,
        }
    }

    /// Inserts or refreshes a template. Re-defining an existing template id is
    /// always allowed (exporters legitimately re-issue templates); only the
    /// introduction of a brand new key is subject to the hard cap.
    pub fn insert(&self, domain: u32, template: TemplateRecord) -> bool {
        let key = (domain, template.template_id);
        if !self.map.contains_key(&key) && self.map.len() >= self.max_templates {
            return false;
        }
        self.map.insert(key, Arc::new(template));
        true
    }

    /// Cheap, lock-light lookup returning a shared handle to the template.
    pub fn get(&self, domain: u32, template_id: u16) -> Option<Arc<TemplateRecord>> {
        self.map
            .get(&(domain, template_id))
            .map(|e| e.value().clone())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Concurrent, size-bounded cache of active flow state.
pub struct FlowCache {
    map: DashMap<FlowKey, FlowRecord>,
    max_flows: usize,
}

impl FlowCache {
    pub fn new(max_flows: usize) -> Self {
        Self {
            map: DashMap::new(),
            max_flows,
        }
    }

    /// Folds a freshly decoded record into the persistent flow state.
    ///
    /// Existing flows accumulate counters and update both exporter and local
    /// observation timestamps.
    /// New flows are admitted only while the cache is below its hard cap; once
    /// full, the record is dropped and counted rather than risking OOM.
    pub fn upsert(&self, fields: &FlowFields, counters: &InternalCounters) {
        self.upsert_in_domain(0, fields, counters);
    }

    /// Like [`Self::upsert`], but scopes an exported `flowId` to the observation
    /// domain in which the exporter guarantees it is unique.
    pub fn upsert_in_domain(
        &self,
        observation_domain_id: u32,
        fields: &FlowFields,
        counters: &InternalCounters,
    ) {
        let key = fields.key_in_domain(observation_domain_id);
        if let Some(mut existing) = self.map.get_mut(&key) {
            existing.bytes = existing.bytes.saturating_add(fields.bytes);
            existing.packets = existing.packets.saturating_add(fields.packets);
            if fields.start_time_ns != 0
                && (existing.start_time_ns == 0 || fields.start_time_ns < existing.start_time_ns)
            {
                existing.start_time_ns = fields.start_time_ns;
            }
            existing.end_time_ns = existing.end_time_ns.max(fields.end_time_ns);
            if fields.original_start_time_ns != 0
                && (existing.original_start_time_ns == 0
                    || fields.original_start_time_ns < existing.original_start_time_ns)
            {
                existing.original_start_time_ns = fields.original_start_time_ns;
            }
            existing.original_end_time_ns = existing
                .original_end_time_ns
                .max(fields.original_end_time_ns);
            existing.last_observed = Instant::now();
            return;
        }

        if self.map.len() >= self.max_flows {
            counters.flows_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        self.map
            .insert(key, FlowRecord::from_fields(fields, Instant::now()));
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Sweeps the cache once, evicting idle flows and rolling over flows that
    /// have exceeded their active timeout. Eviction and active-rollover events
    /// are emitted through `on_emit` before the entry is mutated or removed.
    ///
    /// Iteration is shard-isolated (DashMap's `retain`), so worker threads keep
    /// processing other shards while the aging sweep runs.
    pub fn sweep<F>(&self, cfg: &AgingConfig, counters: &InternalCounters, on_emit: &F)
    where
        F: Fn(&FlowRecord),
    {
        let now = Instant::now();
        self.map.retain(|_key, record| {
            // Idle timeout: no activity for too long -> emit and evict.
            if now.duration_since(record.last_observed) >= cfg.idle_timeout {
                on_emit(record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
                return false;
            }

            // Active timeout: long-lived flow -> emit an interim snapshot and
            // reset counters without destroying the cache entry.
            if now.duration_since(record.first_observed) >= cfg.active_timeout {
                on_emit(record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
                record.bytes = 0;
                record.packets = 0;
                record.first_observed = now;
            }

            true
        });
    }

    /// Drains every remaining flow, emitting each one. Used on shutdown so the
    /// host never loses the residual state still held in the cache.
    pub fn flush_all<F>(&self, counters: &InternalCounters, on_emit: &F)
    where
        F: Fn(&FlowRecord),
    {
        self.map.retain(|_key, record| {
            on_emit(record);
            counters.flows_output.fetch_add(1, Ordering::Relaxed);
            false
        });
    }
}

/// Tunable timing parameters for the background aging engine.
#[derive(Debug, Clone, Copy)]
pub struct AgingConfig {
    /// Evict a flow after this much inactivity.
    pub idle_timeout: Duration,
    /// Emit an interim snapshot once a flow has lived this long.
    pub active_timeout: Duration,
    /// Delay between successive cache sweeps.
    pub scan_interval: Duration,
}

impl Default for AgingConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            active_timeout: Duration::from_secs(120),
            scan_interval: Duration::from_secs(5),
        }
    }
}

/// Owns the background aging thread and the flag used to stop it cleanly.
pub struct AgingHandle {
    running: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl AgingHandle {
    /// Spawns a low-overhead background worker that periodically sweeps `flows`.
    pub fn spawn<F>(
        flows: Arc<FlowCache>,
        counters: Arc<InternalCounters>,
        cfg: AgingConfig,
        on_emit: F,
    ) -> Self
    where
        F: Fn(&FlowRecord) + Send + Sync + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();

        let join = thread::Builder::new()
            .name("netflow-aging".to_string())
            .spawn(move || {
                while thread_running.load(Ordering::Relaxed) {
                    // Sleep in small slices so shutdown stays responsive even
                    // when the scan interval is long.
                    let mut waited = Duration::ZERO;
                    let slice = Duration::from_millis(100);
                    while waited < cfg.scan_interval && thread_running.load(Ordering::Relaxed) {
                        thread::sleep(slice);
                        waited += slice;
                    }

                    if !thread_running.load(Ordering::Relaxed) {
                        break;
                    }

                    flows.sweep(&cfg, &counters, &on_emit);
                }
            })
            .expect("failed to spawn aging thread");

        Self {
            running,
            join: Some(join),
        }
    }

    /// Signals the worker to stop and blocks until it has fully exited.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AgingHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{TemplateField, TemplateRecord};
    use std::sync::atomic::AtomicUsize;

    fn sample_template(id: u16) -> TemplateRecord {
        TemplateRecord::from_fields(
            id,
            vec![TemplateField {
                type_id: 8,
                length: 4,
                enterprise_number: None,
            }],
        )
    }

    fn fields(proto: u8) -> FlowFields {
        FlowFields {
            flow_id: None,
            src_ip: [0u8; 16],
            dst_ip: [0u8; 16],
            src_port: 1,
            dst_port: 2,
            proto,
            bytes: 100,
            packets: 1,
            start_time_ns: 0,
            end_time_ns: 0,
            original_start_time_ns: 0,
            original_end_time_ns: 0,
        }
    }

    #[test]
    fn template_cache_insert_get_and_scope() {
        let cache = TemplateCache::new(10);
        assert!(cache.is_empty());
        assert!(cache.insert(1, sample_template(256)));
        assert!(cache.insert(2, sample_template(256))); // same id, different domain

        assert_eq!(cache.len(), 2);
        assert!(cache.get(1, 256).is_some());
        assert!(cache.get(2, 256).is_some());
        assert!(cache.get(3, 256).is_none());
    }

    #[test]
    fn template_cache_enforces_cap_but_allows_redefinition() {
        let cache = TemplateCache::new(1);
        assert!(cache.insert(1, sample_template(256)));
        // New distinct key rejected once full.
        assert!(!cache.insert(1, sample_template(257)));
        // Re-defining an existing key is always allowed.
        assert!(cache.insert(1, sample_template(256)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn flow_cache_upsert_accumulates() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        let mut first = fields(6);
        first.start_time_ns = 20;
        first.end_time_ns = 30;
        first.original_start_time_ns = 25;
        first.original_end_time_ns = 35;
        cache.upsert(&first, &counters);
        let mut second = fields(6);
        second.start_time_ns = 10;
        second.end_time_ns = 40;
        second.original_start_time_ns = 15;
        second.original_end_time_ns = 45;
        cache.upsert(&second, &counters); // same key

        assert_eq!(cache.len(), 1);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 0);
        let record = cache.map.get(&first.key()).unwrap();
        assert_eq!(record.bytes, 200);
        assert_eq!(record.packets, 2);
        assert_eq!(record.start_time_ns, 10);
        assert_eq!(record.end_time_ns, 40);
        assert_eq!(record.original_start_time_ns, 15);
        assert_eq!(record.original_end_time_ns, 45);
    }

    #[test]
    fn flow_id_overrides_tuple_and_is_scoped_to_domain() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        let mut first = fields(6);
        first.flow_id = Some(99);
        let mut changed_tuple = fields(17);
        changed_tuple.flow_id = Some(99);

        cache.upsert_in_domain(10, &first, &counters);
        cache.upsert_in_domain(10, &changed_tuple, &counters);
        assert_eq!(cache.len(), 1, "flowId takes precedence over the tuple");

        cache.upsert_in_domain(11, &changed_tuple, &counters);
        assert_eq!(cache.len(), 2, "flowId is unique only within its domain");
    }

    #[test]
    fn flow_cache_respects_cap() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(1);
        cache.upsert(&fields(6), &counters); // admitted
        cache.upsert(&fields(17), &counters); // distinct key -> dropped

        assert_eq!(cache.len(), 1);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_evicts_idle_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(&fields(6), &counters);

        let cfg = AgingConfig {
            idle_timeout: Duration::ZERO, // everything is "idle"
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_secs(1),
        };
        let emitted = AtomicUsize::new(0);
        cache.sweep(&cfg, &counters, &|_r| {
            emitted.fetch_add(1, Ordering::Relaxed);
        });

        assert_eq!(cache.len(), 0);
        assert_eq!(emitted.load(Ordering::Relaxed), 1);
        assert_eq!(counters.flows_output.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_rolls_over_active_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(&fields(6), &counters);

        let cfg = AgingConfig {
            idle_timeout: Duration::from_secs(3600), // never idle
            active_timeout: Duration::ZERO,          // always rolled over
            scan_interval: Duration::from_secs(1),
        };
        let emitted = AtomicUsize::new(0);
        cache.sweep(&cfg, &counters, &|_r| {
            emitted.fetch_add(1, Ordering::Relaxed);
        });

        // Entry survives a rollover but its counters are reset.
        assert_eq!(cache.len(), 1);
        assert_eq!(emitted.load(Ordering::Relaxed), 1);
        assert_eq!(counters.flows_output.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_keeps_fresh_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(&fields(6), &counters);

        let cfg = AgingConfig {
            idle_timeout: Duration::from_secs(3600),
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_secs(1),
        };
        cache.sweep(&cfg, &counters, &|_r| panic!("should not emit"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn flush_all_drains_cache() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(&fields(6), &counters);
        cache.upsert(&fields(17), &counters);

        let emitted = AtomicUsize::new(0);
        cache.flush_all(&counters, &|_r| {
            emitted.fetch_add(1, Ordering::Relaxed);
        });

        assert!(cache.is_empty());
        assert_eq!(emitted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn aging_config_defaults() {
        let cfg = AgingConfig::default();
        assert_eq!(cfg.idle_timeout, Duration::from_secs(30));
        assert_eq!(cfg.active_timeout, Duration::from_secs(120));
        assert_eq!(cfg.scan_interval, Duration::from_secs(5));
    }

    #[test]
    fn aging_handle_runs_and_stops() {
        let counters = Arc::new(InternalCounters::default());
        let flows = Arc::new(FlowCache::new(10));
        flows.upsert(&fields(6), &counters);

        let cfg = AgingConfig {
            idle_timeout: Duration::ZERO,
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_millis(10),
        };
        let emitted = Arc::new(AtomicUsize::new(0));
        let sink = emitted.clone();
        let mut handle = AgingHandle::spawn(flows.clone(), counters.clone(), cfg, move |_r| {
            sink.fetch_add(1, Ordering::Relaxed);
        });

        // Give the worker time to perform at least one sweep.
        thread::sleep(Duration::from_millis(300));
        handle.stop();

        assert_eq!(flows.len(), 0, "idle flow should be evicted");
        assert!(emitted.load(Ordering::Relaxed) >= 1);
    }
}
