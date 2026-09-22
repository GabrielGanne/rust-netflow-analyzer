// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::parser::TemplateRecord;
use crate::records::{FlowFields, FlowKey, FlowRecord};
use crate::scope::{ExporterKey, Scope};
use crate::stats::InternalCounters;
use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Template lookup key: templates are scoped to the exporter/transport session
/// and its protocol-tagged observation [`Scope`], so identical template ids from
/// different exporters, protocol versions, or domains never collide.
pub type TemplateKey = (ExporterKey, Scope, u16);

/// Default hard caps. These bound heap growth even under a hostile exporter
/// that floods the engine with unique templates or flows.
pub const DEFAULT_MAX_TEMPLATES: usize = 65_536;
pub const DEFAULT_MAX_FLOWS: usize = 1_000_000;

/// Concurrent, size-bounded cache of decoded templates.
pub struct TemplateCache {
    map: DashMap<TemplateKey, Arc<TemplateRecord>>,
    max_templates: usize,
    /// Live entry count, reserved atomically so the hard cap cannot be
    /// overshot by concurrent writers racing on a `len()` snapshot.
    count: AtomicUsize,
}

impl TemplateCache {
    pub fn new(max_templates: usize) -> Self {
        Self {
            map: DashMap::new(),
            max_templates,
            count: AtomicUsize::new(0),
        }
    }

    /// Inserts or refreshes a template. Re-defining an existing template id is
    /// always allowed (exporters legitimately re-issue templates); only the
    /// introduction of a brand new key is subject to the hard cap.
    ///
    /// The vacant path holds the per-key shard lock (via the `Entry` API) and
    /// reserves a slot with an atomic compare-and-update, so two threads can
    /// never both admit a new key past the cap.
    pub fn insert(&self, exporter: ExporterKey, scope: Scope, template: TemplateRecord) -> bool {
        let key = (exporter, scope, template.template_id);
        match self.map.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.insert(Arc::new(template));
                true
            }
            Entry::Vacant(entry) => {
                if self.reserve_slot() {
                    entry.insert(Arc::new(template));
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Atomically claims one slot below the hard cap, returning `false` when the
    /// cache is already full.
    fn reserve_slot(&self) -> bool {
        self.count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.max_templates).then_some(count + 1)
            })
            .is_ok()
    }

    /// Cheap, lock-light lookup returning a shared handle to the template.
    pub fn get(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template_id: u16,
    ) -> Option<Arc<TemplateRecord>> {
        self.map
            .get(&(exporter, scope, template_id))
            .map(|e| e.value().clone())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drops every template belonging to `exporter`, across all of its scopes
    /// and template ids, releasing each reserved capacity slot. Returns the
    /// number of templates removed. Part of the per-key purge that lets a
    /// transport session be retired without leaking bounded cache slots.
    pub fn purge_exporter(&self, exporter: ExporterKey) -> usize {
        let mut removed = 0usize;
        let count = &self.count;
        self.map.retain(|key, _template| {
            if key.0 == exporter {
                count.fetch_sub(1, Ordering::Relaxed);
                removed += 1;
                return false;
            }
            true
        });
        removed
    }
}

/// Concurrent, size-bounded cache of active flow state.
pub struct FlowCache {
    map: DashMap<FlowKey, FlowRecord>,
    max_flows: usize,
    /// Live entry count, reserved atomically so the hard cap cannot be
    /// overshot by concurrent writers racing on a `len()` snapshot.
    count: AtomicUsize,
}

impl FlowCache {
    pub fn new(max_flows: usize) -> Self {
        Self {
            map: DashMap::new(),
            max_flows,
            count: AtomicUsize::new(0),
        }
    }

    /// Folds a freshly decoded record into the persistent flow state, scoped to
    /// the exporter/transport session and protocol-tagged observation [`Scope`]
    /// it belongs to.
    ///
    /// Existing flows accumulate counters and update both exporter and local
    /// observation timestamps.
    /// New flows are admitted only while the cache is below its hard cap; once
    /// full, the record is dropped and counted rather than risking OOM.
    pub fn upsert(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        fields: &FlowFields,
        counters: &InternalCounters,
    ) {
        let key = fields.key(exporter, scope);
        // The `Entry` API holds the shard lock for `key`, so the vacant branch
        // (which reserves a capacity slot) cannot race another writer inserting
        // the same key.
        match self.map.entry(key) {
            Entry::Occupied(mut occupied) => {
                let existing = occupied.get_mut();
                existing.bytes = existing.bytes.saturating_add(fields.bytes);
                existing.packets = existing.packets.saturating_add(fields.packets);
                if fields.start_time_ns != 0
                    && (existing.start_time_ns == 0
                        || fields.start_time_ns < existing.start_time_ns)
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
                // Descriptive metadata is kept from the first record that carried
                // it; fill in anything a later record adds without overwriting.
                existing.merge_metadata_from(fields);
                existing.last_observed = Instant::now();
            }
            Entry::Vacant(vacant) => {
                if self.reserve_slot() {
                    vacant.insert(FlowRecord::from_fields(
                        fields,
                        exporter,
                        scope,
                        Instant::now(),
                    ));
                } else {
                    counters.flows_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Atomically claims one slot below the hard cap, returning `false` when the
    /// cache is already full.
    fn reserve_slot(&self) -> bool {
        self.count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.max_flows).then_some(count + 1)
            })
            .is_ok()
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
        let count = &self.count;
        self.map.retain(|_key, record| {
            // Idle timeout: no activity for too long -> emit and evict.
            if now.duration_since(record.last_observed) >= cfg.idle_timeout {
                on_emit(record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
                // Release the reserved capacity slot as the entry leaves.
                count.fetch_sub(1, Ordering::Relaxed);
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
        let count = &self.count;
        self.map.retain(|_key, record| {
            on_emit(record);
            counters.flows_output.fetch_add(1, Ordering::Relaxed);
            // Release the reserved capacity slot as the entry leaves.
            count.fetch_sub(1, Ordering::Relaxed);
            false
        });
    }

    /// Emits and removes every flow belonging to `exporter`, across all of its
    /// scopes, releasing each reserved capacity slot. Returns the number of
    /// flows emitted.
    ///
    /// This drains a single transport session's flows through the normal
    /// emission path (so traffic accumulated since the last sweep is not lost)
    /// as the first half of a per-key purge; the caller then drops that key's
    /// templates and clock state.
    ///
    /// Each record is removed with a brief per-shard lock and only then handed
    /// to `on_emit`, so a slow or re-entrant callback cannot block ingestion or
    /// deadlock on a still-held shard write lock. Records are removed and
    /// emitted one at a time, so the larger `FlowRecord`s are never duplicated
    /// and the flows not yet reached stay in the cache if a callback unwinds.
    /// The purge first snapshots the matching keys: a transient allocation
    /// proportional to the number of flows this exporter owns, but of the small
    /// [`FlowKey`]s rather than the records. This guarantees only
    /// deadlock-freedom: purge is **not** atomic against concurrent or
    /// re-entrant ingestion for the same exporter, which the caller must fence
    /// (see [`crate::FlowContext::purge_exporter`]).
    pub fn purge_exporter<F>(
        &self,
        exporter: ExporterKey,
        counters: &InternalCounters,
        on_emit: &F,
    ) -> usize
    where
        F: Fn(&FlowRecord),
    {
        // Snapshot the matching keys under brief read locks (dropped with the
        // iterator), then remove and emit them one at a time so no user
        // callback ever runs while a shard lock is held.
        let keys: Vec<FlowKey> = self
            .map
            .iter()
            .filter(|entry| entry.key().exporter == exporter)
            .map(|entry| *entry.key())
            .collect();

        let mut emitted = 0usize;
        for key in keys {
            // `remove` takes the shard write lock only for the removal and
            // returns the owned record; the lock is released before `on_emit`.
            if let Some((_key, record)) = self.map.remove(&key) {
                // Release the reserved capacity slot as the entry leaves.
                self.count.fetch_sub(1, Ordering::Relaxed);
                on_emit(&record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
                emitted += 1;
            }
        }
        emitted
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
    use crate::scope::SINGLE_EXPORTER;
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
            src_port: 1,
            dst_port: 2,
            proto,
            bytes: 100,
            packets: 1,
            ..Default::default()
        }
    }

    /// A representative scope for the flow-cache tests that do not exercise
    /// scope separation directly.
    const TEST_SCOPE: Scope = Scope::V9Domain(0);

    #[test]
    fn template_cache_insert_get_and_scope() {
        let cache = TemplateCache::new(10);
        assert!(cache.is_empty());
        let d1 = Scope::V9Domain(1);
        let d2 = Scope::V9Domain(2);
        let d3 = Scope::V9Domain(3);
        assert!(cache.insert(SINGLE_EXPORTER, d1, sample_template(256)));
        assert!(cache.insert(SINGLE_EXPORTER, d2, sample_template(256))); // same id, different domain

        assert_eq!(cache.len(), 2);
        assert!(cache.get(SINGLE_EXPORTER, d1, 256).is_some());
        assert!(cache.get(SINGLE_EXPORTER, d2, 256).is_some());
        assert!(cache.get(SINGLE_EXPORTER, d3, 256).is_none());
    }

    #[test]
    fn template_cache_scopes_by_exporter_and_protocol() {
        let cache = TemplateCache::new(10);
        // Same numeric domain id is a distinct key per exporter and per protocol.
        assert!(cache.insert(1, Scope::V9Domain(7), sample_template(256)));
        assert!(cache.insert(2, Scope::V9Domain(7), sample_template(256)));
        assert!(cache.insert(1, Scope::IpfixDomain(7), sample_template(256)));
        assert!(cache.insert(
            1,
            Scope::V5Engine {
                engine_type: 0,
                engine_id: 7,
            },
            sample_template(256),
        ));

        assert_eq!(cache.len(), 4);
        assert!(cache.get(1, Scope::V9Domain(7), 256).is_some());
        assert!(cache.get(2, Scope::V9Domain(7), 256).is_some());
        assert!(cache.get(1, Scope::IpfixDomain(7), 256).is_some());
        // A different exporter's IPFIX domain 7 was never installed.
        assert!(cache.get(2, Scope::IpfixDomain(7), 256).is_none());
    }

    #[test]
    fn template_cache_enforces_cap_but_allows_redefinition() {
        let cache = TemplateCache::new(1);
        let d1 = Scope::V9Domain(1);
        assert!(cache.insert(SINGLE_EXPORTER, d1, sample_template(256)));
        // New distinct key rejected once full.
        assert!(!cache.insert(SINGLE_EXPORTER, d1, sample_template(257)));
        // Re-defining an existing key is always allowed.
        assert!(cache.insert(SINGLE_EXPORTER, d1, sample_template(256)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn template_cache_purge_drops_only_the_exporter() {
        let cache = TemplateCache::new(10);
        let d = Scope::V9Domain(1);
        assert!(cache.insert(1, d, sample_template(256)));
        assert!(cache.insert(1, Scope::IpfixDomain(2), sample_template(300)));
        assert!(cache.insert(2, d, sample_template(256)));
        assert_eq!(cache.len(), 3);

        assert_eq!(cache.purge_exporter(1), 2, "both of exporter 1's templates");
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1, d, 256).is_none());
        assert!(cache.get(2, d, 256).is_some(), "other exporter untouched");

        // The freed slots are reusable: re-adding under the purged key succeeds
        // even in a cache that would otherwise be near a low cap.
        assert!(cache.insert(1, d, sample_template(256)));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn flow_cache_purge_emits_drains_and_reclaims_slots() {
        let counters = InternalCounters::default();
        // Cap of 2 so we can prove the freed slot becomes reusable afterwards.
        let cache = FlowCache::new(2);
        cache.upsert(1, TEST_SCOPE, &fields(6), &counters);
        cache.upsert(2, TEST_SCOPE, &fields(6), &counters);
        assert_eq!(cache.len(), 2);

        let emitted = AtomicUsize::new(0);
        let drained = cache.purge_exporter(1, &counters, &|record| {
            assert_eq!(record.exporter, 1, "only exporter 1's flows are emitted");
            emitted.fetch_add(1, Ordering::Relaxed);
        });

        assert_eq!(drained, 1);
        assert_eq!(emitted.load(Ordering::Relaxed), 1);
        assert_eq!(counters.flows_output.load(Ordering::Relaxed), 1);
        assert_eq!(cache.len(), 1, "exporter 2's flow survives");

        // The reclaimed slot is available again: a new flow is admitted rather
        // than dropped, proving the capacity counter was released.
        cache.upsert(3, TEST_SCOPE, &fields(6), &counters);
        assert_eq!(cache.len(), 2);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn purge_callback_can_reenter_the_cache_without_deadlock() {
        // Regression: on_emit runs after the shard locks are released, so a
        // re-entrant call that locks the same shard (here, re-inserting the
        // purged flow key) completes instead of deadlocking on a held write
        // lock. Under the old lock-held-during-emit code this would hang.
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(1, TEST_SCOPE, &fields(6), &counters);

        let reentered = AtomicUsize::new(0);
        let drained = cache.purge_exporter(1, &counters, &|_record| {
            cache.upsert(1, TEST_SCOPE, &fields(6), &counters);
            reentered.fetch_add(1, Ordering::Relaxed);
        });

        assert_eq!(drained, 1);
        assert_eq!(reentered.load(Ordering::Relaxed), 1);
        // The re-entrant upsert re-admitted the flow after purge drained it.
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
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &first, &counters);
        let mut second = fields(6);
        second.start_time_ns = 10;
        second.end_time_ns = 40;
        second.original_start_time_ns = 15;
        second.original_end_time_ns = 45;
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &second, &counters); // same key

        assert_eq!(cache.len(), 1);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 0);
        let record = cache
            .map
            .get(&first.key(SINGLE_EXPORTER, TEST_SCOPE))
            .unwrap();
        assert_eq!(record.bytes, 200);
        assert_eq!(record.packets, 2);
        assert_eq!(record.start_time_ns, 10);
        assert_eq!(record.end_time_ns, 40);
        assert_eq!(record.original_start_time_ns, 15);
        assert_eq!(record.original_end_time_ns, 45);
    }

    #[test]
    fn flow_id_overrides_tuple_and_is_scoped_to_scope() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        let mut first = fields(6);
        first.flow_id = Some(99);
        let mut changed_tuple = fields(17);
        changed_tuple.flow_id = Some(99);

        let s10 = Scope::V9Domain(10);
        cache.upsert(SINGLE_EXPORTER, s10, &first, &counters);
        cache.upsert(SINGLE_EXPORTER, s10, &changed_tuple, &counters);
        assert_eq!(cache.len(), 1, "flowId takes precedence over the tuple");

        cache.upsert(
            SINGLE_EXPORTER,
            Scope::V9Domain(11),
            &changed_tuple,
            &counters,
        );
        assert_eq!(cache.len(), 2, "flowId is unique only within its scope");
    }

    #[test]
    fn flows_are_scoped_by_exporter_and_protocol() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        // Same 5-tuple under different exporters/protocols must not aggregate.
        cache.upsert(1, Scope::V9Domain(7), &fields(6), &counters);
        cache.upsert(2, Scope::V9Domain(7), &fields(6), &counters);
        cache.upsert(1, Scope::IpfixDomain(7), &fields(6), &counters);
        cache.upsert(
            1,
            Scope::V5Engine {
                engine_type: 0,
                engine_id: 7,
            },
            &fields(6),
            &counters,
        );
        assert_eq!(cache.len(), 4);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flow_cache_respects_cap() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(1);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters); // admitted
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(17), &counters); // distinct key -> dropped

        assert_eq!(cache.len(), 1);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_evicts_idle_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters);

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
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters);

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
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters);

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
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(17), &counters);

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
        flows.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters);

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
