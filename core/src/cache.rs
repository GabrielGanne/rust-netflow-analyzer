// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::parser::TemplateRecord;
use crate::records::{presence, FlowFields, FlowKey, FlowRecord};
use crate::sampling::SamplingRatio;
use crate::scope::{ExporterKey, Scope};
use crate::stats::InternalCounters;
use std::sync::atomic::{AtomicU64, AtomicUsize};

/// Template lookup key: templates are scoped to the exporter/transport session
/// and its protocol-tagged observation [`Scope`], so identical template ids from
/// different exporters, protocol versions, or domains never collide.
pub(crate) type TemplateKey = (ExporterKey, Scope, u16);

/// Default hard caps. These bound heap growth even under a hostile exporter
/// that floods the engine with unique templates or flows.
/// Default maximum number of templates retained in the template cache (65,536).
pub const DEFAULT_MAX_TEMPLATES: usize = 65_536;
/// Default maximum number of active flows retained in the flow cache (1,000,000).
pub const DEFAULT_MAX_FLOWS: usize = 1_000_000;
pub(crate) const TEMPLATE_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// `duration` in nanoseconds, saturating at `u64::MAX`.
fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

struct CachedTemplate {
    record: Arc<TemplateRecord>,
    defined_at_ns: u64,
}

/// Concurrent, size-bounded cache of decoded templates.
pub(crate) struct TemplateCache {
    map: DashMap<TemplateKey, CachedTemplate>,
    max_templates: usize,
    lifetime: Duration,
    next_expiry: Mutex<Option<u64>>,
    /// Latest time any caller has supplied, used by time-less queries such
    /// as [`Self::len`] so they never move the cache's notion of time backwards.
    latest_ns: AtomicU64,
    /// Live entry count, reserved atomically so the hard cap cannot be
    /// overshot by concurrent writers racing on a `len()` snapshot.
    count: AtomicUsize,
}

impl TemplateCache {
    pub(crate) fn new(max_templates: usize) -> Self {
        Self::with_lifetime(max_templates, TEMPLATE_LIFETIME)
    }

    fn with_lifetime(max_templates: usize, lifetime: Duration) -> Self {
        Self {
            map: DashMap::new(),
            max_templates,
            lifetime,
            next_expiry: Mutex::new(None),
            latest_ns: AtomicU64::new(0),
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
    ///
    /// `now_ns` is the definition time (Unix nanoseconds) that starts the
    /// template's lifetime.
    pub(crate) fn insert(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template: TemplateRecord,
        now_ns: u64,
    ) -> bool {
        self.observe(now_ns);
        // Definitions are stamped with the latest time seen, so a definition
        // received after a clock rollback is not already expired for queries
        // evaluated at that latest time.
        let defined_at_ns = self.latest().max(now_ns);
        let key = (exporter, scope, template.template_id);
        for attempt in 0..2 {
            match self.map.entry(key) {
                Entry::Occupied(mut entry) => {
                    // An out-of-order or clock-rolled-back refresh replaces the
                    // layout but never shortens the newest definition's lifetime.
                    let defined_at_ns = entry.get().defined_at_ns.max(defined_at_ns);
                    entry.insert(CachedTemplate {
                        record: Arc::new(template),
                        defined_at_ns,
                    });
                    drop(entry);
                    self.note_definition(defined_at_ns);
                    return true;
                }
                Entry::Vacant(entry) => {
                    if self.reserve_slot() {
                        drop(entry.insert(CachedTemplate {
                            record: Arc::new(template),
                            defined_at_ns,
                        }));
                        self.note_definition(defined_at_ns);
                        return true;
                    }
                }
            }
            if attempt == 0 {
                self.sweep_if_expired(now_ns);
            }
        }
        false
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

    /// Cheap, lock-light lookup returning a shared handle to the template,
    /// unless it has expired by `now_ns`.
    pub(crate) fn get(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template_id: u16,
        now_ns: u64,
    ) -> Option<Arc<TemplateRecord>> {
        self.observe(now_ns);
        let key = (exporter, scope, template_id);
        let entry = self.map.get(&key)?;
        if !self.is_expired(&entry, now_ns) {
            return Some(entry.record.clone());
        }
        drop(entry);
        self.map.remove_if(&key, |_, template| {
            let expired = self.is_expired(template, now_ns);
            if expired {
                self.count.fetch_sub(1, Ordering::Relaxed);
            }
            expired
        });
        None
    }

    /// Like [`Self::get`], evaluated at the latest time the cache has seen.
    pub(crate) fn get_latest(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        template_id: u16,
    ) -> Option<Arc<TemplateRecord>> {
        self.get(exporter, scope, template_id, self.latest())
    }

    fn observe(&self, now_ns: u64) {
        self.latest_ns.fetch_max(now_ns, Ordering::Relaxed);
    }

    fn latest(&self) -> u64 {
        self.latest_ns.load(Ordering::Relaxed)
    }

    fn expiry_of(&self, defined_at_ns: u64) -> u64 {
        defined_at_ns.saturating_add(duration_ns(self.lifetime))
    }

    fn is_expired(&self, template: &CachedTemplate, now_ns: u64) -> bool {
        self.expiry_of(template.defined_at_ns) <= now_ns
    }

    fn note_definition(&self, defined_at_ns: u64) {
        let expiry = self.expiry_of(defined_at_ns);
        let mut next = self.next_expiry.lock().unwrap_or_else(|e| e.into_inner());
        *next = Some(next.map_or(expiry, |current| current.min(expiry)));
    }

    fn sweep_if_expired(&self, now_ns: u64) {
        let mut next = self.next_expiry.lock().unwrap_or_else(|e| e.into_inner());
        if next.is_none_or(|expiry| expiry <= now_ns) {
            self.sweep_expired_at(now_ns, &mut next);
        }
    }

    /// Drops every template expired by `now_ns`, scanning only when the
    /// earliest recorded expiry is due.
    pub(crate) fn sweep_due(&self, now_ns: u64) {
        self.observe(now_ns);
        self.sweep_if_expired(now_ns);
    }

    /// Drops every template expired by `now_ns` (Unix nanoseconds).
    pub(crate) fn sweep_expired(&self, now_ns: u64) {
        self.observe(now_ns);
        let mut next = self.next_expiry.lock().unwrap_or_else(|e| e.into_inner());
        self.sweep_expired_at(now_ns, &mut next);
    }

    fn sweep_expired_at(&self, now: u64, next_expiry: &mut Option<u64>) {
        *next_expiry = None;
        self.map.retain(|_, template| {
            let expiry = self.expiry_of(template.defined_at_ns);
            if expiry <= now {
                self.count.fetch_sub(1, Ordering::Relaxed);
                false
            } else {
                *next_expiry = Some(next_expiry.map_or(expiry, |current| current.min(expiry)));
                true
            }
        });
    }

    pub(crate) fn len(&self) -> usize {
        self.sweep_expired(self.latest());
        self.map.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drops every template belonging to `exporter`, across all of its scopes
    /// and template ids, releasing each reserved capacity slot. Returns the
    /// number of templates removed. Part of the per-key purge that lets a
    /// transport session be retired without leaking bounded cache slots.
    pub(crate) fn purge_exporter(&self, exporter: ExporterKey) -> usize {
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
pub(crate) struct FlowCache {
    map: DashMap<FlowKey, FlowRecord>,
    max_flows: usize,
    /// Live entry count, reserved atomically so the hard cap cannot be
    /// overshot by concurrent writers racing on a `len()` snapshot.
    count: AtomicUsize,
}

impl FlowCache {
    pub(crate) fn new(max_flows: usize) -> Self {
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
    ///
    /// `now_ns` (Unix nanoseconds) is the local observation time that drives
    /// idle and active aging.
    pub(crate) fn upsert_sampled(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        fields: &FlowFields,
        counters: &InternalCounters,
        now_ns: u64,
        ratio: SamplingRatio,
    ) {
        let key = fields.key(exporter, scope);
        // The `Entry` API holds the shard lock for `key`, so the vacant branch
        // (which reserves a capacity slot) cannot race another writer inserting
        // the same key.
        match self.map.entry(key) {
            Entry::Occupied(mut occupied) => {
                let existing = occupied.get_mut();
                let bytes = counter_increment(
                    fields.bytes,
                    fields.present & presence::BYTES_TOTAL != 0,
                    fields.total_bytes,
                    &mut existing.fields.total_bytes,
                );
                let packets = counter_increment(
                    fields.packets,
                    fields.present & presence::PACKETS_TOTAL != 0,
                    fields.total_packets,
                    &mut existing.fields.total_packets,
                );
                existing.bytes = existing.bytes.saturating_add(ratio.expand(bytes));
                existing.packets = existing.packets.saturating_add(ratio.expand(packets));
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
                existing.last_observed_ns = existing.last_observed_ns.max(now_ns);
            }
            Entry::Vacant(vacant) => {
                if self.reserve_slot() {
                    let mut record = FlowRecord::from_fields(fields, exporter, scope, now_ns);
                    record.bytes = ratio.expand(fields.bytes);
                    record.packets = ratio.expand(fields.packets);
                    record.fields.total_bytes = Some(fields.total_bytes.unwrap_or(fields.bytes));
                    record.fields.total_packets =
                        Some(fields.total_packets.unwrap_or(fields.packets));
                    record.present &= !(presence::BYTES_TOTAL | presence::PACKETS_TOTAL);
                    vacant.insert(record);
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

    /// Removes `key` and releases its reserved capacity slot when
    /// `should_remove` returns true, returning the owned record so the caller
    /// can emit it **after** the shard lock is dropped.
    ///
    /// Both the predicate and the slot release run inside `remove_if`'s shard
    /// write lock, atomically with the erase. Decrementing the count under that
    /// same lock closes the window where a concurrent `upsert` on a full cache
    /// could see the key already gone yet the slot still reserved, and drop a
    /// packet even though the removal had freed room.
    fn remove_and_release(
        &self,
        key: &FlowKey,
        should_remove: impl FnOnce(&FlowRecord) -> bool,
    ) -> Option<FlowRecord> {
        self.map
            .remove_if(key, |_k, record| {
                let remove = should_remove(record);
                if remove {
                    self.count.fetch_sub(1, Ordering::Relaxed);
                }
                remove
            })
            .map(|(_k, record)| record)
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Sweeps the cache once, evicting idle flows and rolling over flows that
    /// have exceeded their active timeout. Eviction and active-rollover events
    /// are emitted through `on_emit`.
    ///
    /// `on_emit` is always invoked **after** the entry's shard lock is released,
    /// so a slow or re-entrant callback cannot block ingestion on other shards
    /// or deadlock by calling back into the engine. A candidate flow's timeout
    /// is re-checked while its lock is held before it is evicted or rolled over,
    /// so a flow that a concurrent packet refreshed in between is left alone.
    ///
    /// Elapsed time is `now_ns` minus the recorded observation times,
    /// saturating at zero, so a clock that moves backwards never ages a flow
    /// early.
    pub(crate) fn sweep<F>(
        &self,
        cfg: &AgingConfig,
        counters: &InternalCounters,
        on_emit: &F,
        now_ns: u64,
    ) where
        F: Fn(&FlowRecord),
    {
        let idle = duration_ns(cfg.idle_timeout);
        let active = duration_ns(cfg.active_timeout);
        let idle_due = |r: &FlowRecord| now_ns.saturating_sub(r.last_observed_ns) >= idle;
        let active_due = |r: &FlowRecord| now_ns.saturating_sub(r.first_observed_ns) >= active;
        // Slots are reserved before insertion, so a zero count means an empty
        // map; iterating one would still lock and allocate a guard per shard.
        if self.count.load(Ordering::Relaxed) == 0 {
            return;
        }

        // Read pass: collect only the keys that currently look due. Holding
        // read locks here is safe because no user callback runs; each candidate
        // is re-checked under a write lock below. The buffer is proportional to
        // the number of expiring flows, not the whole cache.
        let candidates: Vec<FlowKey> = self
            .map
            .iter()
            .filter(|entry| idle_due(entry.value()) || active_due(entry.value()))
            .map(|entry| *entry.key())
            .collect();

        for key in candidates {
            // Idle timeout: remove (and release the slot) atomically, but only
            // if still idle, then emit the owned record with the lock released.
            if let Some(record) = self.remove_and_release(&key, idle_due) {
                on_emit(&record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Active timeout: snapshot and reset the counters in place under a
            // brief write lock (dropped as the closure returns), then emit the
            // snapshot outside the lock.
            let snapshot = self.map.get_mut(&key).and_then(|mut entry| {
                let record = entry.value_mut();
                if active_due(record) {
                    let snapshot = record.clone();
                    record.bytes = 0;
                    record.packets = 0;
                    record.first_observed_ns = record.first_observed_ns.max(now_ns);
                    Some(snapshot)
                } else {
                    None
                }
            });
            if let Some(record) = snapshot {
                on_emit(&record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Drains every remaining flow, emitting each one. Used on shutdown so the
    /// host never loses the residual state still held in the cache.
    ///
    /// Like [`sweep`] and [`purge_exporter`], each record is removed with a
    /// brief shard lock and emitted only after that lock is released, so the
    /// callback never runs while a shard is locked.
    ///
    /// [`sweep`]: Self::sweep
    /// [`purge_exporter`]: Self::purge_exporter
    pub(crate) fn flush_all<F>(&self, counters: &InternalCounters, on_emit: &F)
    where
        F: Fn(&FlowRecord),
    {
        let keys: Vec<FlowKey> = self.map.iter().map(|entry| *entry.key()).collect();
        for key in keys {
            if let Some(record) = self.remove_and_release(&key, |_| true) {
                on_emit(&record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
            }
        }
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
    pub(crate) fn purge_exporter<F>(
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
            // Remove and release the slot atomically under the shard lock, then
            // emit the owned record once that lock is dropped.
            if let Some(record) = self.remove_and_release(&key, |_| true) {
                on_emit(&record);
                counters.flows_output.fetch_add(1, Ordering::Relaxed);
                emitted += 1;
            }
        }
        emitted
    }
}

fn counter_increment(
    value: u64,
    is_total: bool,
    advertised_total: Option<u64>,
    previous: &mut Option<u64>,
) -> u64 {
    let baseline = previous.unwrap_or(0);
    let (increment, total) = if is_total {
        (value.saturating_sub(baseline), value.max(baseline))
    } else {
        (
            value,
            advertised_total
                .unwrap_or_else(|| baseline.saturating_add(value))
                .max(baseline),
        )
    };
    *previous = Some(total);
    increment
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

/// `running` flag paired with the condition variable that wakes the worker
/// as soon as it is cleared.
type StopSignal = (Mutex<bool>, Condvar);

/// Owns the background aging thread and the signal used to stop it cleanly.
pub(crate) struct AgingHandle {
    signal: Arc<StopSignal>,
    join: Option<JoinHandle<()>>,
}

impl AgingHandle {
    /// Spawns a low-overhead background worker that sweeps `flows` and
    /// `templates` every `cfg.scan_interval`, at the wall-clock time returned
    /// by `now_ns`. The worker waits on a condition variable, so it sleeps for
    /// exactly the scan interval and [`Self::stop`] wakes it immediately.
    ///
    /// Returns the OS error if the worker thread cannot be created, rather than
    /// panicking, so FFI callers can surface the failure without unwinding.
    pub(crate) fn spawn<F>(
        flows: Arc<FlowCache>,
        templates: Arc<TemplateCache>,
        counters: Arc<InternalCounters>,
        cfg: AgingConfig,
        now_ns: fn() -> u64,
        on_emit: F,
    ) -> std::io::Result<Self>
    where
        F: Fn(&FlowRecord) + Send + Sync + 'static,
    {
        let signal: Arc<StopSignal> = Arc::new((Mutex::new(true), Condvar::new()));
        let worker_signal = signal.clone();

        let join = thread::Builder::new()
            .name("netflow-aging".to_string())
            .spawn(move || {
                let (lock, wake) = &*worker_signal;
                loop {
                    let running = lock.lock().unwrap_or_else(|e| e.into_inner());
                    let (running, _) = wake
                        .wait_timeout_while(running, cfg.scan_interval, |running| *running)
                        .unwrap_or_else(|e| e.into_inner());
                    if !*running {
                        break;
                    }
                    // Sweep with the lock released so `stop` never waits on
                    // a sweep or an emission callback to signal the worker.
                    drop(running);
                    let now = now_ns();
                    flows.sweep(&cfg, &counters, &on_emit, now);
                    templates.sweep_expired(now);
                }
            })?;

        Ok(Self {
            signal,
            join: Some(join),
        })
    }

    /// Signals the worker to stop and blocks until it has fully exited.
    ///
    /// If called from the aging thread itself — for example an emission callback
    /// that tries to tear the engine down — the join is **skipped**: a thread
    /// cannot join itself (that can deadlock or panic depending on the
    /// platform). The worker has already been told to stop and will exit after
    /// the current sweep; the handle is detached instead. Tearing the engine
    /// down from within its own callback is misuse — see the shutdown-sequence
    /// documentation on `netflow_analyzer_destroy` / [`crate::FlowContext::stop_aging`].
    pub(crate) fn stop(&mut self) {
        let (lock, wake) = &*self.signal;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = false;
        wake.notify_all();
        if let Some(handle) = self.join.take() {
            if handle.thread().id() == thread::current().id() {
                // Detach rather than join ourselves; the worker exits on its own.
                return;
            }
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

    impl FlowCache {
        fn upsert(
            &self,
            exporter: ExporterKey,
            scope: Scope,
            fields: &FlowFields,
            counters: &InternalCounters,
            now_ns: u64,
        ) {
            self.upsert_sampled(
                exporter,
                scope,
                fields,
                counters,
                now_ns,
                SamplingRatio::NONE,
            );
        }
    }

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

    /// Arbitrary Unix-nanosecond reference time for the tests.
    const T0: u64 = 1_700_000_000_000_000_000;
    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn template_cache_insert_get_and_scope() {
        let cache = TemplateCache::new(10);
        assert!(cache.is_empty());
        let d1 = Scope::V9Domain(1);
        let d2 = Scope::V9Domain(2);
        let d3 = Scope::V9Domain(3);
        assert!(cache.insert(SINGLE_EXPORTER, d1, sample_template(256), T0));
        assert!(cache.insert(SINGLE_EXPORTER, d2, sample_template(256), T0)); // same id, different domain

        assert_eq!(cache.len(), 2);
        assert!(cache.get(SINGLE_EXPORTER, d1, 256, T0).is_some());
        assert!(cache.get(SINGLE_EXPORTER, d2, 256, T0).is_some());
        assert!(cache.get(SINGLE_EXPORTER, d3, 256, T0).is_none());
    }

    #[test]
    fn template_cache_scopes_by_exporter_and_protocol() {
        let cache = TemplateCache::new(10);
        // Same numeric domain id is a distinct key per exporter and per protocol.
        assert!(cache.insert(1, Scope::V9Domain(7), sample_template(256), T0));
        assert!(cache.insert(2, Scope::V9Domain(7), sample_template(256), T0));
        assert!(cache.insert(1, Scope::IpfixDomain(7), sample_template(256), T0));
        assert!(cache.insert(
            1,
            Scope::V5Engine {
                engine_type: 0,
                engine_id: 7,
            },
            sample_template(256),
            T0,
        ));

        assert_eq!(cache.len(), 4);
        assert!(cache.get(1, Scope::V9Domain(7), 256, T0).is_some());
        assert!(cache.get(2, Scope::V9Domain(7), 256, T0).is_some());
        assert!(cache.get(1, Scope::IpfixDomain(7), 256, T0).is_some());
        // A different exporter's IPFIX domain 7 was never installed.
        assert!(cache.get(2, Scope::IpfixDomain(7), 256, T0).is_none());
    }

    #[test]
    fn template_cache_enforces_cap_but_allows_redefinition() {
        let cache = TemplateCache::new(1);
        let d1 = Scope::V9Domain(1);
        assert!(cache.insert(SINGLE_EXPORTER, d1, sample_template(256), T0));
        // New distinct key rejected once full.
        assert!(!cache.insert(SINGLE_EXPORTER, d1, sample_template(257), T0));
        // Re-defining an existing key is always allowed.
        assert!(cache.insert(SINGLE_EXPORTER, d1, sample_template(256), T0));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn template_cache_purge_drops_only_the_exporter() {
        let cache = TemplateCache::new(10);
        let d = Scope::V9Domain(1);
        assert!(cache.insert(1, d, sample_template(256), T0));
        assert!(cache.insert(1, Scope::IpfixDomain(2), sample_template(300), T0));
        assert!(cache.insert(2, d, sample_template(256), T0));
        assert_eq!(cache.len(), 3);

        assert_eq!(cache.purge_exporter(1), 2, "both of exporter 1's templates");
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1, d, 256, T0).is_none());
        assert!(
            cache.get(2, d, 256, T0).is_some(),
            "other exporter untouched"
        );

        // The freed slots are reusable: re-adding under the purged key succeeds
        // even in a cache that would otherwise be near a low cap.
        assert!(cache.insert(1, d, sample_template(256), T0));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn expired_templates_cannot_decode_and_release_capacity() {
        let cache = TemplateCache::with_lifetime(1, Duration::from_secs(60));
        let scope = Scope::V9Domain(1);
        assert!(cache.insert(1, scope, sample_template(256), T0));
        assert!(cache.get(1, scope, 256, T0 + 59 * SECOND).is_some());

        let later = T0 + 60 * SECOND;
        assert!(cache.get(1, scope, 256, later).is_none());
        assert!(cache.insert(2, scope, sample_template(257), later));
        assert_eq!(cache.len(), 1);
        assert!(cache.get(2, scope, 257, later).is_some());
    }

    #[test]
    fn capacity_admission_sweeps_expired_templates() {
        let cache = TemplateCache::with_lifetime(1, Duration::from_secs(60));
        let scope = Scope::IpfixDomain(1);
        assert!(cache.insert(1, scope, sample_template(256), T0));
        assert!(!cache.insert(2, scope, sample_template(257), T0 + 59 * SECOND));

        let later = T0 + 61 * SECOND;
        assert!(cache.insert(2, scope, sample_template(257), later));
        assert!(cache.get(1, scope, 256, later).is_none());
        assert!(cache.get(2, scope, 257, later).is_some());
        assert_eq!(cache.count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn redefining_template_refreshes_its_lifetime() {
        let cache = TemplateCache::with_lifetime(1, Duration::from_secs(60));
        let scope = Scope::V9Domain(1);
        assert!(cache.insert(1, scope, sample_template(256), T0));
        assert!(cache.insert(1, scope, sample_template(256), T0 + 50 * SECOND));

        assert!(cache.get(1, scope, 256, T0 + 100 * SECOND).is_some());
        assert!(cache.get(1, scope, 256, T0 + 110 * SECOND).is_none());
        assert_eq!(cache.count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn older_refresh_keeps_the_latest_definition_time() {
        let cache = TemplateCache::with_lifetime(1, Duration::from_secs(1800));
        let scope = Scope::V9Domain(1);
        assert!(cache.insert(1, scope, sample_template(256), T0));
        let mut wider = sample_template(256);
        wider.fixed_length = Some(8);
        assert!(cache.insert(1, scope, wider, T0 - 3600 * SECOND));

        let template = cache.get(1, scope, 256, T0 + SECOND).expect("still valid");
        assert_eq!(template.fixed_length, Some(8), "the refreshed layout wins");
        assert!(cache.get(1, scope, 256, T0 + 1800 * SECOND).is_none());
    }

    #[test]
    fn template_time_moving_backwards_never_expires_early() {
        let cache = TemplateCache::with_lifetime(1, Duration::from_secs(60));
        let scope = Scope::V9Domain(1);
        assert!(cache.insert(1, scope, sample_template(256), T0));
        assert!(cache.get(1, scope, 256, T0 - 3600 * SECOND).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn template_defined_after_clock_rollback_survives_latest_queries() {
        let cache = TemplateCache::with_lifetime(1, Duration::from_secs(1800));
        let scope = Scope::V9Domain(1);
        assert!(cache.get(1, scope, 256, T0).is_none());
        let rolled_back = T0 - 3600 * SECOND;
        assert!(cache.insert(1, scope, sample_template(256), rolled_back));

        assert!(cache.get_latest(1, scope, 256).is_some());
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1, scope, 256, rolled_back + SECOND).is_some());
    }

    #[test]
    fn flow_cache_purge_emits_drains_and_reclaims_slots() {
        let counters = InternalCounters::default();
        // Cap of 2 so we can prove the freed slot becomes reusable afterwards.
        let cache = FlowCache::new(2);
        cache.upsert(1, TEST_SCOPE, &fields(6), &counters, T0);
        cache.upsert(2, TEST_SCOPE, &fields(6), &counters, T0);
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
        cache.upsert(3, TEST_SCOPE, &fields(6), &counters, T0);
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
        cache.upsert(1, TEST_SCOPE, &fields(6), &counters, T0);

        let reentered = AtomicUsize::new(0);
        let drained = cache.purge_exporter(1, &counters, &|_record| {
            cache.upsert(1, TEST_SCOPE, &fields(6), &counters, T0);
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
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &first, &counters, T0);
        let mut second = fields(6);
        second.start_time_ns = 10;
        second.end_time_ns = 40;
        second.original_start_time_ns = 15;
        second.original_end_time_ns = 45;
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &second, &counters, T0); // same key

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
        cache.upsert(SINGLE_EXPORTER, s10, &first, &counters, T0);
        cache.upsert(SINGLE_EXPORTER, s10, &changed_tuple, &counters, T0);
        assert_eq!(cache.len(), 1, "flowId takes precedence over the tuple");

        cache.upsert(
            SINGLE_EXPORTER,
            Scope::V9Domain(11),
            &changed_tuple,
            &counters,
            T0,
        );
        assert_eq!(cache.len(), 2, "flowId is unique only within its scope");
    }

    #[test]
    fn flows_are_scoped_by_exporter_and_protocol() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        // Same 5-tuple under different exporters/protocols must not aggregate.
        cache.upsert(1, Scope::V9Domain(7), &fields(6), &counters, T0);
        cache.upsert(2, Scope::V9Domain(7), &fields(6), &counters, T0);
        cache.upsert(1, Scope::IpfixDomain(7), &fields(6), &counters, T0);
        cache.upsert(
            1,
            Scope::V5Engine {
                engine_type: 0,
                engine_id: 7,
            },
            &fields(6),
            &counters,
            T0,
        );
        assert_eq!(cache.len(), 4);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flow_cache_respects_cap() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(1);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0); // admitted
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(17), &counters, T0); // distinct key -> dropped

        assert_eq!(cache.len(), 1);
        assert_eq!(counters.flows_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_evicts_idle_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);

        let cfg = AgingConfig {
            idle_timeout: Duration::ZERO, // everything is "idle"
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_secs(1),
        };
        let emitted = AtomicUsize::new(0);
        cache.sweep(
            &cfg,
            &counters,
            &|_r| {
                emitted.fetch_add(1, Ordering::Relaxed);
            },
            T0,
        );

        assert_eq!(cache.len(), 0);
        assert_eq!(emitted.load(Ordering::Relaxed), 1);
        assert_eq!(counters.flows_output.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_rolls_over_active_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);

        let cfg = AgingConfig {
            idle_timeout: Duration::from_secs(3600), // never idle
            active_timeout: Duration::ZERO,          // always rolled over
            scan_interval: Duration::from_secs(1),
        };
        let emitted = AtomicUsize::new(0);
        cache.sweep(
            &cfg,
            &counters,
            &|_r| {
                emitted.fetch_add(1, Ordering::Relaxed);
            },
            T0,
        );

        // Entry survives a rollover but its counters are reset.
        assert_eq!(cache.len(), 1);
        assert_eq!(emitted.load(Ordering::Relaxed), 1);
        assert_eq!(counters.flows_output.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sweep_keeps_fresh_flows() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);

        let cfg = AgingConfig {
            idle_timeout: Duration::from_secs(3600),
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_secs(1),
        };
        cache.sweep(&cfg, &counters, &|_r| panic!("should not emit"), T0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sweep_callback_can_reenter_the_cache_without_deadlock() {
        // Regression: sweep emits after releasing the entry's shard lock, so an
        // idle-eviction callback that locks the same shard (re-inserting the
        // evicted key) completes instead of deadlocking. Under the old
        // callback-under-retain code this would hang.
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);

        let cfg = AgingConfig {
            idle_timeout: Duration::ZERO, // the flow is immediately idle
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_secs(1),
        };
        let reentered = AtomicUsize::new(0);
        cache.sweep(
            &cfg,
            &counters,
            &|_record| {
                cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);
                reentered.fetch_add(1, Ordering::Relaxed);
            },
            T0,
        );

        assert_eq!(reentered.load(Ordering::Relaxed), 1);
        // The idle flow was evicted and the callback re-admitted one.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn flush_callback_can_reenter_the_cache_without_deadlock() {
        // Regression: flush_all emits each record after releasing its shard
        // lock, so a callback that locks the same shard does not deadlock.
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);

        let reentered = AtomicUsize::new(0);
        cache.flush_all(&counters, &|_record| {
            cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);
            reentered.fetch_add(1, Ordering::Relaxed);
        });

        assert_eq!(reentered.load(Ordering::Relaxed), 1);
        // The original flow was drained and the callback re-admitted one.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn flush_all_drains_cache() {
        let counters = InternalCounters::default();
        let cache = FlowCache::new(10);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);
        cache.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(17), &counters, T0);

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
        let templates = Arc::new(TemplateCache::with_lifetime(10, Duration::from_secs(60)));
        flows.upsert(SINGLE_EXPORTER, TEST_SCOPE, &fields(6), &counters, T0);
        assert!(templates.insert(SINGLE_EXPORTER, TEST_SCOPE, sample_template(256), T0));

        let cfg = AgingConfig {
            idle_timeout: Duration::from_secs(30),
            active_timeout: Duration::from_secs(3600),
            scan_interval: Duration::from_millis(1),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        // A clock far in the future makes the first sweep's outcome independent
        // of when the worker actually wakes up.
        let mut handle = AgingHandle::spawn(
            flows.clone(),
            templates.clone(),
            counters.clone(),
            cfg,
            || u64::MAX,
            move |_r| {
                let _ = tx.lock().unwrap().send(());
            },
        )
        .expect("spawn aging thread");

        rx.recv_timeout(Duration::from_secs(10))
            .expect("worker sweeps within the timeout");
        handle.stop();

        assert_eq!(flows.len(), 0, "idle flow should be evicted");
        assert!(templates.map.is_empty(), "expired template should be swept");
        assert_eq!(counters.flows_output.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stop_wakes_a_worker_with_a_long_scan_interval() {
        let cfg = AgingConfig {
            scan_interval: Duration::from_secs(3600),
            ..AgingConfig::default()
        };
        for _ in 0..20 {
            let mut handle = AgingHandle::spawn(
                Arc::new(FlowCache::new(1)),
                Arc::new(TemplateCache::new(1)),
                Arc::new(InternalCounters::default()),
                cfg,
                || T0,
                |_r| panic!("no sweep is due"),
            )
            .expect("spawn aging thread");
            // Would block for the full hour if stop did not wake the worker.
            handle.stop();
        }
    }
}
