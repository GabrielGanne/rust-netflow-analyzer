use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free diagnostic counters incremented on the hot worker path.
///
/// All updates use `Relaxed` ordering: the values are pure telemetry and never
/// gate any program logic, so cross-thread ordering guarantees are unnecessary.
#[derive(Default)]
pub struct InternalCounters {
    pub packets_processed: AtomicU64,
    pub malformed_packets: AtomicU64,
    pub templates_received: AtomicU64,
    pub data_records_processed: AtomicU64,
    pub flows_evicted: AtomicU64,
    pub flows_dropped: AtomicU64,
}

/// C-compatible, point-in-time snapshot of the engine telemetry.
#[repr(C)]
pub struct LibraryStatsFFI {
    pub packets_processed: u64,
    pub malformed_packets: u64,
    pub templates_received: u64,
    pub data_records_processed: u64,
    pub flows_evicted: u64,
    pub flows_dropped: u64,
    /// Number of flows currently resident in the state cache.
    pub active_flows: u64,
}

impl InternalCounters {
    /// Builds a non-blocking snapshot. `active_flows` is supplied by the caller
    /// because it is a live gauge owned by the flow cache rather than a counter.
    pub fn get_ffi_snapshot(&self, active_flows: u64) -> LibraryStatsFFI {
        LibraryStatsFFI {
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            templates_received: self.templates_received.load(Ordering::Relaxed),
            data_records_processed: self.data_records_processed.load(Ordering::Relaxed),
            flows_evicted: self.flows_evicted.load(Ordering::Relaxed),
            flows_dropped: self.flows_dropped.load(Ordering::Relaxed),
            active_flows,
        }
    }
}
