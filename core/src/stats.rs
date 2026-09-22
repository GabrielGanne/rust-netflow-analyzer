// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free diagnostic counters incremented on the hot worker path.
///
/// All updates use `Relaxed` ordering: the values are pure telemetry and never
/// gate any program logic, so cross-thread ordering guarantees are unnecessary.
#[derive(Default)]
pub struct InternalCounters {
    /// Datagrams whose NetFlow/IPFIX header was parsed successfully.
    pub pkts_parsed: AtomicU64,
    /// Datagrams rejected because their NetFlow/IPFIX header (or IPFIX
    /// `total_length` framing) was malformed. These are dropped whole and are
    /// *not* counted in `pkts_parsed`.
    pub pkts_parse_error: AtomicU64,
    /// Datagrams whose header parsed but whose body was structurally
    /// inconsistent (a FlowSet/Set length that overruns or underflows the
    /// message). The engine uses **partial decoding**: records decoded before
    /// the inconsistency are kept and this counter is incremented, rather than
    /// silently returning success. Such a datagram is still counted in
    /// `pkts_parsed` (its header was valid); this counter marks that its body
    /// could not be fully walked.
    pub malformed_packets: AtomicU64,
    pub clock_dropped_packets: AtomicU64,
    pub clock_fallback_packets: AtomicU64,
    pub templates_received: AtomicU64,
    /// Options templates decoded and stored (NetFlow v9 set id 1, IPFIX set id 3).
    pub options_templates_received: AtomicU64,
    pub data_records_processed: AtomicU64,
    /// Options data records decoded. These carry exporter metadata rather than
    /// observed flows, so they are counted here instead of the flow cache.
    pub options_records_processed: AtomicU64,
    /// Flow records delivered to the configured output callback.
    pub flows_output: AtomicU64,
    pub flows_dropped: AtomicU64,
}

/// C-compatible, point-in-time snapshot of the engine telemetry.
#[repr(C)]
pub struct NetflowAnalyzerStats {
    /// Datagrams whose NetFlow/IPFIX header was parsed successfully.
    pub pkts_parsed: u64,
    /// Datagrams rejected because their NetFlow/IPFIX header (or IPFIX
    /// `total_length` framing) was malformed; dropped whole and not counted in
    /// `pkts_parsed`.
    pub pkts_parse_error: u64,
    /// Datagrams whose header parsed but whose body was structurally
    /// inconsistent (a FlowSet/Set length that overran or truncated the
    /// message). Records decoded before the inconsistency are kept (partial
    /// decoding); these datagrams are also counted in `pkts_parsed`.
    pub malformed_packets: u64,
    /// Packets rejected because exporter clock skew exceeded the configured limit.
    pub clock_dropped_packets: u64,
    /// Skewed packets accepted after rebasing timestamps onto receipt time.
    pub clock_fallback_packets: u64,
    pub templates_received: u64,
    pub data_records_processed: u64,
    /// Flow records delivered to the configured output callback.
    pub flows_output: u64,
    /// Decoded flow records rejected because the flow cache was full.
    pub flows_dropped: u64,
    /// Number of flows currently resident in the state cache.
    pub active_flows: u64,
}

impl InternalCounters {
    /// Builds a non-blocking snapshot. `active_flows` is supplied by the caller
    /// because it is a live gauge owned by the flow cache rather than a counter.
    pub fn get_ffi_snapshot(&self, active_flows: u64) -> NetflowAnalyzerStats {
        NetflowAnalyzerStats {
            pkts_parsed: self.pkts_parsed.load(Ordering::Relaxed),
            pkts_parse_error: self.pkts_parse_error.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            clock_dropped_packets: self.clock_dropped_packets.load(Ordering::Relaxed),
            clock_fallback_packets: self.clock_fallback_packets.load(Ordering::Relaxed),
            templates_received: self.templates_received.load(Ordering::Relaxed),
            data_records_processed: self.data_records_processed.load(Ordering::Relaxed),
            flows_output: self.flows_output.load(Ordering::Relaxed),
            flows_dropped: self.flows_dropped.load(Ordering::Relaxed),
            active_flows,
        }
    }
}
