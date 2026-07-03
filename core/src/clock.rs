// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// Exporter-clock validation and recovery settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockConfig {
    /// Compare packet export times with their local receipt times.
    pub sync_check_enabled: bool,
    /// Largest accepted absolute difference between export and receipt time.
    pub max_skew: Duration,
    /// Correct skewed timestamps using receipt time instead of dropping packets.
    pub fallback_to_receipt_time: bool,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            // Opt-in keeps offline captures and existing callers deterministic.
            sync_check_enabled: false,
            max_skew: Duration::from_secs(300),
            fallback_to_receipt_time: false,
        }
    }
}

/// Latest clock observations for one NetFlow/IPFIX observation domain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockState {
    pub last_export_time_ns: u64,
    pub last_receipt_time_ns: u64,
    pub last_skew_ns: u64,
    pub packets_seen: u64,
    pub clock_issues: u64,
    pub last_was_usable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockDecision {
    Accept { effective_export_time_ns: u64 },
    Fallback { effective_export_time_ns: u64 },
    Drop,
}

/// Concurrent, bounded exporter-clock state keyed by observation domain.
pub struct ClockTracker {
    states: DashMap<u32, ClockState>,
    max_domains: usize,
    domain_count: AtomicUsize,
}

impl ClockTracker {
    pub fn new(max_domains: usize) -> Self {
        Self {
            states: DashMap::new(),
            max_domains,
            domain_count: AtomicUsize::new(0),
        }
    }

    pub fn get(&self, domain: u32) -> Option<ClockState> {
        self.states.get(&domain).map(|entry| *entry.value())
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub(crate) fn observe(
        &self,
        domain: u32,
        export_time_ns: u64,
        receipt_time_ns: u64,
        config: ClockConfig,
    ) -> ClockDecision {
        let skew_ns = export_time_ns.abs_diff(receipt_time_ns);
        let max_skew_ns = config.max_skew.as_nanos().min(u64::MAX as u128) as u64;
        let usable = !config.sync_check_enabled || skew_ns <= max_skew_ns;

        match self.states.entry(domain) {
            Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                state.last_export_time_ns = export_time_ns;
                state.last_receipt_time_ns = receipt_time_ns;
                state.last_skew_ns = skew_ns;
                state.packets_seen = state.packets_seen.saturating_add(1);
                state.clock_issues = state.clock_issues.saturating_add((!usable) as u64);
                state.last_was_usable = usable;
            }
            Entry::Vacant(entry) => {
                let reserved = self
                    .domain_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < self.max_domains).then_some(count + 1)
                    })
                    .is_ok();
                if reserved {
                    entry.insert(ClockState {
                        last_export_time_ns: export_time_ns,
                        last_receipt_time_ns: receipt_time_ns,
                        last_skew_ns: skew_ns,
                        packets_seen: 1,
                        clock_issues: (!usable) as u64,
                        last_was_usable: usable,
                    });
                }
            }
        }

        if usable {
            ClockDecision::Accept {
                effective_export_time_ns: export_time_ns,
            }
        } else if config.fallback_to_receipt_time {
            ClockDecision::Fallback {
                effective_export_time_ns: receipt_time_ns,
            }
        } else {
            ClockDecision::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_check_accepts_and_tracks_large_skew() {
        let tracker = ClockTracker::new(4);
        let decision = tracker.observe(7, 10, 1_000, ClockConfig::default());
        assert_eq!(
            decision,
            ClockDecision::Accept {
                effective_export_time_ns: 10
            }
        );
        let state = tracker.get(7).unwrap();
        assert_eq!(state.last_skew_ns, 990);
        assert!(state.last_was_usable);
    }

    #[test]
    fn enabled_check_can_drop_or_fallback() {
        let tracker = ClockTracker::new(4);
        let mut config = ClockConfig {
            sync_check_enabled: true,
            max_skew: Duration::from_nanos(5),
            fallback_to_receipt_time: false,
        };
        assert_eq!(tracker.observe(7, 10, 20, config), ClockDecision::Drop);

        config.fallback_to_receipt_time = true;
        assert_eq!(
            tracker.observe(7, 10, 20, config),
            ClockDecision::Fallback {
                effective_export_time_ns: 20
            }
        );
        let state = tracker.get(7).unwrap();
        assert_eq!(state.packets_seen, 2);
        assert_eq!(state.clock_issues, 2);
        assert!(!state.last_was_usable);
    }

    #[test]
    fn domain_state_is_bounded() {
        let tracker = ClockTracker::new(1);
        tracker.observe(1, 10, 10, ClockConfig::default());
        tracker.observe(2, 20, 20, ClockConfig::default());
        assert!(tracker.get(1).is_some());
        assert!(tracker.get(2).is_none());
    }
}
