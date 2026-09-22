// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::scope::{ExporterKey, Scope};

/// Clock state is tracked per exporter/transport session and protocol-tagged
/// observation [`Scope`], mirroring how templates and flows are scoped.
type ClockKey = (ExporterKey, Scope);

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

/// Concurrent, bounded exporter-clock state keyed by `(exporter, scope)`.
pub struct ClockTracker {
    states: DashMap<ClockKey, ClockState>,
    max_scopes: usize,
    scope_count: AtomicUsize,
}

impl ClockTracker {
    pub fn new(max_scopes: usize) -> Self {
        Self {
            states: DashMap::new(),
            max_scopes,
            scope_count: AtomicUsize::new(0),
        }
    }

    pub fn get(&self, exporter: ExporterKey, scope: Scope) -> Option<ClockState> {
        self.states
            .get(&(exporter, scope))
            .map(|entry| *entry.value())
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Drops every clock state belonging to `exporter`, across all of its
    /// scopes, releasing each reserved capacity slot. Returns the number of
    /// scopes removed. Part of the per-key purge that retires a transport
    /// session (e.g. an exporter restart) without leaking bounded slots.
    pub fn purge_exporter(&self, exporter: ExporterKey) -> usize {
        let mut removed = 0usize;
        let count = &self.scope_count;
        self.states.retain(|key, _state| {
            if key.0 == exporter {
                count.fetch_sub(1, Ordering::Relaxed);
                removed += 1;
                return false;
            }
            true
        });
        removed
    }

    pub(crate) fn observe(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        export_time_ns: u64,
        receipt_time_ns: u64,
        config: ClockConfig,
    ) -> ClockDecision {
        let skew_ns = export_time_ns.abs_diff(receipt_time_ns);
        let max_skew_ns = config.max_skew.as_nanos().min(u64::MAX as u128) as u64;
        let usable = !config.sync_check_enabled || skew_ns <= max_skew_ns;

        match self.states.entry((exporter, scope)) {
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
                    .scope_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < self.max_scopes).then_some(count + 1)
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

    use crate::scope::SINGLE_EXPORTER;

    const D7: Scope = Scope::V9Domain(7);

    #[test]
    fn disabled_check_accepts_and_tracks_large_skew() {
        let tracker = ClockTracker::new(4);
        let decision = tracker.observe(SINGLE_EXPORTER, D7, 10, 1_000, ClockConfig::default());
        assert_eq!(
            decision,
            ClockDecision::Accept {
                effective_export_time_ns: 10
            }
        );
        let state = tracker.get(SINGLE_EXPORTER, D7).unwrap();
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
        assert_eq!(
            tracker.observe(SINGLE_EXPORTER, D7, 10, 20, config),
            ClockDecision::Drop
        );

        config.fallback_to_receipt_time = true;
        assert_eq!(
            tracker.observe(SINGLE_EXPORTER, D7, 10, 20, config),
            ClockDecision::Fallback {
                effective_export_time_ns: 20
            }
        );
        let state = tracker.get(SINGLE_EXPORTER, D7).unwrap();
        assert_eq!(state.packets_seen, 2);
        assert_eq!(state.clock_issues, 2);
        assert!(!state.last_was_usable);
    }

    #[test]
    fn scope_state_is_bounded() {
        let tracker = ClockTracker::new(1);
        tracker.observe(
            SINGLE_EXPORTER,
            Scope::V9Domain(1),
            10,
            10,
            ClockConfig::default(),
        );
        tracker.observe(
            SINGLE_EXPORTER,
            Scope::V9Domain(2),
            20,
            20,
            ClockConfig::default(),
        );
        assert!(tracker.get(SINGLE_EXPORTER, Scope::V9Domain(1)).is_some());
        assert!(tracker.get(SINGLE_EXPORTER, Scope::V9Domain(2)).is_none());
    }

    #[test]
    fn state_is_independent_per_exporter_and_protocol() {
        let tracker = ClockTracker::new(8);
        let cfg = ClockConfig::default();
        // Same numeric domain 7 stays distinct across exporters and protocols.
        tracker.observe(1, Scope::V9Domain(7), 10, 10, cfg);
        tracker.observe(2, Scope::V9Domain(7), 20, 20, cfg);
        tracker.observe(1, Scope::IpfixDomain(7), 30, 30, cfg);

        assert_eq!(tracker.len(), 3);
        assert_eq!(
            tracker
                .get(1, Scope::V9Domain(7))
                .unwrap()
                .last_export_time_ns,
            10
        );
        assert_eq!(
            tracker
                .get(2, Scope::V9Domain(7))
                .unwrap()
                .last_export_time_ns,
            20
        );
        assert_eq!(
            tracker
                .get(1, Scope::IpfixDomain(7))
                .unwrap()
                .last_export_time_ns,
            30
        );
        assert!(tracker.get(2, Scope::IpfixDomain(7)).is_none());
    }

    #[test]
    fn purge_drops_only_the_exporter_and_reclaims_slots() {
        // Cap of 2 so the reclaimed slot's reuse is observable.
        let tracker = ClockTracker::new(2);
        let cfg = ClockConfig::default();
        tracker.observe(1, Scope::V9Domain(7), 10, 10, cfg);
        tracker.observe(2, Scope::V9Domain(7), 20, 20, cfg);
        assert_eq!(tracker.len(), 2);

        assert_eq!(tracker.purge_exporter(1), 1);
        assert!(tracker.get(1, Scope::V9Domain(7)).is_none());
        assert!(tracker.get(2, Scope::V9Domain(7)).is_some());
        assert_eq!(tracker.len(), 1);

        // The freed slot admits a new scope rather than being rejected by the cap.
        tracker.observe(3, Scope::V9Domain(7), 30, 30, cfg);
        assert_eq!(tracker.len(), 2);
        assert!(tracker.get(3, Scope::V9Domain(7)).is_some());
    }
}
