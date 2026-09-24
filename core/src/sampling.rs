// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Per-sampler packet-sampling state learned from options data records.
//!
//! Exporters advertise their packet-sampling configuration in options data
//! records: `samplingInterval` (IE 34), `samplerRandomInterval` (IE 50), or the
//! count-based `samplingPacketInterval` / `samplingPacketSpace` pair (IE
//! 305/306). Each resolves to a rate — "1 packet in N was sampled", possibly
//! fractional — so the byte and packet counters carried by flow records
//! under-count the real traffic and must be scaled back up.
//!
//! A single observation domain can advertise several samplers (for example one
//! per interface or per `flowSamplerId`), each in its own options record. State
//! is therefore keyed by `(exporter, scope, selector)` — the exporter/transport
//! session, the protocol-tagged observation [`Scope`], and the sampler
//! [`SamplerSelector`] — so per-sampler rates do not overwrite one another (see
//! `docs/exporter-identity.md`). The selector is exactly the identifier a flow
//! record can also carry (`flowSamplerId` / `selectorId`), so a decoded flow can
//! be matched back to the sampler that produced it. Absent any advertisement,
//! callers use the neutral [`SamplingRatio::NONE`].

use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::scope::{ExporterKey, Scope};

/// Identifies *which* sampler within an `(exporter, scope)` a record belongs to.
///
/// It is derived identically from an options record and from a flow record so
/// the two match: a flow's `selectorId` (IE 302) or `flowSamplerId` (IE 48)
/// selects the sampler advertised under the same value. `selectorId` takes
/// precedence when a record carries both. A record that carries neither maps to
/// [`SamplerSelector::Domain`], the single domain-wide sampler — the fallback
/// used by exporters that advertise one global rate and tag no flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SamplerSelector {
    /// No per-sampler identifier: the single domain-wide sampler.
    #[default]
    Domain,
    /// `flowSamplerId` (IE 48).
    FlowSampler(u64),
    /// `selectorId` (IE 302).
    Selector(u64),
}

/// Sampling state is keyed by exporter/transport session, protocol-tagged
/// observation [`Scope`], and the sampler [`SamplerSelector`].
type SamplingKey = (ExporterKey, Scope, SamplerSelector);

/// A packet-sampling rate expressed as an exact `numerator / denominator`
/// fraction of the real traffic that was captured.
///
/// The deprecated "1 in N" elements give `N / 1`; the count-based
/// `samplingPacketInterval` (kept per cycle) and `samplingPacketSpace` (skipped
/// per cycle) give `(interval + space) / interval`, which need not be integral.
/// Keeping both terms avoids truncating a fractional rate before it is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingRatio {
    /// Packets in the sampled population per cycle. Always `>= 1` when stored.
    /// The terms are kept `u64` so a count-based rate whose `interval + space`
    /// exceeds `u32::MAX` is preserved exactly rather than clamped out of shape.
    pub numerator: u64,
    /// Packets actually captured per cycle. Always `>= 1` when stored.
    pub denominator: u64,
}

impl SamplingRatio {
    /// The neutral 1:1 ratio used when no sampling has been advertised.
    pub const NONE: SamplingRatio = SamplingRatio {
        numerator: 1,
        denominator: 1,
    };

    /// Scales an observed (sampled) counter up to its estimated real value,
    /// `count * numerator / denominator`. Multiplies before dividing in `u128`
    /// so a fractional ratio such as `11/2` is not truncated early, and
    /// saturates at `u64::MAX`.
    ///
    /// The result is floored. For an integral rate (all "1 in N" elements, and
    /// count-based sampling that keeps one packet per cycle) this is exact. A
    /// non-integral count-based rate applied per record can lose the sub-unit
    /// remainder of each record; that is an accepted artifact of a statistical
    /// estimate and is far below the sampling error itself.
    pub fn expand(self, count: u64) -> u64 {
        let denominator = (self.denominator as u128).max(1);
        ((count as u128).saturating_mul(self.numerator as u128) / denominator).min(u64::MAX as u128)
            as u64
    }

    /// Whether two ratios denote the same fraction, compared by cross-product so
    /// equivalent forms (for example `1000/1` and `2000/2`) count as equal.
    pub fn equivalent(self, other: SamplingRatio) -> bool {
        (self.numerator as u128) * (other.denominator as u128)
            == (other.numerator as u128) * (self.denominator as u128)
    }
}

/// The rate stored for one sampler key.
///
/// A specific sampler (`FlowSampler`/`Selector`) is precisely attributable, so a
/// re-advertisement is a legitimate reconfiguration and simply replaces the
/// value. The [`SamplerSelector::Domain`] bucket is different: exporters that
/// scope sampling by a finer key we cannot match to a flow (per interface, line
/// card, …) with no `flowSamplerId`/`selectorId` all land here. If such records
/// advertise *different* rates the domain is genuinely multi-sampler and an
/// untagged flow cannot be attributed to any one of them, so the entry becomes
/// [`SamplerRate::Ambiguous`] and stops scaling (a factor of 1) rather than
/// applying an arbitrary wrong rate. See `docs/exporter-identity.md`; matching
/// such flows per interface/line card is not supported in this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SamplerRate {
    Fixed(SamplingRatio),
    Ambiguous,
}

/// Concurrent, size-bounded cache of the sampling ratio advertised per
/// `(exporter, scope, selector)`.
pub struct SamplingTracker {
    rates: DashMap<SamplingKey, SamplerRate>,
    max_samplers: usize,
    sampler_count: AtomicUsize,
}

impl SamplingTracker {
    pub fn new(max_samplers: usize) -> Self {
        Self {
            rates: DashMap::new(),
            max_samplers,
            sampler_count: AtomicUsize::new(0),
        }
    }

    /// Records the latest sampling `ratio` for one sampler, identified by its
    /// `(exporter, scope, selector)`.
    ///
    /// A degenerate ratio (either term zero) cannot scale counters and is
    /// ignored. A specific sampler (`FlowSampler`/`Selector`) is always
    /// refreshed in place. For the [`SamplerSelector::Domain`] bucket a second,
    /// *conflicting* rate marks it ambiguous so untagged flows stop being scaled
    /// instead of being mis-scaled; an equivalent rate (`1000/1` vs `2000/2`) is
    /// not a conflict. A brand new sampler is admitted only while below the hard
    /// cap, so a hostile exporter flooding distinct samplers cannot grow this
    /// cache without bound.
    pub fn observe(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        selector: SamplerSelector,
        ratio: SamplingRatio,
    ) {
        if ratio.numerator == 0 || ratio.denominator == 0 {
            return;
        }
        match self.rates.entry((exporter, scope, selector)) {
            Entry::Occupied(mut entry) => {
                let slot = entry.get_mut();
                *slot = match (*slot, selector) {
                    // A genuinely different domain-wide rate cannot be attributed
                    // to a single sampler, so the whole bucket is poisoned.
                    (SamplerRate::Fixed(existing), SamplerSelector::Domain)
                        if !existing.equivalent(ratio) =>
                    {
                        SamplerRate::Ambiguous
                    }
                    (SamplerRate::Ambiguous, SamplerSelector::Domain) => SamplerRate::Ambiguous,
                    // A specific sampler is precisely attributable: a new rate is
                    // a legitimate reconfiguration that simply replaces it.
                    _ => SamplerRate::Fixed(ratio),
                };
            }
            Entry::Vacant(entry) => {
                let reserved = self
                    .sampler_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < self.max_samplers).then_some(count + 1)
                    })
                    .is_ok();
                if reserved {
                    entry.insert(SamplerRate::Fixed(ratio));
                }
            }
        }
    }

    /// The sampling ratio unambiguously advertised for one sampler, if any.
    /// A poisoned (ambiguous) domain bucket reports `None`.
    pub fn get(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        selector: SamplerSelector,
    ) -> Option<SamplingRatio> {
        match self
            .rates
            .get(&(exporter, scope, selector))
            .map(|e| *e.value())
        {
            Some(SamplerRate::Fixed(ratio)) => Some(ratio),
            Some(SamplerRate::Ambiguous) | None => None,
        }
    }

    /// The sampling ratio to scale a flow by: the sampler's rate when it is
    /// known and unambiguous, otherwise [`SamplingRatio::NONE`] (no scaling).
    pub fn ratio(
        &self,
        exporter: ExporterKey,
        scope: Scope,
        selector: SamplerSelector,
    ) -> SamplingRatio {
        self.get(exporter, scope, selector)
            .unwrap_or(SamplingRatio::NONE)
    }

    pub fn len(&self) -> usize {
        self.rates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rates.is_empty()
    }

    /// Drops every sampling entry belonging to `exporter`, across all of its
    /// scopes and samplers, releasing each reserved capacity slot. Returns the
    /// number of samplers removed. Part of the per-key purge that retires a
    /// transport session (e.g. an exporter restart) without leaking bounded
    /// slots.
    pub fn purge_exporter(&self, exporter: ExporterKey) -> usize {
        let mut removed = 0usize;
        let count = &self.sampler_count;
        self.rates.retain(|key, _rate| {
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::scope::SINGLE_EXPORTER;

    const D7: Scope = Scope::V9Domain(7);
    const SAMPLER_A: SamplerSelector = SamplerSelector::FlowSampler(1);
    const SAMPLER_B: SamplerSelector = SamplerSelector::FlowSampler(2);

    fn ratio(numerator: u64, denominator: u64) -> SamplingRatio {
        SamplingRatio {
            numerator,
            denominator,
        }
    }

    #[test]
    fn expand_multiplies_before_dividing() {
        assert_eq!(SamplingRatio::NONE.expand(42), 42);
        assert_eq!(ratio(1000, 1).expand(3), 3000);
        // 11/2 applied to 2 sampled packets is 11, not 10 (5 * 2).
        assert_eq!(ratio(11, 2).expand(2), 11);
        // A wide count-based ratio near u32::MAX keeps its 2:1 shape.
        let wide = u64::from(u32::MAX);
        assert_eq!(ratio(2 * wide, wide).expand(5), 10);
        // Saturates rather than overflowing.
        assert_eq!(ratio(u64::MAX, 1).expand(u64::MAX), u64::MAX);
    }

    #[test]
    fn observe_stores_and_refreshes_ratio() {
        let tracker = SamplingTracker::new(4);
        assert!(tracker.is_empty());
        assert_eq!(tracker.get(SINGLE_EXPORTER, D7, SAMPLER_A), None);
        assert_eq!(
            tracker.ratio(SINGLE_EXPORTER, D7, SAMPLER_A),
            SamplingRatio::NONE
        );

        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(1000, 1));
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, SAMPLER_A),
            Some(ratio(1000, 1))
        );

        // A later advertisement replaces the previous ratio for that sampler.
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(2000, 1));
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, SAMPLER_A),
            Some(ratio(2000, 1))
        );
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn distinct_samplers_in_one_domain_do_not_overwrite() {
        let tracker = SamplingTracker::new(4);
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(100, 1));
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_B, ratio(200, 1));
        assert_eq!(tracker.len(), 2);
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, SAMPLER_A),
            Some(ratio(100, 1))
        );
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, SAMPLER_B),
            Some(ratio(200, 1))
        );
    }

    #[test]
    fn conflicting_domain_rates_poison_the_bucket() {
        let tracker = SamplingTracker::new(4);
        let domain = SamplerSelector::Domain;
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(100, 1));
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, domain),
            Some(ratio(100, 1))
        );

        // A second, different domain-wide rate cannot be attributed to one
        // sampler, so the bucket is poisoned and stops scaling.
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(200, 1));
        assert_eq!(tracker.get(SINGLE_EXPORTER, D7, domain), None);
        assert_eq!(
            tracker.ratio(SINGLE_EXPORTER, D7, domain),
            SamplingRatio::NONE
        );

        // Even re-seeing the original rate does not un-poison it.
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(100, 1));
        assert_eq!(tracker.get(SINGLE_EXPORTER, D7, domain), None);
    }

    #[test]
    fn equivalent_domain_rate_does_not_poison() {
        let tracker = SamplingTracker::new(4);
        let domain = SamplerSelector::Domain;
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(1000, 1));
        // The same fraction in a different form is not a conflict.
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(2000, 2));
        let stored = tracker.get(SINGLE_EXPORTER, D7, domain).unwrap();
        assert!(stored.equivalent(ratio(1000, 1)));
    }

    #[test]
    fn repeated_identical_domain_rate_stays_fixed() {
        let tracker = SamplingTracker::new(4);
        let domain = SamplerSelector::Domain;
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(1000, 1));
        tracker.observe(SINGLE_EXPORTER, D7, domain, ratio(1000, 1));
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, domain),
            Some(ratio(1000, 1))
        );
    }

    #[test]
    fn specific_sampler_reconfiguration_is_not_ambiguous() {
        // A specific sampler is precisely attributable, so a changed rate is a
        // legitimate reconfiguration that replaces the value (last wins).
        let tracker = SamplingTracker::new(4);
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(100, 1));
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(200, 1));
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, SAMPLER_A),
            Some(ratio(200, 1))
        );
    }

    #[test]
    fn degenerate_ratio_is_ignored() {
        let tracker = SamplingTracker::new(4);
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(0, 1));
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_B, ratio(5, 0));
        assert!(tracker.is_empty());
    }

    #[test]
    fn samplers_are_bounded() {
        let tracker = SamplingTracker::new(1);
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_A, ratio(100, 1));
        tracker.observe(SINGLE_EXPORTER, D7, SAMPLER_B, ratio(200, 1));
        assert_eq!(
            tracker.get(SINGLE_EXPORTER, D7, SAMPLER_A),
            Some(ratio(100, 1))
        );
        assert_eq!(tracker.get(SINGLE_EXPORTER, D7, SAMPLER_B), None);
    }

    #[test]
    fn state_is_independent_per_exporter_and_protocol() {
        let tracker = SamplingTracker::new(8);
        // The same numeric domain 7 stays distinct across exporters and protocols.
        tracker.observe(1, Scope::V9Domain(7), SAMPLER_A, ratio(10, 1));
        tracker.observe(2, Scope::V9Domain(7), SAMPLER_A, ratio(20, 1));
        tracker.observe(1, Scope::IpfixDomain(7), SAMPLER_A, ratio(30, 1));

        assert_eq!(tracker.len(), 3);
        assert_eq!(
            tracker.get(1, Scope::V9Domain(7), SAMPLER_A),
            Some(ratio(10, 1))
        );
        assert_eq!(
            tracker.get(2, Scope::V9Domain(7), SAMPLER_A),
            Some(ratio(20, 1))
        );
        assert_eq!(
            tracker.get(1, Scope::IpfixDomain(7), SAMPLER_A),
            Some(ratio(30, 1))
        );
        assert_eq!(tracker.get(2, Scope::IpfixDomain(7), SAMPLER_A), None);
    }

    #[test]
    fn purge_drops_only_the_exporter_and_reclaims_slots() {
        // Cap of 2 so the reclaimed slot's reuse is observable.
        let tracker = SamplingTracker::new(2);
        tracker.observe(1, Scope::V9Domain(7), SAMPLER_A, ratio(10, 1));
        tracker.observe(2, Scope::V9Domain(7), SAMPLER_A, ratio(20, 1));
        assert_eq!(tracker.len(), 2);

        assert_eq!(tracker.purge_exporter(1), 1);
        assert_eq!(tracker.get(1, Scope::V9Domain(7), SAMPLER_A), None);
        assert_eq!(
            tracker.get(2, Scope::V9Domain(7), SAMPLER_A),
            Some(ratio(20, 1))
        );
        assert_eq!(tracker.len(), 1);

        // The freed slot admits a new sampler rather than being rejected by the cap.
        tracker.observe(3, Scope::V9Domain(7), SAMPLER_A, ratio(30, 1));
        assert_eq!(tracker.len(), 2);
        assert_eq!(
            tracker.get(3, Scope::V9Domain(7), SAMPLER_A),
            Some(ratio(30, 1))
        );
    }
}
