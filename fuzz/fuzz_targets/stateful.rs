// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A sequence of datagrams fed to one context, so templates learned from one
//! packet decode (fixed- and variable-length) data records in later ones, and
//! refreshes, withdrawals, options records, and aging interleave.
//!
//! Input format: repeated `[len_hi, len_lo, delay_secs, packet[len]]`. The
//! delay advances the receipt time; a zero-length packet runs an aging pass.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_analyzer_core::{EngineConfig, FlowContext};

const T0: u64 = 1_700_000_000_000_000_000;
const SECOND: u64 = 1_000_000_000;

fuzz_target!(|data: &[u8]| {
    // Small caps so bounded-cache admission and rejection are reachable.
    let ctx = FlowContext::with_config(EngineConfig {
        max_flows: 64,
        max_templates: 16,
        ..EngineConfig::default()
    });
    let mut now = T0;
    let mut rest = data;
    while let [hi, lo, delay, tail @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([*hi, *lo])).min(tail.len());
        let (packet, next) = tail.split_at(len);
        rest = next;
        now += u64::from(*delay) * SECOND;

        if packet.is_empty() {
            ctx.age_at(now, |_| {});
        } else {
            let _ = ctx.process_packet_at(packet, now);
        }
        assert!(ctx.active_flows() <= 64);
        assert!(ctx.active_templates() <= 16);
    }
    ctx.flush(|_| {});
    assert_eq!(ctx.active_flows(), 0);
});
