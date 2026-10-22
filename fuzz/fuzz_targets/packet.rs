// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One datagram through both entry points: headers, FlowSet/Set framing,
//! template and options-template sets, and the data records they describe
//! when a template precedes its data set in the same packet.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_analyzer_core::FlowContext;

const T0: u64 = 1_700_000_000_000_000_000;

fuzz_target!(|data: &[u8]| {
    let ctx = FlowContext::new();
    let mut decoded = 0usize;
    let result = ctx.decode_packet_at(data, T0, &mut |_, _| decoded += 1);
    if let Ok(records) = result {
        assert_eq!(records, decoded, "every decoded record reaches the sink");
    }

    let fused = FlowContext::new();
    let processed = fused.process_packet_at(data, T0);
    assert_eq!(processed.is_ok(), result.is_ok(), "both paths agree on errors");
    assert!(fused.active_flows() <= processed.unwrap_or(0));
    fused.age_at(u64::MAX, |_| {});
    assert_eq!(fused.active_flows(), 0, "aging at the end of time drains the cache");
});
