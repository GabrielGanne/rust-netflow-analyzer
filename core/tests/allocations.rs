// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use common::{flowset, ipfix_header, packet, sample_v5_packet, template_record, v9_header};
use netflow_analyzer_core::FlowContext;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn count_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(current) = count.get() {
            count.set(Some(current.saturating_add(1)));
        }
    });
}

// SAFETY: All allocation operations are delegated unchanged to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn assert_no_allocations(ctx: &FlowContext, bytes: &[u8], expected: usize) {
    for aggregate in [false, true] {
        let operation = || {
            if aggregate {
                ctx.process_packet_at(bytes, 1_700_000_000_000_000_000)
            } else {
                ctx.decode_packet_at(bytes, 1_700_000_000_000_000_000, &mut |_, _| {})
            }
        };
        assert_eq!(operation(), Ok(expected));

        ALLOCATIONS.with(|count| count.set(Some(0)));
        let result = operation();
        let allocations = ALLOCATIONS.with(|count| count.replace(None).unwrap());

        assert_eq!(result, Ok(expected));
        assert_eq!(allocations, 0, "aggregate={aggregate}, records={expected}");
    }
}

#[test]
fn v5_fixed_record_framing_does_not_allocate() {
    let ctx = FlowContext::new();
    let records = [([192, 0, 2, 1], [192, 0, 2, 2], 1, 100, 1234, 80, 6); 1000];
    let mut bytes = sample_v5_packet(&records);
    for count in [0u16, 1, 1000, u16::MAX] {
        bytes[2..4].copy_from_slice(&count.to_be_bytes());
        assert_no_allocations(&ctx, &bytes, usize::from(count).min(records.len()));
    }
}

fn assert_template_framing_does_not_allocate(ipfix: bool) {
    let ctx = FlowContext::new();
    let header = if ipfix { ipfix_header(1) } else { v9_header(1) };
    let definition = packet(
        header.clone(),
        &[flowset(
            if ipfix { 2 } else { 0 },
            &template_record(256, &[(1, 8)]),
        )],
    );
    ctx.process_packet_at(&definition, 1_700_000_000_000_000_000)
        .expect("template parsed");

    for count in [1, 30, 1000] {
        let body = 100u64.to_be_bytes().repeat(count);
        let bytes = packet(header.clone(), &[flowset(256, &body)]);
        assert_no_allocations(&ctx, &bytes, count);
    }
}

#[test]
fn v9_fixed_record_framing_does_not_allocate() {
    assert_template_framing_does_not_allocate(false);
}

#[test]
fn ipfix_fixed_record_framing_does_not_allocate() {
    assert_template_framing_does_not_allocate(true);
}

#[test]
fn aging_without_flows_or_due_templates_does_not_allocate() {
    let ctx = FlowContext::new();
    let now = 1_700_000_000_000_000_000;
    let definition = packet(
        ipfix_header(1),
        &[flowset(2, &template_record(256, &[(1, 8)]))],
    );
    ctx.decode_packet_at(&definition, now, &mut |_, _| {})
        .expect("template parsed");
    assert_eq!(ctx.age_at(now, |_| {}), 0);

    ALLOCATIONS.with(|count| count.set(Some(0)));
    let emitted = ctx.age_at(now + 1_000_000_000, |_| {});
    let allocations = ALLOCATIONS.with(|count| count.replace(None).unwrap());

    assert_eq!(emitted, 0);
    assert_eq!(allocations, 0);
    assert_eq!(ctx.active_templates(), 1);

    ctx.age_at(now + 31 * 60 * 1_000_000_000, |_| {});
    assert_eq!(ctx.active_templates(), 0);
}
