// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use netflow_analyzer_core::cache::AgingConfig;
use netflow_analyzer_core::clock::ClockConfig;
use netflow_analyzer_core::records::{FlowFields, FlowRecord, NetflowAnalyzerFlowRecord};
use netflow_analyzer_core::scope::{ExporterKey, Scope};
use netflow_analyzer_core::stats::NetflowAnalyzerStats;
use netflow_analyzer_core::{EngineConfig, FlowContext, CLOCK_SKEW_ERROR};

// Protocol discriminator values for `NetflowAnalyzerFlowRecord::scope_protocol`.
// These are literals (rather than re-exports of the core `scope` constants)
// because cbindgen cannot evaluate cross-crate constant paths;
// `scope_protocol_tags_match_core` keeps them in sync.
pub const NETFLOW_ANALYZER_SCOPE_V9: u8 = 0;
pub const NETFLOW_ANALYZER_SCOPE_IPFIX: u8 = 1;
pub const NETFLOW_ANALYZER_SCOPE_V5: u8 = 2;

/// C-compatible callback invoked whenever a flow is emitted: from the
/// background aging thread on idle eviction or active-timeout rollover, and
/// synchronously on the thread that calls `netflow_analyzer_flush` or
/// `netflow_analyzer_purge_exporter`.
///
/// Callback contract (the decode-only [`NetflowAnalyzerRecordCallback`] has a
/// separate, per-call contract documented on that type):
///
/// - Non-null: the callback pointer passed to `netflow_analyzer_create` must be
///   a valid function pointer. A null callback is **rejected** —
///   `netflow_analyzer_create` returns null rather than registering it — so it
///   is never stored or called. `record` is always non-null and points to a
///   valid record for the duration of the call. `user_data` is whatever was
///   supplied at creation and may be null if the host chose so.
/// - Thread: this callback may run on the engine's internal aging thread *or*
///   on any host thread that calls `netflow_analyzer_flush` /
///   `netflow_analyzer_purge_exporter`, so treat it as potentially concurrent
///   with the host's own threads.
/// - `record` lifetime: the pointer is borrowed and valid only for the duration
///   of the call. Copy out any fields you need to retain; never store the
///   pointer or dereference it after returning.
/// - `user_data` lifetime and synchronization: the engine stores the pointer
///   verbatim and hands it back unchanged on every call. The host owns it and
///   must keep whatever it points to valid for as long as the callback can
///   still run: the aging thread may deliver flows until
///   `netflow_analyzer_destroy` returns, and a `flush`/`purge` call until that
///   call returns. `netflow_analyzer_destroy` joins the aging thread but does
///   **not** fence concurrent host calls, so quiesce all other API calls before
///   destroying. Synchronize any access the callback makes with the host's own
///   threads.
/// - Reentrancy and duration: the engine holds no internal cache lock while
///   invoking the callback, so calling back into the engine does not deadlock.
///   Read-only calls (for example `netflow_analyzer_get_stats`) are safe.
///   Packet ingestion is safe *except* for a key currently being purged: when
///   this callback was entered from `netflow_analyzer_purge_exporter`,
///   ingesting for that exporter mid-purge can orphan state (see that
///   function's contract). `netflow_analyzer_flush` and
///   `netflow_analyzer_purge_exporter` re-enter this same callback once per
///   flow they emit, so call them only if the callback is re-entrant. It must
///   **not** call `netflow_analyzer_destroy`. It runs on the aging thread or on
///   the thread that called `flush`/`purge` (packet-processing calls never
///   dispatch it), and should return promptly and must not block, since a slow
///   callback stalls aging or the `flush`/`purge` call.
pub type NetflowAnalyzerFlowCallback =
    Option<extern "C" fn(record: *const NetflowAnalyzerFlowRecord, user_data: *mut c_void)>;

/// C-compatible callback invoked once per decoded data record on the decode-only
/// path (`netflow_analyzer_decode_packet[_at]`), before any aggregation. The
/// `observation_domain_id` scopes the record (NetFlow v5 reports `0`).
///
/// Unlike [`NetflowAnalyzerFlowCallback`], this callback is **not** registered
/// on the context: it is passed to a single `netflow_analyzer_decode_packet*`
/// call and used only during that call. Contract:
///
/// - Non-null: the callback pointer passed to the decode function must be a
///   valid function pointer. A null callback is **rejected** — the decode
///   function returns `-1` and decodes nothing. `record` is always non-null and
///   valid for the duration of the call; `user_data` is whatever was passed to
///   that decode call and may be null.
/// - Thread: it always runs **synchronously on the thread that called
///   `netflow_analyzer_decode_packet*`** — never the aging thread.
/// - `record` lifetime: the pointer is borrowed and valid only for the duration
///   of the call. Copy out any fields you need to retain; never store it.
/// - `user_data` lifetime: the decode call only needs it to stay valid until
///   that call returns; it is not retained afterwards.
/// - Reentrancy and duration: the engine holds no internal cache lock while
///   invoking the callback, so calling back into the engine does not deadlock.
///   Do **not** purge the exporter being decoded from within this callback: the
///   enclosing `netflow_analyzer_decode_packet*` call keeps walking later Sets
///   afterward and can repopulate that key's template/clock state, defeating the
///   purge — defer a same-key purge until the decode call returns. It must
///   **not** call `netflow_analyzer_destroy`, and it should return promptly and
///   must not block.
pub type NetflowAnalyzerRecordCallback = Option<
    extern "C" fn(
        observation_domain_id: u32,
        record: *const NetflowAnalyzerFlowRecord,
        user_data: *mut c_void,
    ),
>;

// Presence bits for `NetflowAnalyzerFlowRecord::present`. A field whose bit is
// clear was not exported by the source records: its value is `0` and should be
// treated as absent rather than a real zero. These are literals (rather than
// re-exports of the core `presence` module) because cbindgen cannot evaluate
// cross-crate constant paths; `presence_bits_match_core` keeps them in sync.
pub const NETFLOW_ANALYZER_PRESENT_FLOW_ID: u32 = 1 << 0;
pub const NETFLOW_ANALYZER_PRESENT_IFACE_IN: u32 = 1 << 1;
pub const NETFLOW_ANALYZER_PRESENT_IFACE_OUT: u32 = 1 << 2;
pub const NETFLOW_ANALYZER_PRESENT_SRC_MAC: u32 = 1 << 3;
pub const NETFLOW_ANALYZER_PRESENT_DST_MAC: u32 = 1 << 4;
pub const NETFLOW_ANALYZER_PRESENT_ICMP_TYPE: u32 = 1 << 5;
pub const NETFLOW_ANALYZER_PRESENT_ICMP_CODE: u32 = 1 << 6;
pub const NETFLOW_ANALYZER_PRESENT_TCP_FLAGS: u32 = 1 << 7;
pub const NETFLOW_ANALYZER_PRESENT_DSCP: u32 = 1 << 8;
pub const NETFLOW_ANALYZER_PRESENT_VLAN_TAG: u32 = 1 << 9;
pub const NETFLOW_ANALYZER_PRESENT_IP_VERSION: u32 = 1 << 10;

/// Tunable engine settings passed from C at construction time. A null pointer
/// to [`netflow_analyzer_create`] selects library defaults for every field.
#[repr(C)]
pub struct NetflowAnalyzerConfig {
    pub max_flows: u64,
    pub max_templates: u64,
    pub idle_timeout_secs: u64,
    pub active_timeout_secs: u64,
    pub scan_interval_secs: u64,
    /// Enable export-time versus receipt-time skew validation.
    pub clock_sync_check_enabled: bool,
    /// Correct skewed timestamps from receipt time instead of dropping packets.
    pub clock_fallback_to_receipt_time: bool,
    /// Maximum accepted clock skew, in nanoseconds. Zero selects the default.
    pub max_clock_skew_ns: u64,
}

/// Wrapper that lets us move the host's opaque `user_data` pointer onto the
/// background aging thread. The host is responsible for ensuring the pointed-to
/// data is safe to access from another thread.
#[derive(Clone, Copy)]
struct SendUserData(*mut c_void);
unsafe impl Send for SendUserData {}
unsafe impl Sync for SendUserData {}

/// Bare function-pointer form of [`NetflowAnalyzerFlowCallback`]. The public
/// type is `Option<..>` so a null pointer from C is representable and rejected
/// at the boundary; once validated as non-null it is stored and passed around
/// as this non-optional pointer.
type FlowCallbackFn =
    extern "C" fn(record: *const NetflowAnalyzerFlowRecord, user_data: *mut c_void);

/// Opaque handle handed back to C. Holds the engine plus the emission callback.
pub struct NetflowAnalyzerContext {
    internal: Arc<FlowContext>,
    callback: FlowCallbackFn,
    user_data: SendUserData,
}

fn engine_config_from(cfg: &NetflowAnalyzerConfig) -> EngineConfig {
    let defaults = EngineConfig::default();
    let nonzero = |value: u64, fallback: usize| {
        if value == 0 {
            fallback
        } else {
            value as usize
        }
    };
    let secs = |value: u64, fallback: Duration| {
        if value == 0 {
            fallback
        } else {
            Duration::from_secs(value)
        }
    };

    EngineConfig {
        max_flows: nonzero(cfg.max_flows, defaults.max_flows),
        max_templates: nonzero(cfg.max_templates, defaults.max_templates),
        aging: AgingConfig {
            idle_timeout: secs(cfg.idle_timeout_secs, defaults.aging.idle_timeout),
            active_timeout: secs(cfg.active_timeout_secs, defaults.aging.active_timeout),
            scan_interval: secs(cfg.scan_interval_secs, defaults.aging.scan_interval),
        },
        clock: ClockConfig {
            sync_check_enabled: cfg.clock_sync_check_enabled,
            max_skew: if cfg.max_clock_skew_ns == 0 {
                defaults.clock.max_skew
            } else {
                Duration::from_nanos(cfg.max_clock_skew_ns)
            },
            fallback_to_receipt_time: cfg.clock_fallback_to_receipt_time,
        },
    }
}

/// Constructor exposed to C to initialize the library and start the background
/// aging thread. Pass a null `config` to use the built-in defaults.
///
/// `callback` receives every emitted flow; see [`NetflowAnalyzerFlowCallback`]
/// for its full contract (non-null requirement, callback thread, `record` and
/// `user_data` lifetimes, reentrancy). The registered callback and `user_data`
/// must remain valid until after `netflow_analyzer_destroy` returns, because
/// the aging thread can deliver flows at any time until then.
///
/// Returns null on failure: a **null `callback`** is rejected (taking the
/// parameter as `Option` lets a null pointer from C arrive safely as `None`),
/// and so is a failure to spawn the background aging thread.
///
/// # Safety
/// `config` must be either null or a valid pointer to a `NetflowAnalyzerConfig`.
/// `user_data` is stored verbatim and handed back to `callback` unchanged.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_create(
    config: *const NetflowAnalyzerConfig,
    callback: NetflowAnalyzerFlowCallback,
    user_data: *mut c_void,
) -> *mut NetflowAnalyzerContext {
    guard_ffi(std::ptr::null_mut(), || unsafe {
        // Reject a null callback instead of accepting an invalid function pointer.
        let Some(callback) = callback else {
            return std::ptr::null_mut();
        };

        let engine_cfg = if config.is_null() {
            EngineConfig::default()
        } else {
            engine_config_from(&*config)
        };

        let internal = Arc::new(FlowContext::with_config(engine_cfg));
        let user_data = SendUserData(user_data);

        // Bridge the emitted Rust records to the C callback. The user_data
        // pointer is wrapped so it can cross into the aging worker. If the
        // worker thread cannot be created, hand back null instead of a context.
        if internal
            .try_start_aging(move |record: &FlowRecord| {
                emit_record(callback, user_data, record);
            })
            .is_err()
        {
            return std::ptr::null_mut();
        }

        Box::into_raw(Box::new(NetflowAnalyzerContext {
            internal,
            callback,
            user_data,
        }))
    })
}

/// Converts a Rust record into its FFI shape and dispatches it to the host.
fn emit_record(callback: FlowCallbackFn, user_data: SendUserData, record: &FlowRecord) {
    let ffi = record.to_ffi();
    callback(&ffi as *const NetflowAnalyzerFlowRecord, user_data.0);
}

/// Error code an FFI entry point returns when it catches an internal Rust panic
/// instead of letting it cross the C ABI boundary.
const NETFLOW_ANALYZER_INTERNAL_ERROR: i32 = -4;

/// Runs `body`, catching any Rust panic so it never unwinds across the C ABI —
/// which since Rust 1.81 would otherwise abort the whole host process. A caught
/// panic yields `on_panic` instead.
///
/// `AssertUnwindSafe` is sound here: on a caught panic the only value observed
/// by C is the fixed `on_panic`, and the engine state lives behind `Arc`/
/// `DashMap`/atomics, which stay memory-safe across an unwind.
fn guard_ffi<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(on_panic)
}

/// A zeroed telemetry snapshot, returned when there is no context to query.
fn zeroed_stats() -> NetflowAnalyzerStats {
    NetflowAnalyzerStats {
        pkts_parsed: 0,
        pkts_parse_error: 0,
        malformed_packets: 0,
        clock_dropped_packets: 0,
        clock_fallback_packets: 0,
        templates_received: 0,
        data_records_processed: 0,
        flows_output: 0,
        flows_dropped: 0,
        active_flows: 0,
    }
}

/// Non-blocking telemetry retrieval for a separate monitoring thread.
///
/// # Safety
/// `ctx` must be null or a pointer previously returned by `netflow_analyzer_create`.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_get_stats(
    ctx: *const NetflowAnalyzerContext,
) -> NetflowAnalyzerStats {
    guard_ffi(zeroed_stats(), || unsafe {
        if ctx.is_null() {
            return zeroed_stats();
        }
        (*ctx).internal.stats()
    })
}

/// Core processing entry point called by C worker threads when a datagram
/// arrives. Returns the number of data records decoded, or a negative error
/// code (`-1` invalid arguments, `-2` malformed packet, `-3` clock rejection,
/// `-4` internal error / caught panic).
///
/// # Safety
/// `ctx` must be a valid context pointer and `packet_bytes` must point to at
/// least `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet(
    ctx: *const NetflowAnalyzerContext,
    packet_bytes: *const u8,
    length: u32,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx).internal.process_packet(data) {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Processing entry point with an explicit Unix-nanosecond receipt timestamp.
/// This is the preferred entry point for offline packet-capture readers.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_process_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet_at(
    ctx: *const NetflowAnalyzerContext,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx).internal.process_packet_at(data, receipt_time_ns) {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Like [`netflow_analyzer_process_packet`], but scopes all template, clock, and
/// flow state to the caller-supplied `exporter_key` and stamps it onto emitted
/// records, so one context can serve many exporters without their state
/// colliding. See `docs/exporter-identity.md` for the exporter-key contract.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_process_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet_from(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: u64,
    packet_bytes: *const u8,
    length: u32,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx).internal.process_packet_from(exporter_key, data) {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Like [`netflow_analyzer_process_packet_from`], with an explicit
/// Unix-nanosecond receipt timestamp.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_process_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet_from_at(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: u64,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx)
            .internal
            .process_packet_from_at(exporter_key, data, receipt_time_ns)
        {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Decode-only entry point: parses a datagram and invokes `callback` once per
/// decoded data record, **without** aggregating into the flow cache. Template
/// state is still updated (it is required to decode). Returns the number of data
/// records decoded, or a negative error code (`-1` invalid arguments, `-2`
/// malformed packet, `-3` clock rejection, `-4` internal error / caught panic).
///
/// This lets a host run the parser as an independent stage and feed its own
/// aggregator, mirroring the local `netflow-parser` node.
///
/// # Safety
/// `ctx` must be a valid context pointer and `packet_bytes` must point to at
/// least `length` readable bytes. `user_data` is passed through unchanged.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_decode_packet(
    ctx: *const NetflowAnalyzerContext,
    packet_bytes: *const u8,
    length: u32,
    callback: NetflowAnalyzerRecordCallback,
    user_data: *mut c_void,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        // Reject a null callback rather than call an invalid function pointer.
        let Some(callback) = callback else {
            return -1;
        };
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        let mut sink = |exporter: ExporterKey, scope: Scope, fields: &FlowFields| {
            let record = fields.to_ffi(exporter, scope);
            callback(
                scope.observation_domain(),
                &record as *const NetflowAnalyzerFlowRecord,
                user_data,
            );
        };
        match (*ctx).internal.decode_packet_scoped(data, &mut sink) {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Decode-only entry point with an explicit Unix-nanosecond receipt timestamp.
/// Preferred for offline packet-capture readers.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_decode_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_decode_packet_at(
    ctx: *const NetflowAnalyzerContext,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
    callback: NetflowAnalyzerRecordCallback,
    user_data: *mut c_void,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        // Reject a null callback rather than call an invalid function pointer.
        let Some(callback) = callback else {
            return -1;
        };
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        let mut sink = |exporter: ExporterKey, scope: Scope, fields: &FlowFields| {
            let record = fields.to_ffi(exporter, scope);
            callback(
                scope.observation_domain(),
                &record as *const NetflowAnalyzerFlowRecord,
                user_data,
            );
        };
        match (*ctx)
            .internal
            .decode_packet_scoped_at(data, receipt_time_ns, &mut sink)
        {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Like [`netflow_analyzer_decode_packet`], but scopes decoding to the
/// caller-supplied `exporter_key`, which is stamped onto each emitted record.
/// See `docs/exporter-identity.md` for the exporter-key contract.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_decode_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_decode_packet_from(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: u64,
    packet_bytes: *const u8,
    length: u32,
    callback: NetflowAnalyzerRecordCallback,
    user_data: *mut c_void,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        // Reject a null callback rather than call an invalid function pointer.
        let Some(callback) = callback else {
            return -1;
        };
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        let mut sink = |exporter: ExporterKey, scope: Scope, fields: &FlowFields| {
            let record = fields.to_ffi(exporter, scope);
            callback(
                scope.observation_domain(),
                &record as *const NetflowAnalyzerFlowRecord,
                user_data,
            );
        };
        match (*ctx)
            .internal
            .decode_packet_from(exporter_key, data, &mut sink)
        {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Like [`netflow_analyzer_decode_packet_from`], with an explicit
/// Unix-nanosecond receipt timestamp.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_decode_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_decode_packet_from_at(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: u64,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
    callback: NetflowAnalyzerRecordCallback,
    user_data: *mut c_void,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || packet_bytes.is_null() {
            return -1;
        }
        // Reject a null callback rather than call an invalid function pointer.
        let Some(callback) = callback else {
            return -1;
        };
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        let mut sink = |exporter: ExporterKey, scope: Scope, fields: &FlowFields| {
            let record = fields.to_ffi(exporter, scope);
            callback(
                scope.observation_domain(),
                &record as *const NetflowAnalyzerFlowRecord,
                user_data,
            );
        };
        match (*ctx)
            .internal
            .decode_packet_from_at(exporter_key, data, receipt_time_ns, &mut sink)
        {
            Ok(records) => records as i32,
            Err(CLOCK_SKEW_ERROR) => -3,
            Err(_) => -2,
        }
    })
}

/// Forces every cached flow to be emitted through the callback immediately.
/// Useful before shutdown so no residual state is lost.
///
/// # Safety
/// `ctx` must be null or a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_flush(ctx: *const NetflowAnalyzerContext) {
    guard_ffi((), || unsafe {
        if ctx.is_null() {
            return;
        }
        let context = &*ctx;
        let callback = context.callback;
        let user_data = context.user_data;
        context
            .internal
            .flush(move |record| emit_record(callback, user_data, record));
    })
}

/// Purges all cached state for one exporter/transport session, reclaiming its
/// slots in every cache. Returns the number of flows emitted, or `-1` if `ctx`
/// is null.
///
/// The exporter's resident flows are emitted through the registered flow
/// callback **first** (so traffic accumulated since the last aging sweep is not
/// lost), then its templates and clock state are dropped. Call this before
/// retiring an exporter key — for example after detecting that the exporter
/// restarted — so the bounded caches do not fill with stale sessions. See
/// `docs/exporter-identity.md` for the key contract and rotation rules.
///
/// Purge is **not** atomic against other use of the same key: the caller must
/// ensure that, while the purge runs, no other call ingests or decodes packets
/// for `exporter_key`. That covers every `netflow_analyzer_process_packet*` and
/// `netflow_analyzer_decode_packet*` entry point (the decode variants still
/// update template and clock state), including the key-`0` functions that map
/// to the reserved single-exporter key; otherwise state added mid-purge can be
/// orphaned. Callbacks run with no cache lock held, so calling this from inside
/// the flow callback does not deadlock; note it re-enters that callback once
/// per drained flow.
///
/// # Safety
/// `ctx` must be null or a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_purge_exporter(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: u64,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() {
            return -1;
        }
        let context = &*ctx;
        let callback = context.callback;
        let user_data = context.user_data;
        context
            .internal
            .purge_exporter(exporter_key, move |record| {
                emit_record(callback, user_data, record)
            }) as i32
    })
}

/// Destructor exposed to C. Stops the aging thread and releases all memory.
///
/// # Required shutdown sequence
/// `ctx` is freed here, so the caller must quiesce all use of it **first**:
///
/// 1. Stop feeding the context: ensure no thread is in, or will enter, any
///    `netflow_analyzer_*` call for this `ctx` (processing, decoding, stats,
///    flush, or purge). Destroy is **not** synchronized against concurrent
///    calls — one racing an in-flight call is a use-after-free.
/// 2. Optionally call `netflow_analyzer_flush` once (from that same quiesced
///    context) to emit residual flows before teardown.
/// 3. Call `netflow_analyzer_destroy` exactly once.
///
/// Do **not** call this from inside the flow or record callback: it runs on the
/// aging thread (or a `flush`/`purge` caller) and would tear down the very
/// engine that is mid-emit. `stop_aging` detaches rather than joins itself in
/// that case (so it will not deadlock), but the context is still freed while the
/// worker may run, so treat destruction-from-callback as unsupported. Calling
/// `netflow_analyzer_destroy(NULL)` and double-free are the caller's
/// responsibility to avoid; only a null pointer is handled as a no-op.
///
/// # Safety
/// `ctx` must be null or a pointer previously returned by `netflow_analyzer_create`,
/// must not be used afterwards, and no other call using `ctx` may run
/// concurrently with this one.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_destroy(ctx: *mut NetflowAnalyzerContext) {
    guard_ffi((), || unsafe {
        if ctx.is_null() {
            return;
        }
        let context = Box::from_raw(ctx);
        context.internal.stop_aging();
        // `context` drops here, releasing the engine and its caches.
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Test callback that counts emissions and records the last flow seen.
    extern "C" fn count_cb(record: *const NetflowAnalyzerFlowRecord, user_data: *mut c_void) {
        unsafe {
            let state = &*(user_data as *const TestState);
            state.count.fetch_add(1, Ordering::Relaxed);
            if let Some(rec) = record.as_ref() {
                state.last_proto.store(rec.proto as u32, Ordering::Relaxed);
            }
        }
    }

    struct TestState {
        count: AtomicU32,
        last_proto: AtomicU32,
    }

    /// Minimal NetFlow v9 packet: header + template (id 256) + one data record.
    fn v9_packet() -> Vec<u8> {
        let mut buf = Vec::new();
        let put = |value: u64, width: usize, buf: &mut Vec<u8>| {
            for i in 0..width {
                buf.push((value >> (8 * (width - 1 - i))) as u8);
            }
        };
        // Header.
        put(9, 2, &mut buf);
        put(2, 2, &mut buf);
        put(1000, 4, &mut buf);
        put(1_700_000_000, 4, &mut buf);
        put(1, 4, &mut buf);
        put(42, 4, &mut buf);
        // Template (id 256): IPV4_SRC, IPV4_DST, PROTOCOL.
        put(0, 2, &mut buf);
        put(20, 2, &mut buf); // 4 + 4 + 3*4
        put(256, 2, &mut buf);
        put(3, 2, &mut buf);
        put(8, 2, &mut buf);
        put(4, 2, &mut buf);
        put(12, 2, &mut buf);
        put(4, 2, &mut buf);
        put(4, 2, &mut buf);
        put(1, 2, &mut buf);
        // Data set (id 256): one 9-byte record.
        put(256, 2, &mut buf);
        put(13, 2, &mut buf); // 4 + 9
        put(0xC0A8_0001, 4, &mut buf);
        put(0x0808_0808, 4, &mut buf);
        put(17, 1, &mut buf);
        buf
    }

    #[test]
    fn config_from_zero_uses_defaults() {
        let zero = NetflowAnalyzerConfig {
            max_flows: 0,
            max_templates: 0,
            idle_timeout_secs: 0,
            active_timeout_secs: 0,
            scan_interval_secs: 0,
            clock_sync_check_enabled: false,
            clock_fallback_to_receipt_time: false,
            max_clock_skew_ns: 0,
        };
        let defaults = EngineConfig::default();
        let cfg = engine_config_from(&zero);
        assert_eq!(cfg.max_flows, defaults.max_flows);
        assert_eq!(cfg.max_templates, defaults.max_templates);
        assert_eq!(cfg.aging.idle_timeout, defaults.aging.idle_timeout);
        assert_eq!(cfg.aging.active_timeout, defaults.aging.active_timeout);
        assert_eq!(cfg.aging.scan_interval, defaults.aging.scan_interval);
        assert_eq!(cfg.clock, defaults.clock);
    }

    #[test]
    fn config_from_values_overrides() {
        let custom = NetflowAnalyzerConfig {
            max_flows: 10,
            max_templates: 5,
            idle_timeout_secs: 7,
            active_timeout_secs: 11,
            scan_interval_secs: 1,
            clock_sync_check_enabled: true,
            clock_fallback_to_receipt_time: true,
            max_clock_skew_ns: 123,
        };
        let cfg = engine_config_from(&custom);
        assert_eq!(cfg.max_flows, 10);
        assert_eq!(cfg.max_templates, 5);
        assert_eq!(cfg.aging.idle_timeout, Duration::from_secs(7));
        assert_eq!(cfg.aging.active_timeout, Duration::from_secs(11));
        assert_eq!(cfg.aging.scan_interval, Duration::from_secs(1));
        assert!(cfg.clock.sync_check_enabled);
        assert!(cfg.clock.fallback_to_receipt_time);
        assert_eq!(cfg.clock.max_skew, Duration::from_nanos(123));
    }

    #[test]
    fn full_lifecycle_decodes_and_emits() {
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;

        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(count_cb), ud) };
        assert!(!ctx.is_null());

        let packet = v9_packet();
        let n =
            unsafe { netflow_analyzer_process_packet(ctx, packet.as_ptr(), packet.len() as u32) };
        assert_eq!(n, 1);

        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.pkts_parsed, 1);
        assert_eq!(stats.pkts_parse_error, 0);
        assert_eq!(stats.data_records_processed, 1);
        assert_eq!(stats.templates_received, 1);
        assert_eq!(stats.active_flows, 1);

        // Flush emits the cached flow through our callback.
        unsafe { netflow_analyzer_flush(ctx) };
        assert_eq!(state.count.load(Ordering::Relaxed), 1);
        assert_eq!(state.last_proto.load(Ordering::Relaxed), 17);
        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.flows_output, 1);
        assert_eq!(stats.flows_dropped, 0);

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    /// Decode-only callback: counts per-record emissions and records the domain.
    extern "C" fn record_cb(
        observation_domain_id: u32,
        record: *const NetflowAnalyzerFlowRecord,
        user_data: *mut c_void,
    ) {
        unsafe {
            let state = &*(user_data as *const TestState);
            state.count.fetch_add(1, Ordering::Relaxed);
            state
                .last_proto
                .store(observation_domain_id, Ordering::Relaxed);
            assert!(!record.is_null());
        }
    }

    #[test]
    fn presence_bits_match_core() {
        use netflow_analyzer_core::records::presence;
        assert_eq!(NETFLOW_ANALYZER_PRESENT_FLOW_ID, presence::FLOW_ID);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_IFACE_IN, presence::IFACE_IN);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_IFACE_OUT, presence::IFACE_OUT);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_SRC_MAC, presence::SRC_MAC);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_DST_MAC, presence::DST_MAC);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_ICMP_TYPE, presence::ICMP_TYPE);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_ICMP_CODE, presence::ICMP_CODE);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_TCP_FLAGS, presence::TCP_FLAGS);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_DSCP, presence::DSCP);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_VLAN_TAG, presence::VLAN_TAG);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_IP_VERSION, presence::IP_VERSION);
    }

    #[test]
    fn scope_protocol_tags_match_core() {
        use netflow_analyzer_core::scope;
        assert_eq!(NETFLOW_ANALYZER_SCOPE_V9, scope::SCOPE_PROTOCOL_V9);
        assert_eq!(NETFLOW_ANALYZER_SCOPE_IPFIX, scope::SCOPE_PROTOCOL_IPFIX);
        assert_eq!(NETFLOW_ANALYZER_SCOPE_V5, scope::SCOPE_PROTOCOL_V5);
    }

    /// Flow callback that records the exporter key of each emitted record.
    extern "C" fn exporter_cb(record: *const NetflowAnalyzerFlowRecord, user_data: *mut c_void) {
        unsafe {
            let keys = &*(user_data as *const std::sync::Mutex<Vec<u64>>);
            if let Some(rec) = record.as_ref() {
                keys.lock().unwrap().push(rec.exporter_key);
            }
        }
    }

    #[test]
    fn process_packet_from_scopes_by_exporter() {
        let keys: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
        let ud = &keys as *const std::sync::Mutex<Vec<u64>> as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(exporter_cb), ud) };

        // Same datagram under two exporter keys must not aggregate together.
        let packet = v9_packet();
        assert_eq!(
            unsafe {
                netflow_analyzer_process_packet_from(ctx, 1, packet.as_ptr(), packet.len() as u32)
            },
            1
        );
        assert_eq!(
            unsafe {
                netflow_analyzer_process_packet_from(ctx, 2, packet.as_ptr(), packet.len() as u32)
            },
            1
        );
        assert_eq!(
            unsafe { netflow_analyzer_get_stats(ctx) }.active_flows,
            2,
            "each exporter keeps its own flow"
        );

        unsafe { netflow_analyzer_flush(ctx) };
        let mut seen = keys.lock().unwrap().clone();
        seen.sort_unstable();
        assert_eq!(seen, vec![1, 2], "emitted records carry their exporter key");

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn purge_exporter_emits_flows_and_resets_state() {
        let keys: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
        let ud = &keys as *const std::sync::Mutex<Vec<u64>> as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(exporter_cb), ud) };

        let packet = v9_packet();
        for key in [1u64, 2] {
            assert_eq!(
                unsafe {
                    netflow_analyzer_process_packet_from(
                        ctx,
                        key,
                        packet.as_ptr(),
                        packet.len() as u32,
                    )
                },
                1
            );
        }
        assert_eq!(unsafe { netflow_analyzer_get_stats(ctx) }.active_flows, 2);

        // Purging exporter 1 emits its one flow through the registered callback
        // and reclaims its slot; exporter 2 is untouched.
        let drained = unsafe { netflow_analyzer_purge_exporter(ctx, 1) };
        assert_eq!(drained, 1);
        assert_eq!(keys.lock().unwrap().as_slice(), &[1]);
        assert_eq!(unsafe { netflow_analyzer_get_stats(ctx) }.active_flows, 1);

        // Null context is rejected; purging an unknown key emits nothing.
        assert_eq!(
            unsafe { netflow_analyzer_purge_exporter(ptr::null(), 1) },
            -1
        );
        assert_eq!(unsafe { netflow_analyzer_purge_exporter(ctx, 99) }, 0);

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn decode_packet_emits_per_record_and_skips_aggregation() {
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(count_cb), ud) };

        let packet = v9_packet();
        let n = unsafe {
            netflow_analyzer_decode_packet(
                ctx,
                packet.as_ptr(),
                packet.len() as u32,
                Some(record_cb),
                ud,
            )
        };
        assert_eq!(n, 1, "one data record decoded");
        // The decode-only callback fired once, carrying the observation domain (42).
        assert_eq!(state.count.load(Ordering::Relaxed), 1);
        assert_eq!(state.last_proto.load(Ordering::Relaxed), 42);

        // Nothing was aggregated: the flow gauge stays at zero.
        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.data_records_processed, 1);
        assert_eq!(stats.active_flows, 0);

        // Null-argument guards.
        let rc = unsafe {
            netflow_analyzer_decode_packet(
                ptr::null(),
                packet.as_ptr(),
                packet.len() as u32,
                Some(record_cb),
                ud,
            )
        };
        assert_eq!(rc, -1);

        // A null callback is rejected without decoding.
        let rc = unsafe {
            netflow_analyzer_decode_packet(ctx, packet.as_ptr(), packet.len() as u32, None, ud)
        };
        assert_eq!(rc, -1);

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn malformed_packet_returns_error_code() {
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(count_cb), ud) };

        let bogus = [0xFFu8, 0xFF, 0x00, 0x00];
        let rc =
            unsafe { netflow_analyzer_process_packet(ctx, bogus.as_ptr(), bogus.len() as u32) };
        assert_eq!(rc, -2);
        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.pkts_parsed, 0);
        assert_eq!(stats.pkts_parse_error, 1);

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn clock_rejection_has_dedicated_error_and_counter() {
        let config = NetflowAnalyzerConfig {
            max_flows: 0,
            max_templates: 0,
            idle_timeout_secs: 0,
            active_timeout_secs: 0,
            scan_interval_secs: 0,
            clock_sync_check_enabled: true,
            clock_fallback_to_receipt_time: false,
            max_clock_skew_ns: 10,
        };
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(&config, Some(count_cb), ud) };
        let packet = v9_packet();
        let export_ns = 1_700_000_000_000_000_000;

        let rc = unsafe {
            netflow_analyzer_process_packet_at(
                ctx,
                packet.as_ptr(),
                packet.len() as u32,
                export_ns + 11,
            )
        };
        assert_eq!(rc, -3);
        assert_eq!(
            unsafe { netflow_analyzer_get_stats(ctx) }.clock_dropped_packets,
            1
        );
        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn null_arguments_are_handled() {
        // Stats on null context returns a zeroed snapshot.
        let stats = unsafe { netflow_analyzer_get_stats(ptr::null()) };
        assert_eq!(stats.pkts_parsed, 0);
        assert_eq!(stats.active_flows, 0);

        // Processing with a null context returns the invalid-arguments code.
        let byte = [0u8];
        let rc = unsafe { netflow_analyzer_process_packet(ptr::null(), byte.as_ptr(), 1) };
        assert_eq!(rc, -1);

        // Flush and destroy on null are safe no-ops.
        unsafe {
            netflow_analyzer_flush(ptr::null());
            netflow_analyzer_destroy(ptr::null_mut());
        }

        // A null flow callback is rejected: no context is created and no invalid
        // function pointer is stored.
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), None, ptr::null_mut()) };
        assert!(ctx.is_null());
    }

    #[test]
    fn guard_ffi_catches_panics() {
        // A panic inside a guarded body is caught and the default is returned,
        // so no unwind can cross the C ABI boundary (which would otherwise abort
        // the process). Silence the panic hook to keep test output clean.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || panic!("boom"));
        std::panic::set_hook(prev);
        assert_eq!(caught, NETFLOW_ANALYZER_INTERNAL_ERROR);

        // The happy path returns the body's value unchanged.
        assert_eq!(guard_ffi(-1, || 5), 5);
    }

    #[test]
    fn custom_config_is_applied() {
        let cfg = NetflowAnalyzerConfig {
            max_flows: 1,
            max_templates: 16,
            idle_timeout_secs: 30,
            active_timeout_secs: 120,
            scan_interval_secs: 5,
            clock_sync_check_enabled: false,
            clock_fallback_to_receipt_time: false,
            max_clock_skew_ns: 0,
        };
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(&cfg, Some(count_cb), ud) };
        assert!(!ctx.is_null());

        let packet = v9_packet();
        let rc =
            unsafe { netflow_analyzer_process_packet(ctx, packet.as_ptr(), packet.len() as u32) };
        assert_eq!(rc, 1);

        unsafe { netflow_analyzer_destroy(ctx) };
    }
}
