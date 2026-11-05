// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # netflow_analyzer_ffi
//!
//! C ABI (FFI) bindings for the `netflow_analyzer_core` NetFlow/IPFIX decoding and flow
//! aggregation engine.
//!
//! This crate exposes an `extern "C"` interface and produces the C header
//! `include/netflow-analyzer.h` using cbindgen. It compiles to both a shared library
//! (`.so` / `.dylib` / `.dll`) and a static archive (`.a`).
//!
//! ## Overview
//!
//! - **Lifecycle**: `netflow_analyzer_create` creates an engine instance and starts the
//!   background aging worker; `netflow_analyzer_destroy` stops aging and reclaims all resources.
//! - **Packet Processing**: `netflow_analyzer_process_packet` (fused decode + aggregation)
//!   and `netflow_analyzer_decode_packet` (per-record callback without flow-cache
//!   aggregation; template, clock, and sampling state is still retained per exporter).
//! - **Exporter Scoping**: Key-aware symbols (`_from` and `_from_at`) allow one engine
//!   context to track multiple exporters concurrently without template or flow collisions.
//! - **Telemetry**: `netflow_analyzer_get_stats` returns a point-in-time snapshot of
//!   parsing diagnostics and resident flow counts.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use netflow_analyzer_core::cache::AgingConfig;
use netflow_analyzer_core::clock::ClockConfig;
use netflow_analyzer_core::records::{FlowFields, FlowRecord, NetflowAnalyzerFlowRecord};
use netflow_analyzer_core::scope::{ExporterKey, Scope};
use netflow_analyzer_core::stats::NetflowAnalyzerStats;
use netflow_analyzer_core::{EngineConfig, FlowContext, PacketError};

// Protocol discriminator values for `NetflowAnalyzerFlowRecord::scope_protocol`.
// These are literals (rather than re-exports of the core `scope` constants)
// because cbindgen cannot evaluate cross-crate constant paths;
// `scope_protocol_tags_match_core` keeps them in sync.
/// Protocol tag for NetFlow v9 scope.
pub const NETFLOW_ANALYZER_SCOPE_V9: u8 = 0;
/// Protocol tag for IPFIX scope.
pub const NETFLOW_ANALYZER_SCOPE_IPFIX: u8 = 1;
/// Protocol tag for NetFlow v5 scope.
pub const NETFLOW_ANALYZER_SCOPE_V5: u8 = 2;

/// ABI version of this library's C interface. Bumped whenever the public struct
/// layouts or function signatures change in a way a compiled consumer must be
/// rebuilt for. A consumer can compare this compile-time value from the header
/// against [`netflow_analyzer_abi_version`] at runtime to detect a header/library
/// mismatch before using the API.
pub const NETFLOW_ANALYZER_ABI_VERSION: u32 = 3;

/// C-compatible callback invoked whenever a flow is emitted: from the
/// background aging thread on idle eviction or active-timeout rollover, and
/// synchronously on the thread that calls `netflow_analyzer_flush` or
/// `netflow_analyzer_purge_exporter`.
///
/// Callback contract (the decode-only [`NetflowAnalyzerRecordCallback`] has a
/// separate, per-call contract documented on that type):
///
/// - Null: passing a null callback to `netflow_analyzer_create` creates a
///   **decode-only** context (no flow cache use, no aging thread); see that
///   function. Otherwise the pointer must be a valid function pointer.
///   `record` is always non-null and points to a valid record for the duration
///   of the call. `user_data` is whatever was supplied at creation and may be
///   null if the host chose so.
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
/// path (`netflow_analyzer_decode_packet*`), before any aggregation. The
/// `observation_domain_id` scopes the record (NetFlow v5 reports `0`); it is
/// redundant with `record->observation_domain` and kept only for source
/// compatibility until the next signature-breaking ABI change.
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
/// Flow ID was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_FLOW_ID: u32 = 1 << 0;
/// Ingress interface index was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_IFACE_IN: u32 = 1 << 1;
/// Egress interface index was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_IFACE_OUT: u32 = 1 << 2;
/// Source MAC address was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_SRC_MAC: u32 = 1 << 3;
/// Destination MAC address was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_DST_MAC: u32 = 1 << 4;
/// ICMP type was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_ICMP_TYPE: u32 = 1 << 5;
/// ICMP code was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_ICMP_CODE: u32 = 1 << 6;
/// Cumulative TCP control flags were present in the record.
pub const NETFLOW_ANALYZER_PRESENT_TCP_FLAGS: u32 = 1 << 7;
/// Differentiated Services Code Point (DSCP) was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_DSCP: u32 = 1 << 8;
/// VLAN identifier was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_VLAN_TAG: u32 = 1 << 9;
/// IP version marker was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_IP_VERSION: u32 = 1 << 10;
/// Source IP address was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_SRC_IP: u32 = 1 << 11;
/// Destination IP address was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_DST_IP: u32 = 1 << 12;
/// IP protocol number was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_PROTO: u32 = 1 << 13;
/// Transport source port was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_SRC_PORT: u32 = 1 << 14;
/// Transport destination port was present in the record.
pub const NETFLOW_ANALYZER_PRESENT_DST_PORT: u32 = 1 << 15;
/// Flow start time was exported; when clear, `start_time_ns` is the packet
/// export time.
pub const NETFLOW_ANALYZER_PRESENT_START_TIME: u32 = 1 << 16;
/// Flow end time was exported; when clear, `end_time_ns` is the packet export
/// time.
pub const NETFLOW_ANALYZER_PRESENT_END_TIME: u32 = 1 << 17;
/// Decode-only byte count is cumulative. Aggregated emissions always clear this bit.
pub const NETFLOW_ANALYZER_PRESENT_BYTES_TOTAL: u32 = 1 << 18;
/// Decode-only packet count is cumulative. Aggregated emissions always clear this bit.
pub const NETFLOW_ANALYZER_PRESENT_PACKETS_TOTAL: u32 = 1 << 19;

/// Tunable engine settings passed from C at construction time. A null pointer
/// to [`netflow_analyzer_create`] selects library defaults for every field.
#[repr(C)]
pub struct NetflowAnalyzerConfig {
    /// Maximum number of active flows retained in the flow cache.
    pub max_flows: u64,
    /// Maximum number of templates retained in the template cache.
    pub max_templates: u64,
    /// Flow idle eviction timeout in seconds.
    pub idle_timeout_secs: u64,
    /// Flow active rollover timeout in seconds.
    pub active_timeout_secs: u64,
    /// Background aging sweep interval in seconds.
    pub scan_interval_secs: u64,
    /// Enable export-time versus receipt-time skew validation.
    pub clock_sync_check_enabled: bool,
    /// Correct skewed timestamps from receipt time instead of dropping packets.
    pub clock_fallback_to_receipt_time: bool,
    /// Maximum accepted clock skew, in nanoseconds. Zero selects the default.
    pub max_clock_skew_ns: u64,
    /// Nonzero selects manual aging: no background wall-clock aging thread is
    /// started, and the host drives aging and template expiry with
    /// [`netflow_analyzer_age_at`]. Use it with the `*_at` entry points, for
    /// example for capture replay. Zero keeps the background thread.
    pub manual_aging: u64,
    /// Reserved for future settings. The caller must zero these (zero-initialize
    /// the whole struct); the engine ignores them today, so a new field added
    /// here later defaults to "unset" for callers that only zeroed it. Kept so
    /// the struct can grow without changing its size or ABI.
    pub reserved: [u64; 7],
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

/// Opaque handle handed back to C. Holds the engine plus the emission callback
/// (`None` for a decode-only context).
pub struct NetflowAnalyzerContext {
    internal: Arc<FlowContext>,
    callback: Option<FlowCallbackFn>,
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

/// Returns the ABI version the linked library was built with
/// ([`NETFLOW_ANALYZER_ABI_VERSION`]). A consumer should compare it against the
/// `NETFLOW_ANALYZER_ABI_VERSION` value its header declares and refuse to run on
/// a mismatch, which signals the header and the linked library disagree on the
/// public struct layouts or signatures.
#[no_mangle]
pub extern "C" fn netflow_analyzer_abi_version() -> u32 {
    NETFLOW_ANALYZER_ABI_VERSION
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
/// A **null `callback`** creates a decode-only context: no aging thread is
/// started, the `netflow_analyzer_process_packet*` entry points return `-1`,
/// `netflow_analyzer_flush` is a no-op, and only the
/// `netflow_analyzer_decode_packet*` entry points (plus stats and purge) are
/// usable. The flow-cache settings in `config` are then ignored.
///
/// With a callback and a nonzero `config->manual_aging`, no aging thread is
/// started either: flows are emitted only by `netflow_analyzer_age_at`,
/// `netflow_analyzer_flush`, and purge. This is the mode for capture replay
/// through the `*_at` entry points, whose timestamps the wall-clock thread
/// would otherwise age against.
///
/// Returns null on failure to spawn the background aging thread.
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
        let (engine_cfg, manual_aging) = if config.is_null() {
            (EngineConfig::default(), false)
        } else {
            (engine_config_from(&*config), (*config).manual_aging != 0)
        };

        let internal = Arc::new(FlowContext::with_config(engine_cfg));
        let user_data = SendUserData(user_data);

        // Bridge the emitted Rust records to the C callback. The user_data
        // pointer is wrapped so it can cross into the aging worker. If the
        // worker thread cannot be created, hand back null instead of a context.
        if let (Some(callback), false) = (callback, manual_aging) {
            if internal
                .try_start_aging(move |record: &FlowRecord| {
                    emit_record(callback, user_data, record);
                })
                .is_err()
            {
                return std::ptr::null_mut();
            }
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
        options_templates_received: 0,
        options_records_processed: 0,
        reserved: [0; 6],
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
        if ctx.is_null() || packet_bytes.is_null() || (*ctx).callback.is_none() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx).internal.process_packet(data) {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
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
        if ctx.is_null() || packet_bytes.is_null() || (*ctx).callback.is_none() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx).internal.process_packet_at(data, receipt_time_ns) {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
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
        if ctx.is_null() || packet_bytes.is_null() || (*ctx).callback.is_none() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx)
            .internal
            .process_packet_from(exporter_key.into(), data)
        {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
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
        if ctx.is_null() || packet_bytes.is_null() || (*ctx).callback.is_none() {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx)
            .internal
            .process_packet_from_at(exporter_key.into(), data, receipt_time_ns)
        {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
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
            Err(PacketError::ClockSkewExceeded) => -3,
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
            Err(PacketError::ClockSkewExceeded) => -3,
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
            .decode_packet_from(exporter_key.into(), data, &mut sink)
        {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
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
        match (*ctx).internal.decode_packet_from_at(
            exporter_key.into(),
            data,
            receipt_time_ns,
            &mut sink,
        ) {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
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
        let Some(callback) = context.callback else {
            return;
        };
        let user_data = context.user_data;
        context
            .internal
            .flush(move |record| emit_record(callback, user_data, record));
    })
}

/// Runs one aging pass at `now_ns` (Unix nanoseconds) on the calling thread:
/// idle flows are evicted and long-lived flows rolled over through the flow
/// callback, and templates expired by `now_ns` are dropped. Returns the number
/// of records emitted, `0` for a decode-only context, `-1` if `ctx` is null, or
/// `-4` on an internal error.
///
/// This is the deterministic counterpart of the background aging thread for
/// hosts that feed packets through the `*_at` entry points with their own
/// timestamps (for example a capture replay). Use one time domain per context:
/// either the wall-clock entry points with background aging, or the `*_at`
/// entry points with this function on a context created with
/// `manual_aging` set. Mixing them ages state against unrelated clocks. Time
/// moving backwards never ages state early.
///
/// # Safety
/// `ctx` must be null or a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_age_at(
    ctx: *const NetflowAnalyzerContext,
    now_ns: u64,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() {
            return -1;
        }
        let context = &*ctx;
        let Some(callback) = context.callback else {
            context.internal.age_at(now_ns, |_| {});
            return 0;
        };
        let user_data = context.user_data;
        let emitted = context.internal.age_at(now_ns, move |record| {
            emit_record(callback, user_data, record)
        });
        i32::try_from(emitted).unwrap_or(i32::MAX)
    })
}

/// Purges one exporter, emitting its resident flows through the registered
/// callback (a decode-only context has none to emit).
fn purge(context: &NetflowAnalyzerContext, exporter: ExporterKey) -> i32 {
    let callback = context.callback;
    let user_data = context.user_data;
    context.internal.purge_exporter(exporter, move |record| {
        if let Some(callback) = callback {
            emit_record(callback, user_data, record)
        }
    }) as i32
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
        purge(&*ctx, exporter_key.into())
    })
}

/// Reads a 16-byte big-endian exporter key (for example a raw IPv6 or
/// IPv4-mapped address in network order).
unsafe fn exporter_key_from_bytes(key: *const u8) -> ExporterKey {
    let mut bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(key, bytes.as_mut_ptr(), 16);
    ExporterKey::from_be_bytes(bytes)
}

/// Like [`netflow_analyzer_purge_exporter`], for a 16-byte exporter key as
/// accepted by the `_from_addr` entry points.
///
/// # Safety
/// `ctx` must be null or a valid context pointer; `exporter_key` must be null
/// or point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_purge_exporter_addr(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: *const u8,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || exporter_key.is_null() {
            return -1;
        }
        purge(&*ctx, exporter_key_from_bytes(exporter_key))
    })
}

/// Like [`netflow_analyzer_process_packet_from_at`], but takes a 16-byte
/// big-endian exporter key, so a raw IPv6 (or IPv4-mapped) exporter address can
/// be used without hashing. A 16-byte key whose first 8 bytes are zero is the
/// same key as the equal 64-bit key. Emitted records carry it split across
/// `exporter_key_hi` (first 8 bytes) and `exporter_key` (last 8 bytes).
///
/// # Safety
/// As [`netflow_analyzer_process_packet`]; `exporter_key` must point to 16
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet_from_addr_at(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: *const u8,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null()
            || exporter_key.is_null()
            || packet_bytes.is_null()
            || (*ctx).callback.is_none()
        {
            return -1;
        }
        let data = std::slice::from_raw_parts(packet_bytes, length as usize);
        match (*ctx).internal.process_packet_from_at(
            exporter_key_from_bytes(exporter_key),
            data,
            receipt_time_ns,
        ) {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
            Err(_) => -2,
        }
    })
}

/// Like [`netflow_analyzer_decode_packet_from_at`], but takes a 16-byte
/// big-endian exporter key; see [`netflow_analyzer_process_packet_from_addr_at`].
///
/// # Safety
/// As [`netflow_analyzer_decode_packet`]; `exporter_key` must point to 16
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_decode_packet_from_addr_at(
    ctx: *const NetflowAnalyzerContext,
    exporter_key: *const u8,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
    callback: NetflowAnalyzerRecordCallback,
    user_data: *mut c_void,
) -> i32 {
    guard_ffi(NETFLOW_ANALYZER_INTERNAL_ERROR, || unsafe {
        if ctx.is_null() || exporter_key.is_null() || packet_bytes.is_null() {
            return -1;
        }
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
        match (*ctx).internal.decode_packet_from_at(
            exporter_key_from_bytes(exporter_key),
            data,
            receipt_time_ns,
            &mut sink,
        ) {
            Ok(records) => records as i32,
            Err(PacketError::ClockSkewExceeded) => -3,
            Err(_) => -2,
        }
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

// Pin the exact C ABI signature — argument types, return type, and the
// `extern "C"` calling convention — of every exported function. Coercing each
// function item to a fixed function-pointer type fails to compile if a
// signature drifts or an `extern "C"` is dropped, forcing a deliberate change
// (and a NETFLOW_ANALYZER_ABI_VERSION bump). The generated C header is derived
// from these same signatures. `abi_checks.c` link-probes every symbol on the C
// side.
const _ABI_SIGNATURES: () = {
    let _: extern "C" fn() -> u32 = netflow_analyzer_abi_version;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerConfig,
        NetflowAnalyzerFlowCallback,
        *mut c_void,
    ) -> *mut NetflowAnalyzerContext = netflow_analyzer_create;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext) -> NetflowAnalyzerStats =
        netflow_analyzer_get_stats;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, *const u8, u32) -> i32 =
        netflow_analyzer_process_packet;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, *const u8, u32, u64) -> i32 =
        netflow_analyzer_process_packet_at;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, u64, *const u8, u32) -> i32 =
        netflow_analyzer_process_packet_from;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, u64, *const u8, u32, u64) -> i32 =
        netflow_analyzer_process_packet_from_at;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerContext,
        *const u8,
        u32,
        NetflowAnalyzerRecordCallback,
        *mut c_void,
    ) -> i32 = netflow_analyzer_decode_packet;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerContext,
        *const u8,
        u32,
        u64,
        NetflowAnalyzerRecordCallback,
        *mut c_void,
    ) -> i32 = netflow_analyzer_decode_packet_at;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerContext,
        u64,
        *const u8,
        u32,
        NetflowAnalyzerRecordCallback,
        *mut c_void,
    ) -> i32 = netflow_analyzer_decode_packet_from;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerContext,
        u64,
        *const u8,
        u32,
        u64,
        NetflowAnalyzerRecordCallback,
        *mut c_void,
    ) -> i32 = netflow_analyzer_decode_packet_from_at;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext) = netflow_analyzer_flush;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, u64) -> i32 =
        netflow_analyzer_age_at;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, u64) -> i32 =
        netflow_analyzer_purge_exporter;
    let _: unsafe extern "C" fn(*mut NetflowAnalyzerContext) = netflow_analyzer_destroy;
    let _: unsafe extern "C" fn(*const NetflowAnalyzerContext, *const u8) -> i32 =
        netflow_analyzer_purge_exporter_addr;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerContext,
        *const u8,
        *const u8,
        u32,
        u64,
    ) -> i32 = netflow_analyzer_process_packet_from_addr_at;
    let _: unsafe extern "C" fn(
        *const NetflowAnalyzerContext,
        *const u8,
        *const u8,
        u32,
        u64,
        NetflowAnalyzerRecordCallback,
        *mut c_void,
    ) -> i32 = netflow_analyzer_decode_packet_from_addr_at;
};

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

    /// NetFlow v9 packet with one options template (id 260) and one options
    /// data record (a samplingInterval), used to exercise the options metrics.
    fn v9_options_packet() -> Vec<u8> {
        let mut buf = Vec::new();
        let put = |value: u64, width: usize, buf: &mut Vec<u8>| {
            for i in 0..width {
                buf.push((value >> (8 * (width - 1 - i))) as u8);
            }
        };
        // Header (domain 42).
        put(9, 2, &mut buf);
        put(2, 2, &mut buf);
        put(1000, 4, &mut buf);
        put(1_700_000_000, 4, &mut buf);
        put(1, 4, &mut buf);
        put(42, 4, &mut buf);
        // Options template FlowSet (id 1): template 260, one scope field
        // (SYSTEM) and one option field (samplingInterval).
        put(1, 2, &mut buf);
        put(18, 2, &mut buf); // 4 + 14
        put(260, 2, &mut buf);
        put(4, 2, &mut buf); // option scope length (bytes)
        put(4, 2, &mut buf); // option length (bytes)
        put(1, 2, &mut buf); // scope field: SYSTEM
        put(4, 2, &mut buf);
        put(34, 2, &mut buf); // option field: samplingInterval
        put(4, 2, &mut buf);
        // Options data FlowSet (id 260): one 8-byte record.
        put(260, 2, &mut buf);
        put(12, 2, &mut buf); // 4 + 8
        put(1, 4, &mut buf); // scope value
        put(1000, 4, &mut buf); // samplingInterval
        buf
    }

    #[test]
    fn options_metrics_surface_in_stats() {
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(count_cb), ud) };

        let packet = v9_options_packet();
        // Options records are not flows, so nothing is returned or cached.
        let n =
            unsafe { netflow_analyzer_process_packet(ctx, packet.as_ptr(), packet.len() as u32) };
        assert_eq!(n, 0);

        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.options_templates_received, 1);
        assert_eq!(stats.options_records_processed, 1);
        // They are counted separately from flow templates/records.
        assert_eq!(stats.templates_received, 0);
        assert_eq!(stats.data_records_processed, 0);
        assert_eq!(stats.active_flows, 0);

        unsafe { netflow_analyzer_destroy(ctx) };
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
            manual_aging: 0,
            reserved: [0; 7],
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
            manual_aging: 0,
            reserved: [0; 7],
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

    #[test]
    fn age_at_ages_on_caller_time() {
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let config = NetflowAnalyzerConfig {
            max_flows: 0,
            max_templates: 0,
            idle_timeout_secs: 0,
            active_timeout_secs: 0,
            scan_interval_secs: 1,
            clock_sync_check_enabled: false,
            clock_fallback_to_receipt_time: false,
            max_clock_skew_ns: 0,
            manual_aging: 1,
            reserved: [0; 7],
        };
        let ctx = unsafe { netflow_analyzer_create(&config, Some(count_cb), ud) };
        assert!(!ctx.is_null());
        assert!(
            !unsafe { (*ctx).internal.is_aging() },
            "manual aging starts no wall-clock worker"
        );

        // A historical capture timestamp: a wall-clock worker would find this
        // flow idle on its first sweep.
        const T: u64 = 1_700_000_000_000_000_000;
        const SECOND: u64 = 1_000_000_000;
        let packet = v9_packet();
        unsafe {
            assert_eq!(
                netflow_analyzer_process_packet_at(ctx, packet.as_ptr(), packet.len() as u32, T),
                1
            );
            // The default idle timeout is 30 seconds.
            assert_eq!(netflow_analyzer_age_at(ctx, T + 29 * SECOND), 0);
            assert_eq!(netflow_analyzer_age_at(ctx, T + 30 * SECOND), 1);
            assert_eq!(netflow_analyzer_get_stats(ctx).active_flows, 0);
            netflow_analyzer_destroy(ctx);
        }
        assert_eq!(state.count.load(Ordering::Relaxed), 1);
        assert_eq!(state.last_proto.load(Ordering::Relaxed), 17);
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
        assert_eq!(NETFLOW_ANALYZER_PRESENT_SRC_IP, presence::SRC_IP);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_DST_IP, presence::DST_IP);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_PROTO, presence::PROTO);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_SRC_PORT, presence::SRC_PORT);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_DST_PORT, presence::DST_PORT);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_START_TIME, presence::START_TIME);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_END_TIME, presence::END_TIME);
        assert_eq!(NETFLOW_ANALYZER_PRESENT_BYTES_TOTAL, presence::BYTES_TOTAL);
        assert_eq!(
            NETFLOW_ANALYZER_PRESENT_PACKETS_TOTAL,
            presence::PACKETS_TOTAL
        );
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
            manual_aging: 0,
            reserved: [0; 7],
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
            assert_eq!(netflow_analyzer_age_at(ptr::null(), 0), -1);
            netflow_analyzer_destroy(ptr::null_mut());
        }

        // A null flow callback creates a decode-only context: fused ingestion
        // is refused, flush is a no-op, and purge has nothing to emit.
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), None, ptr::null_mut()) };
        assert!(!ctx.is_null());
        let packet = v9_packet();
        let len = packet.len() as u32;
        unsafe {
            assert_eq!(
                netflow_analyzer_process_packet(ctx, packet.as_ptr(), len),
                -1
            );
            assert_eq!(
                netflow_analyzer_process_packet_from_addr_at(
                    ctx,
                    [0u8; 16].as_ptr(),
                    packet.as_ptr(),
                    len,
                    1_700_000_000_000_000_000,
                ),
                -1
            );
            netflow_analyzer_flush(ctx);
            assert_eq!(netflow_analyzer_age_at(ctx, u64::MAX), 0);
            assert_eq!(netflow_analyzer_purge_exporter(ctx, 0), 0);
            assert_eq!(netflow_analyzer_purge_exporter_addr(ctx, ptr::null()), -1);
            netflow_analyzer_destroy(ctx);
        }
    }

    extern "C" fn capture_record_cb(
        _domain: u32,
        record: *const NetflowAnalyzerFlowRecord,
        user_data: *mut c_void,
    ) {
        unsafe {
            let out = &mut *(user_data as *mut Vec<(u64, u64, u32)>);
            let rec = &*record;
            out.push((rec.exporter_key_hi, rec.exporter_key, rec.present));
        }
    }

    #[test]
    fn decode_only_context_decodes_with_16_byte_key() {
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), None, ptr::null_mut()) };
        assert!(!ctx.is_null());
        let packet = v9_packet();
        let mut key = [0u8; 16];
        key[0] = 0x20;
        key[1] = 0x01;
        key[15] = 0x07;
        let mut seen: Vec<(u64, u64, u32)> = Vec::new();
        let rc = unsafe {
            netflow_analyzer_decode_packet_from_addr_at(
                ctx,
                key.as_ptr(),
                packet.as_ptr(),
                packet.len() as u32,
                1_700_000_000_000_000_000,
                Some(capture_record_cb),
                &mut seen as *mut _ as *mut c_void,
            )
        };
        assert_eq!(rc, 1);
        assert_eq!(seen.len(), 1);
        let (hi, lo, present) = seen[0];
        assert_eq!(hi, 0x2001_0000_0000_0000);
        assert_eq!(lo, 7);
        let tuple = NETFLOW_ANALYZER_PRESENT_SRC_IP
            | NETFLOW_ANALYZER_PRESENT_DST_IP
            | NETFLOW_ANALYZER_PRESENT_PROTO;
        assert_eq!(present & tuple, tuple);
        assert_eq!(present & NETFLOW_ANALYZER_PRESENT_SRC_PORT, 0);
        assert_eq!(present & NETFLOW_ANALYZER_PRESENT_START_TIME, 0);

        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.data_records_processed, 1);
        assert_eq!(stats.flows_output, 0);
        assert_eq!(
            unsafe { netflow_analyzer_purge_exporter_addr(ctx, key.as_ptr()) },
            0
        );
        unsafe { netflow_analyzer_destroy(ctx) };
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
    fn public_struct_layout_is_pinned() {
        use std::mem::{align_of, offset_of, size_of};

        // Pin the size, alignment, AND every field offset of each public
        // `#[repr(C)]` struct, so even a reorder of equal-width fields (which
        // keeps the size unchanged) is caught here. The generated C header's
        // `static_assert`s (examples/c_integration/abi_checks.c) pin the same
        // numbers on the C side, so both languages must agree. Any deliberate
        // change is an ABI break and must bump NETFLOW_ANALYZER_ABI_VERSION.
        assert_eq!(size_of::<NetflowAnalyzerConfig>(), 120);
        assert_eq!(align_of::<NetflowAnalyzerConfig>(), 8);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, max_flows), 0);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, max_templates), 8);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, idle_timeout_secs), 16);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, active_timeout_secs), 24);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, scan_interval_secs), 32);
        assert_eq!(
            offset_of!(NetflowAnalyzerConfig, clock_sync_check_enabled),
            40
        );
        assert_eq!(
            offset_of!(NetflowAnalyzerConfig, clock_fallback_to_receipt_time),
            41
        );
        assert_eq!(offset_of!(NetflowAnalyzerConfig, max_clock_skew_ns), 48);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, manual_aging), 56);
        assert_eq!(offset_of!(NetflowAnalyzerConfig, reserved), 64);

        assert_eq!(size_of::<NetflowAnalyzerStats>(), 144);
        assert_eq!(align_of::<NetflowAnalyzerStats>(), 8);
        assert_eq!(offset_of!(NetflowAnalyzerStats, pkts_parsed), 0);
        assert_eq!(offset_of!(NetflowAnalyzerStats, pkts_parse_error), 8);
        assert_eq!(offset_of!(NetflowAnalyzerStats, malformed_packets), 16);
        assert_eq!(offset_of!(NetflowAnalyzerStats, clock_dropped_packets), 24);
        assert_eq!(offset_of!(NetflowAnalyzerStats, clock_fallback_packets), 32);
        assert_eq!(offset_of!(NetflowAnalyzerStats, templates_received), 40);
        assert_eq!(offset_of!(NetflowAnalyzerStats, data_records_processed), 48);
        assert_eq!(offset_of!(NetflowAnalyzerStats, flows_output), 56);
        assert_eq!(offset_of!(NetflowAnalyzerStats, flows_dropped), 64);
        assert_eq!(offset_of!(NetflowAnalyzerStats, active_flows), 72);
        assert_eq!(
            offset_of!(NetflowAnalyzerStats, options_templates_received),
            80
        );
        assert_eq!(
            offset_of!(NetflowAnalyzerStats, options_records_processed),
            88
        );
        assert_eq!(offset_of!(NetflowAnalyzerStats, reserved), 96);

        assert_eq!(size_of::<NetflowAnalyzerFlowRecord>(), 216);
        assert_eq!(align_of::<NetflowAnalyzerFlowRecord>(), 8);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, src_ip), 0);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, dst_ip), 16);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, src_mac), 32);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, dst_mac), 38);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, src_port), 44);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, dst_port), 46);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, vlan_tag), 48);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, tcp_flags), 50);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, proto), 52);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, dscp), 53);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, icmp_type), 54);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, icmp_code), 55);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, ip_version), 56);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, scope_protocol), 57);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, scope_engine_type), 58);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, scope_engine_id), 59);
        assert_eq!(
            offset_of!(NetflowAnalyzerFlowRecord, observation_domain),
            60
        );
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, bytes), 64);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, packets), 72);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, iface_in), 80);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, iface_out), 88);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, flow_id), 96);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, exporter_key), 104);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, start_time_ns), 112);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, end_time_ns), 120);
        assert_eq!(
            offset_of!(NetflowAnalyzerFlowRecord, original_start_time_ns),
            128
        );
        assert_eq!(
            offset_of!(NetflowAnalyzerFlowRecord, original_end_time_ns),
            136
        );
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, present), 144);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, exporter_key_hi), 152);
        assert_eq!(offset_of!(NetflowAnalyzerFlowRecord, reserved), 160);
    }

    #[test]
    fn abi_version_query_and_reserved_padding() {
        // The runtime query reports the same version the header declares.
        assert_eq!(netflow_analyzer_abi_version(), NETFLOW_ANALYZER_ABI_VERSION);

        // Reserved padding is present and zeroed on a real telemetry snapshot.
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), Some(count_cb), ud) };
        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.reserved, [0u64; 6]);
        unsafe { netflow_analyzer_destroy(ctx) };
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
            manual_aging: 0,
            reserved: [0; 7],
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
