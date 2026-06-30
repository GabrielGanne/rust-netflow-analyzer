use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use netflow_analyzer_core::cache::AgingConfig;
use netflow_analyzer_core::clock::ClockConfig;
use netflow_analyzer_core::records::{FlowRecord, FlowRecordFFI};
use netflow_analyzer_core::stats::LibraryStatsFFI;
use netflow_analyzer_core::{EngineConfig, FlowContext, CLOCK_SKEW_ERROR};

/// C-compatible callback invoked whenever a flow is emitted (idle eviction,
/// active-timeout rollover, or explicit flush). The `record` pointer is only
/// valid for the duration of the call; copy out anything you need to retain.
pub type FlowCallback = extern "C" fn(record: *const FlowRecordFFI, user_data: *mut c_void);

/// Tunable engine settings passed from C at construction time. A null pointer
/// to [`netflow_analyzer_create`] selects library defaults for every field.
#[repr(C)]
pub struct AnalyzerConfig {
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

/// Opaque handle handed back to C. Holds the engine plus the emission callback.
pub struct AnalyzerContext {
    internal: Arc<FlowContext>,
    callback: FlowCallback,
    user_data: SendUserData,
}

fn engine_config_from(cfg: &AnalyzerConfig) -> EngineConfig {
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
/// # Safety
/// `config` must be either null or a valid pointer to an `AnalyzerConfig`.
/// `user_data` is stored verbatim and handed back to `callback` unchanged.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_create(
    config: *const AnalyzerConfig,
    callback: FlowCallback,
    user_data: *mut c_void,
) -> *mut AnalyzerContext {
    let engine_cfg = if config.is_null() {
        EngineConfig::default()
    } else {
        engine_config_from(&*config)
    };

    let internal = Arc::new(FlowContext::with_config(engine_cfg));
    let user_data = SendUserData(user_data);

    // Bridge the emitted Rust records to the C callback. The user_data pointer
    // is wrapped so it can cross the thread boundary into the aging worker.
    internal.start_aging(move |record: &FlowRecord| {
        emit_record(callback, user_data, record);
    });

    Box::into_raw(Box::new(AnalyzerContext {
        internal,
        callback,
        user_data,
    }))
}

/// Converts a Rust record into its FFI shape and dispatches it to the host.
fn emit_record(callback: FlowCallback, user_data: SendUserData, record: &FlowRecord) {
    let ffi = record.to_ffi();
    callback(&ffi as *const FlowRecordFFI, user_data.0);
}

/// Non-blocking telemetry retrieval for a separate monitoring thread.
///
/// # Safety
/// `ctx` must be null or a pointer previously returned by `netflow_analyzer_create`.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_get_stats(ctx: *const AnalyzerContext) -> LibraryStatsFFI {
    if ctx.is_null() {
        return LibraryStatsFFI {
            packets_processed: 0,
            malformed_packets: 0,
            clock_dropped_packets: 0,
            clock_fallback_packets: 0,
            templates_received: 0,
            data_records_processed: 0,
            flows_evicted: 0,
            flows_dropped: 0,
            active_flows: 0,
        };
    }
    (*ctx).internal.stats()
}

/// Core processing entry point called by C worker threads when a datagram
/// arrives. Returns the number of data records decoded, or a negative error
/// code (`-1` invalid arguments, `-2` malformed packet, `-3` clock rejection).
///
/// # Safety
/// `ctx` must be a valid context pointer and `packet_bytes` must point to at
/// least `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet(
    ctx: *const AnalyzerContext,
    packet_bytes: *const u8,
    length: u32,
) -> i32 {
    if ctx.is_null() || packet_bytes.is_null() {
        return -1;
    }

    let data = std::slice::from_raw_parts(packet_bytes, length as usize);
    match (*ctx).internal.process_packet(data) {
        Ok(records) => records as i32,
        Err(CLOCK_SKEW_ERROR) => -3,
        Err(_) => -2,
    }
}

/// Processing entry point with an explicit Unix-nanosecond receipt timestamp.
/// This is the preferred entry point for offline packet-capture readers.
///
/// # Safety
/// The pointer requirements are identical to [`netflow_analyzer_process_packet`].
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_process_packet_at(
    ctx: *const AnalyzerContext,
    packet_bytes: *const u8,
    length: u32,
    receipt_time_ns: u64,
) -> i32 {
    if ctx.is_null() || packet_bytes.is_null() {
        return -1;
    }
    let data = std::slice::from_raw_parts(packet_bytes, length as usize);
    match (*ctx).internal.process_packet_at(data, receipt_time_ns) {
        Ok(records) => records as i32,
        Err(CLOCK_SKEW_ERROR) => -3,
        Err(_) => -2,
    }
}

/// Forces every cached flow to be emitted through the callback immediately.
/// Useful before shutdown so no residual state is lost.
///
/// # Safety
/// `ctx` must be null or a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_flush(ctx: *const AnalyzerContext) {
    if ctx.is_null() {
        return;
    }
    let context = &*ctx;
    let callback = context.callback;
    let user_data = context.user_data;
    context
        .internal
        .flush(move |record| emit_record(callback, user_data, record));
}

/// Destructor exposed to C. Stops the aging thread and releases all memory.
///
/// # Safety
/// `ctx` must be null or a pointer previously returned by `netflow_analyzer_create`,
/// and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn netflow_analyzer_destroy(ctx: *mut AnalyzerContext) {
    if ctx.is_null() {
        return;
    }
    let context = Box::from_raw(ctx);
    context.internal.stop_aging();
    // `context` drops here, releasing the engine and its caches.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Test callback that counts emissions and records the last flow seen.
    extern "C" fn count_cb(record: *const FlowRecordFFI, user_data: *mut c_void) {
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
        let zero = AnalyzerConfig {
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
        let custom = AnalyzerConfig {
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

        let ctx = unsafe { netflow_analyzer_create(ptr::null(), count_cb, ud) };
        assert!(!ctx.is_null());

        let packet = v9_packet();
        let n = unsafe { netflow_analyzer_process_packet(ctx, packet.as_ptr(), packet.len() as u32) };
        assert_eq!(n, 1);

        let stats = unsafe { netflow_analyzer_get_stats(ctx) };
        assert_eq!(stats.data_records_processed, 1);
        assert_eq!(stats.templates_received, 1);
        assert_eq!(stats.active_flows, 1);

        // Flush emits the cached flow through our callback.
        unsafe { netflow_analyzer_flush(ctx) };
        assert_eq!(state.count.load(Ordering::Relaxed), 1);
        assert_eq!(state.last_proto.load(Ordering::Relaxed), 17);

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn malformed_packet_returns_error_code() {
        let state = TestState {
            count: AtomicU32::new(0),
            last_proto: AtomicU32::new(0),
        };
        let ud = &state as *const TestState as *mut c_void;
        let ctx = unsafe { netflow_analyzer_create(ptr::null(), count_cb, ud) };

        let bogus = [0xFFu8, 0xFF, 0x00, 0x00];
        let rc = unsafe { netflow_analyzer_process_packet(ctx, bogus.as_ptr(), bogus.len() as u32) };
        assert_eq!(rc, -2);

        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn clock_rejection_has_dedicated_error_and_counter() {
        let config = AnalyzerConfig {
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
        let ctx = unsafe { netflow_analyzer_create(&config, count_cb, ud) };
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
        assert_eq!(unsafe { netflow_analyzer_get_stats(ctx) }.clock_dropped_packets, 1);
        unsafe { netflow_analyzer_destroy(ctx) };
    }

    #[test]
    fn null_arguments_are_handled() {
        // Stats on null context returns a zeroed snapshot.
        let stats = unsafe { netflow_analyzer_get_stats(ptr::null()) };
        assert_eq!(stats.packets_processed, 0);
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
    }

    #[test]
    fn custom_config_is_applied() {
        let cfg = AnalyzerConfig {
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
        let ctx = unsafe { netflow_analyzer_create(&cfg, count_cb, ud) };
        assert!(!ctx.is_null());

        let packet = v9_packet();
        let rc = unsafe { netflow_analyzer_process_packet(ctx, packet.as_ptr(), packet.len() as u32) };
        assert_eq!(rc, 1);

        unsafe { netflow_analyzer_destroy(ctx) };
    }
}
