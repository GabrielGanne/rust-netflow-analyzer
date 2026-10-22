/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/*
 * Compile-time ABI layout checks for the generated C header.
 *
 * This translation unit contains no runtime code: the `static_assert`s fire
 * during compilation and pin the size, alignment, and every field offset of
 * every public struct. The Rust side pins the same values
 * (`public_struct_layout_is_pinned` in ffi/src/lib.rs), so C and Rust must
 * agree. Any deliberate change here is an ABI break: bump
 * NETFLOW_ANALYZER_ABI_VERSION.
 *
 * The Makefile compiles this both as C (C11) and as C++ (C++11) to prove the
 * header is usable from both. `static_assert` comes from <assert.h> in C11 and
 * is a keyword in C++11.
 */

#include <assert.h>
#include <stddef.h>

#if defined(__cplusplus)
#define NFA_ALIGNOF(t) alignof(t)
#else
#include <stdalign.h>
#define NFA_ALIGNOF(t) _Alignof(t)
#endif

#include "netflow-analyzer.h"

/* NetflowAnalyzerConfig: five u64 knobs, two bools (+6 pad), two u64, [u64;7].
 * Size, alignment, and every field offset are pinned so a reorder of the two
 * equal-width `u64` knobs (invisible to size alone) is still caught. The Rust
 * side pins the identical numbers in `public_struct_layout_is_pinned`. */
static_assert(sizeof(NetflowAnalyzerConfig) == 120, "Config size changed (ABI break)");
static_assert(NFA_ALIGNOF(NetflowAnalyzerConfig) == 8, "Config alignment changed (ABI break)");
static_assert(offsetof(NetflowAnalyzerConfig, max_flows) == 0, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, max_templates) == 8, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, idle_timeout_secs) == 16, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, active_timeout_secs) == 24, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, scan_interval_secs) == 32, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, clock_sync_check_enabled) == 40, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, clock_fallback_to_receipt_time) == 41, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, max_clock_skew_ns) == 48, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, manual_aging) == 56, "Config layout changed");
static_assert(offsetof(NetflowAnalyzerConfig, reserved) == 64, "Config reserved tail moved");

/* NetflowAnalyzerStats: twelve u64 counters/gauges, then [u64;6]. */
static_assert(sizeof(NetflowAnalyzerStats) == 144, "Stats size changed (ABI break)");
static_assert(NFA_ALIGNOF(NetflowAnalyzerStats) == 8, "Stats alignment changed (ABI break)");
static_assert(offsetof(NetflowAnalyzerStats, pkts_parsed) == 0, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, pkts_parse_error) == 8, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, malformed_packets) == 16, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, clock_dropped_packets) == 24, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, clock_fallback_packets) == 32, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, templates_received) == 40, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, data_records_processed) == 48, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, flows_output) == 56, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, flows_dropped) == 64, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, active_flows) == 72, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, options_templates_received) == 80, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, options_records_processed) == 88, "Stats layout changed");
static_assert(offsetof(NetflowAnalyzerStats, reserved) == 96, "Stats reserved tail moved");

/* NetflowAnalyzerFlowRecord: addresses, ports, scope, counters, times, [u64;8]. */
static_assert(sizeof(NetflowAnalyzerFlowRecord) == 216, "FlowRecord size changed (ABI break)");
static_assert(NFA_ALIGNOF(NetflowAnalyzerFlowRecord) == 8, "FlowRecord alignment changed (ABI break)");
static_assert(offsetof(NetflowAnalyzerFlowRecord, src_ip) == 0, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, dst_ip) == 16, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, src_mac) == 32, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, dst_mac) == 38, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, src_port) == 44, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, dst_port) == 46, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, vlan_tag) == 48, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, tcp_flags) == 50, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, proto) == 52, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, dscp) == 53, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, icmp_type) == 54, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, icmp_code) == 55, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, ip_version) == 56, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, scope_protocol) == 57, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, scope_engine_type) == 58, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, scope_engine_id) == 59, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, observation_domain) == 60, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, bytes) == 64, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, packets) == 72, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, iface_in) == 80, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, iface_out) == 88, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, flow_id) == 96, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, exporter_key) == 104, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, start_time_ns) == 112, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, end_time_ns) == 120, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, original_start_time_ns) == 128, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, original_end_time_ns) == 136, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, present) == 144, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, exporter_key_hi) == 152, "FlowRecord layout changed");
static_assert(offsetof(NetflowAnalyzerFlowRecord, reserved) == 160, "FlowRecord reserved tail moved");

/*
 * A reference to every exported function. Taking each address forces the
 * compiler to see a C-linkage declaration for it (in both C and C++ builds of
 * this file), and, when this object is linked into the demo, forces the linker
 * to resolve every symbol from the static library — a link-time probe covering
 * the exports main.c does not itself call. External linkage keeps it from being
 * reported as unused. (Signatures are pinned on the Rust side; the header is
 * generated from them.)
 */
typedef void (*nfa_anyfn)(void);
const nfa_anyfn netflow_analyzer_abi_export_probe[] = {
    (nfa_anyfn)netflow_analyzer_abi_version,
    (nfa_anyfn)netflow_analyzer_create,
    (nfa_anyfn)netflow_analyzer_destroy,
    (nfa_anyfn)netflow_analyzer_get_stats,
    (nfa_anyfn)netflow_analyzer_flush,
    (nfa_anyfn)netflow_analyzer_age_at,
    (nfa_anyfn)netflow_analyzer_purge_exporter,
    (nfa_anyfn)netflow_analyzer_process_packet,
    (nfa_anyfn)netflow_analyzer_process_packet_at,
    (nfa_anyfn)netflow_analyzer_process_packet_from,
    (nfa_anyfn)netflow_analyzer_process_packet_from_at,
    (nfa_anyfn)netflow_analyzer_decode_packet,
    (nfa_anyfn)netflow_analyzer_decode_packet_at,
    (nfa_anyfn)netflow_analyzer_decode_packet_from,
    (nfa_anyfn)netflow_analyzer_decode_packet_from_at,
    (nfa_anyfn)netflow_analyzer_purge_exporter_addr,
    (nfa_anyfn)netflow_analyzer_process_packet_from_addr_at,
    (nfa_anyfn)netflow_analyzer_decode_packet_from_addr_at,
};
