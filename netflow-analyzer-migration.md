# Migration and C API Comparison Guide

This document compares the C interface exposed by `libnetflow_analyzer_ffi` (`include/netflow-analyzer.h`) with traditional C NetFlow/IPFIX parser implementations (such as `netflow.h`), and details intentional architectural differences and migration considerations.

---

## 1. Architectural Comparison

Traditional C NetFlow architectures typically decouple packet decoding and flow aggregation into discrete pipeline stages connected by lockless ring buffers or queues:

```
[Input / NIC] -> [netflow-parser] -> [flow-table / aggregator] -> [formatters / sinks]
```

- **Traditional Parser Stage (`netflow.h`)**:
  - Stateless per flow: parses NetFlow v5/v9/IPFIX datagrams and emits raw, unaggregated records directly into an output ring buffer.
  - Maintains state only for template definitions and options records needed to decode subsequent data sets.
  - Does not manage timeouts, active rollover, or eviction.
  - Often relies on thread-local state (`__thread`), limiting cross-thread reentrancy.

- **`libnetflow_analyzer_ffi` (`include/netflow-analyzer.h`)**:
  - Provides a **flexible dual-pipeline architecture**:
    1. **Fused Engine (`netflow_analyzer_process_packet*`)**: Integrates zero-copy parsing, sampling scaling, sharded flow aggregation, and a background aging worker in a single context (`NetflowAnalyzerContext`). Emits aggregated flows on idle eviction, active timeout rollover, or explicit flush.
    2. **Decode-Only Pipeline (`netflow_analyzer_decode_packet*`)**: A stateless entry point that updates template state and delivers each decoded record immediately to a caller-supplied callback (`NetflowAnalyzerRecordCallback`) without touching the flow cache. This directly mirrors the decoupled parser model.
  - Thread-safe and reentrant: the underlying Rust engine uses fine-grained concurrent sharding (`DashMap`) and releases all shard locks before invoking callbacks.

---

## 2. Intentional Differences from `netflow.h`

### 2.1 Exporter and Session Identity

- **`netflow.h`**:
  - Scopes state by sender IP address (`ip46_address_t const *sender`) and observation domain.
  - Observation domains are bare integers (`uint32_t`), which can collide across protocol versions or multiple exporters sharing domain `0`.
- **`netflow-analyzer.h`**:
  - Uses an explicit, opaque 64-bit key (`uint64_t exporter_key`) supplied by the caller on ingest (`_from` and `_from_at` symbols).
  - State is keyed by `(exporter_key, Scope)`, where `Scope` discriminator tags (`NETFLOW_ANALYZER_SCOPE_V9`, `IPFIX`, `V5`) ensure protocol namespaces never collide.
  - Allows callers to map arbitrary network dimensions (source IP, port, VLAN, router ID) into stable session keys.
  - Provides `netflow_analyzer_purge_exporter` to flush a retired exporter's resident flows and reclaim all template, clock, and sampling capacity without memory leaks.

### 2.2 Record Format and Field Representation

- **`netflow.h`**:
  - Output records use platform-specific structs with separate IPv4 and IPv6 fields, and lack presence flags to distinguish "field absent from template" from "field value is zero".
- **`netflow-analyzer.h` (`NetflowAnalyzerFlowRecord`)**:
  - **Unified Addresses**: IPv4 and IPv6 addresses are unified into 16-byte IPv4-mapped IPv6 buffers (`src_ip[16]`, `dst_ip[16]`).
  - **Presence Bitmask**: Includes a 32-bit bitmask (`present`) with `NETFLOW_ANALYZER_PRESENT_*` constants. A bit is set only if the field was present in the decoded template, allowing downstream formatters to preserve empty vs. zero semantics.
  - **Comprehensive Metadata**: Extracts and retains `flow_id`, ingress/egress interfaces (`iface_in`, `iface_out`), L2 MAC addresses (`src_mac`, `dst_mac`), ICMP type/code (`icmp_type`, `icmp_code`), TCP flags (`tcp_flags`), DSCP (`dscp`), VLAN tag (`vlan_tag`), and IP version (`ip_version`).
  - **ABI Stability**: The struct is `#[non_exhaustive]` with trailing `reserved` fields. New fields can be added within reserved space without breaking binary layout or recompiling callers.

### 2.3 Clock Drift, Skew Tolerance, and Fallback

- **`netflow.h`**:
  - Validates exporter timestamp against system clock with second-level granularity (`clock_max_skew_sec`).
  - Skewed packets are dropped unconditionally.
- **`netflow-analyzer.h`**:
  - Nanosecond-precision skew tracking (`max_clock_skew_ns`).
  - Supports optional **timestamp fallback** (`clock_fallback_to_receipt_time`): instead of dropping traffic from slightly misconfigured exporters, timestamps are rebased to receipt time while preserving relative durations.
  - Skew rejections and fallback events are tracked in dedicated counters (`clock_dropped_packets`, `clock_fallback_packets`).

### 2.4 Diagnostic Telemetry and Observability

- **`netflow.h`**:
  - Reports basic counters: `pkts_parsed`, `pkts_parse_error`, `flows_output`, `flows_dropped`.
- **`netflow-analyzer.h` (`NetflowAnalyzerStats`)**:
  - Provides a non-blocking snapshot including:
    - Packet framing health (`pkts_parsed`, `pkts_parse_error`, `malformed_packets`).
    - Clock diagnostics (`clock_dropped_packets`, `clock_fallback_packets`).
    - Cache residency and throughput (`templates_received`, `data_records_processed`, `active_flows`, `flows_output`, `flows_dropped`).
    - Options metadata activity (`options_templates_received`, `options_records_processed`).

### 2.5 Error Codes and Safety

- **`netflow.h`**:
  - Returns `0` on success, `-1` on generic error.
- **`netflow-analyzer.h`**:
  - Returns non-negative record count (`>= 0`) on success.
  - Returns specific negative error codes:
    - `-1`: Null pointer or invalid argument.
    - `-2`: Packet framing or parse error (malformed header or invalid Set length).
    - `-3`: Clock skew exceeded configured limit (packet dropped).
  - All C API entry points are wrapped in panic catch guards (`catch_unwind`), ensuring that no Rust panic can unwind into C stack frames.

---

## 3. Configuration Mapping

| `netflow.h` / Traditional Config | `NetflowAnalyzerConfig` Field | Notes |
| :--- | :--- | :--- |
| `clock_sync_check` | `clock_sync_check_enabled` | Boolean flag |
| `clock_max_skew_sec` | `max_clock_skew_ns` | Converted to nanoseconds (seconds × 10^9) |
| *(no equivalent)* | `clock_fallback_to_receipt_time` | Rebase timestamps to receipt time on skew |
| Flowtable capacity | `max_flows` | Hard limit on concurrent active flows (default: 1,000,000) |
| Template cache limit | `max_templates` | Hard limit on concurrent cached templates (default: 65,536) |
| Inactivity timeout | `idle_timeout_secs` | Evict flow after inactivity |
| Active rollover TTL | `active_timeout_secs` | Emit interim record for long-lived flows |
| Aging scan frequency | `scan_interval_secs` | Background worker sweep interval |

---

## 4. Migration Paths

### Option A: Direct Fused Ingestion (Recommended for New Projects)

Use `netflow_analyzer_create` and `netflow_analyzer_process_packet_from`:
- Replaces custom hash tables, timer wheels, and aging loops.
- Flow aggregation, sampling scaling, and timeout emission are handled internally.
- Emitted records are delivered to `NetflowAnalyzerFlowCallback` on idle timeout, rollover, or shutdown.

### Option B: Decode-Only Pipeline (For Existing Pipeline Integration)

Use `netflow_analyzer_decode_packet_from`:
- Functions as a pure parser stage.
- Decodes datagrams and invokes `NetflowAnalyzerRecordCallback` per data record with full field extraction.
- Completely bypasses the internal flow cache, allowing output to feed into external ring buffers, custom aggregation nodes, or Kafka/enrichment pipelines.
