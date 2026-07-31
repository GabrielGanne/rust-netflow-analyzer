# Migration analysis: replacing the local NetFlow parser with `libnetflow_analyzer_ffi`

Reference header: `~/.local/include/netflow-analyzer.h`
Reference library: `~/.local/lib/libnetflow_analyzer_ffi.so` (exports all 6 documented symbols)

This document tracks (1) the feature/output gaps that would need to be added to the
external project before it can replace the local implementation, and (2) an analysis
of the fact that the external library merges *parsing* and *flowtable/aggregation*
into a single engine.

---

## 1. Missing features TODO (to be added to the external `netflow-analyzer` project)

The external `NetflowAnalyzerFlowRecord` only exposes:
`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `bytes`, `packets`,
`start_time_ns`, `end_time_ns`, `original_start_time_ns`, `original_end_time_ns`.

The local `struct flow_record` (`src/flow-record.h`) extracts more, and the CSV/JSON
formatters (`src/formatter-csv.c`, `src/formatter-json.c`) emit all of it. The
following fields/features are therefore **lost** in a straight migration and would
need to be added upstream.

### 1.1 Emitted flow fields missing from `NetflowAnalyzerFlowRecord`

- [x] **`flow_id`** — exporter-provided flow identifier. Used as the primary flow key
      when present (see `flow_key_from_record()` in `src/flowtable.c`), takes precedence
      over the 5-tuple. **Done:** decoded (IE 148) and now exposed as `flow_id` on
      `NetflowAnalyzerFlowRecord` (`0` + clear presence bit when absent).
- [x] **`iface_in` / `iface_out`** — ingress/egress interface indices
      (NetFlow `ingressInterface` / `egressInterface`). 64-bit in local model.
      **Done:** IE 10 / 14 (v5 `input`/`output`), stored as `u64`.
- [x] **`src_mac` / `dst_mac`** — L2 source/destination MAC
      (`sourceMacAddress` / `destinationMacAddress`), 6 bytes each.
      **Done:** IE 56 / 80.
- [x] **`icmp_type` / `icmp_code`** — from `icmpTypeCodeIPv4/6`, `icmpTypeIPv4/6`,
      `icmpCodeIPv4/6`. Local model splits type/code into two `uint8_t`.
      **Done:** IE 32 / 139 (combined, split into type/code) and IE 176-179 (separate).
- [x] **`tcp_flags`** — `tcpControlBits` (1 byte in v5, 2 bytes in v9/IPFIX).
      **Done:** IE 6 (any width) and v5 offset 37; stored as `u16`.
- [x] **`dscp`** — derived from `ipClassOfService` (>>2), `ipDiffServCodePoint`,
      or `postIpDiffServCodePoint` with the priority rules in
      `netflow_v9_decode_flow()` (`src/netflow-parser/netflow.c`).
      **Done:** `ipClassOfService` (IE 5, `>>2`) with `postIpClassOfService`
      (IE 98) as a fallback; `ipClassOfService` wins regardless of field order.
      Note: base IANA has no `ipDiffServCodePoint`; the standard
      `post`-variant carries the same information.
- [x] **`vlan_tag`** — `vlanId` (source VLAN only; `postVlanId` is intentionally dropped).
      **Done:** IE 58 only.
- [x] **`ip_version`** — 0/4/6 marker. Derivable if IPs are always 16-byte mapped,
      but the local code uses it to reject mixed v4/v6 flowsets; confirm behavior.
      **Done:** set to 4/6 from the decoded address family (first family wins);
      `0` when unknown. Mixed-flowset *rejection* is not replicated (out of scope).

### 1.2 "field present / not set" semantics

- [x] **`set_values` bitmask equivalent.** The local model distinguishes
      "field absent" from "field == 0" via per-field flags (`FLOW_*` in
      `src/flow-record.h`), and the formatters emit an **empty** column for unset
      fields vs. `0` for a real zero. **Done:** `NetflowAnalyzerFlowRecord.present`
      is a `u32` bitmask set only for fields actually decoded. Bit values are
      exported as `NETFLOW_ANALYZER_PRESENT_*` in the C header (see the `presence`
      module in `core/src/records.rs`).

### 1.3 Aggregation modes missing from the engine

These are implemented by the local `flowtable` (`src/flowtable.c`,
`src/flowtable-node.c`) and have no equivalent in the external engine:

- [ ] **Flow stitching** (`flow-stitching`, default **on**) — additive accumulation of
      `pkt_num`/`bytes` across records of the same key, saturating at `UINT32_MAX`
      (`flow_record_accumulate()`).
- [ ] **Flow dedup** (`flow-dedup`) — take the max of `pkt_num`/`bytes` instead of sum.
- [ ] **Bidirectional aggregation** (`bidir-aggregation`) — currently a stub locally,
      but part of the intended config surface.
- [ ] **Periodic intermediate dumps.** The local flowtable re-arms a timer and emits an
      intermediate record every TTL while resetting counters, so long flows are dumped
      periodically (see `timer_expiration_cb()`). The external engine only emits on
      idle/active-timeout/flush — confirm whether the active-timeout behavior matches.
- [ ] **Empty-record dropping.** Local drops records where `pkt_num == 0 || bytes == 0`
      (`flow_record_is_empty()`). Confirm/replicate in the engine or downstream.

### 1.4 Option-template / enrichment behavior to verify

- [ ] **IPFIX/v9 option data merge.** Local parser stores option-template data per
      (sender, observation_domain_id) and merges it into subsequent data records
      (`netflow_v9_option_data_store` / `_lookup`, `netflow_v9_merge_flows`). Verify the
      external engine performs equivalent enrichment, otherwise option-carried fields
      (interfaces, sampling, etc.) will be missing.

### 1.5 Stats parity (nice-to-have, not blocking)

The external `NetflowAnalyzerStats` is actually **richer** than the local
`netflow_parser_stats` (adds `clock_dropped_packets`, `clock_fallback_packets`,
`templates_received`, `data_records_processed`, `active_flows`). No gap here —
if anything, the node's `get_stats` can expose more once migrated.

### 1.6 Fields NOT needed from the library

- `src_hostname` / `dst_hostname` are added **downstream** by the `reverse-dns` node,
  not by the parser. The library only needs to expose the IPs (it does). No action.

---

## 2. The parsing + flowtable "mix" — can the library split its concerns?

### 2.1 Current local architecture (two separate stages)

```
udp-input → netflow-parser → flowtable → reverse-dns → json-formatter → file-dumper
```

- **`netflow-parser`** is *stateless per flow*: it decodes NetFlow v5 / v9 / IPFIX
  datagrams into one `flow_record` **per data record** and pushes them to the next
  ring. It keeps state only for **templates** and **option data** (needed to decode).
  It performs **no** aggregation, no timeouts, no eviction.
- **`flowtable`** is the *stateful aggregation stage*: hashtable keyed by flow_id or
  5-tuple + timer wheel. It accumulates/dedups counters, dumps periodically, and
  expires flows to the output ring.

This separation is deliberate and already called out as a design goal in `TODO.md`
("move netflow parser and flowtable to a 'netflow' plugin"). It gives:
- independent tuning/testing of decode vs. aggregation,
- the ability to run decode-only or aggregation-only pipelines,
- clean insertion points for enrichment nodes between the two stages.

### 2.2 What the external library does

The external engine **fuses both stages**. A single context
(`netflow_analyzer_create`) owns the template cache **and** the flow cache; you feed
it raw datagrams (`netflow_analyzer_process_packet[_at]`) and it calls your
`NetflowAnalyzerFlowCallback` only when an **aggregated** flow is evicted (idle /
active timeout / `netflow_analyzer_flush`). There is no API to obtain the raw,
per-record parse output before aggregation.

Config knobs confirm the fusion: `max_flows`, `max_templates`, `idle_timeout_secs`,
`active_timeout_secs`, `scan_interval_secs` are all flowtable concerns living inside
the "analyzer".

### 2.3 Consequence

- A drop-in replacement of **only** `netflow-parser` is **not possible**: the library
  cannot emit un-aggregated per-record output. Using it means it replaces **both**
  `netflow-parser` **and** `flowtable`, and the local `flowtable` aggregation modes
  (stitching/dedup/bidir, intermediate periodic dumps) are bypassed.
- The reduced `NetflowAnalyzerFlowRecord` is a direct result of this fusion: after
  aggregation the engine only keeps the aggregation key (5-tuple) + counters +
  timestamps, discarding the per-record L2/QoS/ICMP metadata the local pipeline emits.

### 2.4 Suggested split for the external project (to discuss upstream)

To make the library composable with this pipeline, consider exposing the two layers
separately:

- [ ] **A decode-only API.** A `parse`/decoder entry point that emits one *full*
      record per data record (with all fields from §1.1 + presence bits from §1.2)
      via a callback, **without** touching the flow cache. This is what would map to
      the local `netflow-parser` node.
- [ ] **A separate aggregator API.** The existing flow-cache/timeout/eviction engine,
      fed by decoded records rather than raw datagrams — mapping to the local
      `flowtable` node. Should carry the full record through aggregation (not just the
      5-tuple) so no fields are lost on eviction.
- [ ] **Keep the fused `process_packet` API** as a convenience wrapper over the two,
      for consumers that want the all-in-one behavior.

If the library exposes the decode-only layer with the full field set, migrating the
local `netflow-parser` alone (keeping our `flowtable`) becomes feasible and preserves
every current output field and aggregation mode.

---

## 3. Config mapping (for reference)

| Local config | External `NetflowAnalyzerConfig` | Notes |
|---|---|---|
| `netflow-parser.clock-sync-check` | `clock_sync_check_enabled` | direct |
| `netflow-parser.clock-max-skew-sec` | `max_clock_skew_ns` | ×1e9 |
| (n/a) | `clock_fallback_to_receipt_time` | new capability |
| `flowtable` size | `max_flows` | |
| (implicit template TTL) | `max_templates` | |
| `flowtable` TTL / tick | `idle_timeout_secs` / `active_timeout_secs` / `scan_interval_secs` | |
| `flow-stitching` / `flow-dedup` / `bidir-aggregation` | **no equivalent** | see §1.3 |
