# Deployment Hardening and Security Guide

This document provides deployment hardening guidelines for services integrating
`rust-netflow-analyzer`, with specific focus on public-facing or multi-tenant
UDP listeners ingesting NetFlow v5, NetFlow v9, and IPFIX datagrams.

---

## 1. Threat Model & UDP Ingestion Realities

NetFlow and IPFIX over plain UDP are **connectionless, unauthenticated, and unencrypted**.
In untrusted or public network environments:

- **Source IP Spoofing**: Attackers can forge IP header source addresses, making
  it trivial to fake exporter origins or simulate millions of distinct peers.
  Without cryptographic authentication or link-level anti-spoofing, packet headers
  cannot be trusted.
- **No Native Handshake**: The listener cannot verify whether a datagram originated
  from a legitimate routing device without external network boundaries or
  cryptographic transport (such as IPsec, WireGuard, or DTLS).
- **Amplification and Flooding**: Exporters or spoofed senders can direct large
  volumes of flow telemetry toward the listener to induce resource starvation.

Failing to harden the listener and engine configuration against hostile traffic
can lead to Denial of Service (DoS) via memory exhaustion, CPU starvation, or
telemetry suppression (dropping legitimate flows).

---

## 2. Hostile High-Cardinality Traffic: Memory & CPU Consequences

A primary attack vector against flow collectors is **high-cardinality traffic injection**,
where hostile or spoofed traffic forces the collector to allocate and manage huge numbers
of distinct state entries.

### 5-Tuple Cardinality Floods
An attacker sending traffic with randomized source/destination IP addresses, ports,
or observation domain IDs causes the engine to construct unique flow keys for every
record:

- **Cache Cap Saturation**: The flow table is bounded by `max_flows` (default: 1,000,000).
  Under a cardinality flood, the table quickly reaches capacity. Once full, any
  subsequent record with an unrecognised key is rejected and discarded, incrementing
  `flows_dropped`. Existing resident flows continue accumulating, but legitimate
  new traffic is dropped.
- **Memory Footprint**: On LP64 (64-bit Linux) architectures, `FlowKey` occupies 56 bytes
  and `FlowRecord` occupies 208 bytes, meaning each stored flow key-value pair requires
  at least 264 bytes of raw payload. When factoring in `DashMap` internal sharding,
  spare bucket capacity as tables double, control bytes, and allocator fragmentation,
  measured resident memory is approximately **550–600 bytes per entry**:
  - **500,000 flows**: ~275–300 MB RSS.
  - **1,000,000 flows**: ~550–600 MB RSS.
  Operators should budget at least 600 MB of heap memory per 1,000,000 configured flows.
  Unbounded or oversized configurations risk out-of-memory (OOM) process termination.
- **CPU & Hash Contention**: Ingesting massive volumes of distinct keys stresses
  hash table operations across the internal `DashMap` shards. While sharding prevents
  a single global lock, concurrent lookups and inserts still compete for shard locks.
- **Aging Sweep Overhead**: The background aging worker periodically scans cache
  shards to evict idle flows (`idle_timeout`) and roll over active flows (`active_timeout`).
  When millions of entries reside in memory, each sweep consumes noticeable CPU and
  memory bandwidth to inspect timestamps and invoke emission callbacks.

### Template and Options Flooding
- Hostile senders can flood NetFlow v9 or IPFIX Template Sets or Options Template Sets
  with oscillating or randomized template IDs.
- The engine caps template storage at `max_templates` (default: 65,536). Exceeding
  the cap rejects further template definitions, protecting heap memory, but prevents
  subsequent legitimate templates from being registered until the exporter state is purged.

### Peer Key Table Exhaustion (Listener Layer)
- A listener that maps each distinct `SocketAddr` to an `ExporterKey` without a
  peer cap can exhaust memory under spoofed source addresses. The reference
  listener caps mappings at 1,024 by default and drops new peers when full.
- The reference listener purges peer keys idle for at least 30 minutes by
  default when a peer returns or capacity is needed, and rotates keys after
  conservative restart detection. Allowed source IPs must still be protected
  against spoofing by the network boundary.

---

## 3. Recommended Hardening Controls

### 3.1 Non-Spoofable Trust Boundaries & Admission Policy

Because UDP datagrams are easily spoofed, IP-based allow-lists alone are insufficient
over public or shared transit. A **cryptographically authenticated or non-spoofable
network boundary is required**:

1. **Non-Spoofable Network Boundaries**:
   - **Dedicated Management Networks**: Isolate flow exporter traffic to dedicated,
     physically isolated out-of-band (OOB) networks or isolated management VLANs.
   - **Authenticated Encapsulation**: Terminate exporter traffic through an
     authenticated VPN tunnel (IPsec or WireGuard) with cryptographically verified
     peer identity before datagrams reach the collector UDP socket.
   - **Anti-Spoofing Filters (BCP 38 / uRPF)**: Ensure intermediate network routers
     enforce Unicast Reverse Path Forwarding (uRPF) to drop spoofed IP packets at the edge.
2. **Interface Isolation**:
   - Bind the UDP listener exclusively to private, management-plane, or VPN tunnel
     interfaces (e.g., `10.x.x.x` or loopback) rather than wildcard addresses (`0.0.0.0` or `::`).
3. **Application-Level Admission Control**:
   - The reference listener accepts only loopback source IPs by default. Supply
     one or more `--allow-exporter <IP>` options for approved remote exporters;
     these replace the loopback defaults. It checks the source IP before
     allocating an `ExporterKey` or invoking `process_packet_from`.
   - Immediately discard datagrams from unknown peers without allocating state.

### 3.2 Ingress Rate Limiting

Apply multi-tiered rate limiting to protect the parser and operating system socket buffers:

- **OS Socket Buffer Sizing**: Configure `SO_RCVBUF` appropriately to absorb
  legitimate bursts without dropping packets, but pair this with a hard limit
  on processing rate to avoid buffer bloat.
- **Per-Exporter Rate Limiting**: Limit the maximum datagrams per second accepted
  from any single source IP (e.g., using a token bucket or leaky bucket algorithm).
  This prevents a single misconfigured or compromised router from dominating CPU capacity.
- **Global Packet Ceiling**: Impose an upper ceiling on total datagrams processed
  per second per worker thread to maintain deterministic latency.

### 3.3 Conservative Cache Sizing and Aging Configuration

Configure `EngineConfig` parameters according to available RAM and traffic characteristics:

```rust
use std::time::Duration;
use netflow_analyzer_core::{AgingConfig, ClockConfig, EngineConfig, FlowContext};

let config = EngineConfig {
    // Bound flow table to fit comfortably in available RAM.
    // 500,000 flows ~= 275-300 MB RAM.
    max_flows: 500_000,

    // Conservative template cap per context.
    max_templates: 8_192,

    // Configure aging timeouts.
    aging: AgingConfig {
        // Aggressive idle timeout under high-cardinality workloads
        // to reclaim slots quickly.
        idle_timeout: Duration::from_secs(15),

        // Active rollover for long-lived flows.
        active_timeout: Duration::from_secs(60),

        // Fast sweep interval to prevent accumulation of dead flows.
        scan_interval: Duration::from_secs(5),
    },

    // Clock drift validation.
    clock: ClockConfig {
        // Opt in to clock validation to detect/drop timestamp poisoning.
        sync_check_enabled: true,
        max_skew: Duration::from_secs(300),
        fallback_to_receipt_time: false,
    },
};

let ctx = FlowContext::with_config(config);

// IMPORTANT: Rust FlowContext does NOT start the background aging thread
// automatically. Senders must explicitly call `start_aging` with an emission
// callback; otherwise idle and active timeouts will never trigger and the cache
// will remain full until explicitly flushed or purged.
ctx.start_aging(|record| {
    // handle emitted flow...
});
```

#### Tuning for High Cardinality
- **Shorter `idle_timeout`**: Reducing `idle_timeout` (e.g., from 30s to 10–15s)
  ensures short-lived scanning or transit flows are evicted quickly, freeing
  slots for subsequent traffic.
- **Shorter `scan_interval`**: Sweeping more frequently (e.g., every 2–5s) prevents
  cache fill spikes during traffic surges.
- **Bounded Listener Peer Table**: Limit the number of concurrent peer mappings in
  the listener.
- **Fenced Peer Key Purge**: When an exporter becomes inactive or is retired,
  fence/quiesce packet ingestion under that key first, then call
  `FlowContext::purge_exporter` to drain residual flows and reclaim template and
  clock tracking slots before releasing the key. Invoking `purge_exporter` while
  packets for that key are still in flight can leave newly arrived flows in the cache
  with their template state deleted.

### 3.4 Observability and Anomaly Detection

Continually monitor engine telemetry by sampling `FlowContext::stats()`:

| Metric | Normal Behavior | Anomaly / Alert Threshold | Remediation / Interpretation |
| :--- | :--- | :--- | :--- |
| `pkts_parse_error` | Near 0 | Sustained increase | Header-level parsing failure, unknown protocol version, or truncated headers. |
| `malformed_packets` | Near 0 | Sustained increase | Body-level framing errors, truncated FlowSets, or malformed template definitions. |
| `flows_dropped` | 0 | Any rate increase (`rate > 0`) | `max_flows` cap reached. Unique flow arrival exceeds cache capacity; legitimate flows are being dropped. Increase `max_flows`, shorten `idle_timeout`, or filter noise. |
| `active_flows` (gauge via `ctx.active_flows()`) | Steady, well below `max_flows` | > 85% of `max_flows` | Approaching capacity. Early warning for flow cache exhaustion. |
| `active_templates` (gauge via `ctx.active_templates()`) | Steady | > 85% of `max_templates` | Approaching template capacity. Check for template ID flooding. |
| `templates_received` / `options_templates_received` | Monotonically slow growth | Rapid spike | Potential template or options flooding attack or rapid redefinition churn. |
| `clock_dropped_packets` | 0 | Sudden spike | Exporter export-time header exceeds `max_skew`, indicating NTP failure, desynchronized device, or header timestamp tampering. (Note: validates packet headers only, not internal record timestamps). |
| `clock_fallback_packets` | 0 | Sudden spike | Exporter clocks drifted beyond threshold; timestamps were rebased to local receipt time. |

Additionally, monitor operating system socket counters:
- **`SO_RXQ_OVFL` / `netstat -s -u` (UDP receive buffer errors)**: Indicates the
  application thread is not draining the UDP socket fast enough to match the
  ingress packet rate.

---

## 4. Production Deployment Checklist

Before exposing a NetFlow/IPFIX collector to production traffic, verify:

- [ ] **Trust Boundary**: Non-spoofable network boundary established (isolated OOB network, IPsec/WireGuard tunnel, or strict uRPF).
- [ ] **Interface**: Socket is bound to an internal management IP, not `0.0.0.0`.
- [ ] **Admission**: The listener enforces an allow-list of trusted exporters before allocating keys.
- [ ] **Rate Limiting**: Multi-tiered rate limiting (per-exporter and global) is active.
- [ ] **Peer Limit & Fencing**: The listener caps maximum peer count and fences ingestion before purging inactive exporters via `purge_exporter`.
- [ ] **Memory Bounds**: `max_flows` and `max_templates` are sized to host RAM (~550–600 bytes per resident flow entry).
- [ ] **Aging Started**: `start_aging` is explicitly called with an emission callback.
- [ ] **Aging Frequency**: `idle_timeout` and `scan_interval` are configured to prevent flow accumulation under burst conditions.
- [ ] **Telemetry Alerting**: Automated alerts are configured for counter increases: `rate(flows_dropped) > 0`, `pkts_parse_error`, and `malformed_packets` spikes.
- [ ] **Clock Hardening**: `clock.sync_check_enabled = true` and `clock.max_skew` are configured to validate datagram header export times against receipt time (individual record-level timestamps are not validated by this check).
