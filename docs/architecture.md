# Architecture

`rust-netflow-analyzer` provides a high-throughput, zero-copy NetFlow and IPFIX
processing pipeline. This document details the system components, data flow,
and concurrency model.

---

## High-Level Pipeline

```
                  +----------------------------------------------+
                  |           Raw Network Datagram (&[u8])       |
                  +----------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |      Zero-Copy Nom Parser     |
                         |  (v5 / v9 / IPFIX Framing)    |
                         +-------------------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
             [Template / Options]                   [Data Records]
                       |                                   |
                       v                                   v
             +--------------------+               +--------------------+
             |  Template Cache    |               |  Sampling Scaling  |
             |  & Clock Tracker   |               |  (Options ratios)  |
             +--------------------+               +--------------------+
                       |                                   |
                       +-----------------+-----------------+
                                         |
                                         v
                      +------------------------------------+
                      |    (exporter_key, Scope) Scoping   |
                      +------------------------------------+
                                         |
                  +----------------------+----------------------+
                  |                                             |
                  v                                             v
        [process_packet*]                              [decode_packet*]
     (Fused Aggregation Path)                         (Decode-Only Path)
                  |                                             |
                  v                                             v
     +--------------------------+                      Caller-provided Sink
     |   Sharded Flow Cache     |                     (&FlowFields directly)
     |   (Additive Stitching)   |
     +--------------------------+
                  |
     +------------+------------+
     |                         |
     v                         v
Background Sweep         Explicit Flush / Purge
 (Aging Worker)          (Synchronous Emission)
```

---

## Core Components

### 1. Zero-Copy Framing and Parser
The parser processes datagram buffers directly without copying payloads onto the heap:
- **NetFlow v5**: Parsed as fixed 48-byte records directly from the packet payload.
- **NetFlow v9 & IPFIX**: Packet headers and Set framing are validated first. Template Sets define the field offsets and lengths used to decode subsequent Data Sets. Variable-length records are decoded with zero-copy sub-slices.

### 2. Exporter Identity and Scoping
All internal state is scoped by `(exporter_key, Scope)`:
- `exporter_key`: An opaque 128-bit integer (`ExporterKey = u128`; C callers pass a `uint64_t` or a 16-byte key via the `*_addr` entry points) supplied by the caller, distinguishing transport sessions (e.g. peer socket address, interface, or router instance).
- `Scope`: Encodes the protocol discriminator (`NetFlow v9`, `IPFIX`, or `NetFlow v5 Engine`) and observation domain ID, preventing domain collisions between distinct protocols or independent devices.

### 3. Sampling Normalization
Options templates configure packet sampling rates (`samplingInterval` IE 34, `samplerRandomInterval` IE 50, or `samplingPacketInterval`/`samplingPacketSpace` IE 305/306):
- Rates are learned and tracked per `(exporter, scope, sampler)`.
- Flow byte and packet counters are scaled immediately at record decode time before aggregation.

### 4. Dual Ingestion Pipelines
- **Fused Aggregation (`process_packet*`)**: Folds decoded flow records into the internal flow table, performing additive stitching for identical keys and updating observation timestamps.
- **Stateless Decode-Only (`decode_packet*`)**: Updates template definitions and clock state but bypasses the flow cache, invoking a user callback per record for consumers managing their own aggregation pipeline.

### 5. Concurrent Sharded State and Aging
- The flow cache and template cache are internally sharded using `DashMap`, allowing concurrent worker threads to ingest packets without a global lock.
- A background worker thread sweeps the flow cache at configurable intervals (`scan_interval`), evicting idle flows (`idle_timeout`) and rolling over active flows (`active_timeout`).
- All callbacks run outside cache locks to avoid blocking ingestion or causing deadlocks.
