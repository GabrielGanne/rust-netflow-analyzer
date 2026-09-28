# rust-netflow-analyzer

Zero-copy NetFlow v5, NetFlow v9, and IPFIX decoding and flow-aggregation engine in Rust, with C ABI bindings.

`rust-netflow-analyzer` parses exported datagrams directly from caller-provided
memory buffers without heap allocation for packet framing, manages template
definitions and clock drift per exporter, and aggregates decoded records into
an internally sharded, size-bounded flow cache with background aging.

The workspace consists of two crates:
- [`netflow_analyzer_core`](core): Pure Rust decoding, aggregation, template management, and clock tracking engine.
- [`netflow_analyzer_ffi`](ffi): C ABI (`cdylib` and `staticlib`) bindings and cbindgen-generated C header (`include/netflow-analyzer.h`).

---

## Supported Protocols

| Protocol | Specification | Decoding Support | Aggregation Support |
| :--- | :--- | :--- | :--- |
| **NetFlow v5** | Legacy fixed format | Full (48-byte records, domain-less, engine type/id scoped) | Additive flow stitching |
| **NetFlow v9** | [RFC 3954](https://datatracker.ietf.org/doc/html/rfc3954) | Template FlowSets, Options Template FlowSets, Data FlowSets, variable-length elements | Additive flow stitching with options sampling normalization |
| **IPFIX** | [RFC 7011](https://datatracker.ietf.org/doc/html/rfc7011) | Template Sets, Options Template Sets, Data Sets, declared length validation, variable-length elements | Additive flow stitching with options sampling normalization |

---

## Architecture

The engine uses a zero-copy parser, an explicit session identity model, and fine-grained sharded state across both a fused aggregation pipeline and a stateless decode-only path.

See the dedicated [Architecture Documentation](docs/architecture.md) for full pipeline diagrams and component details.

---

## Examples

Runnable integration examples are provided in the repository:

- **C Integration (`examples/c_integration`)**: Demonstrates creating an engine context, processing packets, handling flow callbacks, and validating ABI struct layouts:
  ```sh
  make release
  make c-example
  ```
- **Rust Quickstart (`core/examples/quickstart.rs`)**: Demonstrates context configuration, packet ingestion, background aging, and telemetry snapshots:
  ```sh
  cargo run -p netflow_analyzer_core --example quickstart
  ```
- **Reference UDP Listener (`core/examples/udp_listener.rs`)**: A multi-exporter OS-socket daemon ingesting real NetFlow/IPFIX datagrams from a network socket:
  ```sh
  cargo run -p netflow_analyzer_core --example udp_listener -- --help
  ```

---

## Testing and Verification

Run the full local verification gate before submitting changes:

```sh
./tools/test.sh
# or
make check
```

This checks formatting (`cargo fmt --check`), runs debug and release tests across all workspace targets, runs documentation tests, runs Clippy with warnings denied (`-D warnings`), validates dependency policy and security advisories (`cargo deny --locked check`), and builds and runs the C integration test and ABI checks.

---

## Threading and Lifecycle Rules

1. **Concurrent Packet Ingestion**:
   - `FlowContext` is thread-safe (`Send + Sync`) and designed to be shared via `Arc` across worker threads.
   - Concurrent `process_packet*` and `decode_packet*` calls access sharded cache buckets independently without contending on a global mutex.
2. **Single Controlling Thread**:
   - Engine lifecycle transitions — `start_aging`, `stop_aging`, `netflow_analyzer_create`, and `netflow_analyzer_destroy` — must be driven by a **single controlling thread**.
   - Initiating shutdown or calling `stop_aging` from within an emission callback (on the background aging thread) is misuse; as a safety measure, the worker detaches to prevent deadlocks, but synchronous termination is not guaranteed in that case.
3. **Lock-Free Callbacks**:
   - All flow emission callbacks (aging sweep, manual `flush`, and `purge_exporter`) execute **after** releasing internal cache shard locks.
   - User callbacks can safely re-enter the engine (for example to query `stats()`) without deadlocking.
4. **Exporter Key Rotation and Purge**:
   - When an exporter restarts or its session ends, callers must retire the key using `purge_exporter` (or `netflow_analyzer_purge_exporter`).
   - `purge_exporter` emits residual accumulated traffic first, then drops cached templates, clock state, and sampling factors, reclaiming capacity without memory leaks.

---

## Resource Limits and Bounded Memory

To defend against Denial of Service (DoS) attacks and hostile input:

- **Flow Cache Bound**: Controlled by `max_flows` (default: 1,000,000). Once full, new flow keys are rejected, and `flows_dropped` increments. Existing resident flows continue accumulating traffic normally.
- **Template Cache Bound**: Controlled by `max_templates` (default: 65,536). New template definitions beyond the cap are rejected and counted as malformed.
- **Pre-Allocation Limits**: Template field counts are bounded (`MAX_TEMPLATE_FIELDS = 1024`) and verified against remaining datagram bytes before allocating heap memory.
- **Framing Enforcement**: IPFIX declared `total_length` is strictly enforced. Datagrams claiming impossible lengths or Sets that overrun message boundaries are rejected immediately before walking record bodies.

---

## Security Posture

- **Memory Safety**: Pure Rust core engine without `unsafe` blocks in packet parsing or aggregation.
- **Panic Boundaries**: FFI entry points are guarded with `catch_unwind` (`guard_ffi`), translating panics into error codes (`-1`) to prevent undefined behavior across `extern "C"` boundaries.
- **Hostile Input Hardening**:
  - Structural validation stops corrupted FlowSet chains gracefully.
  - Clock skew validation drops or rebases wildly drifted exporter timestamps before they can poison time bounds.
  - For guidance on securing public or multi-tenant listeners, trusted exporter allow-lists, rate limiting, conservative cache sizing, and mitigating hostile high-cardinality traffic, see the [Deployment Hardening Guide](docs/deployment-hardening.md).

---

## Design Constraints

The following limitations are deliberate architectural choices:

- **Hard-Capped Memory**: Memory is bounded by design. The engine will never unbounded-buffer incoming flows or templates; when caps are reached, traffic beyond capacity is dropped rather than risking out-of-memory crashes.
- **Non-Retroactive Normalization**: Packet-sampling scaling is performed per-record at ingestion time. Subsequent options records or reconfigurations do not retroactively rewrite historical counters already folded into aggregates (see [Aggregation Semantics](docs/aggregation.md)).
- **Explicit Exporter Scoping**: The engine does not guess or heuristically merge transport sessions across restarts. Callers must manage exporter keys and issue transport-session resets via `purge_exporter` when exporters restart (see [Exporter Identity](docs/exporter-identity.md)).

---

## Supported Platforms and MSRV

- **Tier 1 Supported Platforms**: Linux `x86_64` and `aarch64` (64-bit, LP64).
- **C ABI Standard**: C11 and C++11 compatible headers (`ffi/include/netflow-analyzer.h`).
- **Minimum Supported Rust Version (MSRV)**: Rust **1.82**.
