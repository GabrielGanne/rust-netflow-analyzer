# Architecture Design Draft: High-Performance NetFlow/IPFIX Analyzer

This document serves as the foundational architectural blueprint for the NetFlow/IPFIX packet processing and analysis library. It outlines key design decisions, memory management strategies, and the roadmap for transitioning from standard OS sockets to kernel-bypass technologies.

---

## 1. Project Objectives

* **Core Function:** Act strictly as an ingestion and state-tracking analysis engine (decoding templates, options, and data records).
* **Language Choice:** **Rust**, providing bare-metal C-equivalent performance alongside compile-time memory safety and data-race prevention.
* **Interoperability:** Expose a C-compatible ABI (`staticlib` / `cdylib`) so the engine can be natively linked into C host projects.
* **I/O Agnostic:** Decouple packet processing from network I/O to support standard OS sockets today and DPDK kernel-bypass tomorrow.

---

## 2. Memory & OOM Management Strategy

To eliminate the risk of unrecoverable Out-Of-Memory (OOM) panics common in naive Rust binaries, the library enforces strict memory constraints:

* **Fallible Allocation:** Collections use explicit pre-allocation boundaries via `.try_reserve()` instead of growing implicitly.
* **Hard-Capped Cache:** State tracking relies on size-bounded data structures to prevent unbounded heap growth from malicious or high-volume exporter flows.
* **Zero-Copy Pipeline:** The parser processes slices of byte streams directly from the network ring buffers rather than allocating memory on the heap for packet data copies.

---

## 3. Core Component Architecture

### A. Parsing Engine (`nom`)

* **Framework:** Committing to `nom` for functional, zero-copy binary parsing.
* **Safety:** Eliminates traditional network parser CVEs (buffer overflows/overreads) via native bounds checking.
* **Dynamic Handling:** Maps incoming variable-length IPFIX/NetFlow v9 data records dynamically using referenced template dimensions without allocating new runtime layout objects.

### B. Global State & Concurrency (`dashmap`)

* **Topology:** A unified, global template and session cache accessible concurrently by multiple worker threads.
* **Implementation:** Utilizing `dashmap` to achieve shard-locked concurrent access. This prevents a single global lock from bottlenecking worker pipelines.
* **Thread Safety:** Rust’s `Send` and `Sync` constraints guarantee that the multi-threaded data path remains secure and panic-safe at the FFI boundary.

### C. Aging & Timeout Engine

* **Background Thread:** A low-priority background worker periodically crawls the active state cache using thread-safe, shard-isolated iteration (`retain`).
* **Idle Timeouts:** Flow contexts that have ceased activity past a configurable duration are safely evicted and passed to the host application.
* **Active Timeouts:** Long-running structural connections (e.g., persistent file downloads) trigger intermediary metric dumps and counter-resets without destroying the underlying cache session.

### D. Control Path & Telemetry (`get_stats`)

* **Mechanism:** Completely lock-free instrumentation using atomic primitives (`AtomicU64`) under `Relaxed` CPU memory ordering.
* **Isolation:** The main monitoring thread calls `get_stats()` via a non-blocking asynchronous data snapshot. Worker processing loops increment diagnostics in nanoseconds without thread contention.

---

## 4. Host Integration & FFI Boundary

The host application (whether written in Rust or C) interacts with the library via a strictly defined control loop:

* **Input:** The host passes raw borrowed byte slices (`&[u8]`) into the core processing function.
* **Output Callbacks:** Upon a successfully processed flow or timeout eviction, the library invokes a C-style functional pointer (`extern "C" fn`) packed with an opaque `void* user_data` reference, allowing the host application to handle persistence or API routing without heap cloning.

---

## 5. Target Project Workspace Layout

```text
netflow-analyzer/
├── Cargo.toml                 # Workspace configuration
├── Makefile                   # Automation for C-headers (cbindgen) and binary targets
├── include/
│   └── netflow_analyzer.h     # Auto-generated C Header file
├── core/                      # Pure Rust Ingestion & State Parsing Engine
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs             # Engine primitives
│       ├── parser.rs          # Low-level nom implementations
│       ├── cache.rs           # DashMap state & background aging systems
│       ├── stats.rs           # Lock-free atomic metrics
│       └── records.rs         # Rigorous, normalized FlowRecord models
├── ffi/                       # C-Compatibility Wrapper Layer
│   ├── Cargo.toml             # Emits staticlib and cdylib artifacts
│   ├── cbndgen.toml           # Mapping directives for header output
│   └── src/
│       └── lib.rs             # C-exposed pointers, wrappers, and callback hooks
└── examples/
    ├── udp_listener.rs        # Reference OS-socket integration (Phase 1)
    └── c_integration/         # Reference C test-bench for library verification

```

---

## 6. Implementation Roadmap

1. **Phase 1 (Current):** Construct the zero-copy `nom` header parsers and the fixed-width `FlowRecord` structure.
2. **Phase 2:** Integrate `dashmap` state caching along with the background aging thread.
3. **Phase 3:** Wrap the internal logic in the `ffi/` layer and validate integration via the C testing sub-project.
4. **Phase 4 (Future):** Introduce a `dpdk_runner` crate to bind the core processing slices directly to pre-allocated hugepage memory regions (`rte_mbuf`).
