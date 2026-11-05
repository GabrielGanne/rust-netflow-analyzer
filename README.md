# rust-netflow-analyzer

Zero-copy NetFlow v5, NetFlow v9, and IPFIX decoding and flow-aggregation engine in Rust, with C ABI bindings.

`rust-netflow-analyzer` parses exported datagrams directly from caller-provided
memory buffers without heap allocation for packet framing, manages template
definitions and clock drift per exporter, and aggregates decoded records into
an internally sharded, size-bounded flow cache with background aging.

| Crate | Contents |
| :--- | :--- |
| [`netflow_analyzer_core`](core) | Pure Rust decoding, aggregation, template, and clock engine (no `unsafe`). |
| [`netflow_analyzer_ffi`](ffi) | C ABI (`cdylib`, `staticlib`) and the generated header `include/netflow-analyzer.h`; error codes, ABI versioning, and installation. |

## Supported Protocols

| Protocol | Specification | Decoding | Aggregation |
| :--- | :--- | :--- | :--- |
| **NetFlow v5** | Legacy fixed format | 48-byte records, scoped by engine type/id | Additive flow stitching, header sampling |
| **NetFlow v9** | [RFC 3954](https://datatracker.ietf.org/doc/html/rfc3954) | Templates, options templates, data, variable-length elements | Additive flow stitching, options sampling |
| **IPFIX** | [RFC 7011](https://datatracker.ietf.org/doc/html/rfc7011) | Templates, options templates, data, length validation, variable-length elements | Additive flow stitching, options sampling |

## Examples

- [`core/examples/quickstart.rs`](core/examples/quickstart.rs): configure a context, ingest a packet, age and flush flows. `cargo run -p netflow_analyzer_core --example quickstart`
- [`core/examples/udp_listener.rs`](core/examples/udp_listener.rs): multi-exporter UDP collector with an exporter allow-list, bounded peer table, and restart detection. `cargo run -p netflow_analyzer_core --example udp_listener -- --help`
- [`examples/c_integration`](examples/c_integration): self-checking C/C++ ABI test covering the fused, manual-aging, and decode-only paths. `make release && make c-example`

## Documentation

- [Architecture](docs/architecture.md): pipeline, components, concurrency, threading and lifecycle rules.
- [Aggregation Semantics](docs/aggregation.md): what an emitted flow represents, sampling normalization, emission paths, out-of-scope modes.
- [Exporter Identity](docs/exporter-identity.md): exporter keys, scopes, and the key rotation and purge contract.
- [Deployment Hardening](docs/deployment-hardening.md): resource limits, hostile input, cache sizing, and monitoring.
- [Testing](docs/testing.md): local gate, benchmarks, fuzzing, and sanitizers.
- [Contributing](CONTRIBUTING.md) and [Releasing](RELEASING.md).

## Testing

```sh
./tools/test.sh   # or: make check
```

## Platforms

Linux `x86_64` and `aarch64` (LP64); C11 and C++11 headers; Rust 1.82 or newer.

## License

Mozilla Public License 2.0 (MPL-2.0). See [`LICENSE`](LICENSE).
