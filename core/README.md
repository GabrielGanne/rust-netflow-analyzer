# netflow_analyzer_core

Zero-copy NetFlow v5/v9 and IPFIX decoding and flow-aggregation engine.

`netflow_analyzer_core` parses exported NetFlow/IPFIX datagrams directly from the
caller's buffer (no intermediate copy), tracks templates and exporter clocks, and
folds decoded data records into an internally sharded, bounded flow cache that can
be aged and flushed concurrently.

## Quick start

```rust,no_run
use netflow_analyzer_core::FlowContext;

let datagram: &[u8] = /* a raw exported NetFlow/IPFIX datagram */ &[];
let ctx = FlowContext::new();
let records = ctx.process_packet(datagram)?;
println!("decoded {records} data records");
let stats = ctx.stats();
# Ok::<(), netflow_analyzer_core::PacketError>(())
```

Use `decode_packet`/`decode_packet_at` for a decode-only path that delivers each
record to a sink without touching the flow cache.

## Aggregation semantics

The engine performs additive flow aggregation keyed by
`(exporter_key, Scope, identity)`, with idle-timeout eviction and active-timeout
rollover (periodic intermediate dumps), and normalizes counters by the sampling
rate advertised in NetFlow v9 / IPFIX options records or the NetFlow v5 header.
Flow deduplication (max-instead-of-sum and cross-observation-point),
bidirectional (biflow) aggregation, and empty-record dropping are **out of
scope** for this release. Timeout-based emission runs on the
background aging worker, which a Rust caller must start with `start_aging`. See
the [aggregation semantics doc][agg] for the full model and its limitations.

[agg]: https://github.com/GabrielGanne/rust-netflow-analyzer/blob/main/docs/aggregation.md

## License

Licensed under the Mozilla Public License 2.0 (MPL-2.0). See the workspace
`LICENSE` file.
