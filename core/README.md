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
# Ok::<(), &'static str>(())
```

Use `decode_packet`/`decode_packet_at` for a decode-only path that delivers each
record to a sink without touching the flow cache.

## License

Licensed under the Mozilla Public License 2.0 (MPL-2.0). See the workspace
`LICENSE` file.
