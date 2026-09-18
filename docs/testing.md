# Testing and performance plan

This repository uses local, repeatable commands as its primary verification
workflow. The commands are intended to be useful on a developer workstation
without CI infrastructure; benchmark output is evidence for comparison, not a
fixed acceptance threshold.

## Current commands

Run the full local gate:

```sh
./tools/test.sh
```

That command checks formatting, runs debug and release tests for every
workspace target, runs documentation tests, runs Clippy with warnings denied,
and builds/runs the C static-library smoke test.

Run only the C integration test:

```sh
make c-example
```

Run the Criterion benchmark suite:

```sh
./tools/bench.sh
```

Additional Criterion arguments can be passed after the command, for example
`./tools/bench.sh v9` or `./tools/bench.sh --save-baseline local`.

## What exists today

- Unit tests cover parser primitives, record decoding, timestamps, cache
  behavior, aging, and clock handling.
- Integration tests cover NetFlow v5, NetFlow v9, IPFIX, decode-only mode,
  malformed/truncated input, limits, metadata, and aging behavior.
- FFI unit tests cover lifecycle, error mapping, configuration, callbacks, and
  decode-only callbacks.
- `examples/udp_listener.rs` is a runnable Rust example.
- `examples/c_integration/main.c` is a runnable C ABI smoke test.
- `core/benches/process_packet.rs` provides v5, v9, IPFIX, warm-cache, and
  cold-context throughput cases.

## Planned additions

1. Stabilize the local gate. Resolve the existing rustfmt drift, then keep
   `tools/test.sh` as the one documented correctness command. Add an explicit
   supported Rust version before adding an MSRV runner.
2. Complete protocol and state-machine coverage. Add table-driven packet
   builders/fixtures for header and FlowSet length boundaries, template
   replacement/expiry, multiple domains, padding, unknown fields, options
   semantics, and all documented error paths.
3. Improve concurrency and lifecycle tests. Cover concurrent processing and
   flushing, repeated aging start/stop, bounded cache behavior under load, and
   replace timing sleeps with an injectable or controllable clock where tests
   need deterministic time.
4. Expand the examples and ABI checks. Add a decode-only C example or extend
   the current one to assert callback fields, null/empty inputs, explicit
   timestamps, and public structure sizes/layouts. Keep examples executable by
   the local gate.
5. Characterize performance. Keep benchmarks representative and small enough
   to run locally; record packet size, records per packet, template warmness,
   cache hit/miss behavior, and environment details when comparing results.
6. Add robustness tooling after the deterministic suite is complete. A future
   fuzz crate should target packet headers, FlowSets, templates, and variable
   length records with checked-in seeds. Sanitizer runs and dependency audits
   should be separate optional local commands because they require extra tools.

## What is intentionally not copied

The classifier-specific Python tests, YAML fixtures, allocation detector, and
configuration-validation recorder do not map directly to this packet parser.
The useful ideas are retained: strict shell scripts, locked dependencies,
separate test artifacts, debug/release coverage, executable examples, seeded
fuzzing, and benchmark records with environment metadata.

The classifier's MSRV script is also deferred until this workspace declares a
`rust-version`; otherwise it would encode an unsupported policy. Likewise,
large benchmark-recording machinery should wait until there are several stable
workloads worth comparing.
