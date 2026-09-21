# netflow_analyzer_ffi

C ABI (FFI) bindings for the [`netflow_analyzer_core`](../core) NetFlow/IPFIX
engine.

This crate builds a `cdylib` and `staticlib` exposing a C-callable surface for
creating an engine, processing datagrams, registering flow/record callbacks, and
reading a telemetry snapshot. The generated C header is
[`include/netflow-analyzer.h`](include/netflow-analyzer.h); regenerate it with
`make header` (cbindgen).

## Quick start

Build the libraries and run the bundled C integration example:

```sh
make release      # build the staticlib/cdylib
make c-example    # compile and run examples/c_integration against it
```

## License

Licensed under the Mozilla Public License 2.0 (MPL-2.0). See the workspace
`LICENSE` file.
