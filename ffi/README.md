# netflow_analyzer_ffi

C ABI (FFI) bindings for the
[`netflow_analyzer_core`](https://github.com/GabrielGanne/rust-netflow-analyzer/tree/main/core)
NetFlow/IPFIX engine.

This crate builds a `cdylib` and `staticlib` exposing a C-callable surface for
creating an engine, processing datagrams, registering flow/record callbacks, and
reading a telemetry snapshot. The generated C header is
[`include/netflow-analyzer.h`](https://github.com/GabrielGanne/rust-netflow-analyzer/blob/main/ffi/include/netflow-analyzer.h); regenerate it with
`make header` (cbindgen).

## Quick start

Build the libraries and run the bundled C integration example:

```sh
make release      # build the staticlib/cdylib
make c-example    # compile and run examples/c_integration against it
```

Install the header, libraries and `netflow-analyzer.pc` for use as an external
dependency (`PREFIX`, `LIBDIR`, `INCLUDEDIR` and `DESTDIR` are honored):

```sh
make install PREFIX=/usr/local
pkg-config --cflags --libs netflow-analyzer
```

## Supported platforms and ABI stability

**Tier 1 (built, tested, and guaranteed):** Linux on `x86_64` and `aarch64`
(64-bit, LP64), using the platform C ABI via `extern "C"`. The generated header
is verified to compile as both **C11** and **C++11** (`cpp_compat`). Other
targets (macOS, Windows, 32-bit, big-endian) may work but are best-effort and
not covered by the tests.

The C interface is versioned:

- `NETFLOW_ANALYZER_ABI_VERSION` (a header `#define`) and the runtime
  `netflow_analyzer_abi_version()` let a consumer detect a header/library
  mismatch and refuse to run on disagreement.
- Every public struct (`NetflowAnalyzerConfig`, `NetflowAnalyzerStats`,
  `NetflowAnalyzerFlowRecord`) carries a trailing `reserved[…]` array so new
  fields can be added within that space without changing its size or layout. A
  field consumes reserved slots and bumps the ABI version (for example
  `NetflowAnalyzerStats` added `options_templates_received` /
  `options_records_processed` in ABI version 2, leaving `reserved[6]`).
- Any change that alters a public struct's size/layout or a function signature
  is an **ABI break** and bumps `NETFLOW_ANALYZER_ABI_VERSION`. So does a change
  to how an existing field is encoded (for example IPv4 addresses gaining the
  `::ffff:` mapped prefix in ABI version 4).

These invariants are enforced by the test suite (run via `make c-example` /
`./tools/test.sh`):

- `public_struct_layout_is_pinned` (Rust, `ffi/src/lib.rs`) pins each struct's
  `size_of`/`align_of` and every field offset.
- `examples/c_integration/abi_checks.c` pins the same sizes, alignments, and
  field offsets with `static_assert`, compiled as **both** C11 and
  C++11, so the two languages must agree.
- `_ABI_SIGNATURES` (Rust, `ffi/src/lib.rs`) pins every exported function's
  signature and `extern "C"` calling convention.
- `tools/check_symbols.sh` confirms the static library exports exactly the
  public `netflow_analyzer_*` symbols.

## License

Licensed under the Mozilla Public License 2.0 (MPL-2.0). See [`LICENSE`](https://github.com/GabrielGanne/rust-netflow-analyzer/blob/main/LICENSE).
