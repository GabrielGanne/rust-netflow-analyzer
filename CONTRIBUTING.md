# Contributing to rust-netflow-analyzer

Thank you for your interest in contributing to `rust-netflow-analyzer`! This document provides guidelines and instructions for contributing to the project.

---

## Development Setup

### Prerequisites

- **Rust**: Version **1.82** or newer (stable toolchain recommended).
- **C/C++ Toolchain**: `gcc` or `clang`, `g++`, and `make` (required to run the C integration and ABI smoke tests).
- **cbindgen** (optional, required only when modifying FFI types): `cargo install cbindgen`.

### Clone and Build

```sh
git clone https://github.com/GabrielGanne/rust-netflow-analyzer.git
cd rust-netflow-analyzer
cargo build
```

---

## Testing and Verification

Before submitting a pull request, run the local verification gate:

```sh
./tools/test.sh
```

`./tools/test.sh` runs the full verification pipeline:
1. `cargo fmt --check` (code formatting)
2. `cargo test` in debug mode across all workspace crates, tests, benchmarks, and examples
3. `cargo test --release` in optimized release mode
4. `cargo test --doc` (documentation tests)
5. `cargo clippy` with warnings denied (`-D warnings`)
6. `cargo build --release`
7. Compilation and execution of the C integration example (`examples/c_integration`) with C11 and C++11 ABI static assertions
8. Public C symbol verification (`tools/check_symbols.sh`)

Additionally, verify documentation build cleanly:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

---

## Code Guidelines

- **Minimal Surface**: Keep the public API compact and strictly typed. Avoid leaking internal caches, atomics, or parser implementation details.
- **Conventions**: Follow standard Rust idioms, naming conventions, and project architecture.
- **Dependencies**: Do not introduce new external dependencies without explicit discussion and justification.
- **C ABI Stability**:
  - Any change to types in `ffi/src/lib.rs` must be reflected in `ffi/include/netflow-analyzer.h` by running `make header`.
  - Public structs in `ffi` are versioned and include trailing `reserved` arrays. If fields are added, consume reserved slots and bump `NETFLOW_ANALYZER_ABI_VERSION`.
  - Maintain the static assertions in `examples/c_integration/abi_checks.c`.
- **Documentation**: All public items must have clear, informative doc comments with examples where appropriate.

---

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Implement your changes with accompanying unit and integration tests.
3. Ensure `./tools/test.sh` passes without any errors or warnings.
4. If your changes affect user-facing behavior, update `CHANGELOG.md` under `[Unreleased]`.
5. Submit your pull request with a descriptive title and summary of changes.
