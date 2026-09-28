# Releasing

This workspace publishes two crates to crates.io. They must be published in a
fixed order because of the dependency between them.

## Publication order

1. `netflow_analyzer_core`
2. `netflow_analyzer_ffi` (depends on `netflow_analyzer_core`)

`netflow_analyzer_ffi` declares `netflow_analyzer_core` as both a `path` and a
`version` dependency. When packaged, cargo rewrites the dependency to the
registry version requirement, so that exact core version must already be
available on crates.io before the FFI crate can be published — or verified *on
its own*. A whole-workspace `cargo package` can still verify the FFI crate
locally against an as-yet-unpublished core (see below). Always publish core
first, then the FFI crate.

## Verifying before release

Run local verification and verify dependency policy:

```sh
./tools/test.sh                    # fmt, tests, clippy, cargo deny, C ABI smoke test
cargo package --workspace          # build every .crate and verify-build each
cargo package --workspace --list   # inspect the file list of every archive
```

`cargo package --workspace` handles the inter-crate dependency automatically: it
packages core, stages it into a temporary local registry, and verifies the FFI
crate against that packaged core. Both archives must build with no errors and no
warnings.

This local staging of unpublished interdependent members requires **Cargo 1.90
or newer** (multi-package publishing, stabilized in Rust 1.90). It is a
release-tooling requirement only and is unrelated to the crates' MSRV
(`rust-version`), which governs consumers, not the machine cutting the release.
On an older cargo, `cargo package --workspace` cannot stage core, so publish (or
dry-run) core first and package the FFI crate only after the matching core
version is live.

Standalone `cargo package -p netflow_analyzer_ffi` (or
`cargo publish --dry-run -p netflow_analyzer_ffi`) still cannot succeed against a
*new, unpublished* core version even on Cargo 1.90+: neither command uploads or
indexes core, so the FFI verify build fails to resolve `netflow_analyzer_core`
from crates.io until the matching core version is actually live. Use
`--workspace` for local verification, and rely on the ordered publish below for
the real release.

Core can also be verified on its own at any time:

```sh
cargo package -p netflow_analyzer_core
cargo publish --dry-run -p netflow_analyzer_core
```

## Publishing

```sh
# 1. Publish core and wait for the crates.io index to propagate it.
cargo publish -p netflow_analyzer_core

# 2. Once core@<version> resolves from crates.io, publish the FFI crate.
cargo publish -p netflow_analyzer_ffi
```

Keep the `version` in `ffi/Cargo.toml`'s `netflow_analyzer_core` dependency in
lockstep with `core/Cargo.toml`'s `version` on every release.
