# Releasing

This workspace publishes two crates to crates.io. They must be published in a
fixed order because of the dependency between them.

## Publication order

1. `netflow_analyzer_core`
2. `netflow_analyzer_ffi` (depends on `netflow_analyzer_core`)

`netflow_analyzer_ffi` declares `netflow_analyzer_core` as both a `path` and a
`version` dependency. When packaged, cargo rewrites the dependency to the
registry version requirement, so that exact core version must already be
available on crates.io before the FFI crate can be published or verified. Always
publish core first, then the FFI crate.

## Verifying before release

Both crates package on their own, so pre-publish checks are independent:

```sh
cargo package -p netflow_analyzer_core
cargo publish --dry-run -p netflow_analyzer_core
```

The FFI crate cannot be dry-run against a *new, unpublished* core version:
`cargo publish --dry-run` neither uploads nor indexes core, so
`cargo publish --dry-run -p netflow_analyzer_ffi` fails to resolve
`netflow_analyzer_core` from the registry until the matching version is actually
live. For a fully local end-to-end check, point cargo at a local registry (for
example [`cargo-http-registry`](https://crates.io/crates/cargo-http-registry) or
a `[source.crates-io].replace-with` mirror) and publish core into it first.

## Publishing

```sh
# 1. Publish core and wait for the crates.io index to propagate it.
cargo publish -p netflow_analyzer_core

# 2. Once core@<version> resolves from crates.io, publish the FFI crate.
cargo publish -p netflow_analyzer_ffi
```

Keep the `version` in `ffi/Cargo.toml`'s `netflow_analyzer_core` dependency in
lockstep with `core/Cargo.toml`'s `version` on every release.
