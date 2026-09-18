#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo="${CARGO:-cargo}"
make_command="${MAKE:-make}"
test_target_dir="${NETFLOW_ANALYZER_TEST_TARGET_DIR:-$repo_root/target/test}"

# Keep the local verification build separate from ordinary cargo artifacts so
# debug and release checks can be repeated without changing the default target.
"$cargo" fmt --all -- --check
"$cargo" test --locked --target-dir "$test_target_dir" --all-targets
"$cargo" test --locked --target-dir "$test_target_dir" --all-targets --release
"$cargo" test --locked --target-dir "$test_target_dir" --doc
"$cargo" clippy --locked --target-dir "$test_target_dir" --all-targets -- -D warnings

# Exercise the public static-library/header integration in addition to Rust
# unit and integration tests.
"$make_command" c-example
