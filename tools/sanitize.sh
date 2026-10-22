#!/usr/bin/env bash
# Runs the test suite under Miri and the Address/Thread sanitizers. Optional:
# needs a nightly toolchain with the `miri` and `rust-src` components.
#
# Usage: tools/sanitize.sh [miri|address|thread]...   (default: all three)
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

toolchain="${NETFLOW_ANALYZER_NIGHTLY:-nightly-2026-10-01}"
target="$(rustc "+$toolchain" -vV | sed -n 's/^host: //p')"
cargo=(cargo "+$toolchain")
packages=(-p netflow_analyzer_core -p netflow_analyzer_ffi)

run_miri() {
    # Unit tests only: they cover the FFI lifecycle, callbacks, and aging
    # thread, while the integration suites' concurrent loads are too slow
    # under the interpreter. Isolation is off because the wall-clock entry
    # points read the real-time clock.
    MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}" \
        "${cargo[@]}" miri test --locked "${packages[@]}" --lib
}

run_sanitizer() {
    local sanitizer="$1"
    shift
    RUSTFLAGS="-Zsanitizer=$sanitizer" RUSTDOCFLAGS="-Zsanitizer=$sanitizer" \
        "${cargo[@]}" test --locked -Zbuild-std --target "$target" \
        --target-dir "target/sanitize-$sanitizer" "${packages[@]}" "$@"
}

modes=("$@")
[ "${#modes[@]}" -eq 0 ] && modes=(miri address thread)
for mode in "${modes[@]}"; do
    case "$mode" in
        miri) run_miri ;;
        address) run_sanitizer address --lib --tests ;;
        # Concurrency-focused: the unit, engine, and lifecycle suites hold the
        # multi-threaded ingestion, flush, aging, and FFI lifecycle tests.
        thread) run_sanitizer thread --lib --test engine --test lifecycle ;;
        *) echo "sanitize: unknown mode '$mode' (miri|address|thread)" >&2; exit 2 ;;
    esac
done
