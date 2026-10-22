#!/usr/bin/env bash
# Verify the FFI static library exports exactly the public C symbols the header
# promises. Guards against an entry point being renamed, dropped, or its
# `#[no_mangle]` accidentally removed. Linux/ELF `nm` is assumed (the declared
# tier-1 platform); on a host without `nm` the check is skipped.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cargo="${CARGO:-cargo}"
lib="$repo_root/target/release/libnetflow_analyzer_ffi.a"

if ! command -v nm >/dev/null 2>&1; then
    echo "check_symbols: nm not found; skipping exported-symbol check" >&2
    exit 0
fi

# Rebuild before inspecting so the archive always reflects the current sources.
# Cargo is incremental (a no-op when up to date), so this is cheap; skipping it
# when a stale archive happens to exist could mask an export regression.
"$cargo" build --release -p netflow_analyzer_ffi --manifest-path "$repo_root/Cargo.toml"

if [ ! -f "$lib" ]; then
    echo "check_symbols: static library not found at $lib" >&2
    exit 1
fi

expected=(
    netflow_analyzer_abi_version
    netflow_analyzer_create
    netflow_analyzer_destroy
    netflow_analyzer_get_stats
    netflow_analyzer_flush
    netflow_analyzer_age_at
    netflow_analyzer_purge_exporter
    netflow_analyzer_process_packet
    netflow_analyzer_process_packet_at
    netflow_analyzer_process_packet_from
    netflow_analyzer_process_packet_from_at
    netflow_analyzer_decode_packet
    netflow_analyzer_decode_packet_at
    netflow_analyzer_decode_packet_from
    netflow_analyzer_decode_packet_from_at
    netflow_analyzer_purge_exporter_addr
    netflow_analyzer_process_packet_from_addr_at
    netflow_analyzer_decode_packet_from_addr_at
)

# Public `netflow_analyzer_*` symbols this crate exports as global text (`T`),
# deduplicated. Archive member header lines have no `$2`, so the type filter
# skips them. The `netflow_analyzer_` prefix scopes the check to our public API
# and ignores unrelated symbols the staticlib may carry.
mapfile -t exported < <(
    nm --defined-only "$lib" 2>/dev/null \
        | awk '$2 == "T" && $3 ~ /^netflow_analyzer_/ { print $3 }' \
        | sort -u
)

# Compare in BOTH directions so the exported set is exactly the expected set:
# a missing symbol means an entry point was dropped/renamed or lost its
# `#[no_mangle]`; an extra symbol means an unintended public symbol slipped in.
mapfile -t expected_sorted < <(printf '%s\n' "${expected[@]}" | sort -u)

missing="$(comm -23 <(printf '%s\n' "${expected_sorted[@]}") <(printf '%s\n' "${exported[@]}"))"
extra="$(comm -13 <(printf '%s\n' "${expected_sorted[@]}") <(printf '%s\n' "${exported[@]}"))"

status=0
if [ -n "$missing" ]; then
    echo "check_symbols: FAILED - missing exported symbols:" >&2
    printf '  %s\n' $missing >&2
    status=1
fi
if [ -n "$extra" ]; then
    echo "check_symbols: FAILED - unexpected exported symbols:" >&2
    printf '  %s\n' $extra >&2
    status=1
fi
if [ "$status" -ne 0 ]; then
    exit 1
fi

echo "check_symbols: exported symbols exactly match the ${#expected_sorted[@]} expected"
