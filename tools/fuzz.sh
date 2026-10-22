#!/usr/bin/env bash
# Runs every fuzz target for a bounded time. Optional: needs cargo-fuzz and
# the nightly toolchain pinned in fuzz/rust-toolchain.toml.
#
# Usage: tools/fuzz.sh [seconds-per-target] [target...]
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/fuzz"

seconds="${1:-60}"
shift || true
if [ "$#" -eq 0 ]; then
    mapfile -t targets < <(cargo fuzz list)
else
    targets=("$@")
fi

for target in "${targets[@]}"; do
    # New inputs go to the ignored corpus/; the checked-in seeds/ stay read-only.
    mkdir -p "corpus/$target"
    cargo fuzz run "$target" "corpus/$target" "seeds/$target" -- \
        -max_total_time="$seconds" -rss_limit_mb=2048
done
