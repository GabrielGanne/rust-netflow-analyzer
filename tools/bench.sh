#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo="${CARGO:-cargo}"
env_dir="${NETFLOW_ANALYZER_BENCH_ENV_DIR:-$repo_root/target/criterion/environment}"
env_file="$env_dir/$(date -u +%Y%m%dT%H%M%SZ).txt"

# Results are only comparable on a like-for-like machine and build, so record
# what produced them next to Criterion's own output.
mkdir -p "$env_dir"
{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "args: $*"
    echo "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "dirty: $(if git diff --quiet HEAD 2>/dev/null; then echo no; else echo yes; fi)"
    echo "kernel: $(uname -srm)"
    echo "cpu: $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -n1)"
    echo "cpus: $(getconf _NPROCESSORS_ONLN)"
    echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
    echo "RUSTFLAGS: ${RUSTFLAGS:-}"
    "$cargo" --version
    rustc -vV
} > "$env_file"
echo "bench: environment recorded in $env_file" >&2

exec "$cargo" bench --locked -p netflow_analyzer_core --bench process_packet -- "$@"
