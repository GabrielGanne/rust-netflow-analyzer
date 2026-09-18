#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo="${CARGO:-cargo}"

exec "$cargo" bench --locked -p netflow_analyzer_core --bench process_packet -- "$@"
