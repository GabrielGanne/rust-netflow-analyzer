#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
cargo_bin_dir="$cargo_home/bin"
if [[ -d "$cargo_bin_dir" && ":$PATH:" != *":$cargo_bin_dir:"* ]]; then
    PATH="$cargo_bin_dir:$PATH"
    export PATH
fi

for tool in cargo-audit cargo-deny; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is required; install it with: cargo install --locked $tool" >&2
        exit 127
    fi
done

# The fuzz harness has its own manifest and lockfile, so neither graph may be
# omitted from repository-level dependency and policy checks.
cargo audit
cargo audit --no-fetch --file fuzz/Cargo.lock
cargo deny --locked check
cargo deny --locked --manifest-path fuzz/Cargo.toml --config deny.toml check
