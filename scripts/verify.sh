#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "fmt check"
cargo fmt --check

echo "test"
cargo test

echo "linux release build"
cargo build --release
