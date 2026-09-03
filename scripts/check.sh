#!/usr/bin/env bash
# Quality gates. Run before every commit and before every milestone is declared
# done. Mirrors what CI runs.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== rustfmt =="
cargo fmt --all -- --check

echo "== check (workspace, all targets) =="
cargo check --workspace --all-targets

echo "== clippy (workspace, all targets, warnings denied) =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests =="
cargo test --workspace --all-features

echo
echo "All quality gates passed."

