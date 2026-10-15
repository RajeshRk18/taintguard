#!/usr/bin/env bash
# One command path for local runs and CI. Usage: scripts/harness-check.sh [quick|ci-linux|ci-macos]
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-quick}" in
quick)
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings
  cargo test
  ;;
ci-linux | ci-macos)
  cargo fmt --check
  cargo clippy --all-targets --locked -- -D warnings
  cargo test --locked
  cargo build --release --locked
  ;;
*)
  echo "usage: $0 [quick|ci-linux|ci-macos]" >&2
  exit 2
  ;;
esac
