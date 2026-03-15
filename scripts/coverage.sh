#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COVERAGE_DIR="$ROOT_DIR/coverage"
IGNORE_REGEX='(^|.*/)(usr/src/rustc[^/]*|rustc)/|(^|.*/)\.cargo/registry/|(^|.*/)registry/src/index\.crates\.io-|(^|.*/)opt/cargo-[^/]+/registry/|(^|.*/)target/llvm-cov-target/|(^|.*/)coverage/target/|(^|.*/)debug/build/'

LLVM_COV_DIR=${LLVM_COV_DIR:-}
if [[ -z "$LLVM_COV_DIR" ]]; then
  if command -v cargo-llvm-cov >/dev/null 2>&1; then
    LLVM_COV_DIR=$(dirname "$(command -v cargo-llvm-cov)")
  elif [[ -x "$HOME/.cargo/bin/cargo-llvm-cov" ]]; then
    LLVM_COV_DIR="$HOME/.cargo/bin"
  fi
fi

if [[ -z "$LLVM_COV_DIR" ]]; then
  cat >&2 <<'MSG'
cargo-llvm-cov is required.
Install it with:
  cargo install cargo-llvm-cov
  rustup component add llvm-tools-preview

If this toolchain is not managed by rustup, install LLVM from the system
package manager instead and make sure `llvm-cov` / `llvm-profdata` are on PATH.
MSG
  exit 1
fi

mkdir -p "$COVERAGE_DIR"
cd "$ROOT_DIR"
export PATH="$LLVM_COV_DIR:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$COVERAGE_DIR/target}"

cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --all-features --tests --no-report
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --html --output-dir "$COVERAGE_DIR"
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --lcov --output-path "$COVERAGE_DIR/lcov.info"
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --summary-only | tee "$COVERAGE_DIR/summary.txt"

echo
echo "Coverage artifacts:"
echo "  HTML:  $COVERAGE_DIR/html/index.html"
echo "  LCOV:  $COVERAGE_DIR/lcov.info"
echo "  Text:  $COVERAGE_DIR/summary.txt"
echo "  Target: $CARGO_TARGET_DIR"
echo "  Scope: repo-focused (dependency registry paths ignored)"
