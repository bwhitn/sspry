#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

# These terms are intentionally narrow: they catch stale source-id naming
# without rejecting legitimate hash concepts such as YARA hash.*, SHA-256 file
# digests, or Bloom hash counts.
patterns=(
  'sha256_by_docid'
  'sha_by_docid'
  'ordered_hashes'
  'hash_chunk'
  'candidate hashes'
  'candidate hash'
  'tree-search-workers'
  'tree_search_workers'
  'source-dedup-min-new-docs'
  'batch-size'
  'rule-manifest'
  'RULE_MANIFEST'
  'LegacyStoreMeta'
  '\blegacy\b'
  'retired workspace work'
  'legacy filename'
  'internal store key stays fixed-width'
  'fixed-width identity layout'
  '\bsha_bytes\b'
  '\bsha_path\b'
  'identity_seed_hashes'
  'seed_hashes'
)

status=0
for pattern in "${patterns[@]}"; do
  if rg -n \
    --glob '*.rs' \
    --glob '*.md' \
    --glob '*.proto' \
    --glob '*.svg' \
    --glob '*.sh' \
    --glob '!scripts/naming_audit.sh' \
    "$pattern" src tests docs proto scripts README.md CMD.md
  then
    echo "naming audit: stale terminology matched pattern: $pattern" >&2
    status=1
  fi
done

if [[ $status -ne 0 ]]; then
  cat >&2 <<'MSG'

Naming audit failed. Use source-id / identity terminology for document identity
values. Reserve hash terminology for actual hash algorithms, YARA hash module
conditions, and Bloom hash counts.
MSG
fi

exit "$status"
