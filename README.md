# Scalable Screening and Prefiltering of Rules for YARA

`sspry` is the command-line binary and crate name.

A mutable file search database with fast candidate retrieval and optional YARA verification.

## What It Is

`sspry` runs as a TCP server, indexes files into a mutable search store, and answers YARA-style searches by combining:

- per-document Tier1 bloom filters
- per-document Tier2 bloom filters
- per-superblock Tier2 summaries
- optional local YARA verification over stored file paths
- shard-local background compaction with deferred physical reclaim

The current search planner is intentionally conservative about recall:

- if a rule has a safe searchable anchor, `sspry` uses it and verifies the rest later
- if a rule is structurally too broad to search safely at scale, `sspry` now returns an explicit planner error instead of pretending it is scaling-safe

The current public CLI is intentionally small:

- `serve`
- `index`
- `delete`
- `search`
- `info`
- `shutdown`
- `yara`

`search` now supports two execution paths:

- RPC search against a running `serve` process via `--addr`
- in-process forest search via `--root`, which opens `tree_*/current` stores directly and can search trees concurrently with `--tree-search-workers`

## Quick Links

- [Quickstart](docs/quickstart.md)
- [Usage](docs/usage.md)
- [Implementation](docs/implementation.md)

## Build

```bash
cargo build
cargo build --release
```

## Test

```bash
cargo test --workspace --all-targets
```

## Coverage

If `cargo-llvm-cov` is installed:

```bash
./scripts/coverage.sh
```

## Notes

- The workspace layout is `current/`, `work_a/`, `work_b/`, and `retired/`.
- The default ingest/search path is bloom-only; the retired exact-gram / DF path has been removed from the normal runtime.
- Search can return candidate digests directly or optionally verify matches locally with `yara-x` when stored paths are available.
- `search --root <forest_root>` is the direct forest path for tree-level threaded search experiments and one-off local queries.
- For large repeated tuning sweeps, the persistent server path is still usually faster than invoking `search --root` once per rule, because the direct local path reopens the forest each time.
- Search now rejects two important non-scaling-safe rule shapes:
  - high-fanout unions with no mandatory anchorable pattern
  - low-information `at pe.entry_point` style stub rules that only contribute tiny generic gram anchors
  - short suffix/range rules where only tiny literals gate `in (filesize-N..filesize)` checks
