# Scalable Screening and Prefiltering of Rules for YARA

`sspry` is the command-line binary and crate name.

A mutable file search database with fast candidate retrieval and optional YARA verification.

## What It Is

`sspry` runs as a TCP server, indexes files into a mutable search store, and answers YARA-style searches by combining:

- exact Tier1 gram postings
- per-document Tier2 bloom filters
- optional local YARA verification over stored file paths
- shard-local background compaction with deferred physical reclaim

The current public CLI is intentionally small:

- `serve`
- `index`
- `delete`
- `search`
- `info`
- `shutdown`
- `yara`

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
cargo test
```

Coverage:

```bash
scripts/coverage.sh
```

Current target:

- line coverage: `95%+`

## Fast Start

Start the server:

```bash
cargo run -- serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db
```

Ingest files or directories:

```bash
cargo run -- index --addr 127.0.0.1:17653 ./samples ./more-samples
```

Inspect server/store state:

```bash
cargo run -- info --addr 127.0.0.1:17653
```

Request graceful shutdown:

```bash
cargo run -- shutdown --addr 127.0.0.1:17653
```

Run a verified search:

```bash
cargo run -- search \
  --addr 127.0.0.1:17653 \
  --rule ./rule.yar \
  --verify
```

Delete by digest or by file path:

```bash
cargo run -- delete --addr 127.0.0.1:17653 <digest-or-file-path>
```

## Current Defaults

Server defaults:

- addr: `127.0.0.1:17653`
- root: `candidate_db`
- shards: `256`
- set-fp: `0.35`
- id-source: `sha256`
- gram-sizes: `3,4`
- search-workers: `max(1, cpus/4)`

Search defaults:

- verification: off by default; enable with `--verify`
- max candidates: `15000` (`0` means unlimited)
- max anchors per pattern: `16`

## Notes

- `--store-path` is a server policy. If enabled on `serve`, ingested documents store the canonical file path as `external_id` for later verification and reporting.
- `--id-source` is also server policy. Clients do not choose identity type.
- `--gram-sizes` is a DB-wide format decision. Supported pairs are `3,4`, `4,5`, `5,6`, and `7,8`.
- `search` without `--verify` returns candidate hashes. `search --verify` reopens candidate files and prints verified matches.
- deletes are immediate logically and reclaimed physically later by shard-local compaction
- compaction runs one shard at a time and swaps the rebuilt shard in at the end
- `SIGINT` and `SIGTERM` trigger graceful drain and shutdown.
- `SIGUSR1` prints a live `info` snapshot to `stderr`.
- `shutdown` is the explicit client/admin command for graceful remote shutdown.
