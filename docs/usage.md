# Usage

## Overview

`yaya` has one public workflow:

1. `serve` starts the TCP server and initializes the store if needed.
2. `index` scans files and submits batched inserts.
3. `search` runs YARA-style queries against the candidate store.
4. `delete` tombstones documents.
5. `info` returns JSON server/store state.
6. `shutdown` requests graceful server drain and shutdown.
7. `yara` runs a direct one-off local YARA check.

## Global Options

Top-level:

- `--perf-report <path>`: write a JSON perf report
- `--perf-stdout`: print the perf report to stdout on exit

## serve

```bash
./target/release/yaya serve [options]
```

Options:

- `--addr <host:port>`
  - TCP bind address
  - env: `YAYA_ADDR`
- `--max-request-bytes <bytes>`
  - hard request-size cap
- `--search-workers <n>`
  - server-side shard search concurrency
- `--root <path>`
  - store root directory
- `--shards <n>`
  - fixed hash shard count
- `--set-fp <p>`
  - bloom target false-positive rate
- `--id-source <sha256|md5|sha1|sha512>`
  - DB-wide identity mode
- `--store-path`
  - store canonical path as `external_id`
- `--gram-sizes <tier2,tier1>`
  - DB-wide gram-size pair

Example:

```bash
./target/release/yaya serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db \
  --shards 256 \
  --set-fp 0.35 \
  --id-source sha256 \
  --gram-sizes 3,4 \
  --store-path
```

## index

```bash
./target/release/yaya index [options] <paths>...
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--batch-size <n>`
  - documents per `insert_batch` request
- `--workers <n>`
  - client-side file scan / feature extraction workers

Notes:

- Identity type is decided by the server's `--id-source`.
- `index` can take files and directories.
- Large remote batches are automatically split by serialized request size.

## delete

```bash
./target/release/yaya delete [options] <values>...
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`

Values can be:

- an existing file path
- a digest string matching the server's configured `--id-source`

If a provided value does not match the server identity format, `delete` returns an error.

## search

```bash
./target/release/yaya search [options] --rule <rule.yar>
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--rule <path>`
- `--max-anchors-per-pattern <n>`
- `--max-candidates <n>` default `15000`; `0` means unlimited
- `--verify`

Behavior:

- default search is unverified
- `--verify` reopens candidate file paths and runs local YARA verification
- verified search requires stored file paths to still exist on disk

## info

```bash
./target/release/yaya info [options]
```

Returns JSON describing:

- identity mode
- gram sizes
- shard count
- search worker count
- drain state and active connections
- bloom policy
- document counts and filter-bucket counts
- startup cleanup counts for abandoned compaction roots
- compaction generation / retired generation counts
- current compaction runtime counters and reclaimed bytes

## shutdown

```bash
./target/release/yaya shutdown [options]
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`

Behavior:

- requests graceful remote shutdown
- server stops accepting new connections
- new mutating RPCs are rejected during drain
- in-flight searches are allowed to finish
- current drain progress is printed on the server side

## yara

```bash
./target/release/yaya yara --rule ./rule.yar <file>
```

This bypasses the database and scans one file directly.

## Environment

- `YAYA_ADDR`
  - default server/client address for `serve`, `index`, `delete`, `search`, and `info`

## Operational Guidance

- Keep `--store-path` enabled if verified search matters.
- Treat `--gram-sizes` as a format choice, not a casual runtime knob.
- Use `--set-fp` to control the disk-size vs candidate-quality tradeoff.
- Use `--search-workers` to control server search parallelism.
- Expect delete to be immediate logically but reclaimed physically later by shard-local compaction.
- `SIGINT` and `SIGTERM` trigger graceful drain and shutdown.
- `SIGUSR1` prints a live `info` snapshot to `stderr`.
