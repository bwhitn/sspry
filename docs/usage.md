# Usage

## Overview

`sspry` has one public workflow:

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
./target/release/sspry serve [options]
```

Options:

- `--addr <host:port>`
  - TCP bind address
  - env: `SSPRY_ADDR`
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
./target/release/sspry serve \
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
./target/release/sspry index [options] <paths>...
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
./target/release/sspry delete [options] <values>...
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
./target/release/sspry search [options] --rule <rule.yar>
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
- indexed search currently supports:
  - literal string anchors with:
    - `ascii`
    - `wide`
  - hex-string anchors
  - `filesize == <const>`
  - exact equality on stored module/runtime metadata:
    - `crx.is_crx`
    - `pe.is_pe`
    - `pe.is_32bit`
    - `pe.is_64bit`
    - `pe.is_dll`
    - `pe.is_signed`
    - `pe.machine`
    - `pe.subsystem`
    - `pe.timestamp`
    - `elf.type`
    - `elf.os_abi`
    - `elf.machine`
    - `macho.cpu_type`
    - `macho.device_type`
    - `dotnet.is_dotnet`
    - `dex.is_dex`
    - `dex.version`
    - `lnk.is_lnk`
    - `lnk.creation_time`
    - `lnk.access_time`
    - `lnk.write_time`
    - `time.now == <const>`
- numeric read equality is accepted in indexed search for literal `==` comparisons:
  - `int32(<offset>)`
  - `uint32(<offset>)`
  - `int32be(<offset>)`
  - `uint32be(<offset>)`
  - `float32(<offset>)`
  - `float64(<offset>)`
  - `float32be(<offset>)`
  - `float64be(<offset>)`
- numeric-read caveats:
  - the numeric predicate is verifier-only in this first phase
  - its literal bytes can contribute anchors when the current gram sizes can represent them
  - if the current gram sizes are larger than the literal width, the rule still needs another string/hex anchor
  - numeric equality only supports literal constants, not expressions such as `uint32(0) == filesize`
  - without `--verify`, candidate results may still include extra false positives

## info

```bash
./target/release/sspry info [options]
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--light`
  - return lightweight server status without walking shard stats
  - includes adaptive publish state and background seal queue state

Returns JSON describing:

- identity mode
- gram sizes
- shard count
- search worker count
- drain state and active connections
- bloom policy
- adaptive publish state
- document counts and filter-bucket counts
- startup cleanup counts for abandoned compaction roots
- compaction generation / retired generation counts
- current compaction runtime counters and reclaimed bytes

## shutdown

```bash
./target/release/sspry shutdown [options]
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
./target/release/sspry yara --rule ./rule.yar <file>
```

This bypasses the database and scans one file directly.

## Environment

- `SSPRY_ADDR`
  - default server/client address for `serve`, `index`, `delete`, `search`, and `info`

## Operational Guidance

- Keep `--store-path` enabled if verified search matters.
- Treat `--gram-sizes` as a format choice, not a casual runtime knob.
- Use `--set-fp` to control the disk-size vs candidate-quality tradeoff.
- Use `--search-workers` to control server search parallelism.
- Expect delete to be immediate logically but reclaimed physically later by shard-local compaction.
- `SIGINT` and `SIGTERM` trigger graceful drain and shutdown.
- `SIGUSR1` prints a live `info` snapshot to `stderr`.
