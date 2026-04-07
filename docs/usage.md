# Usage

## Overview

`sspry` has three main operating styles:

1. Legacy RPC mode:
   - `serve` starts a long-lived TCP server.
   - `index`, `delete`, `search`, `info`, and `shutdown` talk to that server.
2. gRPC prototype mode:
   - `grpc-serve` starts a long-lived TCP gRPC server.
   - `grpc-index`, `grpc-delete`, `grpc-search`, `grpc-info`, and `grpc-shutdown` talk to that server.
3. Local/direct mode:
   - `local-index` writes directly to a local store root and auto-initializes it if needed.
   - `local-delete` operates directly on a local store.
   - `local-info` reports direct local store stats and can also aggregate a forest root.
   - `local-search` and `search-batch` open a forest locally in-process.

`yara` is separate from both of those paths. It scans a single file directly with `yara-x` and does not use the database.

## Global Options

Top-level:

- `--perf-report <path>`: write a JSON perf report
- `--perf-stdout`: print the perf report to stdout on exit

## local-index

```bash
./target/release/sspry local-index [options] --root <path> <paths>...
```

Options:

- `--root <path>`
  - direct local store root
- `--candidate-shards <n>`
  - shard count to create when initializing a new local store
- `--force`
  - reinitialize an existing local store before indexing
- `--tier1-set-fp <p>`
  - Tier1 false-positive rate for a newly created local store
- `--tier2-set-fp <p>`
  - Tier2 false-positive rate for a newly created local store
- `--gram-sizes <tier1,tier2>`
  - DB-wide gram-size pair for a newly created local store
- `--compaction-idle-cooldown-s <seconds>`
  - minimum idle time before shard-local compaction is allowed to run for a newly created local store
- `--path-list`
- `--batch-size <n>`
- `--workers <n>`
- `--verbose`

Use `local-index` when you want direct local ingest without a running server.

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
  - server-side tree query workers per search
  - a forest search runs across at most this many trees at once
- `--root <path>`
  - root path to open
  - auto-detected as one of:
    - mutable workspace root
    - direct published store root
    - forest root containing `tree_*/current`
  - forest-root servers are read-only and intended for search/info
- `--layout-profile <standard|incremental>`
  - shard-layout preset
  - `standard` defaults to 256 shards
  - `incremental` defaults to 32 shards
- `--shards <n>`
  - explicit shard count override
- `--tier1-set-fp <p>`
  - Tier1 false-positive rate override
- `--tier2-set-fp <p>`
  - Tier2 false-positive rate override
- `--id-source <sha256|md5|sha1|sha512>`
  - DB-wide identity mode
- `--store-path`
  - store canonical path as `external_id`
- `--gram-sizes <tier1,tier2>`
  - DB-wide gram-size pair

Example:

```bash
./target/release/sspry serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db \
  --shards 8 \
  --tier1-set-fp 0.35 \
  --tier2-set-fp 0.35 \
  --id-source sha256 \
  --gram-sizes 3,4 \
  --store-path
```

Behavior:

- mutable workspace/direct-store roots support ingest, delete, publish, and search
- forest-root servers open all published `tree_*/current` stores once and answer search/info requests across the forest
- forest-root servers are read-only; use them for persistent RPC search over a finished forest, not for remote ingest
- workspace mode keeps shared policy in root-level `meta.json`
- shard-local state stays in each shard's `store_meta.json`
- `current/` is always present in a workspace; `work_a/` and `work_b/` are created lazily only when publish/indexing needs them

## grpc-serve

```bash
./target/release/sspry grpc-serve [options]
```

Options:

- `--addr <host:port>`
  - TCP bind address
  - env: `SSPRY_ADDR`
- `--grpc-max-message-bytes <bytes>`
  - hard gRPC message-size cap
- `--search-workers <n>`
  - server-side tree query workers per search
  - a forest search runs across at most this many trees at once
- `--root <path>`
  - same root semantics as `serve`
- `--layout-profile <standard|incremental>`
- `--shards <n>`
- `--tier1-set-fp <p>`
- `--tier2-set-fp <p>`
- `--id-source <sha256|md5|sha1|sha512>`
- `--store-path`
- `--gram-sizes <tier1,tier2>`

Behavior:

- `grpc-serve` uses the same DB/workspace initialization rules as `serve`
- gRPC ingest streams documents incrementally; the message cap is per gRPC message, not a whole-document cap
- per-frame gRPC insert chunking is controlled on the client side by `grpc-index --grpc-insert-chunk-bytes`

## index

```bash
./target/release/sspry index [options] <paths>...
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--path-list`
  - treat each input path as a newline-delimited manifest of file paths
- `--batch-size <n>`
  - documents per `insert_batch` request
- `--remote-batch-soft-limit-bytes <bytes>`
  - client-side soft payload cap for remote batches
- `--workers <n>`
  - client-side file scan / feature extraction workers
- `--verbose`
  - print timing details to stderr

Notes:

- identity type is decided by the server or store's `--id-source`
- `index` can take files and directories
- large remote batches are automatically split by serialized request size
- use `local-index` for direct local ingest without RPC

## grpc-index

```bash
./target/release/sspry grpc-index [options] <paths>...
```

Options:

- same ingest options as `index`
- `--grpc-max-message-bytes <bytes>`
  - gRPC client message-size cap
- `--grpc-insert-chunk-bytes <bytes>`
  - per-frame gRPC insert chunk size

Notes:

- `grpc-index` streams row-framed inserts over gRPC instead of using the legacy request-sized RPC batching model

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

For mutable workspaces, `delete` only targets the published `current/` store set.

- if the value exists only in `work_a/` or `work_b/`, the result is `missing`
- `missing` is a normal outcome for multi-server delete fanout where only some servers actually contain the document
- physical reclaim happens later through shard-local compaction of `current/`

## local-delete

```bash
./target/release/sspry local-delete [options] --root <path> <values>...
```

Options:

- `--root <path>`
  - direct local store root

Values can be:

- an existing file path
- a digest string matching the store's configured identity format

## search

```bash
./target/release/sspry search [options] --rule <rule.yar>
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--rule <path>`
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `7.5`; `0` means unlimited
  - percentage of searchable documents
- `--verify`
- `--verbose`

Behavior:

- default search is unverified candidate retrieval
- `--verify` reopens candidate file paths and runs local `yara-x` verification
- `search --addr` uses a persistent RPC server over either a direct store/workspace or a forest-root server
- remote `search --addr` streams candidate pages from the server and the client deduplicates across the forest before applying the final cap
- if the candidate cap is reached, output includes `truncated: true` and `truncated_limit: <n>`
- verified search requires stored file paths to still exist on disk
- candidate order is not guaranteed; search returns an unordered match set

## local-search

```bash
./target/release/sspry local-search [options] --root <root> --rule <rule.yar>
```

Options:

- `--root <path>`
  - in-process forest search root
- `--rule <path>`
- `--tree-search-workers <n>`
  - forest-level tree concurrency
  - `0` means auto up to the tree count
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `7.5`; `0` means unlimited
  - percentage of searchable documents
- `--verify`
- `--verbose`

Behavior:

- `local-search` opens `tree_*/current` directly and searches the forest in-process
- `--tree-search-workers` only applies to `local-search`

Indexed search currently supports these searchable categories:

- literal string anchors and hex-string anchors
- regex strings only when they still contain a searchable mandatory literal
- `filesize` comparisons:
  - `==`, `!=`, `<`, `<=`, `>`, `>=`
- whole-file identity lookups:
  - `hash.sha256(0, filesize) == <digest>`
  - `hash.md5(0, filesize) == <digest>`
  - `hash.sha1(0, filesize) == <digest>`
  - `hash.sha512(0, filesize) == <digest>`
  - these only become direct indexed lookups when the store's `--id-source` matches the hash kind
- boolean metadata with `==` / `!=`:
  - `crx.is_crx`
  - `pe.is_pe`
  - `pe.is_32bit`
  - `pe.is_64bit`
  - `pe.is_dll`
  - `pe.is_signed`
  - `elf.is_elf`
  - `dotnet.is_dotnet`
  - `dex.is_dex`
  - `lnk.is_lnk`
- integer metadata with `==`, `!=`, `<`, `<=`, `>`, `>=`:
  - `pe.machine`
  - `pe.subsystem`
  - `pe.timestamp`
  - `pe.characteristics`
  - `elf.type`
  - `elf.os_abi`
  - `elf.machine`
  - `macho.cpu_type`
  - `macho.cpu_subtype`
  - `macho.file_type`
  - `dex.version`
  - `lnk.creation_time`
  - `lnk.access_time`
  - `lnk.write_time`
- whole-file entropy comparisons:
  - `math.entropy(0, filesize) == <number>`
  - `!=`, `<`, `<=`, `>`, `>=` are also supported
- `time.now` comparisons:
  - `==`, `!=`, `<`, `<=`, `>`, `>=`
- integer metadata compared against:
  - `time.now`
  - another stored integer metadata field

Numeric read equality is also accepted for literal `==` comparisons over the built-in `int*`, `uint*`, and `float*` readers. Current caveats:

- these predicates are still verifier-only semantically
- some offset-`0` cases can be screened from stored first-byte metadata before verification:
  - exact fixed-literal `$str at 0`
  - some offset-`0` numeric read equalities
- numeric equality only supports literal constants, not expressions such as `uint32(0) == filesize`
- without `--verify`, candidate results may still include extra false positives

Indexed search also fails fast on some rule shapes that are structurally unsafe for scalable search:

- high-fanout unions with no mandatory anchorable pattern
- low-information `at pe.entry_point` style stub rules that only contribute tiny generic gram anchors
- short suffix/range rules where only tiny literals gate `in (filesize-N..filesize)` checks

These fail-fast cases are intentional:

- they preserve recall
- they prevent large-corpus near-full scans from being treated as good searchable rules
- the fix is usually to add a stronger mandatory anchor or split the rule into narrower pieces

`--verbose` search output includes per-rule runtime and prepared-query profiling fields such as:

- `query_ms`
- `docs_scanned`
- `candidates`
- `prepared_query_bytes`
- `prepared_mask_cache_bytes`
- `prepared_any_lane_variant_sets`
- `prepared_compacted_any_lane_grams`
- `client_current_rss_kb`
- `client_peak_rss_kb`
- `tree_count`
- `tree_search_workers`

Practical note:

- for repeated rule-by-rule tuning on a preserved DB, `--addr` against a persistent server is usually faster than calling `local-search` once per rule
- `local-search` is the right path for local forest correctness checks and tree-level threaded-search experiments

## search-batch

```bash
./target/release/sspry search-batch [options] --root <root> --json-out <results.json>
```

Options:

- `--root <path>`
  - required forest root
- `--rules-dir <path>`
  - directory of `.yar` files in sorted filename order
- `--rule-manifest <path>`
  - newline-delimited rule path list
- `--json-out <path>`
  - required output JSON path
- `--tree-search-workers <n>`
  - forest-level tree concurrency
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `7.5`
  - percentage of searchable documents
- `--verify`

Behavior:

- opens the forest once and reuses it across the whole rule sweep
- intended for repeated benchmark and profiling passes on a preserved forest
- this is the direct-forest alternative to the persistent RPC server path when you want tree-level threaded search without per-rule reopen overhead

## info

```bash
./target/release/sspry info [options]
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--light`
  - return lightweight server status without walking shard stats
  - includes adaptive publish state and background tier2 snapshot-seal state

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

## local-info

```bash
./target/release/sspry local-info --root <path>
```

Returns JSON describing a direct local store, or aggregated stats for a local forest root.

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
./target/release/sspry yara [options] --rule ./rule.yar <file>
```

Options:

- `--rule <path>`
- `--scan-timeout <seconds>`
- `--show-tags`

This bypasses the database and scans one file directly with `yara-x`.

## Environment

- `SSPRY_ADDR`
  - default server/client address for `serve`, `index`, `delete`, `search`, `info`, and `shutdown`

## Operational Guidance

- keep `--store-path` enabled if verified search matters
- treat `--gram-sizes` as a format choice, not a casual runtime knob
- use `--tier1-set-fp` and `--tier2-set-fp` to control the disk-size vs candidate-quality tradeoff
- use `--layout-profile incremental` or a small explicit `--shards` count when you want lower publish and open fanout on smaller alpha-scale trees
- use `--search-workers` to control how many trees a forest server searches at once per query
- for repeated search tuning, prefer reusing an existing published DB instead of rebuilding it for every planner change
- expect delete to be immediate logically in `current/`, return `missing` when the value is not present there, and be reclaimed physically later by shard-local compaction of `current/`
- `SIGINT` and `SIGTERM` trigger graceful drain and shutdown
- `SIGUSR1` prints a live `info` snapshot to `stderr`
