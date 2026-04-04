# Usage

## Overview

`sspry` has two main operating styles:

1. RPC mode:
   - `serve` starts a long-lived TCP server.
   - `index`, `delete`, `search`, `info`, and `shutdown` talk to that server.
2. Local/direct mode:
   - `init` prepares a direct store root.
   - `index --root ...` writes directly to that store without RPC.
   - `search --root ...` and `search-batch --root ...` open a forest locally in-process.

`yara` is separate from both of those paths. It scans a single file directly with `yara-x` and does not use the database.

## Global Options

Top-level:

- `--perf-report <path>`: write a JSON perf report
- `--perf-stdout`: print the perf report to stdout on exit

## init

```bash
./target/release/sspry init [options]
```

Options:

- `--root <path>`
  - direct store root to initialize
- `--candidate-shards <n>`
  - shard count to create
- `--force`
  - overwrite an existing store root
- `--set-fp <p>`
  - fallback false-positive rate applied to both bloom tiers
- `--tier1-set-fp <p>`
  - Tier1 false-positive rate override
- `--tier2-set-fp <p>`
  - Tier2 false-positive rate override
- `--gram-sizes <tier1,tier2>`
  - DB-wide gram-size pair
- `--compaction-idle-cooldown-s <seconds>`
  - minimum idle time before shard-local compaction is allowed to run

Use `init` when you want a direct local store for `index --root ...` instead of the normal RPC workspace flow.

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
- `--memory-budget-gb <n>`
  - configured indexing memory budget used for backpressure decisions
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
- `--set-fp <p>`
  - fallback bloom false-positive rate
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
  --set-fp 0.35 \
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

## index

```bash
./target/release/sspry index [options] <paths>...
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--root <path>`
  - direct local indexing root
  - bypasses RPC and writes directly to an initialized store
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
- `index --root ...` expects a direct store created with `init`

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
- `--root <path>`
  - in-process forest search root
  - opens `tree_*/current` directly instead of using RPC
- `--timeout <seconds>`
- `--rule <path>`
- `--tree-search-workers <n>`
  - forest-level tree concurrency for `--root`
  - `0` means auto up to the tree count
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `7.5`; `0` means unlimited
  - percentage of searchable documents
- `--verify`
- `--verbose`

Behavior:

- default search is unverified candidate retrieval
- `--verify` reopens candidate file paths and runs local `yara-x` verification
- `--addr` and `--root` are the two search transports:
  - `--addr` uses a persistent RPC server over either a direct store/workspace or a forest-root server
  - `--root` opens the forest locally in-process
- `--tree-search-workers` only affects `--root`
- remote `search --addr` streams candidate pages from the server and the client deduplicates across the forest before applying the final cap
- if the candidate cap is reached, output includes `truncated: true` and `truncated_limit: <n>`
- verified search requires stored file paths to still exist on disk
- candidate order is not guaranteed; search returns an unordered match set

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

- for repeated rule-by-rule tuning on a preserved DB, `--addr` against a persistent server is usually faster than calling `search --root` once per rule
- `search --root` is the right path for local forest correctness checks and tree-level threaded-search experiments

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
- use `--set-fp`, `--tier1-set-fp`, and `--tier2-set-fp` to control the disk-size vs candidate-quality tradeoff
- use `--layout-profile incremental` or a small explicit `--shards` count when you want lower publish and open fanout on smaller alpha-scale trees
- use `--search-workers` to control how many trees a forest server searches at once per query
- for repeated search tuning, prefer reusing an existing published DB instead of rebuilding it for every planner change
- expect delete to be immediate logically but reclaimed physically later by shard-local compaction
- `SIGINT` and `SIGTERM` trigger graceful drain and shutdown
- `SIGUSR1` prints a live `info` snapshot to `stderr`
