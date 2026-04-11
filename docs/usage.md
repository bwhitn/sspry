# Usage

## Overview

`sspry` has three operating styles:

1. Remote/server mode:
   - `serve` starts the long-lived remote server.
   - `index`, `delete`, `search`, `info`, and `shutdown` talk to that server over gRPC.
   - `rule-check` can pull the active scan policy from a live server with `--addr`.
2. Local/direct mode:
   - `local-index` writes directly to a local store root and auto-initializes it if needed.
   - `local-delete` operates directly on a local store.
   - `local-info` reports direct local store stats and can also aggregate a forest root.
   - `local-search` and `search-batch` open a forest locally in-process.
3. Direct YARA scan mode:
   - `yara` scans one file directly with `yara-x` and does not use the database.
   - `rule-check` can also validate a rule offline with explicit `--id-source` / `--gram-sizes` or against a local root with `--root`.

## Global Options

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
- `--max-message-bytes <bytes>`
  - maximum accepted remote message size
  - applies per gRPC message, not per document
- `--search-workers <n>`
  - server-side tree query workers per search
  - one top-level search runs at a time; later searches queue
  - the active search fans out across at most this many trees concurrently
  - default is `max(1, cpus/4)`
- `--root <path>`
  - root path to open
  - auto-detected as one of:
    - mutable workspace root
    - direct published store root
    - forest root containing `tree_*/current`
  - forest-root servers are read-only and intended for search/info
- `--layout-profile <standard|incremental>`
  - shard-layout preset
  - `standard` defaults to 8 shards
  - `incremental` defaults to 8 shards
- `--shards <n>`
  - explicit shard count override for a new DB
  - both layout profiles currently default new DBs to `8` shards
- `--tier1-set-fp <p>`
  - Tier1 false-positive rate override for a new DB
- `--tier2-set-fp <p>`
  - Tier2 false-positive rate override for a new DB
- `--id-source <sha256|md5|sha1|sha512>`
  - DB-wide identity mode for a new DB
- `--store-path`
  - store canonical path as `external_id` for a new DB
- `--gram-sizes <tier1,tier2>`
  - DB-wide gram-size pair for a new DB
  - supported pairs: `3,4`, `4,5`, `5,6`, `7,8`

Behavior:

- mutable workspace/direct-store roots support ingest, delete, publish, and search
- forest-root servers open all published `tree_*/current` stores once and answer search/info requests across the forest
- forest-root servers are read-only; use them for persistent remote search over a finished forest, not for remote ingest
- if `serve` opens an existing DB, init-only flags are ignored and the on-disk policy wins
- if conflicting init-only flags are passed for an existing DB, startup warns and continues
- workspace mode keeps shared policy in root-level `meta.json`
- shard-local state stays in each shard's `store_meta.json`
- `current/` is always present in a workspace; `work_a/` and `work_b/` are created lazily when publish/indexing needs them

Example:

```bash
./target/release/sspry serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db \
  --shards 8 \
  --tier1-set-fp 0.39 \
  --tier2-set-fp 0.16 \
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
- `--max-message-bytes <bytes>`
  - client-side remote message cap
- `--path-list`
  - treat each input path as a newline-delimited manifest of file paths
- `--batch-size <n>`
  - documents per remote flush target
- `--remote-batch-soft-limit-bytes <bytes>`
  - client-side soft payload cap for buffered remote rows before flushing
- `--insert-chunk-bytes <bytes>`
  - per-frame remote insert chunk size
- `--workers <n>`
  - client-side file scan / feature extraction workers
- `--verbose`
  - print timing details to stderr

Notes:

- identity type is decided by the server DB's `--id-source`
- `index` can take files and directories
- remote ingest streams row-framed inserts incrementally over gRPC
- large documents are chunked across multiple frames; they are not treated as one capped request
- only one active indexing session is allowed per server at a time
- when the target server is running in workspace mode, `index` auto-publishes after ingest so newly indexed documents become searchable
- use `local-index` for direct local ingest without a running server

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
  - supported pairs: `3,4`, `4,5`, `5,6`, `7,8`
- `--compaction-idle-cooldown-s <seconds>`
  - minimum idle time before shard-local compaction is allowed to run for a newly created local store
- `--path-list`
- `--batch-size <n>`
- `--workers <n>`
- `--verbose`

Use `local-index` when you want direct local ingest without a running server.

## delete

```bash
./target/release/sspry delete [options] <values>...
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--max-message-bytes <bytes>`

Values can be:

- an existing file path
- a digest string matching the server's configured `--id-source`

Behavior:

- `delete` only targets the published `current/` store set
- if the value exists only in `work_a/` or `work_b/`, the result is `missing`
- `missing` is a normal outcome for multi-server delete fanout where only some servers actually contain the document
- logical delete is immediate for search against `current/`
- physical reclaim happens later through background compaction of `current/`

## local-delete

```bash
./target/release/sspry local-delete [options] --root <path> <values>...
```

Options:

- `--root <path>`

Values can be:

- an existing file path
- a digest string matching the store's configured identity format

## rule-check

```bash
./target/release/sspry rule-check [options] --rule <rule.yar>
```

Options:

- `--rule <path>`
- `--addr <host:port>`
  - use a live server's active scan policy
- `--timeout <seconds>`
  - only used with `--addr`
- `--max-message-bytes <bytes>`
  - only used with `--addr`
- `--root <path>`
  - use a local store or forest root's active scan policy
- `--id-source <sha256|md5|sha1|sha512>`
  - assumed identity source when neither `--addr` nor `--root` is used
- `--gram-sizes <tier1,tier2>`
  - assumed gram-size pair when neither `--addr` nor `--root` is used
- `--max-anchors-per-pattern <n>`
- `--json`

Behavior:

- classifies rules as:
  - `searchable`
  - `searchable-needs-verify`
  - `unsupported`
- reports hard planner failures directly, including policy mismatches such as whole-file hash equality against the wrong DB identity source
- warns when exact semantics require `search --verify`, including:
  - verifier-only offset/count/range/loop constraints
  - ignored indexed-search module predicates like `androguard.*`, `console.*`, and `cuckoo.*`
- `--addr` and `--root` use real DB policy instead of assumptions
- without `--json`, output is plain text intended for humans
- with `--json`, output includes the effective policy, issues, ignored module calls, and verifier-only node kinds

## search

```bash
./target/release/sspry search [options] --rule <rule.yar>
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--max-message-bytes <bytes>`
- `--rule <path>`
  - path to one top-level YARA file
  - normal YARA `include "..."` directives are expanded before search
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `10`; `0` means unlimited
  - percentage of searchable documents
- `--verify`
- `--verbose`

Behavior:

- the client sends validated YARA source to the server
- the server compiles and executes the search plan
- only one top-level search runs at a time per server; later searches queue
- candidate pages stream back to the client
- the client deduplicates across the forest before applying the final cap
- if the candidate cap is reached, output includes `truncated: true` and `truncated_limit: <n>`
- `--verify` reopens candidate file paths and runs local `yara-x` verification
- verified search requires stored file paths to still exist on disk
- candidate order is not guaranteed; search returns an unordered match set
- if the expanded source contains multiple searchable rules, stdout is grouped into one labeled block per rule identifier in source order
- the command exits nonzero if any rule in the expanded source fails to compile or execute

## local-search

```bash
./target/release/sspry local-search [options] --root <root> --rule <rule.yar>
```

Options:

- `--root <path>`
  - in-process forest search root
- `--rule <path>`
  - path to one top-level YARA file
  - normal YARA `include "..."` directives are expanded before search
- `--tree-search-workers <n>`
  - forest-level tree concurrency
  - `0` means auto up to the tree count
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `10`; `0` means unlimited
  - percentage of searchable documents
- `--verify`
- `--verbose`

Behavior:

- `local-search` opens `tree_*/current` directly and searches the forest in-process
- `--tree-search-workers` is the local forest concurrency knob shared by `local-search` and `search-batch`
- if the expanded source contains multiple searchable rules, stdout is grouped into one labeled block per rule identifier in source order
- the command exits nonzero if any rule in the expanded source fails to compile or execute

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
- integer metadata with `==`, `!=`, `<`, `<=`, `>`, `>=`
- whole-file entropy comparisons:
  - `math.entropy(0, filesize)` with `==`, `!=`, `<`, `<=`, `>`, `>=`
- `time.now` comparisons:
  - `==`, `!=`, `<`, `<=`, `>`, `>=`
- integer metadata compared against:
  - `time.now`
  - another stored integer metadata field

Numeric read equality is also accepted for literal `==` comparisons over the built-in `int*`, `uint*`, and `float*` readers. Current caveats:

- these predicates are still verifier-only semantically
- some offset-`0` cases can be screened from stored first-byte metadata before verification
- numeric equality only supports literal constants, not expressions such as `uint32(0) == filesize`
- without `--verify`, candidate results may still include extra false positives

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
  - `0` means auto up to the tree count
- `--max-anchors-per-pattern <n>`
- `--max-candidates <p>` default `10`
  - percentage of searchable documents
- `--verify`

Behavior:

- opens the forest once and reuses it across the whole rule sweep
- intended for repeated benchmark and profiling passes on a preserved forest

## info

```bash
./target/release/sspry info [options]
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--max-message-bytes <bytes>`
- `--light`
  - return lightweight server status without walking shard stats

Returns JSON describing:

- identity mode
- gram sizes
- shard count
- search worker count
- drain state and active connections
- adaptive publish state
- compaction cooldown state:
  - `compaction_idle_cooldown_s`
  - `compaction_cooldown_remaining_s`
  - `compaction_waiting_for_cooldown`
- document counts and filter-bucket counts
- startup cleanup counts for abandoned compaction roots
- compaction runtime counters and reclaimed bytes

## local-info

```bash
./target/release/sspry local-info --root <path>
```

Returns JSON describing a direct local store or aggregated stats for a local forest root.

## shutdown

```bash
./target/release/sspry shutdown [options]
```

Options:

- `--addr <host:port>`
- `--timeout <seconds>`
- `--max-message-bytes <bytes>`

Behavior:

- requests graceful remote shutdown
- server stops accepting new connections
- in-flight active search is allowed to finish
- queued searches do not start once drain begins

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
- use `--search-workers` to control how many trees the active search runs across at once
- for repeated search tuning, prefer reusing an existing published DB instead of rebuilding it for every planner change
- expect delete to be immediate logically in `current/`, return `missing` when the value is not present there, and be reclaimed physically later by background compaction of `current/`
- `SIGINT` and `SIGTERM` trigger graceful drain and shutdown
- `SIGUSR1` prints a live `info` snapshot to `stderr`
