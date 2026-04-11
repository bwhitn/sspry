# CMD

Current public CLI surface for `sspry`.

## Top-Level

```text
Scalable Screening and Prefiltering of Rules for YARA.

Usage: sspry [OPTIONS] <COMMAND>

Commands:
  serve
  index
  local-index
  delete
  local-delete
  rule-check
  search
  local-search
  search-batch
  info
  local-info
  shutdown
  yara
  help
```

## Shared Notes

- `SSPRY_ADDR` sets the default server address for remote client commands.
- `serve` is the only public server command.
- `index`, `delete`, `search`, `info`, and `shutdown` are the public remote client commands.
- `rule-check` validates a rule against a live server policy, a local root, or explicit offline assumptions.
- the public remote transport is gRPC
- `local-index`, `local-delete`, `local-search`, and `local-info` operate directly on disk without RPC.
- `search-batch` is the long-lived local forest runner for repeated sweeps.

## `serve`

```text
Usage: sspry serve [OPTIONS]
```

Key options:

- `--addr <ADDR>`
- `--max-message-bytes <BYTES>`
- `--search-workers <N>`
  - one active top-level search per server
  - the active search runs across at most this many trees at once
  - default is `max(1, cpus/4)`
- `--root <ROOT>`
  - workspace root, direct store root, or forest root
  - default `candidate_db`
- `--layout-profile <standard|incremental>`
- `--shards <N>`
  - both layout profiles currently default new DBs to `8` shards
- `--tier1-set-fp <P>` default `0.38`
- `--tier2-set-fp <P>` default `0.18`
- `--id-source <sha256|md5|sha1|sha512>`
- `--store-path`
- `--gram-sizes <tier1,tier2>` default `3,4`
  - supported pairs: `3,4`, `4,5`, `5,6`, `7,8`

## `index`

```text
Usage: sspry index [OPTIONS] <PATHS>...
```

Remote ingest options:

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`
- `--path-list`
- `--batch-size <N>`
- `--remote-batch-soft-limit-bytes <BYTES>`
- `--insert-chunk-bytes <BYTES>`
- `--workers <N>`
- `--verbose`

Behavior:

- streams row-framed inserts over gRPC
- large documents are chunked across frames
- only one active indexing session is allowed per server at a time
- when the target server is in workspace mode, `index` auto-publishes after ingest so new documents become searchable

## `local-index`

```text
Usage: sspry local-index [OPTIONS] --root <ROOT> <PATHS>...
```

Local ingest options:

- `--root <ROOT>`
- `--candidate-shards <N>` default `1`
- `--force`
- `--tier1-set-fp <P>` default `0.38`
- `--tier2-set-fp <P>` default `0.18`
- `--gram-sizes <tier1,tier2>` default `3,4`
- supported pairs: `3,4`, `4,5`, `5,6`, `7,8`
- `--compaction-idle-cooldown-s <SECONDS>` default `5`
- `--path-list`
- `--batch-size <N>`
- `--workers <N>`
- `--verbose`

## `delete`

```text
Usage: sspry delete [OPTIONS] <VALUES>...
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`

Behavior:

- delete only targets published `current/`
- `missing` is a normal non-error outcome for multi-server fanout
- reclaim happens later through background compaction of `current/`

## `local-delete`

```text
Usage: sspry local-delete [OPTIONS] --root <ROOT> <VALUES>...
```

- `--root <ROOT>`

## `rule-check`

```text
Usage: sspry rule-check [OPTIONS] --rule <RULE>
```

- `--rule <RULE>`
- `--addr <ADDR>`
- `--timeout <SECONDS>` when using `--addr`
- `--max-message-bytes <BYTES>` when using `--addr`
- `--root <ROOT>`
- `--id-source <sha256|md5|sha1|sha512>`
- `--gram-sizes <tier1,tier2>`
- `--max-anchors-per-pattern <N>` default `16`
- `--json`

Behavior:

- returns `searchable`, `searchable-needs-verify`, or `unsupported`
- uses live server policy with `--addr`
- uses on-disk store or forest policy with `--root`
- otherwise falls back to explicit or default offline assumptions
- warns about verifier-only constraints and ignored indexed-search module predicates

## `search`

```text
Usage: sspry search [OPTIONS] --rule <RULE>
```

Remote search options:

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`
- `--rule <RULE>`
- `--max-anchors-per-pattern <N>` default `16`
- `--max-candidates <PERCENT>` default `10`
- `--verify`
- `--verbose`

Behavior:

- client sends validated YARA source
- server compiles and executes the search plan
- server serializes top-level searches and queues later requests
- client deduplicates across the forest and applies the final percentage cap

## `local-search`

```text
Usage: sspry local-search [OPTIONS] --root <ROOT> --rule <RULE>
```

Local forest search options:

- `--root <ROOT>`
- `--rule <RULE>`
- `--tree-search-workers <N>` default `0`
- `--max-anchors-per-pattern <N>` default `16`
- `--max-candidates <PERCENT>` default `10`
- `--verify`
- `--verbose`

Behavior:

- opens `tree_*/current` directly and searches the forest in-process
- `--tree-search-workers 0` means auto up to the tree count

## `search-batch`

```text
Usage: sspry search-batch --root <ROOT> --json-out <JSON_OUT> [OPTIONS]
```

- `--root <ROOT>`
- `--rules-dir <DIR>` or `--rule-manifest <FILE>`
- `--json-out <FILE>`
- `--tree-search-workers <N>` default `0`
- `--max-anchors-per-pattern <N>` default `16`
- `--max-candidates <PERCENT>` default `10`
- `--verify`

Behavior:

- opens the forest once and reuses it across the whole rule sweep
- `--tree-search-workers 0` means auto up to the tree count

## `info`

```text
Usage: sspry info [OPTIONS]
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`
- `--light`

## `local-info`

```text
Usage: sspry local-info --root <ROOT>
```

- `--root <ROOT>`
  - direct local store root or forest root

## `shutdown`

```text
Usage: sspry shutdown [OPTIONS]
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`

## `yara`

```text
Usage: sspry yara [OPTIONS] --rule <RULE> <FILE>
```

- `--rule <RULE>`
- `--scan-timeout <SECONDS>`
- `--show-tags`
