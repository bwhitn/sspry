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
- `serve` is the only server command.
- `index`, `delete`, `search`, `info`, and `shutdown` are RPC client commands.
- `local-index`, `local-delete`, `local-search`, and `local-info` operate directly on disk without RPC.
- `search-batch` is the long-lived local forest runner for repeated sweeps.

## `serve`

```text
Usage: sspry serve [OPTIONS]
```

Key options:

- `--addr <ADDR>`
- `--max-request-bytes <BYTES>`
- `--search-workers <N>`
  - server-side tree query workers per search
  - one search runs across at most this many trees at once
- `--root <ROOT>`
  - workspace root, direct store root, or forest root
- `--layout-profile <standard|incremental>`
- `--shards <N>`
- `--tier1-set-fp <P>` default `0.38`
- `--tier2-set-fp <P>` default `0.18`
- `--id-source <sha256|md5|sha1|sha512>`
- `--store-path`
- `--gram-sizes <tier1,tier2>` default `3,4`

## `index`

```text
Usage: sspry index [OPTIONS] <PATHS>...
```

Remote ingest options:

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--path-list`
- `--batch-size <N>`
- `--remote-batch-soft-limit-bytes <BYTES>`
- `--workers <N>`
- `--verbose`

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
- `--compaction-idle-cooldown-s <SECONDS>` default `5`
- `--path-list`
- `--batch-size <N>`
- `--workers <N>`
- `--verbose`

Behavior:

- auto-initializes a missing direct local store
- writes directly to disk without RPC

## `delete`

```text
Usage: sspry delete [OPTIONS] <VALUES>...
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`

## `local-delete`

```text
Usage: sspry local-delete [OPTIONS] --root <ROOT> <VALUES>...
```

- `--root <ROOT>`

## `search`

```text
Usage: sspry search [OPTIONS] --rule <RULE>
```

Remote search options:

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--rule <RULE>`
- `--max-anchors-per-pattern <N>` default `16`
- `--max-candidates <PERCENT>` default `7.5`
- `--verify`
- `--verbose`

Behavior:

- server streams candidate pages
- client deduplicates across the forest
- client applies the final percentage cap after dedupe
- output includes `truncated: true` and `truncated_limit: <n>` when capped

## `local-search`

```text
Usage: sspry local-search [OPTIONS] --root <ROOT> --rule <RULE>
```

Local forest search options:

- `--root <ROOT>`
- `--rule <RULE>`
- `--tree-search-workers <N>` default `0`
- `--max-anchors-per-pattern <N>` default `16`
- `--max-candidates <PERCENT>` default `7.5`
- `--verify`
- `--verbose`

## `search-batch`

```text
Usage: sspry search-batch --root <ROOT> --json-out <JSON_OUT> [OPTIONS]
```

- `--root <ROOT>`
- `--rules-dir <DIR>` or `--rule-manifest <FILE>`
- `--json-out <FILE>`
- `--tree-search-workers <N>` default `0`
- `--max-anchors-per-pattern <N>` default `16`
- `--max-candidates <PERCENT>` default `7.5`
- `--verify`

## `info`

```text
Usage: sspry info [OPTIONS]
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--light`

## `local-info`

```text
Usage: sspry local-info --root <ROOT>
```

- `--root <ROOT>`

Behavior:

- prints direct local store stats
- also accepts a forest root and prints aggregated stats across trees

## `shutdown`

```text
Usage: sspry shutdown [OPTIONS]
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`

## `yara`

```text
Usage: sspry yara --rule <RULE> [OPTIONS] <FILE_PATH>
```

- `--rule <RULE>`
- `--scan-timeout <SECONDS>` default `60`
- `--show-tags`
