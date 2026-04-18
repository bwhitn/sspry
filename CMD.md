# CMD

Current public CLI surface for `sspry`.

## Top-Level

```text
Scalable Screening and Prefiltering of Rules for YARA.

Usage: sspry [OPTIONS] <COMMAND>

Commands:
  serve
  index
  delete
  rule-check
  search
  info
  local
  shutdown
  help

Default scan mode: sspry --rule <RULE> <FILE>
```

## Shared Notes

- `SSPRY_ADDR` sets the default server address for remote client commands.
- `serve` is the only public server command.
- `index`, `delete`, `search`, `info`, and `shutdown` are the public remote gRPC client commands.
- `rule-check` validates a rule against a live server policy, a local root, or explicit offline assumptions.
- `local` groups the direct on-disk commands and does not use RPC.
- direct YARA scanning is the default mode when the first non-global token is not a known subcommand.

## `serve`

```text
Usage: sspry serve [OPTIONS]
```

Key options:

- `--addr <ADDR>`
- `--max-message-bytes <BYTES>`
- `--search-workers <N>`
  - one active top-level search per server
  - direct/workspace mode fans out over shard work units
  - forest mode fans out over `(tree, shard)` work units
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

## `delete`

```text
Usage: sspry delete [OPTIONS] <VALUES>...
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`

## `rule-check`

```text
Usage: sspry rule-check [OPTIONS] --rule <RULE>
```

Key options:

- `--rule <RULE>`
- `--addr <ADDR>` to validate against a live server policy
- `--root <ROOT>` to validate against a local store or forest policy
- `--id-source <MODE>` and `--gram-sizes <PAIR>` for offline assumptions
- `--max-anchors-per-pattern <N>`
- `--json`

## `search`

```text
Usage: sspry search [OPTIONS] --rule <RULE>
```

Remote search options:

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`
- `--rule <RULE>`
- `--max-anchors-per-pattern <N>`
- `--max-candidates <PERCENT>` default `10`
- `--verify`
- `--verbose`

Behavior:

- expands one top-level rule file, including nested `include` directives
- if the expanded source contains multiple searchable rules, `search` runs one execution per rule
- `--max-candidates` is a percentage of searchable documents; `0` disables the cap

## `info`

```text
Usage: sspry info [OPTIONS]
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`
- `--light`

## `local`

```text
Usage: sspry local [OPTIONS] <COMMAND>

Commands:
  index
  delete
  search
  info
  help
```

Shared note:

- these commands operate directly on a local store or forest root without RPC

### `local index`

```text
Usage: sspry local index [OPTIONS] --root <ROOT> <PATHS>...
```

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

### `local delete`

```text
Usage: sspry local delete --root <ROOT> <VALUES>...
```

- `--root <ROOT>`

### `local search`

```text
Usage: sspry local search [OPTIONS] --root <ROOT> --rule <RULE>
```

- `--root <ROOT>`
- `--rule <RULE>`
- `--tree-search-workers <N>` where `0` means auto up to tree count
- `--max-anchors-per-pattern <N>`
- `--max-candidates <PERCENT>` default `10`
- `--verify`
- `--verbose`

Behavior:

- opens a forest or direct local root in-process
- expands the top-level rule file once, including `include` directives
- if the expanded source contains multiple searchable rules, the opened forest is reused across the rule bundle

### `local info`

```text
Usage: sspry local info --root <ROOT>
```

- `--root <ROOT>`

## `shutdown`

```text
Usage: sspry shutdown [OPTIONS]
```

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`

## Default Scan Mode

```text
Usage: sspry [OPTIONS] --rule <RULE> <FILE>
```

This is the direct `yara-x` scan path. The public help does not show a top-level
`yara` command, but the default invocation is equivalent to the hidden internal
YARA scan command.

Key options:

- `--rule <RULE>`
- `<FILE>`
- `--scan-timeout <SECONDS>` default `60`
- `--show-tags`
