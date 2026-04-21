# CMD

Current public CLI surface for `sspry`.

## Top-Level

```text
Scalable Screening and Prefiltering of Rules for YARA.

Usage: sspry [OPTIONS] <COMMAND>

Commands:
  init
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
- `init` is the public DB/workspace initialization command.
- `index`, `delete`, `search`, `info`, and `shutdown` are the public remote gRPC client commands.
- `rule-check` validates a rule against a live server policy, a local root, or explicit offline assumptions.
- `local` groups the direct on-disk commands and does not use RPC.
- direct YARA scanning is the default mode when the first non-global token is not a known subcommand.

## `init`

```text
Usage: sspry init [OPTIONS]
```

Key options:

- `--root <ROOT>` default `candidate_db`
- `--mode <workspace|local>` default `workspace`
- `--shards <N>`
  - defaults to `8` for `workspace`
  - defaults to `1` for `local`
- `--force`
- `--tier1-set-fp <P>` default `0.38`
- `--tier2-set-fp <P>` default `0.18`
- `--id-source <sha256|md5|sha1|sha512>` default `sha256`
- `--store-path`
- `--gram-sizes <tier1,tier2>` default `3,4`
  - supported pairs: `3,4`, `4,5`, `5,6`, `7,8`
- `--compaction-idle-cooldown-s <SECONDS>` default `5`

Behavior:

- `workspace` mode initializes `<root>/current` for remote `serve`
- `local` mode initializes a direct store at `<root>` for `local index/search/info`
- this is where DB-wide format/layout policy is chosen

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

Behavior:

- opens an existing initialized root
- requires an explicitly initialized workspace root, direct local store root, or forest root
- use `init` first before starting a new workspace or direct local store

## `index`

```text
Usage: sspry index [OPTIONS] <PATHS>...
```

Remote ingest options:

- `--addr <ADDR>`
- `--timeout <SECONDS>`
- `--max-message-bytes <BYTES>`
- `--path-list`
- `--batch-bytes <BYTES>`
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
- `--path-list`
- `--batch-docs <N>`
- `--workers <N>`
- `--verbose`

Behavior:

- writes directly without RPC
- requires an explicitly initialized direct local store root
- use `init --mode local` first before local ingest

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
- `--search-workers <N>` where `0` means auto up to tree count
- `--max-anchors-per-pattern <N>`
- `--max-candidates <PERCENT>` default `10`
- `--verify`
- `--verbose`

Behavior:

- opens a direct local store or forest root in-process
- expands the top-level rule file once, including `include` directives
- if the expanded source contains multiple searchable rules, the opened local root is reused across the rule bundle

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
