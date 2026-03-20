# CMD

Current public CLI surface for `sspry`.

Generated from the current binary help on `2026-03-16`.

## Top-Level

```text
Scalable Screening and Prefiltering of Rules for YARA.

Usage: sspry [OPTIONS] <COMMAND>

Commands:
  serve
  index
  delete
  search
  info
  shutdown
  yara
  help

Options:
      --perf-report <PERF_REPORT>  Write JSON performance report to this path.
      --perf-stdout                Print JSON performance report on exit.
  -h, --help                       Print help
```

## Shared Notes

- `SSPRY_ADDR` sets the default server address for client commands.
- The default server address is `127.0.0.1:17653`.
- `--perf-report` writes a JSON performance report to a file.
- `--perf-stdout` prints a JSON performance report to stdout on exit.

## `serve`

```text
Usage: sspry serve [OPTIONS]

Options:
      --addr <ADDR>
          Bind address as host:port. [env: SSPRY_ADDR=] [default: 127.0.0.1:17653]
      --perf-report <PERF_REPORT>
          Write JSON performance report to this path.
      --max-request-bytes <MAX_REQUEST_BYTES>
          Maximum accepted request size in bytes. [default: 67108864]
      --perf-stdout
          Print JSON performance report on exit.
      --search-workers <SEARCH_WORKERS>
          Server-side shard query workers. Default is max(1, cpus/4). [default: 11]
      --memory-budget-gb <MEMORY_BUDGET_GB>
          Configured indexing memory budget in GiB. Client-side indexing backpressure will use the lower of this value and available memory. [default: 16]
      --tier2-superblock-budget-divisor <TIER2_SUPERBLOCK_BUDGET_DIVISOR>
          Divides the server memory budget to derive the per-shard Tier2 summary-memory budget. Lower values allow more RAM for Tier2 summaries. [default: 4]
      --root <ROOT>
          Workspace root directory. SSPRY will manage current/, work_a/, work_b/, and retired/ under this path. [default: candidate_db]
      --layout-profile <LAYOUT_PROFILE>
          Shard-layout profile. `standard` defaults to 256 shards; `incremental` defaults to 32 shards for denser ingest batches and lower publish fanout. [default: standard] [possible values: standard, incremental]
      --shards <SHARDS>
          Number of independent candidate shards (lock stripes) for ingest/write paths. Overrides --layout-profile when set.
      --set-fp <FILTER_TARGET_FP>
          Target Bloom false-positive rate (default: 0.35). [default: 0.35]
      --id-source <ID_SOURCE>
          DB-wide document identity source used by ingest and delete. [default: sha256] [possible values: sha256, md5, sha1, sha512]
      --store-path
          Store the canonical file path as external_id for each inserted document.
      --gram-sizes <GRAM_SIZES>
          DB-wide gram-size pair as tier2,tier1. Supported pairs: 3,4 4,5 5,6 7,8. [default: 3,4]
  -h, --help
          Print help
```

Example:

```bash
cargo run -- serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db \
  --layout-profile standard
```

## `index`

```text
Usage: sspry index [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  File or directory paths.

Options:
      --addr <ADDR>                Server address as host:port. [env: SSPRY_ADDR=] [default: 127.0.0.1:17653]
      --perf-report <PERF_REPORT>  Write JSON performance report to this path.
      --perf-stdout                Print JSON performance report on exit.
      --timeout <TIMEOUT>          Connection/read timeout in seconds. [default: 30]
      --batch-size <BATCH_SIZE>    Documents per insert_batch request. [default: 64]
      --workers <WORKERS>          Process workers for recursive file scan/feature extraction before batched inserts. Default is auto: CPU-based on solid-state input, capped conservatively on rotational storage.
      --verbose                    Print timing details to stderr.
  -h, --help                       Print help
```

Example:

```bash
cargo run -- index --addr 127.0.0.1:17653 ./samples ./more-samples
```

## `delete`

```text
Usage: sspry delete [OPTIONS] <VALUES>...

Arguments:
  <VALUES>...  Existing file paths or hex digests in the server's configured identity format.

Options:
      --addr <ADDR>                Server address as host:port. [env: SSPRY_ADDR=] [default: 127.0.0.1:17653]
      --perf-report <PERF_REPORT>  Write JSON performance report to this path.
      --perf-stdout                Print JSON performance report on exit.
      --timeout <TIMEOUT>          Connection/read timeout in seconds. [default: 30]
  -h, --help                       Print help
```

## `search`

```text
Usage: sspry search [OPTIONS] --rule <RULE>

Options:
      --addr <ADDR>
          Server address as host:port. [env: SSPRY_ADDR=] [default: 127.0.0.1:17653]
      --perf-report <PERF_REPORT>
          Write JSON performance report to this path.
      --perf-stdout
          Print JSON performance report on exit.
      --timeout <TIMEOUT>
          Connection/read timeout in seconds. [default: 30]
      --rule <RULE>
          Path to YARA rule file.
      --max-anchors-per-pattern <MAX_ANCHORS_PER_PATTERN>
          Keep at most this many anchors per pattern alternative. [default: 16]
      --max-candidates <MAX_CANDIDATES>
          Server-side cap on returned candidate set size; 0 means unlimited. [default: 15000]
      --verify
          Enable local YARA verification over candidate file paths.
      --verbose
          Print timing details to stderr.
  -h, --help
          Print help
```

Examples:

```bash
cargo run -- search --addr 127.0.0.1:17653 --rule ./rule.yar
cargo run -- search --addr 127.0.0.1:17653 --rule ./rule.yar --verify
```

## `info`

```text
Usage: sspry info [OPTIONS]

Options:
      --addr <ADDR>                Server address as host:port. [env: SSPRY_ADDR=] [default: 127.0.0.1:17653]
      --perf-report <PERF_REPORT>  Write JSON performance report to this path.
      --perf-stdout                Print JSON performance report on exit.
      --timeout <TIMEOUT>          Connection/read timeout in seconds. [default: 30]
      --light                      Return lightweight server status without walking shard stats.
  -h, --help                       Print help
```

Examples:

```bash
cargo run -- info --addr 127.0.0.1:17653
cargo run -- info --addr 127.0.0.1:17653 --light
```

## `shutdown`

```text
Usage: sspry shutdown [OPTIONS]

Options:
      --addr <ADDR>                Server address as host:port. [env: SSPRY_ADDR=] [default: 127.0.0.1:17653]
      --perf-report <PERF_REPORT>  Write JSON performance report to this path.
      --perf-stdout                Print JSON performance report on exit.
      --timeout <TIMEOUT>          Connection/read timeout in seconds. [default: 30]
  -h, --help                       Print help
```

Example:

```bash
cargo run -- shutdown --addr 127.0.0.1:17653
```

## `yara`

```text
Usage: sspry yara [OPTIONS] --rule <RULE> <FILE_PATH>

Arguments:
  <FILE_PATH>  Path to the file to scan.

Options:
      --perf-report <PERF_REPORT>    Write JSON performance report to this path.
      --rule <RULE>                  Path to YARA rule file.
      --perf-stdout                  Print JSON performance report on exit.
      --scan-timeout <SCAN_TIMEOUT>  YARA scan timeout in seconds (default: 60). [default: 60]
      --show-tags                    Print matched rule tags.
  -h, --help                         Print help
```

Example:

```bash
cargo run -- yara --rule ./rule.yar ./sample.bin
```
