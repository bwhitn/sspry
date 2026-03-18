# REQ

Project requirements and goals for `sspry`.

## Identity

- Project name: `Scalable Screening and Prefiltering of Rules for YARA`
- Binary and crate name: `sspry`
- Public docs, CLI, and terminology should use `sspry`

## Core Correctness

- False negatives are not acceptable.
- False positives are acceptable when they are part of the normal prefilter/search model and are resolved by later filtering or verification.
- Indexed search must remain conservative whenever a feature cannot be represented exactly in the prefilter stage.
- Search should continue to operate over the published store set only.
- Publishing must not make active indexing incorrect or silently lose work.
- Ingest during publish should work through a double-buffered workspace model.

## Performance Goals

- Optimize for both HDD and SSD behavior.
- Prefer designs that improve sequential IO and avoid unnecessary random IO.
- Keep long-ingest memory usage bounded.
- Operational target: the server component should fit on a typical `16 GiB` machine.
- Assume the rest of the system will commonly consume about `2-6 GiB` of RAM.
- Treat about `10 GiB` server RSS as the practical target, with `10-12 GiB` as the upper bound during long ingest.
- Keep visible publish latency low.
- Improve ingest throughput once correctness and memory/IO behavior are under control.
- Keep search latency low overall, with later optimization at search, publish, and compaction layers as needed.

## Storage and Memory Constraints

- Memory growth should be bounded by active work, not grow unbounded with corpus size.
- Server-side memory budgeting is about the long-lived server process; transient client/index-process memory is a separate concern.
- Avoid new resident indexes unless the measured benefit clearly justifies the memory cost.
- Small resident helper structures are acceptable when they stay well inside the server budget and materially reduce HDD/SSD lookup cost.
- Prefer compact on-disk representations.
- Prefer sequential write/read patterns over rewrite-heavy or randomly probed large structures.
- Keep disk pressure down, especially on HDDs.
- Alpha-phase on-disk format breaks are acceptable unless explicitly frozen later.

## Search and Query Goals

### Existing search model requirements

- Maintain restricted indexed-search planning for safe prefilter execution.
- Keep direct verifier-based `yara` scanning available.
- Preserve explicit verifier fallback where indexed support is incomplete.

### Numeric equality support

Support first-phase indexed handling for equality against literal constants for:
- `int32()`
- `uint32()`
- `int32be()`
- `uint32be()`
- `float32()`
- `float64()`
- `float32be()`
- `float64be()`

Constraints:
- first phase is equality against literal constants only
- expressions like `uint32(x) == filesize` are not first-phase work
- numeric reads may contribute anchors when exact byte anchors are available

### File and metadata search

- Support `filesize` as indexed/searchable metadata.
- Add compact per-document typed metadata for selected module-backed fields.
- Metadata storage should be space efficient.
- Varint-style encodings are acceptable where they reduce stored size without harming correctness.

### Module subset to support

- `crx`
  - `is_crx`
- `pe`
  - `is_pe`
  - `is_32bit`
  - `is_64bit`
  - `is_dll`
  - `is_signed`
  - `Machine`
  - `Subsystem`
  - `timestamp`
- `elf`
  - `Type`
  - `OS ABI`
  - `Machine`
- `macho`
  - `CPU_TYPE`
  - `DEVICE_TYPE`
- `dotnet`
  - `is_dotnet`
- `dex`
  - `is_dex`
  - `version`
- `lnk`
  - `is_lnk`
  - `creation_time`
  - `access_time`
  - `write_time`
- `time`
  - `now`

### String modifier priorities

High priority:
- `ascii`
- `wide`

Medium priority:
- `base64`

Lower priority / likely verifier-first:
- `xor`

Each feature should be classified as one of:
- fully indexable
- constrained prefilter support
- verifier-only fallback

## Concurrency and Publish Model

- Search may continue to read the published root while indexing proceeds in work roots.
- Publishing should swap work buffers and keep new ingest moving into the next work buffer.
- Ingest during publish is required.
- New session gating during publish may be narrowed later, but correctness comes first.
- Search behavior during publish should stay coherent and observable.

## Testing and Validation

- `cargo test --workspace --all-targets` must stay green.
- Performance work should be validated on realistic dataset sizes, not only tiny slices.
- Required large-run checkpoints include at least:
  - `26k`
  - `50k`
- Add larger runs when the bottleneck or scaling question requires them.
- Search-safety regressions should be checked whenever bloom layout, publish/import, verification behavior, or search planning changes.
- Coverage goals:
  - `95%+` line coverage
  - `100%` function coverage where practical

## Documentation and Operability

- Keep CLI documentation current.
- Keep current behavior recorded in `TODO.md`.
- Keep project requirements recorded in this file.
- Keep adaptive publish behavior and `info`/`info --light` surfaces understandable.
- Remove stale references to superseded knobs and legacy naming.

## Working Principles

- Measure first, then optimize.
- Keep accepted changes benchmarked against realistic workloads.
- Reject optimizations that trade correctness or bounded-resource behavior for headline speed.
- Prefer exact storage/query strategies when the alternative risks false negatives.
