# NOW

This file is the short-horizon worklist.

It contains the items to finish before going back to the broader performance backlog in
[TODO.md](/root/pertest/repos/yaya/TODO.md).

## Immediate Priorities

### 1. Rebrand the project and clean up old naming

Project direction:
- project name: `Scalable Screening and Prefiltering of Rules for YARA`
- binary / crate / CLI name: `sspry`

Work:
- rename user-facing project identity from `yaya` to `sspry`
- update package/crate/binary metadata and CLI help text
- scrub remaining old naming in code and tests:
  - `yaya`
  - `tgs`
  - `rgr`
- rename leftover numeric bloom/tier aliases so they use `tier1` / `tier2` naming instead of old `3` / `5` names where those names still describe the bloom tiers rather than literal gram sizes
- update docs so the public name and examples are consistent

Recorded follow-on work after the rename baseline is stable:
- add the upcoming additional search data and stored-data fields to the project plan before returning to the broader backlog
- extend indexed search support for equality checks on:
  - `int32()`
  - `uint32()`
  - `int32be()`
  - `uint32be()`
  - `float32()`
  - `float64()`
  - `float32be()`
  - `float64be()`
- scope that work specifically to `==` comparisons first
- add indexed search support for `filesize`
- add explicit string modifier/classifier support planning for:
  - `xor`
  - `wide`
  - `ascii`
  - `base64`
- prioritize indexed search support by value and feasibility instead of treating all modifiers/expressions as equal
- initial priority split for indexed support:
  - highest priority:
    - `filesize`
    - numeric read equality checks with `==`
    - stored metadata fields from supported modules
    - `ascii`
    - `wide`
  - medium priority / constrained support:
    - `base64`, with explicit bounds on what forms are anchorable/prefilterable
  - lowest priority / likely verifier-first:
    - `xor`, because naive gram expansion can explode candidate anchors and matching cost
- require the search design to document, per feature:
  - whether it is fully indexable
  - whether it only supports a constrained subset for prefilter
  - whether it falls back to verifier-only evaluation
- require `filesize` and module-derived comparison fields to be stored in each document record or an equivalent per-document metadata structure
- require that stored metadata design to be space efficient:
  - compact encoding
  - avoid one-off per-feature blobs where a shared typed metadata layout is possible
  - keep the additional stored-data footprint bounded and measurable
- record the required stored-data additions and query/runtime behavior needed to support those comparisons in indexed search rather than only in direct YARA verification
- add third-order indexed search/runtime support for a defined subset of YARA modules and module-backed fields/functions
- record the module subset explicitly:
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
- capture that this module work needs:
  - stored extracted metadata for indexed search where possible
  - compact per-document storage for comparison fields such as `filesize` and selected module values
  - clear fallback behavior when an expression cannot be fully prefitered
  - a documented boundary between supported indexed-module expressions and verifier-only expressions

Exit criteria:
- public surfaces identify the project as `sspry`
- no intentional internal symbol names remain from the old `yaya` / `tgs` / `rgr` naming schemes
- bloom-tier code and docs consistently use `tier1` / `tier2` terminology where appropriate
- the post-rename plan explicitly captures the numeric-equality search expansion and the stored-data work it depends on
- the post-rename plan explicitly captures `filesize` as indexed/searchable metadata
- the post-rename plan explicitly captures that `filesize` and selected module values must be added to document storage in a space-efficient form
- the post-rename plan explicitly captures the required string modifier/classifier support:
  - `xor`
  - `wide`
  - `ascii`
  - `base64`
- the post-rename plan explicitly captures priority and fallback rules for expensive search features instead of assuming every YARA expression is equally prefilterable
- the post-rename plan explicitly captures the selected YARA module subset and the metadata/search work needed to support it

### 2. Close the current test / coverage gaps

Current measured repo coverage:
- `src/` line coverage: `93.33%`
- `src/` function coverage: `87.98%`
- `src/` region coverage: `91.91%`

Current weakest files:
- [src/app.rs](/root/pertest/repos/yaya/src/app.rs)
  - lines: `92.03%`
  - functions: `88.74%`
- [src/candidate/store.rs](/root/pertest/repos/yaya/src/candidate/store.rs)
  - lines: `90.55%`
  - functions: `86.90%`
- [src/rpc.rs](/root/pertest/repos/yaya/src/rpc.rs)
  - lines: `94.88%`
  - functions: `83.33%`

Work:
- identify the lowest-covered functions in `app.rs` first
- add tests for currently uncovered CLI/error/config branches
- then cover the remaining lower-hit branches in `rpc.rs`
- only after that spend more time on `store.rs`
- keep pushing toward:
  - `100%` function coverage where practical
  - `95%+` line coverage

Exit criteria:
- raise `app.rs` materially from the current `76.96%` line coverage
- keep full `cargo test --workspace --all-targets` green

### 3. Strengthen correctness coverage around recent performance work

Recent work changed:
- adaptive publish policy
- publish/readiness behavior
- insert/store hot paths
- bloom append batching
- Tier2 summary folding

Work:
- add targeted correctness tests for adaptive publish state transitions
- add stronger search-result regression checks after recent insert/store changes
- include at least one `--store-path` / `--verify` style validation path
- keep direct-verifier baseline tests for numeric reads / `filesize`
- keep indexed-search regression coverage for `filesize == <const>`

Exit criteria:
- explicit tests exist for recent behavior changes, not just perf probes
- search and visibility checks are easy to rerun locally

### 4. Make coverage measurement repeatable

Current real coverage run exists here:
- `/root/pertest/results/yaya_coverage_20260315`

Current caveat:
- LLVM aggregation produced `5` mismatched-data warnings

Work:
- add a documented repeatable coverage command/workflow
- make sure it reports repo-only coverage, not dependency totals
- keep the output path and filtering consistent

Exit criteria:
- one reliable local coverage workflow
- one short note on how to read repo-only vs dependency coverage

### 5. Review neglected operational/documentation edges

Work:
- confirm the adaptive publish behavior is reflected in docs/help/output where needed
- make sure there is no remaining stale reference to the removed fixed publish knob
- check that `info` / `info --light` surfaces are still coherent after recent changes
- keep the remaining legacy on-disk `doc_meta5.bin` path under review and decide whether it should be renamed as part of an alpha-format break

Exit criteria:
- no stale user-facing references to removed publish controls
- adaptive publish state is discoverable from current status output

## Order

Work these in this order:
1. rebrand / binary rename / internal naming cleanup
2. record the upcoming additional search/stored-data work after the rename baseline is established
3. coverage-gap audit and new tests in `app.rs`
4. targeted correctness tests for adaptive publish / search / publish visibility
5. repeatable coverage workflow cleanup
6. operational/doc surface cleanup

Only after these are done do we return to [TODO.md](/root/pertest/repos/yaya/TODO.md).

## Notes

Current baseline references:
- coverage artifacts:
  - `/root/pertest/repos/yaya/coverage`
- large ingest baseline:
  - `/root/pertest/results/yaya_ingest_26000_20260315`
- current repo state when this file was created:
  - `HEAD=0c5af11`

## Recorded Decisions

- `filesize` range queries like `filesize > 8 and filesize < 1400` are not first-phase work
  - keep them as second/third-phase work
- numeric read support first phase is equality against literal constants only
  - examples:
    - `uint32(x) == 0x4000`
    - allowed
  - examples not for first phase:
    - `uint32(x) == filesize`
    - not allowed
- module data should use a compact typed per-document metadata block now
  - prefer space-efficient encoding such as varints where it actually reduces stored size
- alpha-phase format breaks are acceptable when they make the design cleaner
  - legacy `doc_meta5.bin` compatibility is not required

## Current State

- public/internal rename is complete for the public product surface; remaining old-name hits are limited to negative tests and historical notes in planning docs
- indexed search now supports `filesize == <const>` when combined with the currently supported restricted rule format
- indexed search now supports compact stored metadata equality for:
  - `pe`
  - `elf`
  - `dex`
  - `lnk`
  - `dotnet.is_dotnet`
  - `time.now` runtime equality
- indexed search now accepts first-phase numeric read equality for:
  - `int32()`
  - `uint32()`
  - `int32be()`
  - `uint32be()`
  - `float32()`
  - `float64()`
  - `float32be()`
  - `float64be()`
  - current behavior is verifier-only for the numeric predicate itself
  - the literal bytes now contribute indexed anchors when the current gram sizes can represent them
  - if the current gram sizes are larger than the literal width, another string/hex anchor is still required
- per-document compact metadata is now stored in `doc_metadata.bin`
- the old `doc_meta5.bin` path has already been replaced by `tier2_doc_meta.bin`
- direct `yara` verification is covered for:
  - `filesize`
  - `int32()`
  - `uint32()`
  - `int32be()`
  - `uint32be()`
  - `float32()`
  - `float64()`
  - `float32be()`
  - `float64be()`
- coverage workflow now uses an isolated target dir and repo-only filtering
- latest repo-only coverage:
  - lines: `93.33%`
  - functions: `87.98%`
  - `app.rs` lines: `92.03%`
