# Performance TODO

Current baseline:
- Repo: `/root/pertest/repos/yaya`
- Current pushed baseline: `62910e5` `Expand search coverage and refresh deps`
- Repo-local git auto maintenance is disabled during benchmark work:
  - `gc.auto = 0`
  - `maintenance.auto = false`

## Current State

Large real ingest baseline:
- Artifact root: `/root/pertest/results/yaya_ingest_26000_20260315`
- Dataset:
  - files: `26,000`
  - bytes: `65,094,641,220`
  - GiB: `60.62410885468125`
- Pure index time:
  - `verbose.index.total_ms = 1,140,232.576`
  - about `19m 0.233s`

Key `26k` ingest buckets:
- `verbose.index.worker_scan_cpu_ms = 34,989,455.853`
- `verbose.index.result_wait_ms = 585,620.851`
- `verbose.index.client_buffer_ms = 35,385.303`
- `verbose.index.submit_ms = 489,616.631`

Server insert/store profile from the same `26k` run:
- `server_index_insert_batch_count = 493`
- `server_index_insert_batch_documents = 26,000`
- `server_index_insert_batch_total_us = 429,576,880`
- `server_index_insert_batch_store_us = 396,819,383`
- dominant store buckets:
  - `store_classify_us = 108,499,451`
  - `store_compact_df_counts_us = 187,097,904`
  - `store_append_sidecars_us = 55,911,413`
  - `store_apply_df_counts_us = 40,297,714`
  - `store_tier2_update_us = 1,360,023`

Interpretation:
- On large ingest, the main bottleneck is server-side submit/store work.
- Inside store work, the two biggest remaining hotspots are:
  1. `compact_df_counts`
  2. `classify`

Current-tree DF compaction rerun, late-run snapshot:
- Artifact root: `/root/pertest/results/sspry_dfcompact_profile_26000_current_20260315_140702`
- The run was intentionally stopped after a late-run live snapshot once the compaction diagnosis was clear.
- Snapshot at `23,359` active docs:
  - `work_df_counts_delta_bytes = 728,515,384`
  - `work_df_counts_delta_compact_threshold_bytes = 1,073,741,824`
  - `store_compact_df_counts_us = 87,330,505`
  - `store_classify_us = 93,892,615`
  - `store_append_sidecars_us = 88,334,406`
  - `store_apply_df_counts_us = 50,140,201`
  - `store_compact_df_counts_check_us = 0`
  - `store_compact_df_counts_persist_snapshot_us = 0`
  - `store_compact_df_counts_refresh_snapshot_us = 0`
  - `store_compact_df_counts_reopen_writers_us = 0`

Read:
- `compact_df_counts` is still a real large-ingest hotspot on the current tree.
- The new split is incomplete: the expensive subphase is not captured by the current
  `check/persist/refresh/reopen` fields.
- The next step is a second instrumentation pass inside `maybe_compact_df_counts()` /
  `persist_df_counts_snapshot_to_root()` before attempting another optimization.

Useful current comparison run:
- Artifact root: `/root/pertest/results/yaya_incremental_large_auto_20260315`
- Current `2000 + 1000`, auto workers:
  - base `2000`
    - `total_ms = 8754.050`
    - `submit_ms = 7355.708`
  - incremental `+1000`
    - `total_ms = 8338.243`
    - `submit_ms = 5793.406`

Latest rejected bounded-memory experiment:
- Exact streaming classify + streaming DF snapshot persist was tested locally and rejected.
- Fresh deterministic datasets used for the rerun:
  - `26k` prefix:
    - `/root/pertest/results/sspry_dataset_26000_sorted_20260316/dataset.json`
    - files: `26,000`
    - bytes: `65,094,641,220`
    - GiB: `60.624108854681`
  - `50k` prefix:
    - `/root/pertest/results/sspry_dataset_50000_sorted_20260316/dataset.json`
    - files: `50,000`
    - bytes: `143,010,953,447`
    - GiB: `133.189329362474`

`26k` exact-streaming rerun:
- Artifact root:
  - `/root/pertest/results/sspry_ingest_26000_20260316_streaming_bounded`
- Final index totals:
  - `verbose.index.total_ms = 801,605.882`
  - `verbose.index.submit_ms = 442,367.917`
  - `verbose.index.server_current_rss_kb = 6,839,812`
  - `verbose.index.server_peak_rss_kb = 6,893,572`
- Dominant server store buckets:
  - `store_append_sidecars_us = 120,491,599`
  - `store_compact_df_counts_us = 101,856,962`
  - `store_classify_us = 73,417,880`
  - `store_classify_df_lookup_us = 34,003,536`
  - `store_apply_df_counts_us = 33,895,899`
- Read:
  - faster than the old `26k` baseline on total time
  - completely fails the memory bar
  - late-run current RSS stayed close to peak instead of dropping to a safe level

`50k` scaling confirmation:
- Artifact root:
  - `/root/pertest/results/sspry_ingest_50000_20260316_streaming_bounded`
- The run was intentionally stopped early to avoid wasting more IO once the RSS slope was clear.
- Last clean light-info sample:
  - sample file:
    - `/root/pertest/results/sspry_ingest_50000_20260316_streaming_bounded/monitor.0008.json`
  - progress:
    - `submitted_documents = 6,803`
    - `progress_percent = 13.606`
  - memory:
    - `current_rss_kb = 2,755,732`
    - `peak_rss_kb = 2,815,092`
- Read:
  - RSS slope is worse than the rejected `26k` run
  - the path is not scaling safely enough to justify further IO on this approach

Conclusion from the reruns:
- exact streaming snapshot reads by themselves are not enough
- even without the original mmap random-probe path, the current classify strategy still grows
  resident memory too aggressively as corpus size increases
- do not land this path
- next attempt needs a different shape:
  - memory bounded by active batch/shard work, not cumulative snapshot state
  - likely locality-aware exact lookup rather than whole-snapshot rereads

Current best bounded-memory path:
- stream DF snapshot compaction instead of materializing a full output payload
- trigger DF compaction from estimated in-memory delta-map size as well as on-disk delta bytes
- artifacts:
  - conservative `1x` memory-trigger run:
    - `/root/pertest/results/sspry_ingest_26000_20260316_memcap`
  - accepted `2x` memory-trigger runs:
    - `/root/pertest/results/sspry_ingest_26000_20260316_memcap2`
    - `/root/pertest/results/sspry_ingest_50000_20260316_memcap2`
  - rejected `4x` memory-trigger run:
    - `/root/pertest/results/sspry_ingest_26000_20260316_memcap4`

`1x` memory-trigger result, `26k`:
- `verbose.index.total_ms = 1,400,599.627`
- `verbose.index.submit_ms = 1,306,711.645`
- `server_current_rss_kb = 1,822,480`
- `server_peak_rss_kb = 1,929,764`
- `server_df_counts_delta_estimated_memory_bytes = 415,499,392`
- read:
  - memory is excellent
  - compaction is too aggressive:
    - `store_compact_df_counts_us = 987,872,127`
  - total time regressed too far to keep as the default

Rejected `4x` memory-trigger result, early `26k` sample:
- artifact:
  - `/root/pertest/results/sspry_ingest_26000_20260316_memcap4/manual.info.full.2.json`
- at `5,362` active docs:
  - `current_rss_kb = 1,938,396`
  - `peak_rss_kb = 1,970,844`
  - `df_counts_delta_estimated_memory_bytes = 2,740,836,736`
- read:
  - too loose
  - already worse than the conservative run at the same stage
  - do not keep

Accepted `2x` memory-trigger result, `26k`:
- artifact:
  - `/root/pertest/results/sspry_ingest_26000_20260316_memcap2`
- final:
  - `verbose.index.total_ms = 1,211,234.179`
  - `verbose.index.submit_ms = 1,083,195.963`
  - `server_current_rss_kb = 2,197,996`
  - `server_peak_rss_kb = 2,321,064`
  - `server_df_counts_delta_estimated_memory_bytes = 955,866,816`
  - `store_us = 979,982,970`
  - `store_classify_us = 162,271,287`
  - `store_compact_df_counts_us = 749,467,991`
- read:
  - about `+6.2%` slower than the old `26k` baseline on wall time
  - but peak RSS is about `-53.1%` lower than the old baseline
  - this is the first tradeoff that actually bounds memory without destroying throughput

Accepted `2x` memory-trigger result, `50k`:
- artifact:
  - `/root/pertest/results/sspry_ingest_50000_20260316_memcap2`
- dataset:
  - files: `50,000`
  - bytes: `143,010,953,447`
  - GiB: `133.189329362474`
- final:
  - `verbose.index.total_ms = 3,559,505.755`
  - `verbose.index.submit_ms = 3,363,931.737`
  - `server_current_rss_kb = 3,459,408`
  - `server_peak_rss_kb = 3,702,620`
  - `server_df_counts_delta_estimated_memory_bytes = 0`
  - `store_us = 3,162,904,426`
  - `store_classify_us = 470,394,772`
  - `store_compact_df_counts_us = 2,279,577,581`
- read:
  - memory stays bounded into a much larger run
  - compaction dominates store time even more strongly than before
  - this should shift the next optimization pass from memory safety to compaction cost

## Landed Wins

Important kept changes already in `master`:
- Adaptive publish:
  - commit: `ce4d203`
  - fixed `--auto-publish-idle-ms` removed from `serve`
  - server now drives publish timing from:
    - visible publish latency
    - seal backlog
    - publish cadence
    - recent ingest/store pressure
    - storage-class initial bias
- Tier2 chunk folding:
  - commit: `84d882c`
  - removed the hot per-byte `% summary_bytes` fold loop
- DF delta map lookup improvement:
  - commit: `024e4b2`
- Insert-side batch bloom appends:
  - commit: `7e925f2`
  - large reduction in bloom payload append cost
- Insert classify improvements:
  - commit: `0448ecd`
- Insert batch metadata/DF hot-path cleanup:
  - commit: `a5f6673`
- Scan-side wins:
  - `66b8026`
  - `bac1dbb`
  - `658bcbd`
  - `6a89e4b`
  - `39c90d1`
- Persistent remote ingest RPC connection:
  - `35f7786`

## Active Backlog

### 1. Large-run `compact_df_counts` profiling

Why:
- On the `26k` ingest it was the single biggest store-side bucket:
  - `187,097,904 us`
- On the current-tree late-run rerun it is still first-tier:
  - `87,330,505 us` by `23,359` docs

Status:
- second-pass subphase instrumentation is now in place locally and should be kept
- first profiled rerun artifact:
  - `/root/pertest/results/sspry_ingest_26000_20260316_memcap2_profiled_rerun`
- later accepted-layout rerun with explicit close timing:
  - `/root/pertest/results/sspry_ingest_26000_20260316_memcap2_profiled_v2`

What it showed:
- the original zeroed subfields were an aggregation bug in `rpc.rs`, now fixed
- once fixed, the outer compaction bucket is no longer opaque
- on the accepted bounded-memory path, the dominant subphase is still the first
  syscall after the large snapshot rewrite:
  - at `4,770` docs:
    - `store_compact_df_counts_us = 51,310,625`
    - `persist_snapshot_collect_delta_us = 518,710`
    - `persist_snapshot_sort_delta_us = 1,641,037`
    - `persist_snapshot_merge_write_us = 1,022,996`
    - `persist_snapshot_flush_us = 1,311`
    - `persist_snapshot_close_us = 1,174`
    - `persist_snapshot_rename_us = 47,718,244`
- read:
  - the real cost is the full DF snapshot rewrite and the dirty-page writeback it triggers
  - it is not primarily sort cost
  - it is not primarily merge-loop CPU
  - it is not primarily file-close cost
  - `rename` is just where the kernel currently charges that writeback stall

Rejected follow-up from this finding:
- versioned snapshot files plus a small current-pointer file
  - artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260316_versioned`
  - result:
    - replacing the live snapshot path in place stopped being expensive
    - but the cost simply moved to the next tiny pointer-file write
    - by `4,356` docs:
      - `store_compact_df_counts_us = 62,338,905`
      - `persist_snapshot_rename_us = 9,199`
      - `persist_snapshot_publish_pointer_us = 59,220,051`
    - worse overall than the accepted path
  - conclusion:
    - the issue is not rename semantics alone
    - it is the full snapshot rewrite / writeback itself

Next step:
- stop trying to micro-fix rename
- reduce or eliminate full DF snapshot rewrites during compaction
- likely path:
  - move DF state toward an exact segment/LSM-style representation
  - bound memory by active batch/shard work
  - keep IO mostly sequential
  - avoid new resident indexes unless measurements prove they are cheap enough

Important note:
- A naive attempt to defer work-root DF compaction was benchmarked and rejected.
- Do not revive it without a stronger, narrower hypothesis.

Rejected experiment:
- local uncommitted patch was benchmarked and reverted

Additional rejected attempts from the `26k` / `50k` deterministic reruns:
- Exact streaming classify against DF snapshots:
  - `26k` artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260316_streaming_bounded`
  - `50k` artifact:
    - `/root/pertest/results/sspry_ingest_50000_20260316_streaming_bounded`
  - result:
    - faster on total time
    - still failed the memory bar badly
    - `26k` finished at about:
      - `server_current_rss_kb = 6,839,812`
      - `server_peak_rss_kb = 6,893,572`
    - `50k` was stopped early at `13.6%` because the RSS slope was already worse than the bad `26k` run
- Sparse fence-index classify + bounded forward scans:
  - artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260316_fence`
  - result:
    - early RSS looked slightly better than the streaming classify path
    - by `22.74%`, it was already at:
      - `current_rss_kb = 2,628,780`
      - `peak_rss_kb = 2,700,916`
    - not enough improvement to justify continuing
- Streaming DF snapshot write only:
  - artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260316_compaction_stream`
  - result:
    - tests passed
    - by `65.16%`, it was already at:
      - `current_rss_kb = 5,501,220`
      - `peak_rss_kb = 5,537,760`
    - already worse than the old full-run `26k` baseline before completion

Read from these failures:
- simply changing lookup locality is not enough
- simply removing the full merged DF payload buffer is not enough
- the next viable path likely needs a different exact DF representation or a different
  classify strategy that stays bounded by active batch/shard work instead of growing with
  large snapshot state
- A/B artifacts:
  - `/root/pertest/results/yaya_dfcompact_defer_ab_20260315/summary.json`
  - `/root/pertest/results/yaya_dfcompact_defer_ab_20260315_rev/summary.json`
- Read:
  - first order looked good
  - reverse-order check was mixed and base-path results regressed
  - not safe enough to keep

### 2. Server insert `classify` on large ingests

Why:
- Still a top store bucket after many earlier wins.
- On the `26k` ingest:
  - `store_classify_us = 108,499,451`

Current direction:
- Work inside `select_indexed_grams` / classify internals.
- Preserve the already-landed wins:
  - no full median sort
  - early return when budget keeps all eligible grams
  - reduced repeated DF normalization

Ideas worth testing:
- better data reuse around eligible/commonness vectors
- reduce repeated passes over the same gram/commonness pairs
- tighter handling for the common all-keep / mostly-keep path

### 3. `apply_df_counts` structural revisit

Why:
- Still material on larger ingests even after earlier hash-map work.
- On the `26k` ingest:
  - `store_apply_df_counts_us = 40,297,714`

What not to retry blindly:
- simple loop micro-tweaks
- obvious overlay maps
- reserve/remove-reserve toggles
- local run-length transforms

Those were already tried and did not clear the bar.

Better next direction:
- change the structure or cadence of DF application only after profiling `compact_df_counts`
- there may be more leverage in reducing compaction interaction than in shaving the raw apply loop

### 4. Re-profile insert/store on current `master`

Why:
- Adaptive publish is now landed.
- The next work should use current `master`, not older baselines.

Preferred harnesses:
- real-world:
  - `/root/pertest/results/yaya_ingest_26000_20260315`
- medium repeatable:
  - deterministic `2000 + 1000` slice from `/root/pertest/data/extracted`

Metrics to watch:
- `verbose.index.total_ms`
- `verbose.index.submit_ms`
- `server_index_insert_batch_store_us`
- `server_index_insert_batch_store_classify_us`
- `server_index_insert_batch_store_apply_df_counts_us`
- `server_index_insert_batch_store_compact_df_counts_us`
- `server_index_insert_batch_store_append_sidecars_us`

### 5. Adaptive publish validation on different storage classes

Current state:
- adaptive publish is landed in `ce4d203`
- live SSD smoke:
  - first publish visible in `256ms`
  - second publish visible in `171ms`

Artifact:
- `/root/pertest/results/yaya_adaptive_smoke_20260315_fix2`

Next checks:
- validate behavior on slower storage
- confirm that seal backlog causes sensible backoff
- confirm that the policy recovers to the fast band after backlog drains

Things to watch:
- `publish.adaptive_idle_ms`
- `publish.adaptive_mode`
- `publish.adaptive_reason`
- `published_df_snapshot_seal.pending_shards`
- `published_tier2_snapshot_seal.pending_shards`

## Rejected Experiments

These were tried and should not be repeated without a materially different hypothesis:
- quiet batch RPC / altered batch response path
  - signal too mixed
- bulk append experiment replacing export/import path
  - regression
- result-channel chunking
  - no real `result_wait_ms` improvement
- packed received-gram payload reuse for dual writes
  - regression
- batch-local DF overlay
  - no clear net win
- Tier2 map-structure rewrite
  - did not clear the bar
- naive defer-work-root DF compaction
  - mixed/order-sensitive result, reverted

## Search Safety Checks

When a performance patch changes anything near:
- classify
- DF
- Tier2 summaries
- publish/import

run a search compare.

Existing compare artifact:
- `/root/pertest/results/yaya_tier2_chunkfold_search_compare_20260315/summary.txt`

Useful sample queries:
- `powershell.exe`
- `mshta.exe`
- `dropbox.com`

If stronger verification is needed:
- rebuild a small slice with `--store-path`
- rerun with `--verify`

## Benchmark Discipline

Keep using this bar before landing performance changes:
- `cargo test -q` must pass
- benchmark against a clean baseline
- reverse order when the delta is small
- reject changes that only win in one order
- prefer deterministic file lists
- remove temporary worktrees after the benchmark

Useful reminder:
- do not let Git auto-maintenance kick back in during benchmark work
- keep benchmark artifacts in `/root/pertest/results/`
- keep only the main repo worktree unless an A/B run is actively using another one

## Search Shortcuts

Goal:
- add a deliberate shorthand layer for common search cases without weakening correctness
- keep false negatives impossible
- allow false positives only when the verifier/search pipeline already tolerates them

Scope ideas:
- aliases for the most common metadata fields and module expressions
- shorthand for common equality checks that already map cleanly to indexed search
- canonical expansion of shortcuts before planning so profiling/debugging still sees the real query shape

Constraints:
- shortcuts must expand to the existing restricted rule/search model
- no hidden semantics changes
- no shortcut should bypass verifier-only handling for numeric/module cases that still need it

## Search Optimization

Goal:
- reduce search latency and candidate counts without increasing false negatives

Current likely directions:
- planner-side shortcut expansion and normalization should happen before DF ordering and branch-budget decisions
- keep improving selectivity ordering for mixed:
  - string anchors
  - numeric-read anchors
  - metadata equality filters
- watch for unnecessary metadata/sidecar reads in candidate evaluation
- profile query-time costs separately for:
  - plan compile
  - DF lookup
  - candidate query
  - verification

Important constraints:
- HDD behavior matters; avoid optimizations that trade a small CPU win for materially more random IO
- keep memory pressure bounded during long-running searches and large candidate pages
- preserve the current bar:
  - false positives are acceptable
  - false negatives are not
