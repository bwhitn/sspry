# Performance TODO

Current baseline:
- Repo: `/root/pertest/repos/yaya`
- Current `HEAD`: `ce4d203` `Make auto publish adaptive`
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

Useful current comparison run:
- Artifact root: `/root/pertest/results/yaya_incremental_large_auto_20260315`
- Current `2000 + 1000`, auto workers:
  - base `2000`
    - `total_ms = 8754.050`
    - `submit_ms = 7355.708`
  - incremental `+1000`
    - `total_ms = 8338.243`
    - `submit_ms = 5793.406`

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

Next step:
- Add a deeper breakdown inside `maybe_compact_df_counts()`:
  - snapshot persist time
  - snapshot refresh time
  - append-writer reopen time
  - any extra file-size checks / metadata work

Goal:
- Determine whether the cost is mostly:
  - snapshot write IO
  - snapshot reload IO
  - writer lifecycle churn
  - or compaction frequency

Important note:
- A naive attempt to defer work-root DF compaction was benchmarked and rejected.
- Do not revive it without a stronger, narrower hypothesis.

Rejected experiment:
- local uncommitted patch was benchmarked and reverted
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
