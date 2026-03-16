# Performance TODO

Current baseline:
- Repo: `/root/pertest/repos/yaya`
- Current pushed runtime baseline: `71ce8ed` `Reuse work stores on first workspace publish`
- Repo-local git auto maintenance is disabled during benchmark work:
  - `gc.auto = 0`
  - `maintenance.auto = false`

## Current State

Current large-ingest baseline on `master`:
- `26k` artifact root:
  - `/root/pertest/results/sspry_ingest_26000_20260316_doublebuf_reuse_r3`
- `50k` artifact root:
  - `/root/pertest/results/sspry_ingest_50000_20260316_doublebuf_reuse_r1`

`26k` current system:
- dataset:
  - files: `26,000`
  - bytes: `65,094,641,220`
  - GiB: `60.624108854681`
- index wall:
  - `743,419 ms`
- first publish:
  - `publish_wait_ms = 61`
  - `last_publish_duration_ms = 137`
  - `last_publish_reused_work_stores = true`
- memory:
  - `current_rss_kb = 4,068,564`
  - `peak_rss_kb = 4,228,352`

`50k` current system:
- dataset:
  - files: `50,000`
  - bytes: `143,010,953,447`
  - GiB: `133.189329362474`
- index wall:
  - `2,148,392 ms`
- first publish:
  - `publish_wait_ms = 181`
  - `last_publish_duration_ms = 876`
  - `last_publish_reused_work_stores = true`
- memory:
  - `current_rss_kb = 6,223,800`
  - `peak_rss_kb = 6,413,300`

Current `50k` insert/store bottleneck order:
- source:
  - `/root/pertest/results/sspry_ingest_50000_20260316_doublebuf_reuse_r1/post_publish.info.light.json`
- `store_classify_us = 412,937,353`
- `store_append_sidecars_us = 312,177,864`
- `store_compact_df_counts_us = 169,653,717`
- `store_apply_df_counts_us = 59,071,649`
- `store_tier2_update_us = 3,560,237`

Interpretation:
- first visible publish is no longer the main problem
- the current system is bottlenecked by server insert/store work again
- inside insert/store, the priorities are now:
  1. `classify`
  2. `append_sidecars`
  3. `compact_df_counts`
  4. `apply_df_counts`
- adaptive publish is currently backing off for ingest pressure on this workload, which is expected:
  - `adaptive_publish.mode = backoff`
  - `adaptive_publish.reason = submit_pressure_high`

Operational notes:
- the first-publish double-buffer reuse fix removed the pathological first-publish memory spike
- search still only sees the published store set
- remote indexing now retries narrow publish pauses, and publish waits for active sessions instead of poisoning them

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

### 1. Server insert `classify` on large ingests

Why:
- this is now the largest store bucket on the current `50k` baseline
- current measurement:
  - `store_classify_us = 412,937,353`

Constraints:
- do not reintroduce the old RSS growth / random-IO failure modes
- memory must stay bounded on `26k` and `50k`
- HDD behavior matters as much as SSD behavior

Immediate next work:
- add finer subphase profiling inside `select_indexed_grams`
- identify the exact split between:
  - DF/commonness lookup
  - eligibility filtering
  - ranking / budget selection
  - final gram materialization
- only then attempt another structural optimize pass

Latest live `26k` classify profile:
- artifact:
  - `/root/pertest/results/sspry_ingest_26000_20260316_classify_profile_r2/live.info.light.3.json`
- at `8,465 / 26,000` docs:
  - `store_classify_us = 26,819,278`
  - `store_classify_df_lookup_us = 13,111,118`
  - `store_classify_binning_us = 6,276,715`
  - `store_classify_eligibility_us = 3,752,417`
  - `store_classify_finalize_us = 2,410,269`
  - `store_classify_dedup_us = 309,739`
  - `store_classify_budget_us = 158,650`
- read:
  - classify is not dominated by dedup or budget math
  - the growing classify cost is exact DF lookup first, binning/sorting second
  - any next pass should target those two areas first

Rejected follow-up:
- batch-local exact DF cache across a single insert batch
  - artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260316_classify_cache_r1/live.info.light.1.json`
  - read:
    - early `15.8%` sample regressed `store_classify_df_lookup_us` enough to reject quickly
    - do not keep this approach

### 2. `append_sidecars` on large ingests

Why:
- this is now the second-largest store bucket on the current `50k` baseline
- current measurement:
  - `store_append_sidecars_us = 312,177,864`

Likely directions:
- split payload build vs payload append vs fsync/writeback-visible stalls
- re-check bloom payload work under the current tiered DF baseline
- prefer reductions in re-encoding and write amplification over new resident caches

### 3. Large-run `compact_df_counts`

Why:
- compaction is still expensive even though it is no longer the top bucket
- current `50k` measurement:
  - `store_compact_df_counts_us = 169,653,717`

What is already known:
- the old bounded-memory snapshot rewrite path paid heavily in writeback stall
- full snapshot rewrite / writeback was the real issue, not sort cost
- several snapshot-local fixes were already rejected

Next direction:
- keep profiling and refining the newer exact segment/tiered DF approach
- measure write amplification directly on `26k` and `50k`
- prefer sequential IO and bounded resident state

### 4. `apply_df_counts` structural revisit

Why:
- still material at scale even after earlier wins
- current `50k` measurement:
  - `store_apply_df_counts_us = 59,071,649`

What not to retry blindly:
- simple loop micro-tweaks
- obvious overlay maps
- reserve/remove-reserve toggles
- local run-length transforms

Better direction:
- revisit after the current classify and compaction profiling, because apply cost may be coupled to the DF layout shape

### 5. Re-profile insert/store on current `master`

Required harnesses:
- `26k`
  - `/root/pertest/results/sspry_ingest_26000_20260316_doublebuf_reuse_r3`
- `50k`
  - `/root/pertest/results/sspry_ingest_50000_20260316_doublebuf_reuse_r1`
- medium deterministic slice if needed for quick A/B checks

Always watch:
- `verbose.index.total_ms`
- `verbose.index.submit_ms`
- `server_index_insert_batch_store_us`
- `server_index_insert_batch_store_classify_us`
- `server_index_insert_batch_store_append_sidecars_us`
- `server_index_insert_batch_store_compact_df_counts_us`
- `server_index_insert_batch_store_apply_df_counts_us`
- `server_current_rss_kb`
- `server_peak_rss_kb`

### 6. Adaptive publish validation on different storage classes

Current state:
- visible publish is now cheap again on the large SSD runs
- `26k` first publish:
  - `137 ms`
- `50k` first publish:
  - `876 ms`

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

### 7. Search shortcuts

Goal:
- add a deliberate shorthand layer for common search cases without weakening correctness
- keep false negatives impossible
- allow false positives only when the verifier/search pipeline already tolerates them

Constraints:
- shortcuts must expand to the existing restricted rule/search model
- no hidden semantics changes
- no shortcut should bypass verifier-only handling for numeric/module cases that still need it

### 8. Search optimization

Goal:
- reduce search latency and candidate counts without increasing false negatives

Current likely directions:
- planner-side shortcut expansion and normalization should happen before DF ordering and branch-budget decisions
- keep improving selectivity ordering for mixed:
  - string anchors
  - numeric-read anchors
  - metadata equality filters
- reduce unnecessary metadata/sidecar reads
- keep HDD behavior and memory bounded

### 9. Workspace double buffering follow-ups

Current state:
- publish now swaps work buffers and reuses work stores on first publish
- active remote indexing no longer fails when publish overlaps it

Open items:
- new index sessions are still blocked while publish is in progress
- search still takes the publish gate during published-root mutation
- stats/info still primarily expose the active work root
- continue perf validation from this new baseline instead of the pre-handoff model

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

## Workspace Double Buffering

Current state:
- landed dual work roots for workspace mode:
  - `work_a`
  - `work_b`
- startup migrates a legacy single `work/` root to `work_a/`
- publish now swaps the active work root first, then publishes the old root
- workspace inserts are no longer blocked on the global publish gate
- search still reads only the published root and remains isolated from in-flight work

What this enables now:
- an active remote index session can keep inserting across a manual publish
- the first publish only exposes the pre-swap work buffer
- later inserts stay in the new active work buffer until the next publish

What is still not done:
- new index sessions are still blocked while a publish is in progress
- search is still blocked by the publish operation gate while published roots are being mutated
- stats/info only surface the active work root; they do not expose the idle root yet

Next likely steps:
- decide whether to allow new index sessions during publish or keep only the active-session overlap
- narrow the publish gate further if we want search to stay live through more of publish
- add targeted perf runs to measure whether double-buffering changes publish latency or long-ingest throughput
