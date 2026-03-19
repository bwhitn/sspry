# Performance TODO

Current baseline:
- Repo: `/root/pertest/repos/yaya`
- Current pushed runtime baseline: `71ce8ed` `Reuse work stores on first workspace publish`
- Repo-local git auto maintenance is disabled during benchmark work:
  - `gc.auto = 0`
  - `maintenance.auto = false`

## Current State
- Bloom-only cutover is now the default live path:
  - public `candidate_df` replanning transport is removed
  - live exact-gram persistence is removed from ingest/import/delete
  - compatibility-only gram wire fields are removed from the app/RPC surface
  - the CLI no longer prints the retired `legacy_query:` exact-gram expression on search
  - query-plan wire decode no longer accepts the retired pre-`ast` payload shape
  - workspace startup now rejects the retired single `work/` root instead of auto-migrating it
  - candidate stats no longer emit the retired `gram_sizes` and `filter_bucket_counts` aliases
  - live duplicate/import timing metrics are renamed from `classify_*` to `resolve_doc_state_*`
  - the dead `ENABLE_PRESSURE_PUBLISH = false` gate is removed; live backpressure/pressure telemetry remains
  - bloom sizing no longer carries the dead `filter_size_divisor` parameter or its hardcoded `= 1` constants
  - the old test-only `scan_file_features_bloom_only()` convenience wrapper is removed; tests use the explicit gram-size scanner entrypoint now
  - the old default/tier2-size query-plan convenience wrappers are removed; tests use local helpers over `*_with_gram_sizes`
  - candidate insert wire now carries `bloom_item_estimate` / `tier2_bloom_item_estimate` and no longer carries redundant explicit bloom-hash counts
  - unused cargo dependencies `rustc-hash` and `hashbrown` are removed
  - the rpc transport integration test no longer duplicates local default-size bloom/query helper wrappers
- `features.rs` status:
  - default ingest is on the bloom-only scanner path
  - production `DocumentFeatures` no longer exposes the retired gram-era fields
  - the `entropy_*`, `bucket_*`, and exact-gram selection helpers are now test-only in `features.rs`
  - production still keeps the HLL `estimate_*grams*` helpers because app-side bloom sizing depends on them
  - dead public reexports for exact-gram helper utilities were removed from `candidate/mod.rs`
- `26k` bloom-only verification after the compatibility-wire cleanup:
  - artifact:
    - `/root/pertest/results/sspry_verify_26000_bloomcut_20260318_r2`
  - `index_wall_ms = 563,508`
  - `files_per_minute_wall = 2768.37`
  - `current_rss_kb = 243,800`
  - `peak_rss_kb = 354,084`
  - `db_bytes = 18,539,136,064`
  - `store_us = 28,269,116`
  - `store_classify_df_lookup_us = 0`
  - `store_append_sidecars_us = 26,714,030`
  - `store_tier2_update_us = 1,363,948`
- Read from that `26k` verification:
  - the bloom-only cleanup held under a real release ingest
  - the default path no longer performs any DF/classify lookup work
  - ingest/store time is now overwhelmingly bloom-side append work
- verification coverage now includes one full CLI roundtrip test:
  - `serve --store-path`
  - `index` over a temp dataset
  - wait for auto-publish
  - `search --verify`
  - `delete` the matching file path
  - assert the published search path immediately stops returning that verified match
  - note:
    - delete applies directly to the published store and the active work store
    - it does not wait for a second publish cycle

- Full-corpus run `r6` on `4cbcd5a` was rejected and stopped at `30,981 / 260,278` docs (`11.90%`).
- Grouped DF segment lookups regressed into very large exact local scans:
  - `store_classify_df_lookup_segment_rows_examined = 13,216,478,954`
  - `store_classify_df_lookup_segment_visits = 51,626`
  - `store_classify_df_lookup_segment_point_lookups = 0`
  - `store_classify_df_lookup_us = 159,136,764` at only `30,981` docs
- Memory interpretation for this regression:
  - `VmRSS = 4,786,084 KB`
  - `RssAnon = 1,597,620 KB`
  - `RssFile = 3,188,464 KB`
- Action: revert `4cbcd5a` and continue full-corpus testing from the safer fence-index baseline.


Latest large-run stall check:
- `120k` artifact root:
  - `/root/pertest/results/sspry_stallcheck_120000_20260317_r2`
- dataset:
  - files: `120,000`
  - bytes: `341,905,356,438`
  - GiB: `318.424113503657`
- result:
  - completed successfully
  - `index_wall_ms = 8,712,406`
  - `files_per_minute_wall = 826.41`
  - `avg_sampled_current_rss_kb = 7,233,236.88`
  - `max_sampled_current_rss_kb = 11,170,672`
  - `max_sampled_peak_rss_kb = 11,311,044`
  - `final_db_bytes = 110,684,438,124`

Important read from the `120k` run:
- the full-corpus stall does not reproduce at `120k`
- but ingest slows down steadily as the corpus grows
- the cleanest steady-state slowdown is `Q2 -> Q3`, not `Q1`
- `Q2 -> Q3` per-doc store growth:
  - `store_us/doc`: `65.4 ms -> 73.8 ms`
  - `classify_us/doc`: `11.0 ms -> 15.3 ms`
  - `classify_df_lookup_us/doc`: `9.8 ms -> 14.1 ms`
  - `compact_df_counts_us/doc`: `23.2 ms -> 29.1 ms`
  - `append_sidecars_us/doc`: `29.3 ms -> 27.8 ms`
- interpretation:
  - `classify_df_lookup` is the clearest monotonic scaler
  - `compact_df_counts` is the secondary steady-state grower
  - `append_sidecars` is still large, but it does not show the same clean steady-state worsening

Current large-ingest baseline on `master`:
- `26k` artifact root:
  - `/root/pertest/results/sspry_ingest_26000_20260316_doublebuf_reuse_r3`
- `50k` artifact root:
  - `/root/pertest/results/sspry_ingest_50000_20260316_doublebuf_reuse_r1`

Pressure-publish/backpressure validation on local `master`:
- valid `26k` pressure run:
  - `/root/pertest/results/sspry_ingest_26000_20260317_pressure_r6`
- tuned `50k` pressure validation:
  - `/root/pertest/results/sspry_ingest_50000_20260317_pressure_r3`
- current read:
  - the tuned policy now does the right thing operationally:
    - first pressure publish during active indexing is cheap and reuses work stores
    - later active-session publish thresholds shrink to smaller chunks
    - seal backlog blocks another pressure publish and converts into stronger ingest backpressure
    - current tuned active-session republish thresholds are:
      - `2048` docs
      - `4 GiB` estimated input bytes
  - validated large-run memory:
    - `26k`: `peak_rss_kb = 9,971,436`
    - `50k`: validated through `97.886%` with `peak_rss_kb = 9,851,628`
  - validated `26k` timing:
    - `total_ms = 725,760.387`
    - `submit_ms = 335,424.167`
    - `publish_runs_total = 2`
  - validated `50k` behavior:
    - `97.886%` sample:
      - `submitted_documents = 48,943`
      - `publish_runs_total = 2`
      - `last_publish_imported_docs = 9,228`
      - `index_backpressure_events_total = 687`
      - `index_backpressure_sleep_ms_total = 54,350`
      - `current_rss_kb = 9,184,488`
    - the earlier `13 GiB` second-publish spike did not recur after the tighter republish thresholds
  - operational follow-up:
    - verbose remote index RSS reporting now uses the lightweight status endpoint instead of full stats
    - the earlier `Resource temporarily unavailable (os error 11)` tail failure should be rechecked later on a full completed `50k`/larger run, but it is no longer blocking this pressure-policy tuning pass

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

Current large-run insert/store priority order:
- source:
  - `/root/pertest/results/sspry_stallcheck_120000_20260317_r2/final.info.light.json`
- `store_append_sidecars_us = 2,552,260,490`
- `store_classify_us = 2,356,714,720`
- `store_classify_df_lookup_us = 2,208,038,954`
- `store_compact_df_counts_us = 2,140,133,620`
- `store_apply_df_counts_us = 135,508,102`
- `store_tier2_update_us = 8,460,711`

Interpretation:
- first visible publish is no longer the main problem
- the current system is bottlenecked by server insert/store work again
- inside insert/store, the immediate optimization priorities are now:
  1. `classify_df_lookup`
  2. `compact_df_counts`
  3. `append_sidecars`
  4. `apply_df_counts`
- adaptive publish is currently backing off for ingest pressure on this workload, which is expected:
  - `adaptive_publish.mode = backoff`
  - `adaptive_publish.reason = submit_pressure_high`
- with the tuned pressure policy, active-session publish/import can now stay under the practical memory envelope on `26k` and `50k`
- for memory budgeting on a `16 GiB` deployment target, treat anon pressure as the primary limit:
  - monitor `RssAnon` / `Pss_Anon` and system `Active(anon) + Inactive(anon)` alongside `VmRSS`
  - file-backed mmap growth still matters for IO/locality, but `VmRSS` alone is too pessimistic for the server budget

Operational notes:
- the first-publish double-buffer reuse fix removed the pathological first-publish memory spike
- search still only sees the published store set
- remote indexing now retries narrow publish pauses, and publish waits for active sessions instead of poisoning them

Current profiling additions on local `master`:
- insert-side sidecar telemetry now also exposes:
  - `store_append_bloom_payload_assemble_us`
  - `store_append_metadata_payload_us`
  - `store_append_doc_row_build_us`
- per-session insert-batch submetrics are now reset correctly on new index sessions

Current sidecar read from the telemetry pass (`26k` profile):
- artifact:
  - `/root/pertest/results/sspry_ingest_26000_20260317_sidecar_profile_r1/final.info.light.json`
- `store_append_sidecars_us = 34,781,302`
- `store_append_sidecar_payloads_us = 33,455,741`
- `store_append_bloom_payload_assemble_us = 7,616,550`
- `store_append_bloom_payload_us = 17,760,087`
- `store_append_tier2_bloom_payload_us = 13,797,903`
- `store_append_doc_row_build_us = 6,542,741`
- `store_append_doc_records_us = 352,594`
- `store_append_metadata_payload_us = 143,540`

Interpretation:
- metadata payload writes are noise
- exact-gram sidecars are no longer the dominant sidecar problem
- the real sidecar pressure is:
  1. Tier1/Tier2 bloom payload handling
  2. doc-row build work
  3. much later, doc-record appends

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

### 0. Bloom-only `50k` experiment matrix

Why:
- exact indexed grams are currently a relatively small disk component compared with blooms
- if most real searches still fall through to bloom checks, exact grams/DF may be paying too much ingest cost for too little search value
- block-level coarse summaries scale better than adding more per-file structures

Immediate matrix:
- baseline `50k`: current exact-gram path with the default `4 KiB` Tier2 superblock summary cap
- bloom-only `50k`: `--no-grams` with the default `4 KiB` summary cap
- bloom-only `50k`: `--no-grams --tier2-superblock-summary-cap-kib 8`
- bloom-only `50k`: `--no-grams --tier2-superblock-summary-cap-kib 16`
- bloom-only `50k`: `--no-grams --tier2-superblock-summary-cap-kib 32`

Record for each run:
- index wall time
- average and interval files/minute
- DB bytes and largest file sizes per top-level buffer/root
- server `VmRSS`, `RssAnon`, `RssFile`, and system `Active(anon) + Inactive(anon)`
- compaction and publish timings
- post-publish search timings and candidate counts

Search set for the matrix:
- the 7 user-provided YARA rules as-is
- plus a few additional indexed-safe rules so the matrix still has meaningful indexed-search coverage when unsupported syntax appears in the user set

Interpretation target:
- if bloom-only materially improves ingest while search timings/candidate counts stay acceptable, revisit whether exact grams and DF should remain in the default path
- if bloom-only hurts search too much, keep exact grams and spend any extra budget on stronger block/superblock summaries before touching per-file bloom size

Current read after the `8/16/32 KiB` matrix:
- bloom-only is the current direction
- `32 KiB` is the best point so far on the `50k` matrix
- the DB growth from `8 KiB -> 32 KiB` is small enough to keep
- the remaining search problems are concentrated in a few heavy rules, not the whole search path
- `32 KiB` Tier2 superblock summaries consumed:
  - `301,526,016` bytes (`287.56 MiB`)
  - about `0.76%` of the whole `50k` DB

`50k` bloom-only matrix summary:
- `8 KiB`
  - index wall: `1900.58 s`
  - DB bytes: `39,725,199,651`
  - supported searches:
    - `01`: timed out at about `183.59 s`
    - `08`: `172.79 s`
    - `09`: `21.51 s`
    - `10`: `2.34 s`
    - `11`: `2.26 s`
    - `12`: `2.26 s`
- `16 KiB`
  - index wall: `1892.48 s`
  - DB bytes: `39,803,460,859`
  - supported searches:
    - `01`: timed out at about `183.71 s`
    - `08`: `193.53 s`
    - `09`: `5.62 s`
    - `10`: `2.28 s`
    - `11`: `2.23 s`
    - `12`: `2.21 s`
- `32 KiB`
  - index wall: `1614.96 s`
  - DB bytes: `39,928,655,219`
  - supported searches:
    - `01`: timed out at about `182.46 s`
    - `08`: `141.97 s`
    - `09`: `2.01 s`
    - `10`: `2.16 s`
    - `11`: `2.06 s`
    - `12`: `2.08 s`

Immediate search improvements on the bloom-only baseline:
1. keep `32 KiB` as the current coarse-summary baseline
2. done:
   - search no longer replans through the retired remote DF path
   - per-doc search evaluation now lazy-loads metadata and bloom sidecars instead of reading metadata + tier1 + tier2 up front for every scanned doc
3. done: re-profile the heavy supported rules on the `50k` `32 KiB` baseline after the lazy-load patch
  - artifact:
    - `/root/pertest/results/sspry_searchprofile_50000_32k_20260319_r3/search_summary.json`
  - all supported rules still scanned all `50,000` docs
  - all supported rules skipped `0` superblocks
  - all supported rules loaded all `50,000` tier1 blooms
  - tier1 bloom bytes touched per search:
    - `25,405,137,920` bytes (`23.66 GiB`)
  - heavy supported rule totals:
    - `01`: timed out at `180s+`
    - `08`: `177.56s`
    - `09`: `102.66s`
    - `10`: `14.59s`
    - `11`: `46.94s`
    - `12`: `29.75s`
4. current bottleneck read:
  - metadata is no longer the problem
  - planner/DF work is no longer the problem
  - block admission is doing no useful filtering on the `50k` `32 KiB` baseline
  - `64 KiB` helped some search totals on `50k`, but still skipped `0` superblocks and still loaded all `50,000` tier1 blooms
  - the next useful lever was smaller blocks plus a non-folded block-summary shape, not larger folded summaries
5. bloom-size cleanup:
  - new chosen bloom sizes should stay aligned to `8` bytes so future `u64`-oriented bloom paths remain possible without another format change
6. current local accepted search slice:
  - block summaries now use sampled exact `u64` words instead of modulo-folded OR summaries
  - search mask evaluation now uses `u64` word masks
  - admitted blocks prefetch tier1 bloom slices before per-doc evaluation
  - default `docs_per_block` is now `32` and still scales upward under the existing superblock-memory budget
  - local `26k` smoke comparison:
    - previous `128`-doc blocks:
      - artifact: `/root/pertest/results/sspry_searchsmoke_26000_32k_20260319_r1/search_summary.json`
      - `index_wall_ms = 722,055`
      - superblocks skipped per supported rule: `0-1`
      - `01`: `6.128 s`
    - new `32`-doc blocks:
      - artifact: `/root/pertest/results/sspry_searchsmoke_26000_32k_20260319_r2_block32/search_summary.json`
      - `index_wall_ms = 561,343`
      - superblocks skipped per supported rule: `10-49`
      - `01`: `1.104 s`
  - full `50k` validation on this baseline:
    - artifact: `/root/pertest/results/sspry_searchprofile_50000_32k_20260319_r4/search_summary.json`
    - `index_wall_ms = 1,629,496`
    - publish finished cleanly with `current_rss_kb = 1,107,468`, `peak_rss_kb = 1,272,588`
    - supported-rule totals:
      - `01`: `267.88 s`
      - `08`: `7.96 s`
      - `09`: `24.67 s`
      - `10`: `1.79 s`
      - `11`: `10.55 s`
      - `12`: `3.79 s`
    - supported-rule scan shape:
      - docs scanned: `49,884-49,966 / 50,000`
      - superblocks skipped: `12-29`
      - tier1 bloom loads: `49,884-49,966`
      - tier1 bloom bytes per search: about `25.40 GiB`
    - read:
      - this is better than the old all-zero-skip path, but still far too close to a full scan
      - `08` improved dramatically, but `01` is still unacceptable and `09/11/12` are still too expensive
      - this baseline is not ready for `100k`
  - dual-gate `50k` follow-up:
    - artifact: `/root/pertest/results/sspry_searchprofile_50000_32k_20260319_r5/search_summary.json`
    - change set:
      - add a second block gate over tier2 blooms
      - batch dense tier1 block reads through one contiguous mmap span when offsets are packed enough
    - `index_wall_ms = 1,841,625`
    - supported-rule totals:
      - `01`: `233.38 s`
      - `08`: `12.78 s`
      - `09`: `25.87 s`
      - `10`: `1.81 s`
      - `11`: `10.97 s`
      - `12`: `3.16 s`
    - supported-rule scan shape:
      - docs scanned: `49,873-49,966 / 50,000`
      - superblocks skipped: `12-30`
      - tier1 bloom loads: `49,873-49,966`
      - tier1 bloom bytes per search: still about `25.40 GiB`
    - read:
      - this improved `01` and `12`, but block rejection still barely moved
      - the dense read path is not enough by itself because the current sampled-word summary still admits almost every block
      - the next search cut has to be a stronger dedicated block signature, not more tuning on the current sampled summary
  - next validation should not be `100k`; the next useful step is a stronger block gate and true contiguous block bloom reads before trying larger corpus search runs

Current indexing follow-up:
- accepted next cut:
  - batch `sha_by_docid`, `doc_meta`, and `tier2_doc_meta` appends in the hot insert path instead of appending those doc records one document at a time
- why:
  - the finished `50k` search-profile run still showed `store_append_sidecars_us = 563,206,853` out of `store_us = 586,659,295`
  - the write path is still the main indexing slope problem after the bloom-only cutover
- next validation:
  - rerun a quick `26k` or `50k` ingest slice on the batched doc-record path before doing larger-corpus indexing again

Current local `26k` smoke check for the lazy-load search patch:
- artifact:
  - `/root/pertest/results/sspry_searchopt_26000_32k_20260318_r1`
- `index_wall_ms = 550,937`
- `db_bytes = 18,590,729,011`
- `current_rss_kb = 701,284`
- `peak_rss_kb = 701,284`
- `last_publish_duration_ms = 88`
- supported-rule search totals:
  - `01`: `0.810 s`, `0` candidates
  - `08`: `0.705 s`, `151` candidates
  - `09`: `0.777 s`, `168` candidates
  - `10`: `0.852 s`, `0` candidates
  - `11`: `0.802 s`, `3` candidates
  - `12`: `0.776 s`, `10` candidates
- read:
  - the lazy-load patch is functionally clean on a real bloom-only ingest/search pass

Current local search-worker follow-up:
- change set:
  - query scanning inside one store now parallelizes across blocks with bounded worker threads
  - the live path still uses the existing sampled-word block gate and dense tier1 block prefetch
- `2000`-file published smoke artifact:
  - `/root/pertest/results/sspry_smoke_parallel_2000_20260319_r1`
- dataset:
  - `/root/pertest/results/sspry_dataset_2000_sorted_20260319_from26000/dataset.json`
  - `file_count = 2,000`
  - `bytes_total = 6,552,639,181`
- index/publish:
  - `elapsed_ms = 157,451.837`
  - `files_per_minute_wall = 762.14`
  - `server_peak_rss_kb = 502,092`
  - `last_publish_duration_ms = 85`
  - `last_publish_reused_work_stores = true`
- supported-rule search totals:
  - `01`: `0.166 s`, `docs_scanned = 1,286`, `superblocks_skipped = 114`
  - `08`: `0.122 s`, `docs_scanned = 1,922`, `superblocks_skipped = 17`
  - `09`: `0.172 s`, `docs_scanned = 1,791`, `superblocks_skipped = 42`
  - `10`: `0.172 s`, `docs_scanned = 909`, `superblocks_skipped = 151`
  - `11`: `0.146 s`, `docs_scanned = 1,494`, `superblocks_skipped = 84`
  - `12`: `0.147 s`, `docs_scanned = 1,630`, `superblocks_skipped = 61`
- read:
  - the bounded worker scan path is functionally clean on published search
  - the query wall times are now comfortably sub-second on this small published slice
  - block rejection is still the structural next target on larger corpora; worker parallelism reduces wall time but does not change the underlying admitted-block rate
  - all six supported rules completed without timeout on the `26k` smoke run
  - next validation should be the same search pack on the `50k` `32 KiB` baseline

Rejected follow-ups on top of the worker path:
- sampled lane summaries inside `32`-doc blocks
  - artifact:
    - `/root/pertest/results/sspry_smoke_lane4_2000_20260319_r2/search_summary.json`
  - kept total summary bytes bounded and held `docs_per_block = 32`
  - but search got worse than the worker-only baseline:
    - `08`: `docs_scanned 1993`, `superblocks_skipped 3`
    - `09`: `docs_scanned 1954`, `superblocks_skipped 10`
    - `10`: `docs_scanned 1287`, `superblocks_skipped 88`
    - `11`: `docs_scanned 1808`, `superblocks_skipped 33`
    - `12`: `docs_scanned 1936`, `superblocks_skipped 12`
  - not worth carrying to `50k`
- folded `u64`-word lane signatures
  - artifact:
    - `/root/pertest/results/sspry_smoke_lane4_2000_20260319_r3/search_summary.json`
  - slightly better ingest/storage shape than sampled lanes
  - but block rejection collapsed even further:
    - `08`: `docs_scanned 1998`, `superblocks_skipped 1`
    - `09`: `docs_scanned 1989`, `superblocks_skipped 2`
    - `10`: `docs_scanned 1955`, `superblocks_skipped 4`
    - `11`: `docs_scanned 1988`, `superblocks_skipped 2`
    - `12`: `docs_scanned 1988`, `superblocks_skipped 3`
  - rejected
- current read:
  - deriving block gates from the existing per-doc bloom bytes is not strong enough
  - the next credible search move is a dedicated block-gate signature built from the scan path itself, not another transformation of the stored per-doc blooms

### 0a. Bloom-only cutover and dead-code removal

Accepted direction:
- bloom-only is now the working default direction
- exact grams and DF are being treated as legacy code pending removal

Removal phases:
1. Search-side cutover
   - done:
     - default search no longer uses remote `candidate_df`
     - local query path also no longer replans with DF
     - verbose timing still reports `df_lookup_ms = 0.000`
2. Query-planner/RPC cleanup
   - done:
     - removed the dead `candidate_df` client/server transport and tests
     - removed the remaining default-path `df_counts` planner wiring
     - query-plan compilation now uses one bloom-only anchor-ordering path
3. Store persistence cleanup
   - done:
     - live bloom-only ingest no longer persists exact grams
      - empty `grams_received.bin` / `grams_indexed.bin` files are no longer materialized during compaction/import
      - publish/import structs no longer carry gram payload bytes/counts through the live bloom-only path
      - dead tier1 exact-gram selection code has been removed
     - removed the gram sidecar plumbing entirely from the live store path
     - removed dead exact-gram sidecar helpers and related sidecar retarget tests
4. CLI/test cutover
   - done:
     - added coverage for the planner cutover and store cleanup slices
     - removed dual-mode compatibility tests and fixtures that only existed to preserve exact-gram wire behavior
5. Final cleanup
   - remove `--no-grams` once bloom-only is the only ingest mode
   - remove dead docs, counters, and benchmark branches tied only to exact grams/DF
6. DF storage removal
   - done:
     - removed DF deltas, segments, compaction/seal paths, RPC stats, and related tests from the normal bloom-only path
     - removed the remaining compatibility-only field names/counters that still mentioned grams or DF externally

`features.rs` read after the bloom-only cutover:
- the main app index path is now on the dedicated bloom-only scan entrypoint
- normal ingest no longer collects `unique_grams`
- the remaining gram-era logic in `features.rs` is test scaffolding, not live ingest behavior

Current local `26k` verification on the bloom-only cleanup tree:
- artifact:
  - `/root/pertest/results/sspry_verify_26000_bloomcut_20260318_r1`
- result:
  - completed successfully
  - `index_return_ms = 787,709`
  - `files_per_minute = 1,980.43`
  - `current_rss_kb = 333,160`
  - `peak_rss_kb = 397,792`
  - `last_publish_duration_ms = 88`
- insert-store read:
  - `store_us = 53,005,196`
  - `store_classify_df_lookup_us = 0`
  - `store_append_sidecars_us = 51,513,044`
  - `store_tier2_update_us = 1,326,464`
- read:
  - the bloom-only cutover survived a real deterministic ingest after the store/planner cleanup
  - default ingest is now overwhelmingly dominated by bloom sidecar append work, not DF/classify

Required tests while cutting over:
- search verbose output still reports timing fields
- remote search and verify continue to work on the bloom-only path
- candidate paging/counting does not regress when DF lookup is removed from the default search flow

### 1. Server insert `classify_df_lookup` on large ingests

Why:
- this is the clearest monotonic steady-state grower on the `120k` run
- current `120k` measurement:
  - `store_classify_df_lookup_us = 2,208,038,954`
- clean steady-state growth:
  - `Q2 -> Q3`: `9.8 ms/doc -> 14.1 ms/doc`

Constraints:
- do not reintroduce the old RSS growth / random-IO failure modes
- memory must stay bounded on `26k`, `50k`, and `120k`
- HDD behavior matters as much as SSD behavior

Immediate next work:
- add finer lookup-shape profiling inside `select_indexed_grams`
- identify the exact split between:
  - snapshot scan distance
  - segment fan-out
  - segment linear scans vs point lookups
  - delta overlay lookups
- only then attempt another structural optimize pass

Current lookup-shape telemetry status:
- landed on local `master` in the current work-in-progress branch
- early live `26k` read (`0.49%`):
  - `classify_df_lookup_delta_lookups = 1,585,826`
  - snapshot/segment counters were still `0`
- later live `26k` read (`39.68%`):
  - `classify_df_lookup_segment_visits = 10,281`
  - `classify_df_lookup_segment_rows_examined = 1,395,035,912`
  - `classify_df_lookup_segment_point_lookups = 3,916,265`
  - `classify_df_lookup_delta_lookups = 119,850,601`
- read:
  - early classify lookup is dominated by the delta overlay
  - later classify lookup is doing both:
    - heavy linear segment row examination
    - a meaningful amount of segment point lookup work
  - that is enough evidence to target segment lookup shape next instead of guessing

Clean large-run baseline with lookup-shape telemetry:
- `50k` artifact:
  - `/root/pertest/results/sspry_ingest_50000_20260317_baseline_lookupshape_r1/summary.json`
- result:
  - wall: `2,222,174 ms`
  - current RSS: `5,710,748 KB`
  - peak RSS: `5,740,812 KB`
  - `store_classify_df_lookup_us = 771,462,568`
  - `classify_df_lookup_segment_point_lookups = 966,912,699`
  - `classify_df_lookup_segment_rows_examined = 0`
  - `classify_df_lookup_segment_visits = 89,132`
  - `classify_df_lookup_delta_lookups = 547,852,118`
- read:
  - on the accepted baseline, late-run classify lookup is dominated by segment point lookups
  - linear segment scans are not the main cost on this path
  - segment fan-out is already low enough that reducing point-lookup cost matters more than reducing visits

Accepted follow-up:
- sparse exact per-segment fence index for DF segment point lookups
  - `26k` artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260317_fence_r1/summary.json`
  - `50k` artifact:
    - `/root/pertest/results/sspry_ingest_50000_20260317_fence_r1/summary.json`
  - `50k` telemetry baseline -> fence:
    - wall: `2,222,174 -> 1,939,193 ms` (`-12.7%`)
    - `classify_df_lookup_us`: `771,462,568 -> 518,609,072` (`-32.8%`)
    - `classify_us`: `843,705,371 -> 594,560,288` (`-29.5%`)
    - current RSS: `5,710,748 -> 5,698,116 KB` (flat)
    - peak RSS: `5,740,812 -> 5,841,312 KB` (`+1.8%`)
  - read:
    - this is the first classify_df_lookup change that materially improved the `50k` large-run baseline without breaking the memory envelope
    - keep this path and use it as the new classify baseline

Updated immediate priority order after the fence-index change:
1. remaining `classify` cost
2. `append_sidecars`
3. `compact_df_counts`
4. `apply_df_counts`

Rejected follow-up after lookup-shape profiling:
- range-aware segment pruning plus relevant-span scan selection
  - `26k` artifact:
    - `/root/pertest/results/sspry_ingest_26000_20260317_segmentrange_r2/summary.json`
  - `50k` artifact:
    - `/root/pertest/results/sspry_ingest_50000_20260317_segmentrange_r1/summary.json`
  - `26k` baseline -> experiment:
    - wall: `743,419 -> 770,317 ms` (`+3.6%`)
    - current RSS: `4,068,564 -> 3,905,468 KB` (`-4.0%`)
    - peak RSS: `4,228,352 -> 4,026,760 KB` (`-4.8%`)
  - `50k` baseline -> experiment:
    - wall: `1,860,862 -> 2,551,075 ms` (`+37.1%`)
    - current RSS: `6,223,800 -> 5,648,160 KB` (`-9.2%`)
    - peak RSS: `6,413,300 -> 5,783,752 KB` (`-9.8%`)
  - read:
    - memory moved the right way
    - runtime regressed far too much, especially at `50k`
    - do not keep this path

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

### 2. Large-run `compact_df_counts`

Why:
- this is the secondary steady-state grower on the `120k` run
- current `120k` measurement:
  - `store_compact_df_counts_us = 2,140,133,620`
- clean steady-state growth:
  - `Q2 -> Q3`: `23.2 ms/doc -> 29.1 ms/doc`

Likely directions:
- keep the exact segment/tiered DF representation
- reduce merge/write cost without rebuilding large resident state
- measure write amplification directly on `50k` and `120k`

### 3. `append_sidecars` on large ingests

Why:
- this is still the largest absolute store bucket on the `120k` run
- current `120k` measurement:
  - `store_append_sidecars_us = 2,552,260,490`

What is already known:
- metadata payload writes are noise
- bloom payload handling and doc-row build work dominate
- sidecars are large, but they are not the cleanest steady-state scaler

Next direction:
- keep the new subphase split
- focus on bloom payload handling and doc-row build work
- prefer reductions in encoding/write amplification over resident caches

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
- classify partial-selection / `select_nth_unstable` pass
  - `26k` looked good
  - `50k` store/classify drifted the wrong way
  - do not retry without a different late-run hypothesis
- lower-copy vectored bloom sidecar append
  - removed bloom assembly cost
  - late `50k` write pressure shifted into doc-row/doc-record cost
  - no net keepable win
- DF row-buffer compaction write pass
  - `26k` top-line stayed flat
  - compaction bucket itself regressed
  - not worth keeping

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
- startup rejects the retired single `work/` root
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
