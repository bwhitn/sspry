# NOW

This file is the short-horizon worklist.

It reflects the current state after the `100k` balanced forest ingest/search experiment.

## Immediate Priorities

### 1. Keep the many-tree ingest direction, but only for ingest

Current state:
- `4 x 25k` byte-balanced trees with explicit writeback drain kept `100k` ingest in a tight `844-875 files/min` band
- this is materially better evidence than the earlier collapsing single-tree and naive forest runs
- the drain phase is doing real work; it reliably clears dirty/writeback backlog before the next tree

Work:
- treat `older trees immutable` as the leading storage direction
- keep one active mutable tree and roll to a new tree at the measured writeback knee
- preserve the writeback-aware forest harness as the evaluation path for larger ingest runs

Exit criteria:
- the many-tree ingest shape is the default scaling experiment for `100k+`
- tree rollover and drain behavior are documented as the current ingest strategy

### 2. Fix large-corpus search on the many-tree shape

Current state:
- the `100k` forest fanout fixed the old `01` timeout case
- other supported rules are still too slow:
  - `08`: `289.914 s`
  - `09`: `251.910 s`
  - `10`: `73.704 s`
  - `11`: `205.955 s`
  - `12`: `209.681 s`
- queries still scan almost the full corpus and read about `53 GiB` of tier1 bloom data per search

Work:
- reduce reopened-tree full-scan behavior before touching more corpus size
- focus on:
  - tree-level / block-level prefilters that actually reject work
  - reopened-search locality
  - tier1 bloom I/O reduction
- keep forest fanout measurements as the main search benchmark for this architecture

Exit criteria:
- supported forest searches at `100k` stop behaving like near-full scans
- heavy rules no longer sit in the multi-minute range

### 3. Continue reducing the write-path slope

Current state:
- `append_sidecars` is still the dominant ingest hot bucket
- exact-capacity payload assembly is a real improvement and should remain the baseline

Work:
- keep attacking `append_sidecars`
- keep `append_doc_records_us` and `tier2_update_us` secondary targets
- prefer changes that improve sustained large-corpus throughput, not short synthetic wins

Exit criteria:
- the next `100k+` ingest run improves sustained files/min materially from the current forest baseline
- writeback pressure is lower or easier to drain between trees

## Order

Work these in this order:
1. keep the many-tree ingest direction
2. fix large-corpus search on top of it
3. continue reducing the write-path slope

Only after these are stable do we return to broader cleanup or new feature work.
