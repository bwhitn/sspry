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
- the accepted whole-tree gate now rejects some trees before any per-doc bloom I/O
- supported `200`-file forest smoke:
  - `01`: `docs_scanned = 0`, `tier1_bloom_bytes = 0`
  - `10`: `docs_scanned = 0`, `tier1_bloom_bytes = 0`
  - `11`: `docs_scanned = 9`, `tier1_bloom_bytes = 14.35 MiB`
  - `12`: `docs_scanned = 4`, `tier1_bloom_bytes = 6.99 MiB`
  - `08`: `docs_scanned = 24`, `tier1_bloom_bytes = 24.45 MiB`
  - `09`: `docs_scanned = 26`, `tier1_bloom_bytes = 21.77 MiB`
- the `100k` forest is still not good enough:
  - `08`: `396.535 s`
  - `09`: `316.611 s`
  - `10`: `88.383 s`
  - `11`: `264.048 s`
  - `12`: `181.229 s`
- large-corpus queries still scan too much inside trees and still move about `53 GiB` of tier1 bloom data per search

Work:
- keep the whole-tree gate and push the next selectivity layer inside each tree
- focus on:
  - within-tree prefilters that actually reject work after a tree passes the tree gate
  - reopened-search locality
  - tier1 bloom I/O reduction
- keep forest fanout measurements as the main search benchmark for this architecture

Exit criteria:
- supported forest searches at `100k` stop behaving like near-full scans inside accepted trees
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
