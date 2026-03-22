# NOW

This file is the short-horizon worklist.

It reflects the current state after the `25k` and `50k` scaling passes on the curated searchable rule set.

## Immediate Priorities

### 1. Keep search and index practical on a `16 GiB` target

Current state:
- remote index session segmentation plus forced publish boundaries cut the early `25k` index memory spike from about `13.26 GiB` anon to about `1.38 GiB` at first publish
- search-side retained memory is materially better after prepared-plan cache caps and mask dedup
- the remaining memory problem is not generic RSS inflation; it is rule-shape-specific active query cost plus large file-backed residency on large corpora

Work:
- keep the segmented single-worker-safe remote index path as the safe default
- keep using `smaps_rollup` plus live `info --light` to separate anonymous from file-backed memory
- reject structurally unsafe search rules instead of trying to force them through the scaling-safe set

Exit criteria:
- the default remote ingest path stays under the practical `16 GiB` budget envelope
- large-corpus search does not need ad hoc cache flushing or one-off tuning to stay stable

### 2. Reduce `docs_scanned` on the remaining broad-but-allowed search families

Current state:
- high-fanout union rules with no mandatory anchorable pattern are now rejected up front
- low-information `at pe.entry_point` stub rules are now rejected up front
- short suffix/range rules with only tiny near-EOF literals are now rejected up front
- the next remaining bad family is rules that are still structurally searchable but scan too much of the corpus
- current evidence says candidate pruning improved first; the next meaningful win has to happen earlier in the scan path

Work:
- rank remaining heavy rules by `docs_scanned`, not just `query_ms`
- separate:
  - common-anchor / common-gram rules
  - genuinely salvageable rules with stronger mandatory structure
- keep removing rules from the scaling-safe set when there is no recall-safe path to narrow the first scan

Exit criteria:
- the remaining scaling-safe set no longer contains near-full-corpus scan rules at `50k`
- `docs_scanned` is the primary metric that improves, not just candidate count

### 3. Preserve fast iteration on large corpora

Current state:
- `run_forest_probe.py --reuse-existing-db` exists and is the right default for search tuning
- the probe defaults now target:
  - `10,000` files per tree
  - `120s` per-tree search timeout before tree-batch scaling
- preserved `25k` and `50k` DB roots are now part of the normal profiling workflow
- per-rule prepared-query memory profiling is available in verbose search output
- `search --root` plus `--tree-search-workers` now exists for in-process forest search and tree-level concurrency checks
- `search-batch` now exists for long-lived in-process forest sweeps without per-rule reopen overhead
- early `50k` batch checkpoints show the control-flow is correct, but resident memory still climbs too much for this to replace the persistent server path as the default tuning loop yet
- clearing local prepared-query caches between batch rules materially reduced search-batch anon on the preserved `50k` slice
  - `5`-rule slice:
    - anon max: about `11.64 GiB -> 3.71 GiB`
    - peak RSS: about `55.77 GiB -> 47.84 GiB`
    - private clean stayed about flat at `44.13 GiB`

Work:
- keep search tuning on reused DBs, not fresh rebuilds
- keep emitting per-rule prepared-query memory fields during profiling
- use `search-batch` for direct-forest repeated sweeps
- keep one-shot `search --root` for correctness / threading spot checks
- keep the persistent server path as the default large-slice tuning loop until `search-batch` resident memory is lower
- treat the remaining `search-batch` memory problem as mostly file-backed residency driven by scan breadth, not retained anon cache growth
- update docs whenever the searchable/scaling-safe boundary changes

Exit criteria:
- planner/runtime tuning loops do not require re-indexing just to measure search changes
- rule-family profiling and rebucketing are documented and repeatable

## Order

Work these in this order:
1. keep memory practical on the `16 GiB` target
2. reduce `docs_scanned` on the remaining broad search families
3. preserve fast reuse-based profiling
