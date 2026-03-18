# NOW

This file is the short-horizon worklist.

It contains the items to finish before going back to the broader performance backlog in
[TODO.md](/root/pertest/repos/yaya/TODO.md).

## Immediate Priorities

### 1. Finish the bloom-only cutover

Current state:
- the normal ingest/search path is bloom-only
- retired exact-gram / DF runtime plumbing has been removed from the live path
- the remaining work is cleanup of stale docs, help text, and any last compatibility-only surfaces

Work:
- remove any remaining public references to exact grams / DF in docs, help text, and metrics
- keep pruning compatibility-only code that no longer protects a supported format or protocol
- keep the current workspace layout documented as `current/`, `work_a/`, `work_b/`, and `retired/`

Exit criteria:
- public docs and help match the bloom-only runtime
- no live-path metrics or help strings still describe the retired exact-gram / DF model

### 2. Improve bloom-only search latency

Current baseline:
- `32 KiB` Tier2 superblock summaries are the best measured point so far on the `50k` corpus
- some supported searches are already fast
- the heaviest supported rules still spend too long in the query path and can still hit the RPC timeout

Work:
- profile the slow supported search rules from the `8/16/32 KiB` comparison
- reduce candidate and block scans before considering higher summary sizes
- keep search improvements recall-safe and compatible with optional local verification

Exit criteria:
- heavy supported searches improve materially from the current `32 KiB` baseline
- no regression in the already-fast supported searches

### 3. Close the current test / coverage gaps

Work:
- keep `cargo test --workspace --all-targets` green during the cutover cleanup
- run a fresh coverage pass from the bloom-only baseline
- use that report to target the next low-value uncovered branches

Exit criteria:
- one fresh repeatable coverage result on the current tree
- clear next test targets from the coverage report

## Order

Work these in this order:
1. finish bloom-only cutover cleanup
2. tighten bloom-only search performance
3. refresh tests and coverage

Only after these are done do we return to [TODO.md](/root/pertest/repos/yaya/TODO.md).
