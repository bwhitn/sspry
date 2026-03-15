# Adaptive Publish Policy

## Goal

The fixed `--auto-publish-idle-ms` knob has been removed. The current server-owned policy should:

- publishes quickly on fast, lightly loaded systems
- backs off on slow or saturated systems
- uses observed behavior rather than assuming every machine is NVMe or HDD

## What Recent Measurements Show

From the current incremental workspace implementation on this machine:

- visible publish is cheap on the fast path
  - fresh `1000`-doc publish:
    - `last_publish_duration_ms: 27`
    - visibility lag after `index` return: `48ms`
  - incremental `+500` publish:
    - `last_publish_duration_ms: 179`
    - `last_publish_promote_work_ms: 154`
    - `last_publish_promote_work_import_ms: 56`
    - visibility lag after `index` return: `391ms`
- background sealing is still the hidden tail
  - right after visibility flips, both DF and Tier2 queues can still have about one shard set pending
  - example after the `+500` publish:
    - `published_df_snapshot_seal.pending_shards: 62`
    - `published_tier2_snapshot_seal.pending_shards: 61`
- current ingest on this SSD box is no longer worker-bound and no longer client-buffer-bound
  - `2000`-doc base ingest:
    - `verbose.index.total_ms: 8754`
    - `result_wait_ms: 257`
    - `client_buffer_ms: 374`
    - `submit_ms: 7356`
    - `workers: 33`
  - `+1000` incremental ingest:
    - `verbose.index.total_ms: 8338`
    - `result_wait_ms: 1974`
    - `client_buffer_ms: 196`
    - `submit_ms: 5793`
    - `workers: 33`

These numbers mean the adaptive policy should optimize for *visible publish latency* first, then use seal backlog as the main reason to delay future publishes. On fast storage, the next publish decision should not be driven by old client-side buffering assumptions.

## Inputs The Policy Should Use

The server should maintain moving averages or recent-window samples for:

- visible publish time
  - `last_publish_duration_ms`
- promote/import time
  - `last_publish_promote_work_ms`
  - `last_publish_promote_work_import_ms`
- background seal backlog
  - pending DF snapshot shards
  - pending Tier2 snapshot shards
- publish cadence
  - time since last completed publish
  - number of publishes in the recent window
- ingest/store pressure
  - recent `submit_ms`
  - recent server insert-batch store time
- staged work size
  - `work_doc_delta_vs_published`
  - `work_disk_usage_delta_vs_published`
- optional storage prior
  - detected input/output storage class when known

The storage class should only bias the starting point. It should not override observed runtime behavior.

In practice:

- on fast solid-state storage:
  - if visible publish is still subsecond and seal backlog drains, bias toward immediate publish
- on slower or saturated storage:
  - if `submit_ms` stays high and seal backlog keeps growing, bias toward batching more work before the next publish

## Proposed Policy

Use a small internal idle window with bounded adaptation:

- minimum idle: `0ms`
- maximum idle: `5000ms`
- initial idle:
  - `0ms` on known solid-state
  - `500ms` on unknown storage
  - `1500ms` on known rotational storage

Then adjust from runtime signals:

1. Fast path
- if:
  - recent visible publish p95 `< 500ms`
  - DF backlog is below one shard set
  - Tier2 backlog is below one shard set
  - recent publish rate is low
- set idle to `0-100ms`

2. Moderate path
- if:
  - recent visible publish p95 is `500ms .. 2000ms`
  - or background seal backlog is growing but bounded
- set idle to `250-1000ms`

3. Backoff path
- if:
  - recent visible publish p95 `> 2000ms`
  - or seal backlog remains high across multiple cycles
  - or publishes are arriving faster than sealing can drain
  - or recent submit/store pressure remains high
- set idle to `2000-5000ms`

## Guardrails

- never start a publish while another publish is in progress
- never let the adaptive window shrink while seal backlog is still rising
- shrink the window slowly after a backlog event
- grow the window quickly when backlog or publish duration spikes
- on storage that is detected as rotational or unknown, do not enter the `0-100ms` band until observed publish/seal behavior is healthy for several cycles

## Debug Surface

The public fixed knob is already gone. Keep only internal stats/debug output for:

- current adaptive idle window
- recent publish p50/p95
- current seal backlog

## Next Implementation Step

Implement an internal `AdaptivePublishState` on the server that updates after:

- every publish
- every seal-worker completion
- every completed index session

Then have `publish_readiness()` consume that state instead of the fixed idle constant.
