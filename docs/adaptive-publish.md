# Adaptive Publish Policy

## Goal

Replace the temporary fixed `--auto-publish-idle-ms` knob with a server-owned policy that:

- publishes quickly on fast, lightly loaded systems
- backs off on slow or saturated systems
- uses observed behavior rather than assuming every machine is NVMe or HDD

## What Recent Measurements Show

From the current incremental workspace implementation:

- first publish after a fresh build is cheap
  - `last_publish_duration_ms` around `25ms`
  - visibility lag after `index` return around `55ms`
- moderate incremental publish is still cheap on the visible path
  - `last_publish_duration_ms` around `295ms`
  - `last_publish_promote_work_ms` around `258ms`
  - visibility lag after `index` return around `290ms`
- background sealing is the hidden tail
  - after publish, both DF and Tier2 seal queues can still show about one touched-shard set pending
- after worker auto-tuning on solid-state input, ingest is no longer worker-bound
  - `result_wait_ms` became small
  - `client_buffer_ms` is now the larger client-side cost

These numbers mean the adaptive policy should optimize for *visible publish latency* first and treat background seal backlog as the main reason to delay future publishes.

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
- staged work size
  - `work_doc_delta_vs_published`
  - `work_disk_usage_delta_vs_published`
- optional storage prior
  - detected input/output storage class when known

The storage class should only bias the starting point. It should not override observed runtime behavior.

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
- set idle to `2000-5000ms`

## Guardrails

- never start a publish while another publish is in progress
- never let the adaptive window shrink while seal backlog is still rising
- shrink the window slowly after a backlog event
- grow the window quickly when backlog or publish duration spikes

## Removal Of The Fixed Knob

After the adaptive policy is validated:

- remove public `--auto-publish-idle-ms`
- keep only internal stats/debug output for:
  - current adaptive idle window
  - recent publish p50/p95
  - current seal backlog

## Next Implementation Step

Implement an internal `AdaptivePublishState` on the server that updates after every publish and after every seal-worker completion, then have `publish_readiness()` consume that state instead of the fixed idle constant.
