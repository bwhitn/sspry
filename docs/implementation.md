# Implementation

`sspry` is a mutable file-search engine built around per-document bloom filters, per-superblock Tier2 summaries, and optional local YARA verification.

## Architecture

![Architecture](images/architecture.svg)

At a high level:

1. `serve` starts the TCP server and owns the store.
2. `index` scans files client-side and sends batched documents.
3. The server stores:
   - per-document Tier1 bloom filters
   - per-document Tier2 bloom filters
   - per-superblock Tier2 summaries
   - metadata and optional stored file paths
4. `search` compiles a restricted YARA rule into a query plan.
5. The store returns candidate digests.
6. If `--verify` is enabled, the client reopens stored file paths and verifies matches locally with `yara-x`.

## Query Flow

![Query Flow](images/query-flow.svg)

The query path is:

1. Parse restricted YARA into fixed literals / boolean structure.
2. Extract Tier1 and Tier2 grams from the rule using the DB-wide gram sizes.
3. Build an anchor plan with branch ordering and per-pattern anchor reduction.
4. Query shards in parallel.
5. Use Tier2 superblock summaries to skip groups of files.
6. Use per-document Tier1 and Tier2 blooms to refine candidates.
7. Rank and page candidates.
8. Optionally verify file paths locally.

## Storage Layout

![Storage Layout](images/storage-layout.svg)

The current store is hash-sharded by document identity.

Per shard, the implementation persists binary sidecars for:

- document metadata
- normalized document ids
- Tier1 bloom blobs
- Tier2 bloom blobs
- Tier2 superblock summaries
- deleted state
- optional `external_id` values

The open/search path is intentionally lazy:

- bloom blobs are not materialized for all docs up front
- sidecars are viewed through lightweight metadata plus mmap/lazy reads
- external ids are loaded when needed

That is what keeps search RAM bounded compared with eager whole-store reconstruction.

## Delete, Compaction, and Reclaim

Deletes are immediate logically:

- the document is marked deleted
- query paths stop returning it
- Tier2 summaries are updated so deleted docs stop contributing to future block checks

Physical reclaim is deferred.

Each shard now keeps a small compaction manifest with:

- current generation id
- retired generation roots waiting for deletion

Compaction runs shard-local and copy-on-write:

1. snapshot one shard
2. rebuild that shard using live docs only
3. write the rebuilt shard beside the current one
4. atomically swap the rebuilt shard into place
5. move the old shard root into a retired generation path
6. garbage-collect retired generation roots later

Search remains available during the expensive rebuild phase because compaction does not rewrite the live shard in place.

Current limitation:

- this is not full MVCC yet
- there is still a brief lock during final shard swap/reopen
- generation retirement is simpler than a fully mature generation manager

## Identity Model

The server decides identity at store creation time:

- `sha256`
- `md5`
- `sha1`
- `sha512`

The internal store key stays fixed-width. Non-`sha256` identities are normalized into the internal document id space.

Important consequence:

- clients do not choose identity type
- ingest and delete both follow the server's configured `--id-source`

## Gram Model

`--gram-sizes <tier2,tier1>` is a DB-wide format choice.

Supported pairs:

- `3,4`
- `4,5`
- `5,6`
- `7,8`

Rules:

- smaller size = Tier2 bloom gram size
- larger size = Tier1 bloom gram size
- the choice is persisted in metadata
- stores must be queried with the same gram model they were created with

## Ingest Path

Client-side indexing does the expensive file scan and feature extraction before sending batches.

For each file, the client computes:

- normalized document id
- Tier1 bloom grams
- Tier2 bloom grams
- file size
- optional stored path

Remote indexing uses:

- document-count batching
- request-size-aware splitting
- automatic retry/bisection when a serialized request exceeds the RPC cap

That keeps large ingest runs from failing on a single oversized batch.

## Search Planning

The planner compiles rules into a restricted query tree and chooses anchor grams.

Current search improvements include:

- OR branch ordering by estimated selectivity
- duplicate OR subtree and alternative dedup
- dynamic shard scheduling across server search workers
- bounded server-side query-result cache
- prepared-query artifact cache inside the store
- candidate scoring before verification/pagination

These are intended to be recall-safe planner/runtime improvements.

## Verification Model

Search without `--verify` returns candidate digests.

Search with `--verify`:

1. requires stored paths (`--store-path` at `serve` time)
2. reopens candidate files locally
3. runs `yara-x` verification
4. returns verified matches

This means verified search quality depends on:

- candidate quality from the store
- stored paths remaining valid
- files still existing on disk

## Current Known Gaps

These are the main implementation gaps worth keeping in view:

- compaction is shard-local and working, but it is not yet a full multi-generation MVCC design
- long-lived store cleanup and sweep behavior need another pass
- short common literals are still the hardest precision case because the engine is gram-based and mostly non-positional
- some advanced search-planner ideas are still not implemented, including stronger rescue for very common literals
- shutdown drains existing requests, rejects new mutations during drain, and is available both by signal and explicit RPC/CLI command

## Why The Design Looks Like This

The current tradeoffs are deliberate:

- mutable store instead of rebuild-only index
- bloom tiers and superblock summaries instead of retained exact gram postings
- server-owned store policy so clients stay simple
- narrow public CLI so alpha users only touch meaningful knobs
