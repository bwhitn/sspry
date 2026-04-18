# Scalable Screening and Prefiltering of Rules for YARA (SSPRY)

`sspry` is the command-line binary and crate name.

A mutable file search database with fast candidate retrieval and optional YARA verification.

## Overview

SSPRY is a scalable way to reduce the set of files that need to be scanned based on the YARA rule you intend to use. The public search path supports both single-rule lookups and small bundled rule sets loaded from one top-level YARA file with normal `include "..."` directives. It is intended to avoid false negatives and have limited false positives. Other projects have done similar things, but the goal of this one is to do so in a scalable way that trades upfront processing for reduced memory and search processing, while keeping the overall database (Forest) size smaller than the sum of the files; however, it has a fair amount of disk I/O during searches. In addition to those, the database needs to support the insertion and deletion of items.

## Terms
Candidate - An individual document that is returned as a possible match.<br>
Document - An individual file.<br>
Document ID - The hash used to uniquely identify the file in the forest. (MD5, SHA1, SHA256, SHA512)<br>
Forest - A collection of Trees.<br>
Metadata sidecar - The metadata contains the subset of YARA-relevant values that can be checked during search.<br>
Shard - A partition inside a Tree used to stripe ingest/write work and bound shard-local files.<br>
Tier 1 bloom filter - A broader filter used first to gate some Tier 2 reads and help improve the accuracy.<br>
Tier 2 bloom filter - A more precise filter used to further narrow candidate sets.<br>
Tree - A single logical storage unit that contains a number of Shards.

## General Methodology
The general methodology involves a Forest that operates similarly to a Log-Structured Merge Tree (LSM Tree). The general idea is to append new items via a publish routine and perform deletions lazily via a compaction routine. The overall format isn’t really a Tree, but a physically split set of long data streams (a forest). Each file consists of a Tier 1 (T1) and a Tier 2 (T2) bloom filter, which, by default, are 3-gram and 4-gram bloom filters, respectively, along with an optional metadata sidecar containing YARA-specific information (pe.is_pe, file entropy for math.entropy(0, filesize), etc.). T1 is a lighter bloom filter that will gate some required T2 bloom filter reads and slightly reduce false positives. T2 is a more precise bloom filter with a much lower false-positive rate. The supported gram-size pairs are `3,4`, `4,5`, `5,6`, and `7,8`. The blooms are sized based on the false-positive (fp) value p and the approximate number of ngrams, computed by applying the HyperLogLog function to all grams, yielding results typically within 1% accuracy.

These forests are broken into Trees of fixed-sized documents, and each Tree is further split into Shards. Each shard contains the data needed for the search to include T1 and T2 blooms, along with the metadata sidecar. These are broken down to prevent excessively large files. When a file is removed, it is annotated immediately, but won’t be physically removed until compaction is completed. Compaction rebuilds a shard, which is then swapped out for the previous one. Indexing, on the other hand, is done via publishing, which appends to the active shard set.

Duplicate detection is prevented on insert into the same shard. This does mean there could be duplicates inserted into the Forest in other Trees. In the future, maintenance runs will mark duplicates for deletion within the same forest, but this doesn’t currently happen. This won’t affect searches, as they are inserted into a hash set that automatically deduplicates them.

Most bloom-backed searches read the T1 blooms across the Trees being searched. Possible T1 matches may then require T2 reads and metadata checks. If a rule has no searchable string anchors, it may fall back to metadata checks, direct identity lookups, or later verification depending on the rule structure. An example of this could be a condition like “filesize < 4kb and pe.is_pe and pe.timestamp > time.now”, which could find a PE file smaller than 4kb and with a timestamp greater than the time of the search start.

## Program Architecture
The program's architecture is primarily client-server. During ingest, the client scans files and sends per-document bloom and metadata rows to the server. During search, the client sends validated YARA source and the server handles search planning, disk I/O, and candidate retrieval. The exception to this is the direct local path, where `local search` opens a forest in-process. A quick note: these are clients and servers and do not have any built-in security, so it is recommended that they be on a closed network.

Additionally, if you opt to store path information when creating the Forest, you can automatically verify search results using it.

The client can also distribute files across multiple servers in a round-robin fashion. This can improve indexing throughput and spread search work across machines, but it also splits the corpus across those servers. As a result, built-in verification becomes more difficult unless the original files are still available to the system performing the verification.

## General Operation Complexity
* Search is generally linear in the amount of data the server has to examine.
* Server-side indexing is append-oriented and mostly sequential, so for normal batch sizes it behaves close to constant in practice, even though it still grows with the amount of data written. Client-side indexing scales with file size, the number of unique n-grams, and the amount of metadata extraction work.
*  Removals are usually cheap up front, while heavier cleanup work is deferred to compaction.
* All of this is with respect to the configured bloom sizing and the general occasional overhead from publishing and compaction.

## General Notes
* There are many trade-offs with this pre-Yara search screening method. With T1, if the p (fp) rate is too low, the blooms are larger, so the minimum amount of disk IO required to search will increase. The same goes for T2, but to an even greater degree: the larger the ngram size, the more unique ngrams there will be. While some YARA modules and common condition evaluations are stored in metadata, storing all metadata would drastically increase the Forest size.
* This is still in early development, and many refinements are needed. These refinements could break some items, rendering the current Forest unusable and requiring it to be deleted and recreated.
* Trying to compare this to similar projects isn’t easy. It would probably be easier to do a feature comparison chart.
* When using “time.now” in a YARA rule, there is a chance of a false negative because the search evaluates it at the time it starts, whereas verification happens later, and it will be evaluated again during that time.

## Current Issues
* Deduplication across forest.
* multi serve search
* Clean up CLI

## Quick Links

- [Quickstart](docs/quickstart.md)
- [Usage](docs/usage.md)
- [Implementation](docs/implementation.md)

## Build

```bash
cargo build
cargo build --release
```

## Test

```bash
cargo test --workspace --all-targets
```

## Coverage

If `cargo-llvm-cov` is installed:

```bash
./scripts/coverage.sh
```

## Benchmarking

For server-side search benchmarks with CPU and anon-memory sampling:

```bash
./scripts/server_search_bench.sh \
  --root ./candidate_db \
  --addr 127.0.0.1:18663 \
  --out ./results/bench_runtime_workers6 \
  --mode-label runtime \
  --search-workers 6 \
  --rule-manifest /path/to/rules.manifest \
  --bundle-rule /path/to/bundle_10rules.yar
```

The benchmark helper records:

- per-phase client elapsed, user CPU, system CPU, average CPU percent, and max RSS
- per-phase server CPU time and average CPU percent
- peak `VmRSS`, `RssAnon`, `VmSwap`, `Pss_Anon`, `Private_Clean`, and `Private_Dirty`
- raw timestamped `/proc` samples in `server_samples.tsv`

`--bundle-rule` should point to one top-level YARA file, commonly an include file that expands to the rule set you want to bundle into one remote `search` request. Use `--server-extra-arg` and `--search-extra-arg` to forward extra serve/search flags when needed.
