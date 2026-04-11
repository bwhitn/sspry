# Quickstart

This is the shortest path from zero to a working `sspry` instance.

This page shows the normal RPC workflow. If you want direct local operation without a server, use `local-index`, `local-search`, `local-info`, and `local-delete`.

## 1. Build

```bash
cargo build --release
```

## 2. Start the Server

```bash
./target/release/sspry serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db
```

That initializes the store if it does not exist yet.

In the normal RPC workflow, `--root` is a workspace root. `sspry` manages `current/` under that path and creates `work_a/` / `work_b/` lazily when publish or remote ingest needs them.

## 3. Ingest Files

```bash
./target/release/sspry index \
  --addr 127.0.0.1:17653 \
  ./samples ./more-samples
```

If you want later verified searches to reopen the original files, start the server with `--store-path`.

## 4. Check Store State

```bash
./target/release/sspry info --addr 127.0.0.1:17653
```

## 5. Run a Search

Unverified candidate search:

```bash
./target/release/sspry search \
  --addr 127.0.0.1:17653 \
  --rule ./rule.yar
```

By default, `search` caps returned candidates at `10%` of searchable documents. Set `--max-candidates 0` to disable that cap.

Verified search:

```bash
./target/release/sspry search \
  --addr 127.0.0.1:17653 \
  --rule ./rule.yar \
  --verify
```

## 6. Delete Documents

Delete one or more documents by digest or original file path:

```bash
./target/release/sspry delete \
  --addr 127.0.0.1:17653 \
  <digest-or-file-path> <digest-or-file-path>
```

## 7. Shut The Server Down

Graceful remote shutdown:

```bash
./target/release/sspry shutdown --addr 127.0.0.1:17653
```

Signals:

- `SIGINT` / `SIGTERM`: graceful drain and shutdown
- `SIGUSR1`: print a live `info` snapshot to `stderr`

## Recommended First Server Config

```bash
./target/release/sspry serve \
  --addr 127.0.0.1:17653 \
  --root ./candidate_db \
  --shards 8 \
  --tier1-set-fp 0.35 \
  --tier2-set-fp 0.35 \
  --id-source sha256 \
  --gram-sizes 3,4 \
  --store-path
```

## When To Change Defaults

- Change `--gram-sizes` if you want a different recall/precision/storage tradeoff.
- Supported gram-size pairs are `3,4`, `4,5`, `5,6`, and `7,8`.
- Change `--tier1-set-fp` and `--tier2-set-fp` if you want smaller or larger bloom filters.
- Change `--id-source` only before you build a store; it is DB-wide behavior.
- Increase `--shards` only after measuring ingest/publish contention. For smaller alpha-scale trees, starting with the default `8` keeps open and publish fanout low.
- If you prefer profile-based layout instead of an explicit shard count, `--layout-profile incremental` starts with a denser 8-shard layout.
