# Quickstart

This is the shortest path from zero to a working `sspry` instance.

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
  --shards 256 \
  --set-fp 0.35 \
  --id-source sha256 \
  --gram-sizes 3,4 \
  --store-path
```

## When To Change Defaults

- Change `--gram-sizes` if you want a different recall/precision/storage tradeoff.
- Change `--set-fp` if you want smaller or larger bloom filters.
- Change `--id-source` only before you build a store; it is DB-wide behavior.
