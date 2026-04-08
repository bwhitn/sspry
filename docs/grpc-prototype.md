# gRPC Transport Notes

The public remote transport is now gRPC.

Current public remote commands:

- `serve`
- `index`
- `delete`
- `search`
- `info`
- `shutdown`

Current request model:

- search sends validated YARA source to the server instead of a serialized compiled-plan payload
- ingest streams row-framed binary insert messages incrementally over gRPC
- large documents are chunked across multiple gRPC messages instead of requiring one whole-request payload
- `index` publishes automatically after ingest when the target server is running in workspace mode so newly indexed documents become searchable

Operational behavior:

- `serve --max-message-bytes` bounds per-message size
- `index --insert-chunk-bytes` controls client-side insert frame chunking
- only one active indexing session is allowed per server at a time
- only one top-level search runs at a time per server; later searches queue
- delete targets `current/` only
- background compaction reclaims deleted docs from `current/`

What was validated on this branch:

- small and large files
- default FP and very low FP
- interrupted ingest recovery
- interrupted search recovery
- delete plus background reclaim
- fresh 10k low-FP end-to-end run
- fresh 50k end-to-end run
- warm 50k search parity checks against the older remote path

Remaining migration note:

- legacy framed-RPC code still exists internally in the tree for compatibility and test scaffolding, but it is no longer the public remote interface
