## gRPC Prototype

This branch carries a parallel gRPC prototype surface.

Current status:

- the existing custom framed RPC remains the active implementation
- protobuf generation is wired in through `build.rs`
- generated Rust types live under `sspry::grpc::v1`
- `grpc-serve` provides a parallel TCP-only tonic server prototype
- implemented gRPC methods:
  - `Ping`
  - `Stats`
  - `Status`
  - `Publish`
  - `SearchStream`
  - `InsertStream`
  - `Delete`
  - `Shutdown`

Prototype CLI surface:

- `grpc-serve`
- `grpc-index`
- `grpc-delete`
- `grpc-search`
- `grpc-info`
- `grpc-shutdown`

Current request model:

- gRPC search sends validated YARA source to the server rather than a serialized compiled-plan JSON payload.
- gRPC ingest streams row-framed binary insert messages incrementally rather than the old manual upload begin/chunk/commit flow or a single whole-batch payload.
- `grpc-index` publishes automatically after ingest when the target server is running in workspace mode so newly indexed documents become visible to `grpc-search`.
- `grpc-serve` bounds per-message size with `--grpc-max-message-bytes`; large documents still stream incrementally and are not treated as one capped request.

Design constraints to keep in mind during the migration:

1. The current custom search RPC sends a dynamic compiled query plan.
   - A direct protobuf port of that JSON shape would be weak.
   - The prototype now leans toward server-validated YARA source for search requests instead.

2. The current insert path mixes JSON requests with large binary uploads.
   - gRPC client streaming should replace the manual begin/chunk/commit upload flow.

3. The current transport supports both TCP and Unix sockets.
   - The prototype currently supports TCP only.
   - Keep Unix-socket support as an explicit follow-up decision instead of an accidental regression.

4. The current custom RPC is the correctness baseline.
   - New gRPC handlers should be introduced in parallel and compared against the existing path before cutover.
