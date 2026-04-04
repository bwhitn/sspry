## gRPC Prototype

This branch carries a parallel gRPC prototype surface.

Current status:

- the existing custom framed RPC remains the active implementation
- protobuf generation is wired in through `build.rs`
- generated Rust types live under `sspry::grpc::v1`
- no CLI command has been moved to gRPC yet

Design constraints to keep in mind during the migration:

1. The current search RPC sends a dynamic compiled query plan.
   - A direct protobuf port of that JSON shape would be weak.
   - Prefer redesigning the search request surface before replacing the transport.

2. The current insert path mixes JSON requests with large binary uploads.
   - gRPC client streaming should replace the manual begin/chunk/commit upload flow.

3. The current transport supports both TCP and Unix sockets.
   - Keep that requirement visible while evaluating the final gRPC server shape.

4. The current custom RPC is the correctness baseline.
   - New gRPC handlers should be introduced in parallel and compared against the existing path before cutover.
