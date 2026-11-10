### An UNAVAILABLE answered before anything was done is replayed by w17 clients

The w17 SDK no longer replays a handler's `UNAVAILABLE` unless the handler marks it replay-safe (`grpcerr.ReplaySafe`). The plugin marks the ones it answers before the call changed anything (reads, lookups), so a w17 client still retries those; an `UNAVAILABLE` after a write is returned to the caller. Needs the SDK release that has `grpcerr.ReplaySafe`.
