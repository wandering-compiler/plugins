### A read-only method's outage is sent again by a w17 client

With an SDK whose servers stop w17 clients replaying a handler's `UNAVAILABLE`
(`grpcerr.AnsweredHeader`), every auth method that writes nothing — `Authenticate`,
`AuthenticateAdmin`, `ResolveUser`, `WhoAmI` and the `Get…`/`List…` methods — marks
its outage replay-safe (`grpcerr.ReplaySafe`), so a client still retries it. Methods
that write (sign-in, sign-up, every change) answer an outage once. Needs the SDK
release that adds `grpcerr.ReplaySafe`.
