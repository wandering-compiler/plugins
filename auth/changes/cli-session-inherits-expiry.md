### A CLI login lasts only as long as the session that approved it (`cli_login`)

`CliToken` used to mint a session with the full `session_token_ttl_seconds`, so a browser session could renew itself indefinitely: approve a CLI login shortly before it expired, receive a fresh full-lifetime session, repeat.

- **The CLI session now inherits the approving session's expiry.** It expires at the earlier of the normal session TTL from now and the expiry of the browser session that approved it, with no minimum. An approving session that never expires gives the normal TTL. A CLI login therefore ends when the browser session that approved it would have, and signing in again in the browser is what starts a new lifetime.
- **`CliAuthorize` refuses an approving session that is no longer live** (revoked, expired) with the opaque `UNAUTHENTICATED`, and `CliToken` refuses a code whose approving session expired before the exchange.
- **New column `CliAuthCode.session_expires_at`** (nullable `DATETIME`) and new query `AuthQuery.GetLiveSessionExpiry`, both under `cli_login`. Generate a migration for the new column.
