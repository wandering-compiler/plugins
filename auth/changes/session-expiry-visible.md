### An expired session says so, with its date

An expired bearer used to answer the same `UNAUTHENTICATED: invalid credentials` as an unknown one, so a client could not tell that signing in again would fix it.

- **An expired token now answers `SESSION_EXPIRED`.** A token that exists and is past its `expires_at` is refused with `UNAUTHENTICATED` carrying an `ErrorDetail` (code `SESSION_EXPIRED`, a translated sentence naming the expiry date) and a `google.rpc.ErrorInfo` (reason `SESSION_EXPIRED`, domain `auth.w17`, metadata `expires_at` in RFC 3339 UTC). An expired API token answers the same code, with a sentence that says to create a new token. With device binding (same release) the code is said only to the holder of the token's key, and a revoked token answers it too; anyone else, and an unknown token, gets `invalid credentials`, no detail. New queries `AuthQuery.GetExpiredToken` and `GetExpiredTokenWithType` (`api_token`); they run only when the normal lookup found nothing. Two new msgids reach the project catalog.
- **`last_used_at` is now written** (`api_token`) when a token authenticates, at most once a minute per token (application clock), by the new mutation `AuthMutation.TouchTokenLastUsed`. A failed write does not fail the request.
- **No migration** for this change: no column, table or index is added.
