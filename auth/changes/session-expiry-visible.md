### An expired session says so, with its date

An expired bearer used to answer the same `UNAUTHENTICATED: invalid credentials` as an unknown one, so a client could not tell that signing in again would fix it.

- **An expired token now answers `SESSION_EXPIRED`.** A token that exists and is past its `expires_at` is refused with `UNAUTHENTICATED` carrying an `ErrorDetail` (code `SESSION_EXPIRED`, a translated sentence naming the expiry date) and a `google.rpc.ErrorInfo` (reason `SESSION_EXPIRED`, domain `auth.w17`, metadata `expires_at` in RFC 3339 UTC). An expired API token answers the same code, with a sentence that says to create a new token. An unknown or revoked token is unchanged: `invalid credentials`, no detail. New queries `AuthQuery.GetExpiredToken` and `GetExpiredTokenWithType` (`api_token`); they run only when the normal lookup found nothing. Two new msgids reach the project catalog.
- **`last_used_at` is now written** (`api_token`) when a token authenticates, at most once a minute per token (application clock), by the new mutation `AuthMutation.TouchTokenLastUsed`. A failed write does not fail the request.
- **Expired session tokens are deleted at the next sign-in.** `IssueToken` deletes the user's expired session tokens in the same transaction as the new session. The deletion emits no `TokenRevoked` event: those tokens were already refused everywhere. API and bot tokens, never-expiring tokens and live sessions are kept. There is no scheduled sweep.
- **No migration.** No column, table or index is added; the delete uses the existing `UserToken.user_id` index.
