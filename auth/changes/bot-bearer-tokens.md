### Machine accounts can get a bearer token with no key

A machine account's token no longer has to be bound to a key. `IssueBotToken` without `public_key` mints a **bearer token**: there is no JWK to make and paste. The program sends `Authorization: Bearer <token>` and signs nothing. People's sessions and API tokens stay bound to their device key; nothing changes for them.

- **`IssueBotTokenReq.public_key` (5) is optional.**
  - Present: the token is bound to that key, as before.
  - Absent: the token starts with `w17bot_` and is bound to no device. `IssueBotTokenResp.bearer` (5, new) is true and `device_id` is empty. The program must not send a DPoP proof with it: a proof beside a bearer token is refused.
- **A bearer token always expires.**
  - The expiry is the request's `expires_at`. Without one, it is the deployment's `api_token_default_ttl_hours`, or 90 days when that is 0. "Never" is not offered.
  - It lies at most 366 days ahead. A later `expires_at` is refused with `TOKEN_EXPIRY_TOO_FAR` (`INVALID_ARGUMENT`, on `expires_at`), and a longer default is cut to 366 days.
- **Authenticate still refuses every proofless request** with `DEVICE_PROOF_REQUIRED` before the lookup, with one exception: where `service_account` is on, a token sent as `Bearer` (the configured scheme) with the `w17bot_` prefix, outside the MCP surface and the admin plane. A bearer token never opens the admin console.
  - That token passes only when its row is flagged `bearer`, belongs to a machine account and is bound to no device. Anything else gets the plain `invalid credentials`.
  - An ended bearer token answers `SESSION_EXPIRED`.
  - `AuthResp.device_id` is empty for it.
- **Migration** (`service_account`): new column `UserToken.bearer` (17, `FALSE` by default). Existing rows are unchanged, so every existing token keeps working exactly as it did.
- **API additions:**
  - New mutation `AuthMutation.IssueBotBearerToken` (`service_account`). It emits `ApiTokenCreated` with an empty `key_thumbprint`.
  - New fields `GetTokenWithTypeResp.bearer` (12) and `GetExpiredTokenWithTypeResp.bearer` (6).
- **Ending a bearer token:** revoke it on the admin `Sessions` page (`user_admin`, which `service_account` requires), or disable the machine account. A bound bot token also ends when its key's device is revoked; a bearer token has no device.
