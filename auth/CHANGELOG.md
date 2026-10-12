# auth — changelog

## 0.1.0-rc.25

### One bootstrap administrator, even under concurrent first sign-ups

The `first_user` roles (typically every permission) were decided by reading "no users yet" before the sign-up transaction. Two sign-ups racing on an empty deployment both read zero, and both became administrators.

- **New table `BootstrapClaim` (rbac)** with one row on a constant key. Generate a migration as usual.
- **The sign-up that receives the `first_user` roles writes the claim** in its own transaction (`AuthMutation.ClaimBootstrapAdmin`, `UPSERT … ON CONFLICT DO NOTHING`). A concurrent sign-up waits on the key, conflicts, and gets the default roles. A rolled-back sign-up leaves the claim free.
- **The claim is never reopened.** Once an administrator was handed out, an empty user table does not hand out another. A deployment that already has users never writes the claim, and behaves as before: deleting every account there still reopens the bootstrap. The same holds for a seeded first account.

### A reset or a password change spends every other reset link

Each reset request inserts a new link, and a successful reset consumed only the link it used. Any other link the person had asked for, or one intercepted from their mailbox earlier, could set the password again until it expired. A password change left them all alive too.

- **`ResetPassword` and `ChangePassword` spend every live link of the account** in the same transaction as the new password. They use the new `AuthMutation.SpendPasswordResetTokens` (password_reset).
- **`password_change` without `password_reset`** builds and behaves as before: there are no links to spend.

### OAuth: the callback hands out a single-use code, not a session (breaking)

The OAuth callback used to redirect the browser with the session token in the URL fragment, and its `state` was valid forever, reusable, and tied to no browser. Anyone could start a sign-in with their own provider account and send the callback link to someone else. Whoever opened it was signed in to the sender's account and kept working there (login CSRF).

The browser that starts a sign-in now proves it is the one finishing it:

- **`OAuthAuthorizeURL` requires `code_challenge`**, the PKCE S256 challenge (RFC 7636) of a verifier the page keeps. The signed `state` carries a sha256 of it, never the challenge itself, and now expires after ten minutes.
- **`OAuthCallback` returns `code`, not `token`.** It is a single-use login code, stored as its hash, valid for two minutes and bound to that challenge. The REST callback redirects to `redirect_after#code=…`. `OAuthCallbackResp` drops `user_id`, `token` and `device_trust_token`.
- **New `OAuthExchange` (`POST /auth/oauth/exchange`, public, failed_only)** redeems the code with `code_verifier` and returns `user_id`, `token` and, under `devices`, `device_trust_token`. A wrong verifier spends the code. The device is resolved from this request, which comes from the page itself.
- **New table `OAuthLoginCode`.** Generate a migration as usual.
- **Towards the provider:** the authorize URL carries the plugin's own PKCE challenge (`code_challenge`, `code_challenge_method=S256`) and an OIDC `nonce`, and the token request carries the matching `code_verifier`. Both derive from the state under the client secret, so nothing is stored. A provider that supports neither ignores them. On the `id_token` path (no `userinfo_url`), a token whose `aud` does not name the client id, whose `azp` names another client, whose `exp` has passed, or whose `nonce` is not this sign-in's is refused.
- **The `fakeidp` sandbox** checks PKCE and echoes the nonce for codes it issued from `/authorize`, and sets the `id_token`'s `aud` to the requesting client id. Rebuild its image.

**Migrating a frontend:**

1. Before redirecting to `/auth/oauth/{provider}/authorize`, generate a fresh verifier for this sign-in (never reuse one), store it in `sessionStorage`, and add `code_challenge` to the request.
2. On the landing page, read `code` from the fragment (not `token`), take the verifier out of `sessionStorage` (read, then delete), and `POST` both to `/auth/oauth/exchange`. Delete the verifier before the call, so a failed exchange leaves none behind: a leftover verifier would redeem a code someone else started with its challenge.
3. Store the returned token as before.

A state signed by an older release has no challenge and is refused, so a sign-in in flight during the upgrade has to start again.

### A disabled account holds no working credential

`Authenticate` now refuses every token of a disabled account, session or API, and `IssueBotToken` refuses a disabled machine account with `FAILED_PRECONDITION`.

`DisableUsers` deletes the account's tokens, but nothing checked the flag afterwards. A token minted after the disable worked: one issued by `IssueBotToken` for a disabled bot, or a session from a sign-in racing the disable.

What changes:

- **`GetUserByTokenWithPermissions` projects `user.disabled_at`** (under `user_admin`), and **`GetTokenWithType` joins the owner** and returns it as `user` (`GetTokenWithTypeResp.user`, field 7). Both are the lookups `Authenticate` already runs, so this adds no round trip.
- **Re-enabling an account gives nothing back,** as before: its tokens were deleted when it was disabled.

### An API token can no longer mint credentials

`CreateApiToken`, `CliAuthorize`, `RegisterClient`, `SetClientEnabled`, `EnrollTotp` and `GenerateRecoveryCodes` now answer `PERMISSION_DENIED` (detail `SESSION_REQUIRED`) unless the caller authenticated with a session token.

`CreateApiToken` and `CliAuthorize` mint a new credential from the holder's roles, not from the caller's narrowed permissions. So an API token limited to one permission, given access to `POST /auth/tokens`, could mint a token carrying every API-realm permission of its holder, and through the CLI exchange (`CliAuthorize` → `CliToken`) it could become a full session. The others create credentials of their own: `RegisterClient` a client secret and a callback that `CliAuthorize` sends a session's code to (`SetClientEnabled` restores a retired one), and `EnrollTotp` / `GenerateRecoveryCodes` the account's second factor, which a token could otherwise take over and lock the person out with.

What changes:

- **Creating a credential needs a signed-in session.** A user does it from the app. Automation that minted API tokens with a token has to use a session or, for a machine account, `IssueBotToken`, which stays open to tokens because it is held to the caller's own resolved permissions.
- **The caller is told apart by `AuthResp.session_token_id`,** which `Authenticate` now sets only for a session-realm token (sign-in, device, CLI) and leaves empty for any other, an API or bot token included. A deployment that authenticates through something other than this plugin's `Authenticate` gets no `session_token_id` and is refused, as `Logout` already is.

## 0.1.0-rc.24

### Bearer tokens are stored as a hash

Session and API tokens (`UserToken`) used to be stored as they are handed out, so whoever could read the table or a backup of it held every live token. A token is now stored only as `token_hash`, the sha256 of the token. The handler that mints a token generates it, stores the hash, and returns the token to the caller once. A lookup hashes the bearer it is presented and compares.

What changes:

- **New column `UserToken.token_hash`.** Generate a migration as usual (`w17ctl migrate generate`). `UserToken.token` becomes nullable and nothing writes it any more.
- **Existing tokens keep working.** A token minted before this release is still found by its value. The first request that `Authenticate` resolves with it moves the row to `token_hash` and clears `token` (`AuthMutation.UpgradeTokenHash`). Nobody is signed out by the upgrade. Hand-written code that resolves a token through `GetUserByToken` does not move the row; it runs `UpgradeTokenHash` itself if it should.
- **A token that is never used stays in the clear** until a later release drops the `token` column, which ends every such token. To close it sooner, revoke the tokens that are still unhashed (`token_hash IS NULL`): their owners sign in again or reissue an API token.
- **Storage callers:** `IssueToken` and `IssueApiToken` take the hash (`token_hash`) and no longer return the token. `GetUserByToken`, `GetUserByTokenWithPermissions`, `GetTokenWithType` and `DeleteToken` take `token_hash`, plus `legacy_token`, the token itself, which finds only a row minted before this release. The old `token` field is gone, so code that set only the token does not compile: a lookup by the token alone would miss every hashed row. Hash the token with sha256, hex-encode it, and pass both.
- **No rollback past this release.** A token minted by this release exists only as its hash, so going back to rc.23, which looks tokens up by `token` alone, signs out every session and invalidates every API token issued since the upgrade.
- **Fixtures** that seed a `UserToken` with a known `token` keep working through the legacy path. A fixture may instead seed `token_hash` with the sha256 of the token.

## 0.1.0-rc.23

### A successful OAuth sign-in no longer spends the per-address limit twice

`OAuthCallback` is `public_limit: failed_only`. A callback with a forged or replayed code or state fails and spends a token. A real one comes back from the provider and redirects the browser, and that is free. Before this, an OAuth sign-in spent two tokens: the authorize hop and the callback. With the defaults (burst 10) an office behind one address could get only about five people through in a burst before a 429.

`OAuthAuthorizeURL` still spends a token on every request. It builds a signed redirect and checks no secret.

## 0.1.0-rc.22

Needs w17 platform 1.11 (`requires_w17: ">=1.11"`): `public_limit` on a REST preset endpoint.

### Registration and reset requests count against the per-address limit

The gateway limits the endpoints that take no credential per client address (`*_RATELIMIT_PER_MINUTE`, default 30 a minute with a burst of 10). Until now every such endpoint spent a token only when it failed. That is right for a sign-in, where an attacker's guesses fail and a legitimate user's sign-in succeeds. It is wrong for an endpoint that does its work when it succeeds:

- `SignUp` creates an account and sends a mail. A registration from a fresh address never fails, so one address could register without limit.
- `RequestPasswordReset` sends a mail and answers success whether or not the address exists, so it never spent a token and could mail any address without limit.

From platform 1.11 an endpoint spends a token on every request unless it says otherwise. This release marks the endpoints that check a guessable secret `public_limit: failed_only`, so a correct answer stays free:

- `SignIn`
- `ConfirmSignUp`
- `VerifyMfa`
- `ResetPassword`
- `VerifyEmail`
- `CliToken`

`SignUp`, `RequestPasswordReset` and the two OAuth hops now spend a token on every request.

If a test suite registers many accounts from one address, turn the limit off in the test stack. `w17ctl test` does this itself from v0.1.0-rc.70, through the generated `compose.test.yaml`. For your own runs, use `docker compose -f compose.yaml -f compose.test.yaml` or set `<DOMAIN>_GATEWAY_RATELIMIT_PER_MINUTE=0`.

## 0.1.0-rc.21

### Recovery codes

Confirming an authenticator (`ConfirmTotp`) now returns ten one-time recovery codes, shown once. The codes are stored as SHA-256 hashes in the new `UserRecoveryCode` table.

- A recovery code works wherever the authenticator's code does: `VerifyMfa`, and the step-up of `EnrollTotp`, `DisableTotp` and `GenerateRecoveryCodes`. Each code works once. It may be typed in any case, with or without the dash.
- `GenerateRecoveryCodes` (`POST /auth/mfa/recovery-codes`) replaces the set. It needs a confirmed authenticator, plus a current code or a recovery code. Without an authenticator it is refused with `TOTP_NOT_ENROLLED`.
- `GetMfaStatus` reports `recovery_codes_remaining`.
- `DisableTotp` deletes the codes together with the authenticator.
- Spending a code emits `RecoveryCodeUsed` (`auth.mfa.recovery_code_used`), so a consumer can tell the person.

### A TOTP code is accepted once

`UserTotpSecret.last_step` records the highest time step accepted. A code is taken only for a later step, through one conditional `UPDATE` (`ClaimTotpStep`). Before this, a code worked for its whole window of about 90 seconds, so a code read over someone's shoulder or captured by a phishing page could sign in a second time (RFC 6238 §5.2). The code that confirms an authenticator counts too. A client that verified twice with the same code now needs the next one.

### Re-enrolling over a confirmed authenticator needs a code

`EnrollTotpReq.code` is now required when the caller already has a confirmed authenticator. It takes a current code or a recovery code. Re-enrolling replaces the authenticator, which turns the second factor off until the new one is confirmed. Before this, a hijacked session could do through `EnrollTotp` what `DisableTotp`'s code requirement prevents. A lost phone is now: sign in with a recovery code, then enrol with another one.

### The step-up has a guess budget

The step-up is the code that `EnrollTotp`, `DisableTotp` and `GenerateRecoveryCodes` ask for. Five wrong codes lock it for 15 minutes, refused with `STEP_UP_LOCKED` (ResourceExhausted) even for the right code, and a success resets the count. The counter is `UserTotpSecret.stepup_attempts` and `stepup_locked_until`, updated in one statement (`RecordStepUpAttempt`), so concurrent guesses cannot race past the lock.

The step-up comes from a session, outside any sign-in challenge's budget. Without this limit a stolen session could keep trying six-digit codes until one of the three valid ones came up. `DisableTotp` had no limit before this release.

A recovery-shaped code is checked as a recovery code without reading the seed. This way a legacy authenticator whose `two_factor_secret_key` is gone can still be replaced with a recovery code.

### `ConfirmTotp` refuses an authenticator that is already confirmed

It answers `TOTP_ALREADY_CONFIRMED`. Re-confirming used to be a harmless no-op. With recovery codes it would hand a fresh set to whoever holds the session, with no step-up budget. Use `GenerateRecoveryCodes` for a new set.

### The QR code comes with the enrolment

`EnrollTotpResp.qr_svg` is `otpauth_uri` as a QR code: a self-contained SVG with black modules on white and the quiet zone included. Render it as it is. Encoding is done by `rsc.io/qr`, the SVG rendering by `lib/qrsvg`. The client no longer needs a QR library, and the seed is never handed to one.

New storage methods:
- `AuthMutation`: `ClaimTotpStep`, `RecordStepUpAttempt`, `LockStepUp`, `ResetStepUp`, `CreateRecoveryCode`, `DeleteRecoveryCodes`, `ConsumeRecoveryCode`;
- `AuthQuery`: `CountRecoveryCodes`.

## 0.1.0-rc.20

Needs w17 platform 1.10 (`requires_w17: ">=1.10"`): a project with a `CRYPTED_SECRET` column may now use `RETURNING` on mutations, as long as no encrypted column is returned.

### TOTP seeds and OAuth client secrets are encrypted with the project's field key

Two stored secrets are read back as plain values and are now `CRYPTED_SECRET` columns, encrypted with the project's field keyring (`W17_FIELD_KEYS`):

- `UserTotpSecret.seed` holds the TOTP seed.
- `OAuthProvider.secret` holds the OAuth client secret.

`W17_FIELD_KEYS` is the one key for every encrypted column of a project: the local stack gets a development key from `.env.defaults`, and a deployment gets its own key from `w17ctl secrets field-key`. Before this release, the TOTP seed was encrypted by the plugin's own cipher under the `two_factor_secret_key` knob, and the client secret was stored in the clear.

Nothing has to be migrated by hand. Existing values move the first time they are used:

- A seed enrolled by rc.19 or earlier is still in `UserTotpSecret.secret`. On its next verification it is decrypted with `two_factor_secret_key` and moved into `seed`. Keep the knob set until every authenticator has moved.
- A client secret in `OAuthProvider.client_secret` moves into `secret` at the provider's next sign-in. That happens only while `secret` is empty. Once `secret` is set, it wins and the plaintext copy is cleared, so a rotation made in the admin before the first sign-in is kept. Rotate the secret in `secret`. A fixture cannot seed an encrypted column, so a dev sandbox keeps seeding `client_secret`.

New deployments leave `two_factor_secret_key` empty, and enrolling no longer needs it. A later release removes the knob and both legacy columns.

New storage methods: `AuthMutation.MoveTotpSeed`, `AuthMutation.MoveOAuthProviderSecret` and `AuthMutation.ClearOAuthProviderLegacySecret`. A move is keyed by the row it read: a TOTP seed by the enrolment row's id, so a re-enrolment in between keeps its new seed, and a client secret by the legacy value still being there.

`GetTotpSecretResp.seed` and `GetProviderByNameResp.secret` carry the decrypted values. A decrypted value is returned as a top-level field, not inside the row message.

`CreateTotpSecretReq.secret` (field 2) is replaced by `seed`. Hand-written code that called `CreateTotpSecret` now passes the plaintext seed.

## 0.1.0-rc.19

Needs w17 platform 1.9 (`requires_w17: ">=1.9"`): `DisableUsers` acts on one id set in two statements.

### Disabling an account ends its sessions and tokens

`DisableUsers` (`user_admin`) now also deletes every token of the disabled accounts, sessions and API tokens alike. Before this release they kept working until they expired (30 days for a session), so disabling a departing person did not end their access. Re-enabling an account gives no token back.

### A password change signs the person out everywhere else

`ChangePassword` (`password_change`) deletes every other session of the account in the same unit of work as the new password, and keeps the session the change came from. API tokens are kept. If the sign-out fails, the password is not changed.

New storage method: `AuthMutation.DeleteOtherSessionTokens`.

### An open invitation's link is spent at registration

Registering through an open invitation's link binds the invitation to the registering address. One open link used to register any number of accounts until somebody accepted it; under `invite_only` that was a way to create accounts. Now a second registration through the same link is refused under `invite_only`, and without it the second account simply does not get the invitation. Acceptance is unchanged.

New storage method: `AuthMutation.BindOpenOrgInvite`.

### Removed

`AuthMutation.MarkOrgInviteAccepted`. Nothing called it: acceptance is `ConsumeOrgInviteByToken`. Hand-written code that called it should call that instead.

### Documented

The README now has a section on what a consumer has to know: sessions and tokens, invitations (the plugin sends no mail, the link is returned once to the inviter), the CLI-login client registry (one list for the deployment — grant its four RPCs to an operator role only), and where a refusal's sentence for a person is.

## 0.1.0-rc.18

### Machine accounts in a realm without organizations

`service_account` no longer requires `org_membership`. A realm without organizations is one organization (a platform's own backoffice, say): there a machine account holds a realm-wide role, the bot directory lists the realm's machine accounts, and any operator who may mint tokens may mint one for it. With `org_membership` on, nothing changes: a machine account still joins the operator's active organization and is listed and minted for only there.

With `tenant_scope` on (with or without organizations) an operator now sees, and mints for, only the machine accounts of their own tenant.

### Minting is held to the operator's role ceiling

`IssueBotToken` now refuses a machine account that holds a role the operator could not grant (`PERMISSION_DENIED`, detail `ROLE_ABOVE_CALLER`). `CreateBot` already held the role to that ceiling; a bot created by someone with more could still be minted for by someone with less, and the token acts with the bot's roles. If your operators mint for bots created by others, check the operators' roles.

### Breaking for hand-written code that calls these storage methods

- `AuthQuery.GetBotInOrg` → `GetOrgMember`, gated `org_membership`; it no longer filters on the account's kind.
- `AuthQuery.ListBotUsers` → `ListOrgMemberAccounts`, gated `org_membership`; it returns every member, and the caller keeps the machine accounts.
- `ListApiRealmRolesResp.roles` is `ApiRealmRole` (was `OrgScopedRole`, which needs `org_membership`).
- New `AuthQuery.ListRealmMachineAccounts` (gated `service_account`), unpaged.

Generated code needs nothing beyond `w17ctl plugin update` and `codegen`. `service_account` now requires `authenticate_turnkey` (it already came with `api_token`'s activations in practice).

## 0.1.0-rc.17

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
- A generated `go.mod` may keep a `replace` line for the old path beside the new one. It is harmless, and you may delete it.
- Hand-written code that imports the plugin's packages directly (a `lib/…` package, say) must change its import paths. It must also change any `replace` directive in its own `go.mod` that names the old module path.

No behaviour change since 0.1.0-rc.16. This release carries the module path and comment edits only.
