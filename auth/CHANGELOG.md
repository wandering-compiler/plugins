# auth — changelog

## 0.1.0-rc.27

### A bearer token is written by IssueApiToken; IssueBotBearerToken is gone

In rc.26, `ApiTokenCreated` had two emit sites: `IssueApiToken`, and `IssueBotBearerToken` for a machine account's bearer token. A consumer that enabled `service_account` could not generate code, because an event has exactly one emit site.

- **`AuthMutation.IssueBotBearerToken` is removed.** The bearer token is written by `AuthMutation.IssueApiToken`, using a new `IssueApiTokenReq.bearer` (11, field-gated `service_account`, set only by the machine-account path).
- **`IssueApiTokenReq.device_id` may be empty**, but only for a bearer token. The handler still refuses any other API token without a device.
- Nothing changes on the wire or in the schema compared with rc.26: the same column and the same `ApiTokenCreated` event, with an empty `key_thumbprint` for a bearer token.

## 0.1.0-rc.26

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

## 0.1.0-rc.25

### Upgrading to device identity (read first)

This release binds every token to a device key and stops deleting rows from the auth tables. The entries below give the details; this is the order to upgrade in.

1. **Platform and clients first.**
   - Move to platform 1.12 or newer and the w17ctl that comes with it. The console refuses this plugin on an older platform: its gateway does not verify the proofs, and every sign-in would be refused.
   - Regenerate the project, so the gateway verifies DPoP proofs and the admin, the generated clients and the e2e runner sign their requests.
   - Hand-written clients must send DPoP too: SDK `ts/dpop` in TypeScript, `dpopclient` in Go. A bound token goes as `Authorization: DPoP <token>` with a `DPoP` proof header, and every sign-in request needs a proof.
2. **Configure the gateway** (`<P>` is the surface's env prefix):
   - `<P>_DPOP_ORIGIN` is required: the public URL clients reach the REST surface (or the admin) at, with the base path when a proxy serves it under one. `<P>_RPC_DPOP_ORIGIN` is required with an rpc surface. The binary refuses to boot without them, and a wrong value refuses every proof.
   - `<P>_DPOP_NONCE_KEY` (base64, at least 32 bytes, the same on every replica) and `<P>_DPOP_REDIS_DSN` (the replay store every replica shares) are required in production.
   - `<P>_DPOP_SINGLE_REPLICA=true` (one replica, a per-boot nonce key, an in-memory replay store) is honoured only with `W17_ENV=dev`.
3. **Generate and apply the migration.** No row is deleted or rewritten: every existing row stays live, and old Device rows stay as history.
   - Base tier: new tables `Device` (where `devices` was off) and `SignInEvent`. New columns: `UserToken.device_id`, `mcp_only`, `revoked_at`, `revoked_by`, `revoke_reason`, `public_computer`, `approved_by_device_id`, and `User.device_trust_revoked_at`. Where `devices` was on, `Device` gains `thumbprint`, `revoked_at` and `api_key`, and loses `identifier` and `trust_token_hash`.
   - `two_factor`: `MfaChallenge.thumbprint`, `public_computer`; `UserTotpSecret.revoked_at`, `ended_key`; `UserRecoveryCode.revoked_at`.
   - `cli_login`: `CliAuthCode.session_expires_at`, `approved_by_device_id`; `AuthClient.revoked_at`.
   - `user_admin`: `User.erased_at`.
   - `rbac`: `Role.deleted_at`, `ended_key`; `RolePermission.removed_at`, `removed_by`; `UserRole.revoked_at`, `revoked_by`, `ended_key`; new table `RolePermissionChange`.
   - `org_membership`: `Organization.deleted_at`, `ended_key`; `OrgMembership.removed_at`, `removed_by`, `ended_key`.
   - `org_invite`: `OrgInvite.closed_at`, `closed_by`.
   - `sign_up_confirmation`: `PendingSignUp.claimed_at`, `superseded_at`.
   - Unique indexes: `ended_key` joins the unique keys of `Role`, `Organization`, `OrgMembership`, `UserRole` and `UserTotpSecret`. `Role.name` and `Organization.slug` are unique among live rows only. The pending-invitation index also skips closed rows.
4. **Sign in again and re-issue tokens.**
   - Every existing session is refused once, so everyone signs in again, one time. A pending second-factor challenge has to be started over.
   - API tokens and machine-account tokens issued before this release are refused. Issue them again with the public JWK of the program that uses them: `w17ctl key public`, or the SDKs' keygen helper. The program then signs every request with that key.
5. **Update project code that calls the plugin's storage directly.**
   - Renamed: `DeleteToken` → `RevokeToken`, `DeleteSessionToken` → `RevokeSessionToken`, `DeleteApiToken` → `MarkApiTokenRevoked`, `DeleteOtherSessionTokens` → `RevokeOtherSessionTokens`, `DeleteUserSessionsForReset` → `RevokeTokensForReset`, `DeleteDeviceTokens` → `RevokeDeviceTokens`, `DeleteUndevicedSessions` → `RevokeUndevicedSessions`, `DeleteAllUserTokens` → `RevokeAllUserTokens`, `DeleteAuthClient` → `RevokeAuthClient`, and `DeleteUser` → `BeginUserErasure` + `EraseUser` (through `AuthService.EraseAccount`, or `AuthService.EraseUsers` for several).
   - Also renamed: `DeleteOrgMembership` → `MarkOrgMembershipRemoved`, `DeleteOrgInvite` → `CloseOrgInvite`, `ClearExpiredOrgInvite` → `CloseExpiredOrgInvite`, `DeletePendingSignUpsForEmail` → `SupersedePendingSignUpsForEmail`, `DeleteTotpSecret` → `RevokeTotpSecret`, and `DeleteRecoveryCodes` → `RevokeRecoveryCodes`. `AuthService.DeleteClient` keeps its name and route and now revokes the registration.
   - Removed: `DeleteTokenPermissions`, `PurgeExpiredPendingSignUps`, and the device rpcs `GetDeviceByIdentifier`, `CreateDevice`, `TouchDevice`, `DeleteDevice` and `DeleteAllUserDevices` (now `RegisterDevice` and `MarkDeviceRevoked`). The `X-Device-Id` and `X-Device-Trust` headers and `device_trust_token` are gone too.
   - Changed requests and responses:
     - `IssueToken` requires `device_id`.
     - `RevokeDeviceTokensReq` requires `revoked_by` and `keep_token_id` (the nil UUID keeps none).
     - `CreateApiTokenReq` and `IssueBotTokenReq` require `public_key`.
     - `AuthQuery.GetUserToken` returns `UserTokenAdminDetail`.
     - Several revoke responses are empty now.
   - Roles: `AddPermissionToRole` revives a removed pair and still refuses one the role holds (`ALREADY_EXISTS`). It and `AssignRoleToUser` refuse a deleted or unknown role (`NOT_FOUND` / `ROLE_NOT_FOUND`). A preset role deleted at runtime stays deleted across re-seeds; declare it under a new key to bring it back.
   - Events: `UserDeleted` (`auth.user.deleted`) keeps its name and topic; the erasure emits it (erasure is the plugin's deletion). New `ApiTokenCreated`. The token and MFA events carry `device_id`.
6. **The admin changes.**
   - The `delete` on the Users, ServiceAccounts and Sessions pages stays, with its button, its permission (the model's `delete`) and its response, so hand-written admin tests (`admin.Users.Delete` → `user_id`, `admin.Sessions.Delete` → `token_id`) keep passing. It no longer deletes: on Users and ServiceAccounts it erases the account (`AuthService.EraseAccount`), on Sessions it revokes the token (`AuthService.RevokeSession`), the operator recorded either way. Revoked and erased rows stay listed.
   - New pages, opt-in: `Devices` (feature `admin_devices`) and `SignIns` (feature `admin_sign_ins`), both requiring `user_admin`. The upgrade adds no page to an existing activation. To get them, enable the features and, if your admin declares `nav` groups, add the pages to one: an admin with nav groups must list every page, and the build refuses one it does not list.
   - The Sessions page shows each session's device by its label, without a link to the Devices page.
   - The admin's sign-in form has a "This is a public computer" box, and the app's sign-in requests take `public_computer`. Such a session never trusts the device, is kept in session storage only, and expires after `public_session_ttl_seconds`.
   - Federated (OAuth) sign-in to the admin needs `oauth` enabled on the admin's realm. Without it the sign-in returns a token bound to no key, and the admin refuses it.
7. **Opt-in features.** Everything this release adds to a published surface is behind a feature that is off by default, so an upgrade adds no page, endpoint, admin action, permission or scaffolded e2e test to an existing activation:
   - `admin_sign_ins` — the admin `SignIns` page (requires `user_admin`).
   - `admin_devices` — the admin `Devices` page and its `Revoke` action (requires `user_admin`).
   - `my_sign_ins` — `GET /auth/sign-ins`, the caller's own sign-in history (requires `authenticate_turnkey`).
   - `client_secret_rotation` — `POST /auth/clients/{id}/rotate-secret` (requires `cli_login`).

   One addition is not optional: with `oauth`, `POST /auth/oauth/exchange` is published, because the callback now hands the browser a login code instead of a session and the exchange is the only way to redeem it. A project with `oauth` gets a scaffolded e2e test for it on the next generation and should write it (or keep its own test of the OAuth flow).
8. **Known limits.**
   - MCP clients keep their OAuth flow without DPoP. Their tokens (`mcp_only`) are accepted only on the MCP surface.
   - On a surface that binds devices, the e2e runner skips MCP scenarios and counts the skips.

### A CLI login lasts only as long as the session that approved it (`cli_login`)

`CliToken` used to mint a session with the full `session_token_ttl_seconds`, so a browser session could renew itself indefinitely: approve a CLI login shortly before it expired, receive a fresh full-lifetime session, repeat.

- **The CLI session now inherits the approving session's expiry.** It expires at the earlier of the normal session TTL from now and the expiry of the browser session that approved it, with no minimum. An approving session that never expires gives the normal TTL. A CLI login therefore ends when the browser session that approved it would have, and signing in again in the browser is what starts a new lifetime.
- **`CliAuthorize` refuses an approving session that is no longer live** (revoked, expired) with the opaque `UNAUTHENTICATED`, and `CliToken` refuses a code whose approving session expired before the exchange.
- **New column `CliAuthCode.session_expires_at`** (nullable `DATETIME`) and new query `AuthQuery.GetLiveSessionExpiry`, both under `cli_login`. Generate a migration for the new column.

### Every token is bound to a device key (breaking)

A session used to be a bearer token that worked from anywhere until it expired. Now every token is bound to the device that signed in: a key pair its client holds, identified by the RFC 7638 thumbprint of its public key. The client proves it holds the key on every request with a DPoP proof (RFC 9449); the gateway verifies the proof and passes the plugin only the thumbprint.

- **Every existing session is refused once.** Sessions issued before this version carry no binding, so the next request with one is refused (`DEVICE_PROOF_REQUIRED` without a proof, `invalid credentials` with one) and the person signs in again, one time. API tokens issued before it are refused the same way. Later upgrades do not sign anybody out.
- **Clients must send DPoP proofs.** A bound token goes as `Authorization: DPoP <token>` with a `DPoP` proof header; every sign-in request (`SignIn`, `SignUp` when it issues a session, `ConfirmSignUp`, `VerifyMfa`, `OAuthExchange`, `CliToken`) needs a proof too, and is refused without one before anything else happens. The gateway verifies the proofs from platform 1.12 on, which this version requires; the generated TypeScript client, the SDKs and w17ctl sign for you once updated. Deploy them together.
- **New refusals** (`UNAUTHENTICATED`, with an `ErrorDetail` and a `google.rpc.ErrorInfo` in domain `auth.w17`): `DEVICE_PROOF_REQUIRED` (no proof — decided before the token is looked up, so it says nothing about the token) and `DEVICE_REVOKED` (said only to the holder of the bound key; the client generates a new key and signs in as a new device). `SESSION_EXPIRED` is now also said only to the holder of the bound key. A token proved by another key, bound to none, or unknown is the same plain `invalid credentials`: a stolen token without its key tells its holder nothing. The `DPoP` scheme is matched case-insensitively.
- **MCP keeps its OAuth flow without DPoP.** New column `UserToken.mcp_only` (default false): a token minted by the MCP OAuth flow is accepted without a proof, only on the surface the gateway marks `x-w17-surface: mcp`, and refused everywhere else.
- **VerifyMfa must be signed by the key of the SignIn it completes.** New column `MfaChallenge.thumbprint` (nullable); a challenge raised before this version cannot be completed (sign in again).
- **`AuthResp.device_id`** carries the verified device of every authenticated request.
- **Device identity is base tier.** The `Device` table, `UserToken.device_id` and `User.device_trust_revoked_at` exist in every activation. The `devices` feature is now only the management endpoints (`ListDevices`, `RevokeDevice`, `RevokeOtherDevices`, `RevokeAllDevices`); revoking a device stamps `Device.revoked_at` instead of deleting the row, so the key stays refused for good (what else a revocation ends: see the Devices page entry). `two_factor_scope=new_devices` works without `devices`, and trust belongs to the (account, device) pair.
- **Removed:** the `X-Device-Id` and `X-Device-Trust` headers, the device trust token (`device_trust_token` on `SignInResp`, `VerifyMfaResp` and `OAuthExchangeResp`), `Device.identifier`, `Device.trust_token_hash`, and the storage rpcs `GetDeviceByIdentifier`, `CreateDevice`, `TouchDevice`, `DeleteDevice` and `DeleteAllUserDevices` (replaced by `RegisterDevice` and `MarkDeviceRevoked`; no statement deletes a Device row). `IssueToken` now requires `device_id`.
- **API tokens and machine-account tokens are bound to the key of the program that uses them**, never to the browser that created them: `CreateApiToken` and `IssueBotToken` take that key (see "API tokens and machine-account tokens are bound to the program's key").
- **Migration.** Generate and apply a migration: new table `Device` (unique `(user_id, thumbprint)`) and columns `UserToken.device_id`, `UserToken.mcp_only`, `MfaChallenge.thumbprint` (with `two_factor`) and `User.device_trust_revoked_at` where the `devices` feature was off; where it was on, `Device` loses `identifier` and `trust_token_hash` and gains `thumbprint` (nullable) and `revoked_at`. **No data is cleared:** existing Device rows stay as history with a NULL `thumbprint`. They name no key, so nothing can sign in with them, a token bound to one is refused like any unbound token, and `ListDevices` leaves them out; they remain in the table for audit. Every device signs in once more and is registered as new.

### Operators see and revoke devices; "this is a public computer"; a CLI login records its approver

An operator could revoke a session but not a device, and could not see which device a session belonged to. A sign-in at a shared computer was treated like any other: the device could become trusted and the session lasted the full lifetime. A CLI session did not say which browser had approved it.

- **New admin page `Devices`**, opt-in: enable the new feature `admin_devices` (requires `user_admin`) and, if your admin declares `nav` groups, add `Devices` to one — an admin with nav groups must list every page. It is not part of `user_admin`, so upgrading adds no page to an existing activation. The page lists every device of every account — the owner, label, key thumbprint, address, first and last seen, `trusted_at`, the account's last trust revocation, whether the trust still stands (`trusted`), and `revoked_at`. Revoked devices and legacy ones (recorded before device binding, no key) are listed too. New queries `AuthQuery.ListAllDevices` (cursor-paged, the newest first by `created_at`) and `GetDevice`, projection `DeviceAdminRow`.
- **Its `Revoke` action** (`AuthService.RevokeDevices`) revokes each selected device for good and every token bound to it — reason `DEVICE_REVOKED`, the operator as `revoked_by` — in one transaction per device. The key can never sign in to that account again (`DEVICE_REVOKED`). A device already revoked keeps its first revocation; revoking it again only ends the API tokens it created (see the machine keys entry). An empty selection is refused. A legacy device can be revoked like any other.
- **Revoking a device also ends the CLI sessions it approved** (`UserToken.approved_by_device_id`), from the Devices page and from the owner's own `RevokeDevice` / `RevokeOtherDevices` / `RevokeAllDevices`: a stolen browser session could otherwise approve the thief's own CLI key, and that CLI session would outlive the revoked device. `RevokeDeviceTokens` runs a second statement for them (same reason, actor and account) that spares `keep_token_id` (new, 4; required — pass the nil UUID to keep none): `RevokeOtherDevices` keeps the caller's own session, even when the caller is a CLI session one of those devices approved. A CLI code approved by a device revoked before the CLI redeems it mints nothing (new query `AuthQuery.GetCliApproverRevocation`, `cli_login`); the refusal is the opaque one, recorded as `REFUSED`. Ending the approving browser *session* (Logout, the admin Sessions revoke) leaves the CLI sessions it approved alive, by design: revoke the device, or the CLI session itself.
- **`AuthMutation.RevokeDeviceTokens` and `MarkDeviceRevoked` are base tier now** (they were `devices` only), and `RevokeDeviceTokensReq` has a new required `revoked_by` (3). Project code calling `RevokeDeviceTokens` directly must pass it — the device's owner, as the `devices` calls do.
- **The `Sessions` page shows each session's device**: its label (`device_label`; not a link, since the Devices page is opt-in), its key thumbprint, and `public_computer`. The detail (`AuthQuery.GetUserToken`, which now returns `UserTokenAdminDetail` instead of `UserToken`) adds the device, whether it is a public-computer session and, for a CLI session, the device that approved it.
- **"This is a public computer."** `SignInReq` (3), `OAuthExchangeReq` (4), `SignUpReq` (5) and `ConfirmSignUpReq` (3) take `public_computer`; `VerifyMfa` takes the choice from its challenge (`MfaChallenge.public_computer`, `two_factor`), never from its own request. Such a session never makes the device trusted, even after a passed second factor, and does not use trust the device already had, so `two_factor_scope=new_devices` asks the second factor at every sign-in from it. It expires after the new **`public_session_ttl_seconds`** (default 0 = 8 hours, capped at the session lifetime, so a deployment with sessions shorter than 8 hours boots unchanged); only an explicit value longer than `session_token_ttl_seconds` fails the boot. The responses (`SignInResp` 6, `VerifyMfaResp` 4, `OAuthExchangeResp` 4, `SignUpResp` 5, `ConfirmSignUpResp` 3) echo it, so the client keeps the token in session storage only (the clients' part comes with the SDK release). `CliToken` has no such option.
- **New columns** `UserToken.public_computer` (15) and `SignInEvent.public_computer` (11), both `FALSE` by default; the admin `SignIns` detail and `ListMySignInEvents` show it.
- **A CLI login records the browser that approved it.** `CliAuthorize` reads the Device row the approving session is bound to (`GetLiveSessionExpiry` now also returns `device_id`) onto the code (`CliAuthCode.approved_by_device_id`, 11), and `CliToken` writes it on the CLI session (`UserToken.approved_by_device_id`, 16). The CLI session stays bound to the CLI's own key.
- **Erasure:** nothing new to erase. The new columns are a flag and references to Device rows, whose label and address an erasure already blanks.
- **Migration.** Generate and apply a migration: new columns `UserToken.public_computer`, `UserToken.approved_by_device_id`, `SignInEvent.public_computer`, and with `two_factor` `MfaChallenge.public_computer`, with `cli_login` `CliAuthCode.approved_by_device_id`. Existing rows take the defaults (`FALSE`, NULL).

### A password change or a disable ends device trust

With `devices`, a trusted device used to stay trusted after the account's password was changed or the account was disabled, so under `two_factor_scope=new_devices` it kept skipping the second factor, also for whoever had signed in from it with the old password.

- **`ChangePassword` (`password_change`) and `DisableUsers` (`user_admin`) now end the trust of every device of the account**, in the same statement that writes the new password or `disabled_at`. The session a change came from keeps working, but its device passes the second factor again on the next sign-in; so does every device of a re-enabled account. `ListDevices` shows these devices as untrusted. A sign-in already in flight when the change commits cannot trust the device after it.
- **A password reset still keeps device trust**, unchanged.
- **New column `User.device_trust_revoked_at`** (nullable, base tier with device binding) and query `AuthQuery.GetDeviceTrustRevokedAt`; it is part of the device-binding migration.
- **OAuth sign-in does not ask for the plugin's second factor**, also for an account that has one confirmed. This is now a recorded decision, not an open question: the provider already verified the identity. An OAuth sign-in still never makes the device trusted.

### `src/gen` is generated, not shipped

- **Needs w17ctl v0.1.0-rc.75 or newer.** The release no longer carries `src/gen` (the pb, the `EnvConfig` / `ClientSet` / `HandlerRegistry` contract and the feature constants). A consumer's staging generates all of it for each activation from `plugin.yaml` and the protos, and w17ctl does that from rc.75 on. An older w17ctl expects the release to carry the contract; upgrade it before you take this release.
- Nothing in your project changes: the same activation, the same env variables, the same configuration, no migration.

### API tokens and machine-account tokens are bound to the program's key (breaking)

An API token's device is the program that uses it — a CI job, a script, a machine account — not the browser that created it, and a token bound to that browser would be useless to the program. The request carries the program's public key and the token is bound to it. An API token issued before this version is refused like any unbound token: issue it again with the program's key.

- **`CreateApiTokenReq.public_key` (4) and `IssueBotTokenReq.public_key` (5) are required**: the JSON of a PUBLIC JWK, `{"kty":"EC","crv":"P-256","x":…,"y":…}` or `{"kty":"OKP","crv":"Ed25519","x":…}`. The plugin computes its RFC 7638 thumbprint, registers it as a device of the token's owner (labelled `API token: <name>` or `Machine account key`) and binds the token to it. `CreateApiTokenResp.device_id` (4) and `IssueBotTokenResp.device_id` (4) return the thumbprint. The program sends `Authorization: DPoP <token>` with a DPoP proof signed by its key on every request; without one, or signed by another key, the token is refused exactly like a session.
- **The key is read strictly.** One JSON object of at most 1024 bytes, no duplicate member; base64url coordinates of 32 bytes in their canonical spelling (no line breaks); a P-256 point on the curve; only the members a key export carries (`alg`, `use`, `key_ops`, `kid`, `ext`) beside the key's own, none of them `null`. **A JWK with any private member is refused** before anything else is read, and nothing of it is stored, logged or repeated back.
- **New refusals**, on the `public_key` field with an `ErrorDetail` only (never `UNAUTHENTICATED`): `DEVICE_KEY_REQUIRED` and `DEVICE_KEY_INVALID` (`INVALID_ARGUMENT`; a request with no `public_key` at all is refused earlier by the gateway's field validation, `INVALID_ARGUMENT` with `REQUIRED_VIOLATION` on `public_key`, so `DEVICE_KEY_REQUIRED` reaches only callers that bypass it, such as in-process project code), `DEVICE_KEY_REVOKED` (`FAILED_PRECONDITION`: the key's device was revoked for good — generate a new key), `BOT_KEY_MISMATCH` (`FAILED_PRECONDITION`).
- **`IssueBotToken` needs a signed-in session**, as `CreateApiToken` does (`PERMISSION_DENIED`, `SESSION_REQUIRED`): an API token — a machine account's own, or an operator's — no longer mints machine tokens.
- **A machine account has exactly one key.** Its first token registers it; later tokens must name the same key (its replicas share it), another is refused with `BOT_KEY_MISMATCH`. To replace it, revoke the account's device on the admin `Devices` page, then issue with the new key. New queries `AuthQuery.LockMachineAccount` and `ListMachineKeys` (`service_account`).
- **A key is a program's or a signed-in device's, never both.** New column `Device.api_key` (12, `FALSE` by default; `RegisterDeviceReq.api_key`, 5, written when the row is created). A program's key never signs in, the key of a device that signs in is refused for an API token (`DEVICE_KEY_INVALID`), and `ListDevices`, `RevokeOtherDevices` and `RevokeAllDevices` (`devices`) list and revoke signed-in devices only — API tokens keep surviving them. The admin `Devices` page lists every key, so an operator can end an API token by revoking its key.
- **The creator is recorded.** The creating caller's device (the operator's, for a machine account) is stored as `UserToken.approved_by_device_id` (new `IssueApiTokenReq.device_id` 6, required, and `approved_by_device_id` 7; new query `AuthQuery.GetUserDeviceByThumbprint`, `api_token`). Revoking that ONE device on purpose — the owner's `RevokeDevice`, the admin `Devices` revoke — ends the API tokens it created too (new mutation `AuthMutation.RevokeApprovedApiTokens`, `api_token`): a stolen browser session could have created one bound to the thief's key. `RevokeOtherDevices` and `RevokeAllDevices` keep sparing API tokens (`RevokeDeviceTokens`' second statement now matches session tokens only). A machine account's tokens are the account's, not the operator's, so revoking the operator's device leaves them.
- **The creator recorded is the ROOT approver**: for a token created from a CLI session, the browser that approved the CLI login (new query `AuthQuery.GetSessionApprover`), so revoking that browser ends the CLI session and the token. The admin `Devices` page revokes an already revoked device again only to end the API tokens it created.
- **New event `ApiTokenCreated`** (`auth.api_token.created`, `api_token`), emitted for every new API token, a machine account's included: `token_id`, `user_id` (the owner), `created_at`, `name`, `device_id` (the creating request's key — a CLI's own), `key_thumbprint` (the program's key), `created_by`. No secret. `IssueApiTokenReq` takes the event-only `thumbprint` (8), `key_thumbprint` (9) and `created_by` (10).
- **After a compromise**: "sign out everywhere else" and a password change keep API tokens; review `ListApiTokens` and revoke the stolen device itself (see README).
- **Issuance is in the sign-in history**: methods `API_TOKEN` (7) and `BOT_TOKEN` (8) and outcome `KEY_REFUSED` (19); one row per call, the success row in the transaction that mints the token.
- **`ListApiTokens` shows each token's key**: `ApiTokenInfo.device_thumbprint` (8) and `device_revoked_at` (9).
- **Migration.** Generate and apply a migration: new column `Device.api_key` (`FALSE` on existing rows — every existing device signed in). Callers of `CreateApiToken` and `IssueBotToken` must send `public_key`; the SDKs' key helper comes with the client release.

### Nothing in the auth tables is deleted, in any table (breaking)

Tokens, accounts, devices and clients are kept (see "Tokens, accounts and clients are revoked, not deleted" and the device binding); the remaining sixteen `DELETE` statements — roles, role grants, role permissions, organizations, memberships, invitations, pending sign-ups, authenticators and recovery codes — are now state changes too. The rows stay as the history, and every read skips ended rows, so what callers and permission checks see is what the delete gave. A test now refuses any `DELETE` in any auth proto or in the plugin's Go.

- **How a removed key is reused.** A table whose key must be reusable after a removal gets an `ended_key` column (`''` while live, the row's own id once ended) inside its unique index: `Role (name, ended_key)`, `Organization (slug, ended_key)`, `OrgMembership (user_id, org_id, ended_key)`, `UserRole (user_id, role_id[, org_id], ended_key)` (all three variants), `UserTotpSecret (user_id, ended_key)`. Re-adding is the same INSERT and creates a new row; the ended row is never rewritten. `Role.name` and `Organization.slug` are no longer unique on their own (a deleted role's name and a deleted organization's slug can be taken again, as before). `RolePermission` keeps its `(role_id, permission_id)` index — the platform's role seed upserts on it — and revives instead: see below.
- **rbac.** `DeleteRole` stamps `Role.deleted_at`, revokes every grant of the role and frees its name; its permission rows stay. **A preset role deleted at runtime now stays deleted**: it keeps its `preset_key`, and the role seed (which matches on that key and never writes `deleted_at`) leaves it deleted on every re-seed, where it used to re-create it. To bring it back, declare it under a new key. `RevokeRoleFromUser` stamps `UserRole.revoked_at` and takes an optional `revoked_by`. `RemovePermissionFromRole` stamps `RolePermission.removed_at` and takes an optional `removed_by`. `AddPermissionToRole` is an UPSERT that revives a removed pair, behind two guards: a deleted or unknown role is refused with `NOT_FOUND` / `ROLE_NOT_FOUND` (by a no-op UPDATE that locks the role row, so concurrent writes naming one role run one after another), and a permission the role already carries with `ALREADY_EXISTS` / `PERMISSION_ALREADY_GRANTED` (as before); so `RolePermissionAdded` and the log row come only from a real change. It takes an optional `added_by`. **`AssignRoleToUser` refuses a deleted or unknown role** (`NOT_FOUND` / `ROLE_NOT_FOUND`; it used to insert a grant for any id), and `ListUserOrgGrants` skips grants of deleted roles. Both permission calls append to the new append-only table `RolePermissionChange` (`role_id`, `permission_id`, `kind` ADDED/REMOVED — new enum `RolePermissionChangeKind` — `changed_by`). `UpdateRole` refuses a deleted role (NotFound). Every role and permission query skips deleted roles, revoked grants and removed permissions; **`GetUserPermissions` now joins `Role`**, so a deleted role's permissions are no longer reported (it used to keep granting them).
- **org_membership.** `DeleteOrganization` stamps `Organization.deleted_at`, removes the organization's memberships and revokes its org-scoped grants, and frees its slug. The admin Organizations page now deletes through the new **`AuthService.RemoveOrganization`**, which first closes the organization's pending invitations (with `org_invite`: new mutation `CloseOrgInvitesOfOrg`, the caller as `closed_by`) and then calls `DeleteOrganization`, in one transaction. **`DeleteOrgMembership` is renamed `MarkOrgMembershipRemoved`** (optional `removed_by`; `AuthService.RemoveOrgMembership` passes the caller): it stamps `removed_at` / `removed_by` and revokes the member's org grants with the same actor. `UpdateOrgMembership` takes an optional `changed_by` (passed by `UpdateOrgMembershipRole`), recorded as `revoked_by` on the grants a role change replaces. `UpdateOrganization` refuses a deleted organization. Every organization and membership query skips ended rows, so a deleted organization's `owner_id` grants nothing.
- **org_invite.** **`DeleteOrgInvite` is renamed `CloseOrgInvite`** (optional `closed_by`; `RevokeOrgInvite` passes the caller) and **`ClearExpiredOrgInvite` `CloseExpiredOrgInvite`**: both stamp `OrgInvite.closed_at`. The pending index becomes `(org_id, email) WHERE accepted_at IS NULL AND closed_at IS NULL`. A closed invitation is refused like a spent one and is not listed. `GetPendingOrgInviteByToken`, `BindOpenOrgInvite`, `ConsumeOrgInviteByToken` and `ListPendingInvitesForEmail` also require the invitation's organization to be live, so a deleted organization's invitations cannot be used even when it was deleted through `AuthMutation.DeleteOrganization` directly.
- **sign_up_confirmation.** `ClaimPendingSignUp` is `UPDATE … SET claimed_at = NOW() … RETURNING` (still exactly-once). **`DeletePendingSignUpsForEmail` is renamed `SupersedePendingSignUpsForEmail`** (stamps `superseded_at`), and **`PurgeExpiredPendingSignUps` is removed** — SignUp no longer purges; an expired registration stays, refused by its `expires_at`. New eraser `ErasePendingSignUpAddress`: an erasure (`EraseUsers`) now also ends the address's pending registrations and replaces their address and hashes, since they are no longer deleted at confirmation.
- **two_factor.** **`DeleteTotpSecret` is renamed `RevokeTotpSecret`**: it stamps `UserTotpSecret.revoked_at` and clears `seed` and `secret`; **`DeleteRecoveryCodes` is renamed `RevokeRecoveryCodes`**: it stamps `UserRecoveryCode.revoked_at` on the unused codes. A revoked authenticator verifies nothing and a revoked code is refused like a used one. `TotpDisabled` still fires on both disable and re-enrolment.
- **Events** keep their names and payloads.
- **Migration.** Generate and apply a migration: new columns `Role.deleted_at`, `Role.ended_key`, `RolePermission.removed_at` / `removed_by`, `UserRole.revoked_at` / `revoked_by` / `ended_key` (rbac); table `RolePermissionChange` (rbac); `Organization.deleted_at` / `ended_key`, `OrgMembership.removed_at` / `removed_by` / `ended_key` (org_membership); `OrgInvite.closed_at` / `closed_by` (org_invite); `PendingSignUp.claimed_at` / `superseded_at` (sign_up_confirmation); `UserTotpSecret.revoked_at` / `ended_key`, `UserRecoveryCode.revoked_at` (two_factor). The unique indexes listed above are replaced. No data changes: every existing row is live (`ended_key` `''`, every new state column NULL).
- **The platform's role seed** of a release that knows `RolePermission.removed_at` ends the rows a declaration drops instead of deleting them, revives a declared permission removed at runtime (only a change to the declaration removes a seeded permission for good), and logs its changes in `RolePermissionChange`; it leaves a deleted role's permissions alone. An older platform still prunes with a `DELETE`: update both together.

### Tokens, accounts and clients are revoked, not deleted (breaking)

Revoking a token, erasing an account and revoking a registered client used to delete rows, so afterwards nobody could say which credential had existed, who ended it or why. Every one of those paths now writes a state instead, and the rows stay as the history.

- **Tokens are revoked, not deleted.** New base-tier columns `UserToken.revoked_at` (nullable), `UserToken.revoked_by` (nullable UUID: the holder for a logout, an API-token revoke, a password change and the devices calls; the operator for an admin revoke or an erasure; NULL for a reset, a disable and `RevokeToken`) and `UserToken.revoke_reason` (new enum `RevokeReason`, default `REVOKE_REASON_NONE`). The first revocation stands: every revoking statement is guarded on `revoked_at IS NULL`, so revoking a revoked token changes nothing and is not an error.
- **A revoked token is refused exactly as an expired one.** Every token lookup filters `revoked_at IS NULL` beside the expiry. The holder of the bound key hears `SESSION_EXPIRED`, dated when the token ended, or `DEVICE_REVOKED` when its device was revoked; anyone else the plain `invalid credentials`. Until now a revoked token, being gone, always answered `invalid credentials`. `GetExpiredToken` / `GetExpiredTokenWithType` read revoked rows too and return `revoked_at` and `device_revoked_at`; their `expires_at` is now nullable.
- **Expired tokens stay**, refused by their `expires_at`; nothing sweeps them.
- **Storage mutations renamed** to say what they do: `DeleteToken` → `RevokeToken`, `DeleteSessionToken` → `RevokeSessionToken`, `DeleteApiToken` → `MarkApiTokenRevoked`, `DeleteOtherSessionTokens` → `RevokeOtherSessionTokens`, `DeleteUserSessionsForReset` → `RevokeTokensForReset`, `DeleteDeviceTokens` → `RevokeDeviceTokens`, `DeleteUndevicedSessions` → `RevokeUndevicedSessions`, `DeleteAllUserTokens` → `RevokeAllUserTokens`, `DeleteAuthClient` → `RevokeAuthClient`, `DeleteUser` → `EraseUser`. `DeleteTokenPermissions` is removed: a revoked API token keeps its subset rows. `RevokeUserToken` keeps its name, revokes instead of deleting and takes `revoked_by`. Several responses lost the ids of the rows they deleted (`RevokeTokensForResetResp`, `RevokeDeviceTokensResp`, `RevokeUndevicedSessionsResp`, `RevokeAllUserTokensResp` are empty). Project code calling any of them by the old name must be updated.
- **`DeleteUser` is now erasure (GDPR) by pseudonymisation** (`user_admin`). New column `User.erased_at`, new service methods `AuthService.EraseAccount` (one account) and `AuthService.EraseUsers` (the bulk form) and storage mutations `AuthMutation.BeginUserErasure` (first: access ends) and `AuthMutation.EraseUser` (last: the address and `erased_at`). The row stays (one transaction with a transaction coordinator; without one a partial erasure has already ended the account's access and retrying completes it); its address becomes `erased-<id>@erased.invalid` (the old address can sign up again; the `erased.invalid` domain is now refused with `INVALID_ARGUMENT` / `EMAIL_INVALID` at SignUp, ConfirmSignUp, OAuth account creation, CreateBot and the admin Users page's update, which now goes through the new `AuthService.UpdateAccount`), the password hash becomes the unusable `!`, the account is disabled, every token is revoked (`REVOKE_REASON_USER_ERASED`) and every device revoked with its label and IP blanked. With the matching features on, the same transaction blanks OAuth identities (the provider subject is replaced, so the person can sign up through the provider again) and login codes (including those of the sign-in that created the account), clears the authenticator seed and spends recovery codes and pending challenges, spends reset and verification links, and clears the address on invitations sent to it (a pending one is ended) (new mutations `EraseOAuthData`, `EraseTwoFactorData`, `SpendEmailVerificationTokens`, `EraseOrgInviteAddress`). `EnableUsers` leaves an erased account disabled and `UpdateUser` refuses it. A second erase is a no-op.
- **Event `UserDeleted` (`auth.user.deleted`) keeps its name, topic and fields**; the erasure emits it. Erasure is the plugin's deletion, so a subscriber that cleaned up on a delete erases its copy of the person's data there. Nothing to re-subscribe, and a project's events lock is unchanged.
- **Admin pages: `delete` erases or revokes; nothing is deleted.** The Users and ServiceAccounts pages keep their `delete` (same button, same model `delete` permission, same response `user_id`), now bound to `AuthService.EraseAccount`, which erases the account with the operator recorded. The Sessions page keeps its `delete` (response `token_id`), now bound to `AuthService.RevokeSession`, which revokes the token with the operator recorded as `revoked_by`; revoked sessions stay listed with `revoked_at` and `revoke_reason`. No page action is added, so an existing admin gets no new permission and no new scaffolded e2e test. Users lists `erased_at`. The bulk forms `AuthService.EraseUsers` and `AuthService.RevokeSessions` are for project code and refuse an empty selection.
- **Registered clients are revoked, not deleted** (`cli_login`). New column `AuthClient.revoked_at`. The unique `(client_id, redirect_uri)` index is unchanged, so a revoked pair stays taken: `RegisterClient` refuses it with `FAILED_PRECONDITION` / `CLIENT_REVOKED`; register the callback under a new `client_id`. A client that lost its secret keeps its `client_id` through the new `AuthService.RotateClientSecret` (`POST /auth/clients/{id}/rotate-secret`, published by the new opt-in feature `client_secret_rotation`, which requires `cli_login`; storage `RotateAuthClientSecret`), which refuses a revoked registration. `AuthService.DeleteClient` keeps its name, request and route (`DELETE /auth/clients/{id}`) and now revokes; a revoked registration is refused exactly as an unregistered one, `SetClientEnabled` cannot restore it, and `ListClients` shows it with `revoked_at`.
- **`ListApiTokens`** lists revoked tokens too, with `revoked_at` and `revoke_reason` (new `ApiTokenInfo` fields).
- **`ResetPasswordResp.sessions_revoked`** is now true for an account that held no live token (the revocation no longer answers NotFound for nothing to do).
- **Migration.** Generate and apply a migration: new columns `UserToken.revoked_at`, `revoked_by`, `revoke_reason` (default 0), `User.erased_at` (with `user_admin`) and `AuthClient.revoked_at` (with `cli_login`). No data changes: every existing token is live (`revoke_reason` 0), every existing registration live.

### An expired session says so, with its date

An expired bearer used to answer the same `UNAUTHENTICATED: invalid credentials` as an unknown one, so a client could not tell that signing in again would fix it.

- **An expired token now answers `SESSION_EXPIRED`.** A token that exists and is past its `expires_at` is refused with `UNAUTHENTICATED` carrying an `ErrorDetail` (code `SESSION_EXPIRED`, a translated sentence naming the expiry date) and a `google.rpc.ErrorInfo` (reason `SESSION_EXPIRED`, domain `auth.w17`, metadata `expires_at` in RFC 3339 UTC). An expired API token answers the same code, with a sentence that says to create a new token. With device binding (same release) the code is said only to the holder of the token's key, and a revoked token answers it too; anyone else, and an unknown token, gets `invalid credentials`, no detail. New queries `AuthQuery.GetExpiredToken` and `GetExpiredTokenWithType` (`api_token`); they run only when the normal lookup found nothing. Two new msgids reach the project catalog.
- **`last_used_at` is now written** (`api_token`) when a token authenticates, at most once a minute per token (application clock), by the new mutation `AuthMutation.TouchTokenLastUsed`. A failed write does not fail the request.
- **No migration** for this change: no column, table or index is added.

### Every sign-in attempt is recorded, and events name the device

The plugin kept no record of sign-in attempts: a failed password, a refused device or a burst of guesses at one address left nothing behind, and the token and MFA events did not say which device caused them.

- **New table `SignInEvent`** (base tier, append-only): `created_at`, `user_id` (NULL when the attempt reached no account), `address` (the address named, normalised), `device_id` (the Device row) and `thumbprint` (the proof's key, also when no Device row exists), `ip`, `user_agent`, `method` (new enum `SignInMethod`: PASSWORD, MFA, SIGN_UP, SIGN_UP_CONFIRM, OAUTH, CLI, API_TOKEN, BOT_TOKEN) and `outcome` (new enum `SignInOutcome`: OK, MFA_REQUIRED, UNKNOWN_ACCOUNT, WRONG_PASSWORD, ACCOUNT_DISABLED, MACHINE_ACCOUNT, DEVICE_PROOF_REQUIRED, DEVICE_REVOKED, WRONG_CODE, TOO_MANY_ATTEMPTS, OTHER_DEVICE, RATE_LIMITED, EMAIL_TAKEN, SIGN_UP_REFUSED, UNVERIFIED_EMAIL, CLIENT_REFUSED, ERROR, REFUSED, KEY_REFUSED). Indexes `(user_id, created_at)`, `(address, created_at)` and `created_at`.
- **Every attempt on every mint path writes exactly one row**: `SignIn` (the admin's sign-in too), `SignUp` when it issues a session, `ConfirmSignUp`, `VerifyMfa`, `OAuthExchange`, `CliToken`, `CreateApiToken` and `IssueBotToken`, whatever the outcome — a request without a proof and an unknown address included. A parked registration (`sign_up_confirmation`) records nothing. New mutation `AuthMutation.RecordSignInEvent`.
- **Nothing a caller gets changes.** A success writes its row in the transaction that issues the session (`SignIn`, `VerifyMfa`, `OAuthExchange` and `CliToken` now mint in one: IssueToken and the row; device trust is renewed after it commits), so a failed history write fails that sign-in. A refusal writes its row on its own; a failed write is logged and the refusal is unchanged.
- **A refusal's row is bounded**: written synchronously on a context the caller's cancellation does not end, for at most 2 seconds (plus half a second for the account read an erased-account check may need). A byte that is not UTF-8 in the address, user agent or client address is stored as U+FFFD (also in `Device.label` / `ip`).
- **An attempt at an erased account** (a challenge or an OAuth / CLI code issued before the erasure, the placeholder typed at SignIn) is written with the placeholder address and without `ip` / `user_agent`. `GetUserByEmail` now also projects `erased_at` (`user_admin`). When the account cannot be read, the row keeps no `ip` / `user_agent`.
- **`SignInEvent.device_id` is the Device row's UUID**; the key thumbprint the events call `device_id` is the `thumbprint` column, which the admin list shows.
- **`CliToken` reports a failed mint as its other refusals do** (opaque, or `AUTH_UNAVAILABLE` for an outage) instead of passing the store's error through.
- **The person's own history:** `AuthService.ListMySignInEvents`, REST `GET /auth/sign-ins`, published by the new opt-in feature `my_sign_ins` (requires `authenticate_turnkey`; off by default, so an upgrade adds no endpoint and no scaffolded e2e test): the caller's latest 100 rows, newest first. New query `AuthQuery.ListUserSignInEvents`.
- **The operator's:** a new admin page `SignIns`, opt-in: enable the new feature `admin_sign_ins` (requires `user_admin`) and, if your admin declares `nav` groups, add `SignIns` to one. It is not part of `user_admin`, so upgrading adds no page to an existing activation. Queries `ListSignInEvents` (cursor-paged) and `GetSignInEvent` (`user_admin`).
- **Erasure** (`EraseUsers`) also pseudonymises the history: the account's rows and the rows that reached no account but named its address get the placeholder address, and lose `ip` and `user_agent` (new mutation `EraseSignInEvents`, `user_admin`).
- **Events carry `device_id`** — the key thumbprint, the value of `AuthResp.device_id`: `TokenIssued` (4), `TokenRevoked` (3), `UserTokenRevoked` (2, the operator's device), `MfaChallengeRequested` (7), `MfaVerified` (3), `RecoveryCodeUsed` (2), `TotpEnrolled` (3), `TotpConfirmed` (2), `TotpDisabled` (2). Their mutations take an event-only `thumbprint` (`IssueTokenReq` 5, `RevokeSessionTokenReq` 4, `RevokeUserTokenReq` 3, `ConsumeMfaChallengeReq` 2, `ConsumeRecoveryCodeReq` 3, `CreateTotpSecretReq` 4, `ConfirmTotpSecretReq` 2, `RevokeTotpSecretReq` 2); project code calling them directly may pass one.
- **Migration.** Generate and apply a migration: the new table `SignInEvent`. No existing row changes.

### A provider can be configured outside the admin

`OAuthProvider` could only be created or edited on the generated admin page, and a fixture could set only the plaintext legacy `client_secret`, which the plugin moves to the encrypted `secret` and clears. A deployment that does not expose the admin had no way to put a provider's secret in place.

- **New mutation `AuthMutation.UpsertOAuthProvider`** (`oauth`) creates or rewrites a provider by `name`, writes `secret` encrypted with the project's field key and clears `client_secret`. Call it from the project's own code, for example at start with values from the deployment's secrets.
- **The provider's `name` is unique across tenants**; under `tenant_scope` the tenant is set when the provider is created.
- **A rewrite replaces every field.** A blank field clears it, and `enabled` left out turns the provider off, so send the whole configuration each time. It is meant for the project's own code, never for a name a tenant chose.

### The admin counts only realm-wide roles

The admin preset authenticated through `Authenticate`, which selects an organization (from the request, or the caller's only one) and lets that organization's roles grant permissions. A role scoped to one organization, a wildcard one above all, therefore passed every admin page for every organization. The same was true of organization ownership.

- **New `AuthService.AuthenticateAdmin`**, which the admin preset now uses as its `user_lookup`. It is `Authenticate` with no organization selected, so only realm-wide roles survive the narrowing, and ownership grants nothing. The admin is one console across every organization.
- **App endpoints are unchanged.** They keep `Authenticate` and its organization scoping.
- **A project that wires `user_lookup` by hand** should point it at `AuthenticateAdmin`.
- **An admin page over an `org_id`-scoped model now refuses** with `missing required scope: org_id`, for every caller. No organization means no `org_id` scope on the admin's storage calls. Such a page used to serve whichever single organization the caller belonged to, which was never the whole console.
- **`tenant_scope` is unchanged.** The admin still stamps the caller's `tenant_id`, so it stays inside the caller's tenant.

### OAuth and sign-up refusals carry a code

An OAuth refusal used to be the bare opaque `invalid credentials`, so a page could not tell a person what to do. Every OAuth handler now answers with an `ErrorDetail` code. The status code and message stay as they were.

| Code | When |
|---|---|
| `OAUTH_ACCOUNT_UNVERIFIED` | An account exists for the provider's address and never verified it, so it is not linked. |
| `OAUTH_EMAIL_UNVERIFIED` | An account exists for the address and the provider did not verify it. |
| `ACCOUNT_DISABLED` | The sign-in resolved to a disabled account. Only OAuth says this; a password sign-in still answers `INVALID_CREDENTIALS`. |
| `OAUTH_FAILED` | Everything else: the state, the login code, the verifier, the provider's answer. |

Saying these plainly tells an attacker nothing new. `OAUTH_ACCOUNT_UNVERIFIED` and `ACCOUNT_DISABLED` are reached only after the provider proved that the caller owns the address. `OAUTH_EMAIL_UNVERIFIED` is not, because the provider did not verify the address. It says only what the refusal already said: the callback succeeds when no account holds the address and refuses when one does.

Only refusals this plugin made pass through as they are. A storage answer that carries its own detail (not found, a timeout) is still classified, as an outage or as `OAUTH_FAILED`.

The sign-up gates gain codes too, on `SignUp` and the OAuth exchange alike. Outages still answer `AUTH_UNAVAILABLE`.

| Code | When |
|---|---|
| `SIGNUP_NOT_INVITED` | `invite_only`, and nothing invites the address. |
| `INVITE_OTHER_ADDRESS` | The invitation link is bound to another address (or an open link was already used by another registration), and nothing invites this one. The other address is not revealed. |
| `SIGNUP_CLOSED` | The address is outside `sign_up_allowlist`. |

### Registering through a provider can carry an invitation

Under `invite_only`, an OPEN invitation (one that names no address, for example sent by SMS) could not be used to register through a provider. The callback created the account and had no way to receive the token. Only a bound invitation whose address matched the provider's worked.

- **The callback no longer creates an account.** For an identity that has none, the login code keeps the provider-verified identity (subject, address, whether the provider verified it). `OAuthLoginCode` gains `provider_id`, `external_id`, `email` and `email_verified`, and `user_id` is now nullable.
- **`OAuthExchange` creates it, with the new `invite_token`.** The rules are the same as `SignUp`: the allowlist, `invite_only`, a bound invitation's address, and an open link spent by its first registration. Without a valid invitation the exchange refuses with the gate's coded refusal. The token travels only in the page's own exchange request, never in a URL or through the provider.
- **The user, its roles, the verified address, the spent invitation and the identity link commit together.** Before, the identity link was written after the user's transaction.
- **An identity that already has an account ignores the token.** The exchange resolves the identity again before creating, so a second login code for the same subject (another tab) signs in to the account the first one made instead of failing.
- **A refused registration spends the login code.** The page has to start the sign-in again, with the invitation, to retry.
- **Generate a migration.** `OAuthLoginCode` gains four columns and `user_id` becomes nullable; the new text columns default to empty, so existing rows migrate.

### One bootstrap administrator, even under concurrent first sign-ups

The `first_user` roles (typically every permission) were decided by reading "no users yet" before the sign-up transaction. Two sign-ups racing on an empty deployment both read zero, and both became administrators.

- **New table `BootstrapClaim` (rbac)** with one row on a constant key. Generate a migration as usual.
- **The sign-up that receives the `first_user` roles writes the claim** in its own transaction (`AuthMutation.ClaimBootstrapAdmin`, `UPSERT … ON CONFLICT DO NOTHING`). A concurrent sign-up waits on the key, conflicts, and gets the default roles. A rolled-back sign-up leaves the claim free.
- **The claim is never reopened.** Once an administrator was handed out, an empty user table does not hand out another. A deployment that already has users never writes the claim, and a seeded first account writes none either. Accounts are no longer deleted (an erased one stays as a pseudonymised row), so the user table never empties again and the bootstrap does not reopen there.

### An invitation to a role with a long name can be accepted

`OrgMembership.role` held 32 characters, while a role name holds 100. An invitation to a role whose name was longer than 32 characters was created, and then every acceptance failed when it wrote the membership. Changing a member to such a role on the admin's OrgMemberships page failed the same way.

- **`OrgMembership.role`, `AddOrgMembershipReq.role` and `UpdateOrgMembershipRoleReq.role` hold 100 characters**, as wide as `Role.name` (org_membership). Generate a migration as usual; it widens one column.

### A reset or a password change spends every other reset link

Each reset request inserts a new link, and a successful reset consumed only the link it used. Any other link the person had asked for, or one intercepted from their mailbox earlier, could set the password again until it expired. A password change left them all alive too.

- **`ResetPassword` and `ChangePassword` spend every live link of the account** in the same transaction as the new password. They use the new `AuthMutation.SpendPasswordResetTokens` (password_reset).
- **`password_change` without `password_reset`** builds and behaves as before: there are no links to spend.

### `password_change` builds without `api_token`

`DeleteOtherSessionTokens` filtered on `UserToken.token_type`, a column only `api_token` adds. An activation with `password_change` and without `api_token` failed code generation.

- **The filter is now `?feature(api_token) token_type = 1`.** Without `api_token`, every token is a session, and the sweep deletes the other ones.
- **`DeleteOtherSessionTokensReq` drops `token_type`** (field 3, now reserved). The statement names the session realm itself.

### `api_token` requires `rbac`

`GetUserRolePermissionsByRealm` reads `UserRole`, `Role` and `RolePermission`, the tables `rbac` adds. An activation with `api_token` and without `rbac` failed code generation; it is now refused by the manifest instead. `rbac` is on by default, so only an activation that turned it off is affected.

### An OAuth sign-in no longer makes the device trusted

An OAuth sign-in skips the plugin's second factor, and with `devices` it still marked the device trusted. Under `two_factor_scope=new_devices` a trusted device skips the second factor, so after one OAuth sign-in, password sign-ins from that device skipped it too.

- **`OAuthExchange` binds the session to the device and does not trust it.** It returns no `device_trust_token`.
- **A device becomes trusted only by passing the second factor (`VerifyMfa`).** A password sign-in that met no second factor renews the trust of a device that already has it and grants none. Before, with `devices` on and `two_factor` off, every password sign-in trusted its device, so switching on `two_factor_scope=new_devices` later let every device that had ever signed in skip the new factor. Such a deployment should clear existing trust (`trusted_at`, `trust_token_hash` on `Device`) when it turns `two_factor` on.

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
