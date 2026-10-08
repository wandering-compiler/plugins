# auth — changelog

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

### The QR code comes with the enrolment

`EnrollTotpResp.qr_svg` is `otpauth_uri` as a QR code: a self-contained SVG with black modules on white and the quiet zone included. Render it as it is. Encoding is done by `rsc.io/qr`, the SVG rendering by `lib/qrsvg`. The client no longer needs a QR library, and the seed is never handed to one.

New storage methods:
- `AuthMutation`: `ClaimTotpStep`, `CreateRecoveryCode`, `DeleteRecoveryCodes`, `ConsumeRecoveryCode`;
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
