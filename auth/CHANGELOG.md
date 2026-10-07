# auth — changelog

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

The README now has a section on what a consumer has to know: sessions and tokens, invitations (the plugin sends no mail, the link is returned once to the inviter), and where a refusal's sentence for a person is.

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
