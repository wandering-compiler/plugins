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
   - Renamed: `DeleteToken` → `RevokeToken`, `DeleteSessionToken` → `RevokeSessionToken`, `DeleteApiToken` → `MarkApiTokenRevoked`, `DeleteOtherSessionTokens` → `RevokeOtherSessionTokens`, `DeleteUserSessionsForReset` → `RevokeTokensForReset`, `DeleteDeviceTokens` → `RevokeDeviceTokens`, `DeleteUndevicedSessions` → `RevokeUndevicedSessions`, `DeleteAllUserTokens` → `RevokeAllUserTokens`, `DeleteAuthClient` → `RevokeAuthClient`, and `DeleteUser` → `BeginUserErasure` + `EraseUser` (through `AuthService.EraseUsers`).
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
   - Delete buttons are gone. Users and ServiceAccounts erase (`Erase`), and Sessions and Devices revoke (`Revoke`). Revoked and erased rows stay listed.
   - New pages: `Devices` and `SignIns` (`user_admin`).
   - The admin's sign-in form has a "This is a public computer" box, and the app's sign-in requests take `public_computer`. Such a session never trusts the device, is kept in session storage only, and expires after `public_session_ttl_seconds`.
   - Federated (OAuth) sign-in to the admin needs `oauth` enabled on the admin's realm. Without it the sign-in returns a token bound to no key, and the admin refuses it.
7. **Known limits.**
   - MCP clients keep their OAuth flow without DPoP. Their tokens (`mcp_only`) are accepted only on the MCP surface.
   - On a surface that binds devices, the e2e runner skips MCP scenarios and counts the skips.
