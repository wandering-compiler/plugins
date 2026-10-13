# auth — behaviour specification

This document says what the `auth` plugin does, feature by feature, and what it
must never do: the security, consistency, performance and failure properties an
application built on it relies on. It is the reference the plugin's tests and
the example projects are measured against. A property listed here without a
proof is a gap, not a promise.

It covers plugin version 0.1.0-rc.24.

## How to read it

- Every **invariant** is one MUST or MUST NOT statement about observable
  behaviour, with a stable id (`<feature>/<name>`, `interaction/<a>-<b>-<name>`,
  `auth/<name>`). Ids do not change when the wording does, so tests and
  examples can cite them.
- **Categories:** Security · Consistency & concurrency · Performance · Failure &
  configuration.
- **Proof** names the unit tests in `auth/src/handlers` (or `auth/src/lib/…`)
  that demonstrate the invariant. Those tests run the handlers against
  in-memory fakes of the generated storage clients. They prove sequencing and
  wire shape, not what only the database can enforce (a unique index, a
  conditional `UPDATE`/`DELETE … RETURNING` under concurrency, a `NOW()`
  comparison, a transaction rollback, column encryption). Such rows say
  **unit (mock) only** and name what a live test would have to show. `none`
  means nothing proves it yet.
- **public** means the REST preset endpoint takes no credential
  (`exclude_auth`). **failed_only** means the gateway's per-address limiter
  charges such an endpoint only for a failed request; a public endpoint
  without it is charged for every request.
- **Gaps / suspected defects** after each feature are what the code does not
  enforce although the invariant requires it, found by reading the code. The
  ones re-checked against the code are collected under
  [Verified findings](#verified-findings).

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| (base tier) | always | — | — |
| `rbac` | on | — | — |
| `authenticate_turnkey` | on | `rbac` | — |
| `sign_up_turnkey` | on | — | — |
| `sign_up_confirmation` | off | `sign_up_turnkey` | — |
| `sign_in_turnkey` | on | — | — |
| `tenant_scope` | off | `sign_up_turnkey` | `oauth` |
| `api_token` | off | `rbac` | — |
| `devices` | off | `sign_in_turnkey` | — |
| `oauth` | off | `email_verification` | — |
| `two_factor` | off | `sign_in_turnkey` | — |
| `password_reset` | off | — | — |
| `email_verification` | off | — | — |
| `cli_login` | off | — | — |
| `org_membership` | off | `authenticate_turnkey`, `rbac` | — |
| `org_invite` | off | `org_membership`, `rbac` | — |
| `password_change` | off | — | — |
| `service_account` | off | `api_token`, `user_admin`, `rbac`, `authenticate_turnkey` | — |
| `user_admin` | off | — | — |

`go_files_combined`: `service_account_tenant.go` (`service_account` +
`tenant_scope`), `service_account_org.go` (`service_account` +
`org_membership`), `signup_confirm_tenant.go` (`sign_up_confirmation` +
`tenant_scope`).

## Verified findings

Gaps confirmed by re-reading the handlers and the DQL. Each is a defect to fix
before an example may claim the invariant; the invariant id says which. Row 7
is the exception: it is read from the DQL and the manifest, and stays a
suspected defect until a build of that feature combination confirms it.

| # | finding | invariants | where |
|---|---|---|---|
| 1 | **Fixed.** The OAuth `state` was an HMAC over a nonce, the provider and the redirect, and nothing else: no expiry, not single-use, not bound to the browser that started the flow, and the callback carried the session. A callback URL captured by one person signed whoever opened it into that person's account (login CSRF). Now the browser sends a PKCE challenge at authorize, the state expires, the callback hands out only a single-use login code bound to that challenge, and `OAuthExchange` redeems it with the verifier. PKCE and an OIDC nonce go to the provider too. | `oauth/*` (state), `interaction/oauth-*` | `src/handlers/oauth.go` (`signOAuthState`, `verifyOAuthState`) |
| 2 | **Fixed.** `CliAuthorize` accepted any authenticated caller, whatever its realm, and `CliToken` then minted a full SESSION token with a fresh lifetime. A session could renew itself indefinitely, and an API token whose permissions include the CLI endpoints could become an unnarrowed session. Since rc.25 `CliAuthorize` refuses any caller that did not authenticate with a session (`SESSION_REQUIRED`). The renewal is closed by inheritance: `CliAuthorize` reads the approving session's `expires_at` (`GetLiveSessionExpiry`, live rows of the caller only; a missing or expired row refuses) and binds it to the code (`CliAuthCode.session_expires_at`), and `CliToken` mints with min(normal session TTL from now, that expiry), with no floor. A non-expiring approving session gives the normal TTL. | `interaction/api_token-cli_login-realm-escalation`, `cli_login/*` | `src/handlers/cli_login.go` (`CliAuthorize`, `CliToken`) |
| 3 | **Fixed in rc.25.** `CreateApiToken` used only the caller's user id: it checked neither the caller's realm nor its permission subset, so a narrowed API token that may call it minted a token with every API-realm permission of its holder. `CreateApiToken` now requires a session caller and refuses an API token (`PERMISSION_DENIED`, `SESSION_REQUIRED`). | `api_token/*` (narrow-only) | `src/handlers/apitoken.go` (`CreateApiToken`) |
| 4 | **Fixed in rc.25.** Token authentication never read `disabled_at`; disabling relied on deleting the tokens. `IssueBotToken` did not check it either, so a working token could be minted for a disabled machine account, and a sign-in racing a disable could leave a live session. Both resolvers now run the disabled gate on the token's owner, and `IssueBotToken` refuses a disabled machine account. | `interaction/user_admin-service_account-disabled-bot-token`, `user_admin/*` | `src/handlers/service_account.go` (`IssueBotToken`), token lookups in `proto/queries/auth_query.proto` |
| 5 | **Fixed in rc.25 (the race).** The first-user role decision (`CountUsers == 0` → `first_user` roles) was read before the sign-up transaction and nothing serialised it: concurrent first sign-ups could each become a bootstrap administrator. The first_user set is now assigned only to the sign-up that writes the `BootstrapClaim` row inside its transaction; the others get the default roles, and a claim once written is never reopened. Only a sign-up writes the claim: a seeded first account, or a deployment that had users before rc.25, holds none, so deleting every account there reopens the bootstrap. That the first stranger to register on an open deployment becomes the administrator is documented, not changed: seed the first account before opening sign-up. | `interaction/rbac-sign_up-first-user-race` | `src/handlers/signup_roles.go` (`resolveSignupRoleIDs`) |
| 6 | **Fixed.** A successful password reset consumed only the token used; every other live reset link of the account still worked afterwards, also after a password change. Both now spend every live link of the account (`SpendPasswordResetTokens`) in the same transaction as the new password. | `password_reset/*` | `src/handlers/reset.go`, `ConsumePasswordResetToken` |
| 7 | **Fixed.** `DeleteOtherSessionTokens` (`password_change`) filtered on `token_type`, a column that exists only with `api_token`, without a feature guard, so `password_change` without `api_token` could not generate. The filter is now `?feature(api_token) token_type = 1`, and `make check-stage` reports any statement that names another feature's column ungated. | `interaction/password_change-without-api_token-build` | `proto/mutations/auth_mutation.proto` (`DeleteOtherSessionTokens`) |
| 8 | **Fixed (trust); Decided (OAuth second factor).** An OAuth sign-in skips the second factor and, with `devices`, used to mark the device trusted; under `two_factor_scope=new_devices` later password sign-ins from that device then skipped the second factor too. The OAuth exchange now binds the session to the device without trusting it. A password change and disabling an account used to leave device trust in place; both now stamp `User.device_trust_revoked_at` in the statement that changes the password or disables the account, and a device trusted at or before that instant counts as untrusted at sign-in and in `ListDevices`, the caller's own device included. A reset keeps trust by design (`interaction/credential-change-device-trust`). **Decided:** an OAuth sign-in does not ask for this plugin's second factor, also for an account that has one confirmed: the provider already verified the identity, and asking for a second factor at the provider and again here is not wanted. | `interaction/oauth-devices-two_factor-trust-laundering`, `oauth/second-factor-policy`, `interaction/credential-change-device-trust` | `src/handlers/oauth.go`, `src/handlers/devices.go`, `UpdateUserPasswordIfUnchanged`, `DisableUsers` |

## Per feature

### (base tier)

- **Purpose.** The identity record and the bearer-token store every other feature builds on. It is always present.
- **Adds.** Tables `User` (`email` unique, `password_hash` PASSWORD-typed) and `UserToken` (`token_hash` unique, sha256 hex; legacy `token` nullable and unique; `user_id` indexed; `expires_at` nullable). Queries `GetUserByEmail`, `GetUserByToken`, `GetUserById`. Mutations `CreateUser` (emits `UserCreated`), `IssueToken` (emits `TokenIssued`, never carrying the token), `DeleteToken`, `UpgradeTokenHash`, `UpdateUserPassword`. No REST endpoints.
- **Env knobs.** `password_hash_algo` (argon2id | bcrypt | scrypt | pbkdf2; an unknown value fails `RegisterPlugin`), `session_token_ttl_seconds` (default 30 days; `<= 0` uses the default).
- **Requires / conflicts / combined files.** None.

| id | invariant | category | proof |
|---|---|---|---|
| `base/token-stored-as-hash` | A minted bearer token MUST be stored only as its sha256 digest. The plaintext MUST be returned to the caller exactly once and MUST NOT appear in any column or event. | Security | `TestNewBearerToken` (digest ≠ token, two mints differ). Whether `IssueToken` binds only `token_hash` is visible in the DQL, not tested. |
| `base/token-entropy` | A bearer token MUST come from a CSPRNG with at least 256 bits of entropy (64 characters from `randstr.Token`). | Security | `TestNewBearerToken` (length and non-repetition only). |
| `base/stored-digest-is-not-a-credential` | Presenting a stored `token_hash` value as a bearer MUST NOT authenticate. The lookup hashes the presented value, and the legacy column is NULL on every hashed row. | Security | none |
| `base/legacy-token-migrates-once` | A legacy row (plaintext token, no hash) resolved by a lookup MUST be moved to `token_hash`, with `token` cleared, by a statement guarded on `token_hash IS NULL`. A concurrent second upgrade MUST change nothing. A failed upgrade MUST NOT fail the request. | Consistency & concurrency | `TestUpgradeLegacyToken`, `TestResolvePrincipalSession_LegacyRowIsMovedToTheHash`, `TestResolvePrincipalRealmAware_LegacyRowIsMovedToTheHash`. **Unit (mock) only:** a live test would race two requests carrying one legacy token and assert that exactly one `UPDATE` matched and the row ends with the correct hash and a NULL `token`. |
| `base/session-ttl-stamped` | Every session token MUST be minted with `expires_at = now + session_token_ttl_seconds`, falling back to 30 days when the value is `<= 0`. It MUST NOT be minted with a zero or NULL expiry. The one exception is earlier, never later: a CLI session ends no later than the session that approved it (`cli_login/no-lifetime-extension`). | Security | `TestSessionTokenExpiry_ConfiguredTTL`, `TestSessionTokenExpiry_DefaultWhenUnset`, `TestIssueSession_StampsExpiry`, `TestCliToken_ANonExpiringApproverGivesTheNormalTTL` |
| `base/expired-token-refused` | A token with `expires_at <= NOW()` MUST NOT resolve in any token lookup. | Security | none. A live test would mint a token with a past `expires_at` and assert `Authenticate` refuses it. The predicate is SQL-only. |
| `base/expired-token-says-so` | A bearer that EXISTS and is past `expires_at` MUST be refused with Unauthenticated carrying `ErrorDetail{code: SESSION_EXPIRED}` (translated sentence naming the expiry) and `google.rpc.ErrorInfo{reason: SESSION_EXPIRED, domain: auth.w17, metadata.expires_at: RFC 3339 UTC}`. An unknown token, a failed expiry probe, and an outage MUST keep their previous answers (opaque refusal with no detail; Unavailable), and the probe runs only on the live lookup's NotFound. An expired row MUST NOT be moved to the hash or stamped as used. | Security | `TestAuthenticate_ExpiredSessionSaysSo`, `TestAuthenticate_ExpiredApiTokenSaysSo`, `TestAuthenticate_UnknownTokenStaysOpaque`, `TestAuthenticate_LookupOutageIsNotProbedForExpiry`, `TestResolvePrincipalSession_ExpiredVsUnknown`, `TestSessionExpired_StatesUTC`, `TestSessionExpiryStatements` (`GetExpiredToken`, `GetExpiredTokenWithType` match expired rows only). **Unit (mock) only:** the `expires_at <= NOW()` predicate is SQL. |
| `base/expired-sessions-swept-at-mint` | Minting a session (`IssueToken`) MUST delete, in the same transaction, the user's tokens with `expires_at <= NOW()` and, under `api_token`, `token_type = SESSION` only. It MUST NOT delete another user's token, a live or never-expiring token, or an API or bot token. | Consistency & concurrency | `TestSessionExpiryStatements` (the sweep op's conjuncts, no OR, ahead of the insert). **Unit (statement text) only:** a live test would mint a session for a user holding an expired session, an expired API token and a live session, and assert only the first is gone. |
| `base/password-hash-at-rest` | `User.password_hash` MUST hold only a salted, PHC-encoded hash from the configured algorithm. An empty plaintext MUST NOT be hashed. | Security | `TestHashVerify_RoundTrip`, `TestHash_DifferentSaltPerCall`, `TestHash_RejectsEmptyPlain` (`lib/passwordhash`) |
| `base/email-canonical` | Every write and lookup of `User.email` MUST use one canonical form (trimmed, lower-cased), so that two spellings cannot become two accounts. | Consistency & concurrency | `TestSignUpThenSignIn_EmailSpellingDoesNotSplitTheAccount`, `TestSignIn_NormalizesEmailForLookup` (handler paths only; see gaps) |
| `base/email-unique` | At most one `User` row MUST exist per address. The guarantee MUST come from the unique index, not from a read-then-insert. | Consistency & concurrency | `TestSignUp_ATakenAddressSaysSignInInstead`. **Unit (mock) only:** a live test would run two concurrent `CreateUser` calls for one address and assert one row plus one `EMAIL_TAKEN`. |
| `base/token-lookup-indexed` | Every token lookup MUST be served by a unique index (`token_hash`, or legacy `token`). Role resolution MUST be served by the `UserRole.user_id` and `RolePermission.role_id` indexes. | Performance | none (schema only) |
| `base/unknown-hash-algo-fails-boot` | An unrecognised `password_hash_algo` MUST fail `RegisterPlugin`. It MUST NOT fall back silently. | Failure & configuration | `TestHash_RejectsUnknownAlgo` (library level only). The boot path in `plugin.go` is untested. |

**Gaps / suspected defects**

1. **Canonical email is a handler convention, not a storage rule.** `normalizeEmail` runs in SignUp, SignIn, password reset and OAuth. `AuthMutation.CreateUser` and `UpdateUser` (`user_admin`, `auth_mutation.proto:2149`) write `:email` as given, and the unique index on `User.email` is case-sensitive. An address written with upper-case letters by an admin form, a fixture or hand-written code can never be found by `SignIn`, which looks up the lower-cased form. Normalise in the DQL or the field type, or use a case-insensitive unique index.
2. **No password rehash on login.** `SignIn` calls `VerifyAndRotate(..., nil)` (`auth_service.go:773`), so a stored hash is never upgraded. Changing `password_hash_algo` or raising cost parameters affects only passwords set afterwards, and weaker hashes stay at rest indefinitely.
3. **Unhashed legacy tokens persist until a later release drops the column.** A legacy token that is never presented stays in plaintext at rest. This is documented, but nothing enforces or reports how many remain.
4. **No password policy.** The only plugin-level rule is "non-empty" (`passwordhash.Hash`), and there is no maximum length either. Under `password_hash_algo=bcrypt`, a password longer than 72 bytes makes `Hash` return an error, which the sign-up and reset paths surface as an internal error instead of a validation refusal.

---

### rbac

- **Purpose.** Role-based permissions: roles, their permission grants, and user-to-role links. It also stages the declarative sign-up role assignment (`first_user` / `default`).
- **Adds.** Tables `Role` (`name` unique; `preset_key` unique and nullable; flags `all_permissions`, `assign_first_user`, `assign_default`), `RolePermission` (unique `(role_id, permission_id)`; `permission_id` `CHECK`-constrained to the deployed `AclPermission` ids), `UserRole` (unique `(user_id, role_id)`, or two partial uniques under `org_membership`), `BootstrapClaim` (one row on the constant key `slot`). Queries `GetUserPermissions`, `GetUserByTokenWithPermissions`, `GetUserRoleGrants`, `ListRoleGrants`, `CountUsers`, `GetFirstUserRoles`, `GetDefaultRoles`, `ListRoles`, `GetRole`. Mutations `CreateRole`, `UpdateRole`, `DeleteRole`, `AssignRoleToUser`, `RevokeRoleFromUser`, `AddPermissionToRole`, `RemovePermissionFromRole`, each emitting its lifecycle event, and `ClaimBootstrapAdmin` (no event). Admin preset: the Roles page and the `auth_user_count` widget. No REST endpoints.
- **Requires / conflicts / combined files.** None. Default on. Go file `handlers/signup_roles.go`.

| id | invariant | category | proof |
|---|---|---|---|
| `rbac/permission-id-in-catalogue` | A `RolePermission.permission_id` outside the deployed permission catalogue MUST be refused by the database. | Security | none. A live test would insert an id that is not in the lock and expect a check violation mapped to InvalidArgument. |
| `rbac/no-duplicate-grants` | A user MUST NOT hold the same realm-wide role twice, and a role MUST NOT carry the same permission twice. Duplicates MUST be refused by unique indexes, including realm-wide rows (`org_id IS NULL`) under `org_membership`. | Consistency & concurrency | none (schema only) |
| `rbac/wildcard-from-deployed-lock` | A role with `all_permissions` MUST expand to the full deployed lock at authentication time. It MUST NOT expand to `RolePermission` rows. It MUST expand only if the role survived every narrowing axis. | Security | `TestResolvePrincipalRealmAware_Wildcard_GrantsAll`, `TestNarrowGrants_WildcardRoleMustPassTheOrgAxis` (both through other features' resolvers; the session-only resolver has no wildcard test) |
| `rbac/role-update-cannot-widen` | `UpdateRole` MUST change only `name` and `description`. The privilege flags MUST stay declarative, so the admin edit form cannot widen a grant. | Security | none (DQL only) |
| `rbac/deleted-role-grants-nothing` | After `DeleteRole`, no query MUST report any permission that role carried. | Security | none (see gap 2) |
| `rbac/first-user-bootstrap-once` | The `first_user` role set (typically a wildcard superadmin) MUST be granted to at most one account per deployment, even when the first registrations arrive concurrently. | Security | `TestAssignSignupRoles_FirstUserGetsBootstrapRoles`, `TestAssignSignupRoles_LaterUserGetsDefaultRoles`, `TestAssignSignupRoles_ConcurrentFirstSignUpsGetOneBootstrapAdmin`, `TestAssignSignupRoles_ATakenClaimIsNotReopened`, `TestBootstrapSlot_FitsItsColumn` (the claim key passes the column's validation). **Unit (mock) only**, with a scripted `CountUsers` and a mocked claim. A live test would fire N concurrent SignUps against an empty table and assert exactly one holder of the `first_user` roles. |
| `rbac/signup-roles-atomic` | The sign-up role links MUST commit in the same transaction as the `User` row and its first token. A failed assignment MUST leave no account. | Consistency & concurrency | none. No test drives SignUp or ConfirmSignUp through the transaction fake with a failing `AssignRoleToUser`. |
| `rbac/role-resolution-cost` | Authenticating a request MUST cost a bounded number of indexed queries: one token lookup and one role-grant query, plus one query per staged scope decorator. | Performance | none |

**Gaps / suspected defects**

1. **The first stranger to register becomes the bootstrap admin.** The race is fixed in rc.25: the `first_user` set goes only to the sign-up that writes the `BootstrapClaim` row inside its transaction (`assignSignupRoleIDs`). What remains is by design and documented in the README: `sign_up_turnkey` is on by default and public, so the first person to reach `/auth/register` on an empty deployment becomes superadmin unless the operator seeds an account first. A seeded account writes no claim, so on such a deployment deleting every account reopens the bootstrap. Without `DistTx` the claim commits on its own, ahead of the role links; a failure after it leaves the claim taken for good (see `sign_up_turnkey` gap 2). The blocked sign-up gets the default roles only under READ COMMITTED (PostgreSQL's default) or MySQL; a PostgreSQL server defaulting to REPEATABLE READ or SERIALIZABLE answers it with a serialization failure instead.
2. **`GetUserPermissions` ignores deleted roles.** Its DQL (`auth_query.proto:1060`) joins `RolePermission` to `UserRole` without joining `Role`. `DeleteRole` removes only the `Role` row (no foreign keys, no cascade; the comment makes the caller responsible for cleanup), and the admin Roles page exposes that delete. Hand-written code that authorises with `GetUserPermissions` keeps granting a deleted role's permissions. `Authenticate` is unaffected because `GetUserRoleGrants` inner-joins `Role`.
3. **Orphan link rows accumulate.** Deleting a role leaves its `UserRole` and `RolePermission` rows behind indefinitely.
4. **A stale contract comment.** The comment on `GetUserByTokenWithPermissions` describes a single round trip that returns permissions. The DQL returns only the user and the token. Permissions come from a second query (`GetUserRoleGrants`).

---

### authenticate_turnkey

- **Purpose.** The gateway's bearer resolver (`Authenticate`), plus `WhoAmI` and `Logout`.
- **Adds.** Mutation `DeleteSessionToken` (sole emitter of `TokenRevoked`). Service methods `Authenticate`, `AuthenticateAdmin`, `WhoAmI`, `Logout`. REST endpoints `GET /auth/whoami` and `POST /auth/logout` (both bearer). MCP tool `WhoAmI`. Admin `user_lookup` (`AuthenticateAdmin`).
- **Requires.** `rbac`. No conflicts or combined files.

| id | invariant | category | proof |
|---|---|---|---|
| `authenticate_turnkey/opaque-refusal` | Every refusal (missing header, wrong scheme, empty token, unknown, expired or revoked token, failed decorator or narrower) MUST produce one identical `Unauthenticated` wire status whose message never carries the cause. | Security | `TestUnauthenticated_WireStatusIsAlwaysOpaque`, `TestUnauthenticated_TwoCallsWithDifferentCauses_WireResponseIdentical`, `TestAuthnError_EveryRefusalIsStillTheSameOpaqueAnswer`, `TestAuthnError_NotFoundNeverBecomesOperational` (constructor level; `Authenticate`'s header parsing has no direct test) |
| `authenticate_turnkey/outage-is-not-refusal` | A storage outage (Unavailable, DeadlineExceeded, ResourceExhausted, Aborted, Internal) MUST surface as `Unavailable` with `AUTH_UNAVAILABLE`. It MUST NOT surface as bad credentials. | Failure & configuration | `TestAuthnError_AnOutageIsNotReportedAsBadCredentials`, `TestUnauthenticated_OutageCarriesItsOwnCode` |
| `authenticate_turnkey/scopes-server-derived` | `scopes["user_id"]` and every decorator-added scope MUST come from the resolved token, never from client input. A decorator or narrower error MUST fail the request closed. | Security | `TestResolveTenantScope_LookupErrorPropagates` (decorator half only) |
| `authenticate_turnkey/session-id-only-for-sessions` | `AuthResp.session_token_id` MUST be set only when the bearer is a session token. | Security | `TestResolvePrincipalRealmAware_ReturnsTokenID`, `TestResolvePrincipalRealmAware_ApiTokenHasNoSessionID` |
| `authenticate_turnkey/logout-own-session-only` | `Logout` MUST delete exactly the caller's current session row, guarded on both `id` and `user_id`. It MUST be idempotent for an already-revoked session. | Security | `TestLogout_RevokesCurrentSession`, `TestLogout_AlreadyRevoked_Idempotent`, `TestLogout_MutationError_Propagates`. **Unit (mock) only** for the ownership guard: a live test would call `DeleteSessionToken` with another user's token id and assert the row survives. |
| `authenticate_turnkey/logout-refuses-unknown-session` | `Logout` without a resolvable session id (API-token bearer, or an envelope missing field 4) MUST be refused with `FailedPrecondition`. It MUST NOT return a false success. | Failure & configuration | `TestLogout_NoSessionToken_Refused`, `TestLogout_NoCaller_Unauthenticated` |
| `authenticate_turnkey/whoami-fails-closed` | `WhoAmI` and every self-service handler MUST refuse a call that carries no gateway-stamped principal. | Security | `TestLogout_NoCaller_Unauthenticated` (shared `callerUserID` path); no `WhoAmI`-specific test |

**Gaps / suspected defects**

1. **The scheme prefix is case-sensitive.** `Authenticate` requires the exact prefix `"<Scheme> "` (`auth_service.go:684`), so `authorization: bearer <t>` is refused. RFC 7235 treats the scheme name as case-insensitive.
2. **No direct test of `Authenticate`.** Header lookup, scheme stripping, decorator and narrower ordering, and the final `AuthResp` are untested end to end at unit level. Tests reach only the resolvers and the error constructor.
3. **`kind` is not re-checked per request.** `Authenticate` refuses a disabled account on every request (under `user_admin`, both resolvers run the disabled gate on the token's owner), but it does not read `kind`: a machine account authenticates with its API tokens by design.

---

### sign_in_turnkey

- **Purpose.** Email and password sign-in that issues a session bearer.
- **Adds.** Service method `SignIn`. REST endpoint `POST /auth/login` (**public, failed_only**). Admin `login_method`.
- **Requires / conflicts / combined files.** None. Default on.

| id | invariant | category | proof |
|---|---|---|---|
| `sign_in_turnkey/indistinguishable-refusals` | Unknown address, wrong password, machine account and disabled account MUST produce byte-identical wire refusals (code, message and user-facing detail). | Security | `TestSignIn_TheFourRefusalsAreIndistinguishable`, `TestSignIn_EveryRefusalReachesTheWireWithAMessage`, `TestUnauthenticatedSignIn_AllGatesRenderIdentically` |
| `sign_in_turnkey/constant-time-miss` | An unknown address MUST cost one password-hash verification with the configured parameters, so that timing does not reveal whether an account exists. | Security | `TestSignIn_UserNotFound_RunsDummyVerify` (asserts the dummy verify runs, not the elapsed time) |
| `sign_in_turnkey/gates-after-password` | The machine-account and disabled-account gates MUST run only after a successful password verification. | Security | none for the ordering. `TestSignIn_RejectsDisabledAccount` and `TestSignIn_RefusesAMachineAccountThatHasAPassword` show the gates refuse with the correct password; no test shows they are not consulted before it. |
| `sign_in_turnkey/no-token-before-all-gates` | No token MUST be issued until every gate (password, machine, disabled, device, second factor) has passed. | Security | `TestSignIn_RejectsDisabledAccount`, `TestSignUpThenSignIn_AWrongPasswordIsStillRefused` |
| `sign_in_turnkey/canonical-lookup` | The address MUST be normalised before lookup. | Consistency & concurrency | `TestSignIn_NormalizesEmailForLookup` |
| `sign_in_turnkey/failed-attempts-limited` | Failed sign-ins MUST be charged to the gateway's per-address limiter (`public_limit: failed_only`). Successful ones MUST NOT be charged. | Security | none (manifest only; the enforcement is in the gateway) |
| `sign_in_turnkey/outage-not-wrong-password` | A lookup outage MUST answer `Unavailable`. It MUST NOT answer "Wrong email or password." | Failure & configuration | `TestAuthnError_AnOutageIsNotReportedAsBadCredentials` (constructor level) |

**Gaps / suspected defects**

1. **No per-account throttle or lockout.** Guessing is bounded only per client address by the gateway. Credential stuffing spread across many addresses has no per-account ceiling, and the plugin neither records failed attempts nor emits an event for them.
2. **Weak hashes are never upgraded.** See base gap 2.

---

### sign_up_turnkey

- **Purpose.** Self-service registration that creates the account and its first session in one call.
- **Adds.** Service method `SignUp`. REST endpoint `POST /auth/register` (**public**, charged on every request). Gates on `sign_up_allowlist` (and `invite_only` when `org_invite` is staged).
- **Env knobs.** `sign_up_allowlist` (addresses and `@domain` entries; a malformed entry fails boot).
- **Requires / conflicts / combined files.** None. Default on. Go file `handlers/signup.go`.

| id | invariant | category | proof |
|---|---|---|---|
| `sign_up_turnkey/gates-before-work` | The allowlist and invite gates MUST run before any password hashing and before any write. An address outside the allowlist MUST receive one fixed answer, whatever else is true of it. | Security | `TestSignUpAllowlist_GatesThePlainSignUp`, `TestSignUpAllowlistGate` |
| `sign_up_turnkey/allowlist-fails-boot` | A malformed `sign_up_allowlist` entry MUST fail boot. At request time an unparsable list MUST refuse everyone. | Failure & configuration | `TestParseSignUpAllowlist` |
| `sign_up_turnkey/atomic-registration` | The user row, its role links, an open-invitation claim and the first token MUST commit together or not at all. | Consistency & concurrency | none (no transaction-fake test for SignUp) |
| `sign_up_turnkey/taken-address-answer` | A taken address MUST be refused with `AlreadyExists` / `EMAIL_TAKEN`, derived from the unique index. | Consistency & concurrency | `TestSignUp_ATakenAddressSaysSignInInstead`. **Unit (mock) only:** see `base/email-unique`. |
| `sign_up_turnkey/session-ttl` | The token SignUp mints MUST carry the session TTL. | Security | none (SignUp's own mint is untested; `TestIssueSession_StampsExpiry` covers the SignIn path) |
| `sign_up_turnkey/every-request-limited` | Every SignUp request MUST be charged to the gateway's per-address limiter. | Performance | none (manifest only) |

**Gaps / suspected defects**

1. **Account enumeration by design.** Without `sign_up_confirmation`, `SignUp` answers `EMAIL_TAKEN` for a registered address, so the endpoint reveals which addresses have accounts, at the gateway limiter's rate. This is accepted, but should be stated in the consumer documentation next to `sign_in_turnkey/indistinguishable-refusals`.
2. **The transaction silently degrades.** When `DistTx` is nil, SignUp runs its writes as separate statements (`signup.go:111`). That is intended for tests, but a mis-wired bundle would degrade to non-atomic registration without any error. A wired handler should refuse to boot without a coordinator. Under `rbac` it also commits the `BootstrapClaim` ahead of the role links, so a failure between them leaves the claim taken by an account without the `first_user` roles, and the claim is never reopened.
3. **An empty or over-long password is a server error.** It reaches `PasswordHash.Hash`, which returns an error that is passed through raw, so the caller gets an internal error instead of InvalidArgument. Whether the PASSWORD field type rejects an empty value at the gateway is outside the plugin.
4. **Bootstrap admin.** See `rbac` gap 1.

---

### sign_up_confirmation

- **Purpose.** Prove the address before the account exists. SignUp parks a pending registration and mails a code. `ConfirmSignUp` creates the account.
- **Adds.** Table `PendingSignUp` (`email` indexed; `password_hash` and `code_hash` both hashed with the password hasher; `attempts`; `expires_at`; `tenant_id` under `tenant_scope`). Mutations `CreatePendingSignUp` (emits `SignUpConfirmationRequested` with the plaintext code), `RecordPendingSignUpAttempt`, `ClaimPendingSignUp`, `DeletePendingSignUpsForEmail`, `PurgeExpiredPendingSignUps`. Service method `ConfirmSignUp`. REST endpoint `POST /auth/register/confirm` (**public, failed_only**).
- **Env knobs.** `sign_up_confirmation_ttl_seconds` (default 900).
- **Requires.** `sign_up_turnkey`. Combined file `handlers/signup_confirm_tenant.go` with `tenant_scope`. Default off.

| id | invariant | category | proof |
|---|---|---|---|
| `sign_up_confirmation/no-account-before-proof` | SignUp MUST create no `User` row and issue no token. It MUST return only `confirmation_required` and `pending_id`. | Security | `TestSignUpConfirmation_SignUpParksAndConfirmCreates` |
| `sign_up_confirmation/secrets-hashed` | The pending row MUST store only hashes of the password and the code. The plaintext code MUST travel only in `SignUpConfirmationRequested`. | Security | `TestSignUpConfirmation_SignUpParksAndConfirmCreates` |
| `sign_up_confirmation/code-entropy` | The code MUST be 8 uniformly random Crockford base32 characters from a CSPRNG (about 2^40 possibilities). | Security | `TestSignUpConfirmation_SignUpParksAndConfirmCreates` (alphabet and length only) |
| `sign_up_confirmation/signup-does-not-enumerate` | SignUp MUST answer a taken address exactly as a new one, with no lookup and the same work. Only ConfirmSignUp, given the mailed code, MAY reveal that the account exists. | Security | `TestSignUpConfirmation_ATakenAddressIsNotRevealedBySignUp`, `TestConfirmSignUp_ATakenAddressSaysSignInInstead` |
| `sign_up_confirmation/abandoned-blocks-nobody` | Any number of pending rows MAY exist for one address. None of them MUST block the owner's registration, and confirming one MUST delete every other pending row for that address in the same transaction. | Consistency & concurrency | `TestSignUpConfirmation_AnAbandonedRegistrationBlocksNobody`, `TestSignUpConfirmation_NoNumberOfStrangersRefusesTheOwner` |
| `sign_up_confirmation/attempt-budget-atomic` | Each pending row MUST accept at most 5 code checks. The attempt MUST be counted by the same statement that returns the hash, before the check, so concurrent guesses cannot share one budget. | Security | `TestSignUpConfirmation_WrongCodesAreRefusedAndExhaustTheRow`. **Unit (mock) only:** a live test would send more than 5 concurrent wrong guesses and assert that `attempts` ends above 5 while at most 5 were evaluated. |
| `sign_up_confirmation/single-use` | Two confirmations of one pending row MUST yield at most one account. `DELETE ... RETURNING` is the guard. | Consistency & concurrency | `TestSignUpConfirmation_ACodeIsSingleUse`. **Unit (mock) only:** a live test would race two correct confirmations and assert one user and one opaque refusal. |
| `sign_up_confirmation/expiry-in-statement` | An expired pending row MUST behave exactly like a missing one in every read and claim, through `expires_at > NOW()` in the WHERE clause. | Security | `TestSignUpConfirmation_AnExpiredRegistrationIsRefused`. **Unit (mock) only:** the predicate is SQL. |
| `sign_up_confirmation/uniform-refusal` | A wrong code, a spent, expired or exhausted row and an unknown id MUST all produce one identical refusal. | Security | `TestSignUpConfirmation_WrongCodesAreRefusedAndExhaustTheRow`, `TestSignUpConfirmation_ACodeIsSingleUse`, `TestSignUpConfirmation_AnExpiredRegistrationIsRefused` |
| `sign_up_confirmation/allowlist-rechecked` | The allowlist MUST be re-checked at confirmation, against the stored address. | Security | `TestSignUpAllowlist_GatesBothSteps` |
| `sign_up_confirmation/confirm-is-proof` | A confirmed account MUST be recorded as `SELF_CONFIRMED` (when `email_verification` is staged) in the same transaction that creates it. | Consistency & concurrency | `TestSignUpConfirmation_SignUpParksAndConfirmCreates` |
| `sign_up_confirmation/tenant-from-request-time` | Under `tenant_scope`, the account MUST be created in the tenant resolved at SignUp. It MUST NOT be created in whichever tenant the confirmation request names. | Security | none |

**Gaps / suspected defects**

1. **The plaintext code rides the event bus.** `SignUpConfirmationRequested.code` (and likewise the reset and verification tokens) is published on the plugin's `events` channel with no marking that keeps it off a client-facing event stream or out of a durable transport. "Never persisted" holds only for the plugin's own tables. See also `password_reset` gap 1.
2. **The invite gate is not re-run at confirmation.** Only the allowlist is. An invitation revoked or expired between SignUp and ConfirmSignUp still produces an account. The open-invitation claim made at SignUp persists.
3. **An outage reads as a wrong code.** `RecordPendingSignUpAttempt` errors of every kind map to `errSignUpConfirmInvalid` (`signup_confirm.go:233`), so the person is told the code is wrong while the store is down. `VerifyMfa` does the same with `RecordMfaAttempt` (`two_factor/fail-closed-on-unaccounted-guess`); failing closed is right in both, but neither reports the outage as `Unavailable` the way `Authenticate` and the consume paths do.
4. **Expired rows are never swept globally.** Pending rows are purged only for the address being registered again (`signup_confirm.go:162`). Rows for addresses that never return accumulate, and `expires_at` has no index.
5. **Every SignUp costs two password-hash derivations.** One is for the password and one for an 8-character code. On a public endpoint guarded only by the per-address limiter, that is a deliberate CPU and memory cost per request. A fast keyed hash of the code would carry the same security given the attempt budget.

---

### tenant_scope

- **Purpose.** Single-tenant isolation. Every user belongs to exactly one `Tenant`, and `Authenticate` publishes `tenant_id` as both a data scope and an event label.
- **Adds.** Table `Tenant` (`name` slug unique; `domain` unique, nullable and indexed). Column `User.tenant_id` (NOT NULL, indexed). Queries `GetUserTenant`, `GetTenantBySlug`, `GetTenantByDomain`. A scope decorator, and the tenant-aware SignUp create path. Forwarded header `Host`.
- **Requires.** `sign_up_turnkey`. **Conflicts with** `oauth`. Combined files: `service_account_tenant.go` (with `service_account`) and `signup_confirm_tenant.go` (with `sign_up_confirmation`). Default off.

| id | invariant | category | proof |
|---|---|---|---|
| `tenant_scope/scope-from-user-row` | `scopes["tenant_id"]` and `labels["tenant_id"]` MUST come from the authenticated user's stored tenant. They MUST NOT come from a header or a request field. | Security | `TestResolveTenantScope_PublishesBothKeys` |
| `tenant_scope/lookup-error-fails-closed` | A tenant lookup failure MUST fail `Authenticate`. | Failure & configuration | `TestResolveTenantScope_LookupErrorPropagates` |
| `tenant_scope/no-tenantless-principal` | A principal whose tenant cannot be resolved MUST NOT be served unscoped. | Security | `TestResolveTenantScope_NoTenantStampsNeither` asserts the opposite: an empty tenant stamps neither key and the request proceeds (see gap 3) |
| `tenant_scope/signup-requires-tenant` | SignUp MUST resolve a tenant from the URL slug (preferred) or the forwarded Host, port stripped. When neither names an existing tenant, it MUST refuse with `TENANT_UNKNOWN` (InvalidArgument) and write nothing. | Failure & configuration | `TestResolveSignupTenant_ByForwardedHost` (the success path only) |
| `tenant_scope/oauth-excluded` | Activating `tenant_scope` together with `oauth` MUST fail codegen. | Failure & configuration | none in this repository (enforced by the manifest's `conflicts_with`) |
| `tenant_scope/tenant-lookup-indexed` | Tenant resolution MUST be served by the unique indexes on `Tenant.name` and `Tenant.domain`, and `GetUserTenant` by the primary key. | Performance | none (schema only) |

**Gaps / suspected defects**

1. **Addresses are unique across all tenants.** `User.email` is globally unique (`models.proto:72`), and `GetUserByEmail` has no tenant predicate. As a result:
   - the same person cannot hold accounts in two tenants;
   - SignUp in tenant B reveals that an address is registered in tenant A (`EMAIL_TAKEN`);
   - `SignIn` arriving on tenant B's host signs in a tenant-A account, and the session is scoped to A.

   Either make uniqueness `(tenant_id, email)` and scope the lookup by the request's tenant, or document that a tenant does not partition identities.
2. **Any caller can register into any tenant.** The tenant is chosen by a client-supplied slug or Host. Without `sign_up_allowlist` or `invite_only`, every tenant accepts open self-registration. That should be stated as a property of the feature.
3. **An empty tenant fails open.** When `GetUserTenant` returns an empty id, `resolveTenantScope` (`tenant.go:165`) stamps nothing and `Authenticate` succeeds. `NOT NULL` makes the case unlikely, but a scope that is required for isolation should refuse instead of returning an unscoped principal. Whether the gateway then refuses a `tenant_id`-scoped model is outside the plugin.
4. **Bootstrap roles are global.** `CountUsers` counts every tenant, so the bootstrap-admin roles go to the first user of the deployment. Each tenant's first user receives only the default roles. That is defensible, but undocumented.

---

### password_change

- **Purpose.** An authenticated principal replaces its own password, proving the current one. No mail channel is needed.
- **Adds.** Mutations `UpdateUserPasswordIfUnchanged` (compare-and-swap on the verified hash; with `devices` it also stamps `User.device_trust_revoked_at`) and `DeleteOtherSessionTokens`. Service method `ChangePassword`. REST endpoint `POST /auth/password/change` (bearer).
- **Requires / conflicts / combined files.** None. Default off.

| id | invariant | category | proof |
|---|---|---|---|
| `password_change/caller-only` | The account changed MUST be the authenticated principal's, read by user id. It MUST NOT be an address from the request. | Security | `TestChangePassword_WritesUnderTheVerifiedHash` |
| `password_change/current-password-required` | A wrong current password MUST write nothing and end no session. | Security | `TestChangePassword_WrongCurrentPasswordWritesNothing` |
| `password_change/compare-and-swap` | The write MUST apply only while the stored hash still equals the one just verified. A concurrent change MUST turn the later request into the wrong-password refusal. | Consistency & concurrency | `TestChangePassword_RefusesWhenTheHashMovedUnderneath`. **Unit (mock) only:** a live test would run two concurrent changes from one old password and assert one success, one refusal, and a final hash matching the winner. |
| `password_change/other-sessions-end-atomically` | Every other SESSION token MUST be deleted in the same transaction as the new hash. The caller's own session and all API tokens MUST be kept. A failed sweep MUST roll back the password. | Security | `TestChangePassword_EndsEveryOtherSession`, `TestChangePassword_AFailedSignOutFailsTheChange` (the failure is returned; no test wires `DistTx`, so the rollback itself is **unit (mock) only**: a live test would make the sweep fail and assert the old password still signs in) |
| `password_change/ends-device-trust` | With `devices`, a successful change MUST end the trust of every device of the account, the caller's own included, in the same statement as the new hash. The caller's session keeps working; its device passes the second factor again on the next sign-in under `new_devices`. | Security | `TestChangePassword_RevokesDeviceTrustInTheSameStatement` (the statement), `TestResolveSignInDevice_TrustRevokedByACredentialChange_NotTrusted` (the read side). **Unit (mock) only:** a live test would change the password and show a replayed trust token no longer skips the challenge. |
| `password_change/errors-not-disguised` | A non-NotFound write failure MUST surface as itself. It MUST NOT surface as a wrong password. | Failure & configuration | `TestChangePassword_OtherWriteErrorsAreNotDisguised` |
| `password_change/hash-outside-tx` | The new hash MUST be derived before the transaction opens, so no row lock is held during the derivation. | Performance | none |
| `password_change/guess-budget` | Verifying the current password MUST be bounded per account, because a stolen session must not become an unlimited offline-speed oracle for the password. | Security | none (see gap 2) |

**Gaps / suspected defects**

1. **Fixed: build failure without `api_token`.** The session-realm filter of `DeleteOtherSessionTokens` is now gated `?feature(api_token)`. Without `api_token`, every token is a session.
2. **No attempt limit on the current-password check.** `ChangePassword` is bearer-authenticated, so the gateway's `failed_only` limiter for public endpoints does not apply. Whoever holds a session can guess the current password without bound.
3. **Outstanding reset tokens survive a change.** Live `PasswordResetToken` rows (`password_reset`) are not invalidated, so a reset link issued before the change can still override it.
4. **The wrong-password refusal looks like an expired session.** It is `Unauthenticated` (`password_change.go:68`), which REST clients commonly treat as "session expired" and answer by signing the user out. FailedPrecondition or InvalidArgument with a field detail fits a request from an authenticated caller.

---

### password_reset

- **Purpose.** The forgotten-password flow. A single-use, time-bounded token is delivered by a hand-written mail subscriber and then redeemed for a new password.
- **Adds.** Table `PasswordResetToken` (`token_hash` unique sha256; `user_id` indexed; `expires_at`; `consumed_at`). Mutations `CreatePasswordResetToken` (emits `PasswordResetRequested` with the plaintext token), `ConsumePasswordResetToken`, `DeleteUserSessionsForReset`. Service methods `RequestPasswordReset` and `ResetPassword`. REST endpoints `POST /auth/password/reset-request` (**public**, charged on every request) and `POST /auth/password/reset` (**public, failed_only**).
- **Env knobs.** `password_reset_ttl_seconds` (default 3600).
- **Requires / conflicts / combined files.** None. Default off.

| id | invariant | category | proof |
|---|---|---|---|
| `password_reset/request-constant-answer` | `RequestPasswordReset` MUST return the same empty success whether or not the address has an account, including when the lookup fails. | Security | `TestRequestPasswordReset_UnknownEmail_NoOp`, `TestRequestPasswordReset_KnownEmail_StoresHashEmitsPlaintext`. **Violated** on the error path: a `CreatePasswordResetToken` failure is returned, and only for an existing account (gap 3). |
| `password_reset/token-hashed-high-entropy` | The token MUST be 256 bits from a CSPRNG. Only its sha256 MUST be stored, and the plaintext MUST travel only in `PasswordResetRequested`. | Security | `TestRequestPasswordReset_KnownEmail_StoresHashEmitsPlaintext` |
| `password_reset/consume-atomic` | Single use and expiry MUST be enforced by one conditional `UPDATE` (`consumed_at IS NULL AND expires_at > NOW()`). Two concurrent redemptions MUST set at most one password. | Consistency & concurrency | `TestResetPassword_InvalidToken_Rejected`. **Unit (mock) only:** a live test would race two `ResetPassword` calls with one token and assert exactly one success and one opaque refusal. |
| `password_reset/consume-and-write-together` | Spending the token and writing the password MUST commit together. A failure after the consume MUST leave the token unspent. | Consistency & concurrency | `TestConsumePaths_TheTokenAndItsWriteDoNotSeparate`, `TestResetPassword_FailureAfterConsume_RollsBack`, `TestResetPassword_Success_CommitsOnTheHandlersConnection`, `TestResetPassword_BeginRefused_SpendsNothing` |
| `password_reset/opaque-refusal` | An unknown, expired or used token MUST produce one identical `Unauthenticated` answer. An outage MUST surface as `Unavailable`. | Security | `TestConsumePaths_ABadTokenIsAlwaysTheSameOpaqueRefusal`, `TestConsumePaths_AnOutageIsStillAnOutage` |
| `password_reset/all-tokens-revoked` | A successful reset MUST revoke every token of the account, sessions and API tokens alike, and MUST report whether that sweep ran. | Security | `TestResetPassword_ValidToken_UpdatesAndRevokes`, `TestResetPassword_ReportsWhenTheSessionSweepDidNotRun`, `TestResetPassword_ReportsASweepThatSucceeded` |
| `password_reset/one-live-token-per-account` | Redeeming a token, or changing the password by any route, MUST invalidate every other outstanding reset token of that account, in the same transaction as the new password. | Security | TestResetPassword_SpendsEveryOtherResetLink, TestChangePassword_SpendsTheAccountsResetLinks (**unit (mock) only**: a live test requests two links, redeems one, and asserts the other is refused) |
| `password_reset/no-hash-for-bogus-token` | No password-hash derivation MUST run for a token that fails the consume. | Performance | none (ordering in `consumeAndSetPassword`, untested) |
| `password_reset/request-limited` | Every reset request MUST be charged to the gateway's per-address limiter. | Performance | none (manifest only) |

**Gaps / suspected defects**

1. **Reset tokens on a shared events channel.** `PasswordResetRequested.token` is a credential that takes over the account. It goes onto the project's `events` channel, and nothing in the plugin marks it as server-only. Any subscriber, a durable transport, or a project that relays that channel to clients sees live reset tokens. The same applies to `EmailVerificationRequested.token` and `SignUpConfirmationRequested.code`. Mark secret-bearing events as non-broadcast, or deliver them through a dedicated hook.
2. **Fixed: sibling tokens stayed valid.** A reset and a password change now spend every live link of the account in their transaction. These are the only paths that set the password of an existing account: `user_admin` has no password write, and sign-up and OAuth create a new account, which has no links yet. Still open: an admin email change (`UpdateUser`, `user_admin`) leaves the links sent to the old address alive until they expire, and so does disabling an account.
3. **The request endpoint still enumerates accounts.** `RequestPasswordReset` returns immediately for an unknown address, but for a known one it performs an INSERT and an event emit (`reset.go:41-62`). The difference is a measurable timing signal. Worse, a `CreatePasswordResetToken` failure is returned to the caller (`reset.go:61`), and it can occur only for an existing account, so it is an error-channel oracle. Answer success on that path, or do equivalent work for unknown addresses.
4. **The session sweep runs outside the transaction.** `DeleteUserSessionsForReset` runs after commit (`reset.go:111`). A thief's session survives a failed sweep, flagged only by `sessions_revoked=false`, and survives briefly even on success. `ChangePassword` already performs its sweep inside the transaction, and reset could do the same.
5. **No per-account issuance limit.** Mail flooding of one victim is bounded only per requesting client address.

---

### email_verification

- **Purpose.** Address-ownership verification through a single-use link. It is also the home of `User.email_proof`, the floor that `email_proof_required` (in `org_invite`) reads.
- **Adds.** Table `EmailVerificationToken` (`token_hash` unique sha256; `user_id` indexed; `expires_at`; `consumed_at`). Columns `User.email_verified_at` and `User.email_proof` (UNPROVEN, DERIVED_FROM_INVITE, SELF_CONFIRMED). Mutations `CreateEmailVerificationToken` (emits `EmailVerificationRequested` with the plaintext token), `ConsumeEmailVerificationToken`, `MarkEmailVerified`, `MarkEmailDerivedFromInvite`. Service methods `RequestEmailVerification` and `VerifyEmail`. REST endpoints `POST /auth/email/verify-request` (bearer) and `POST /auth/email/verify` (**public, failed_only**). Seams installed: the invite email-proof gate, `markEmailDerived`, `markEmailConfirmed`.
- **Env knobs.** `email_verification_ttl_seconds` (default 86400). `email_proof_required` is read through this feature's gate.
- **Requires / conflicts / combined files.** None (`oauth` requires it). Default off.

| id | invariant | category | proof |
|---|---|---|---|
| `email_verification/own-address-only` | `RequestEmailVerification` MUST mint a token only for the authenticated caller's stored address. | Security | `TestRequestEmailVerification_StoresHash` |
| `email_verification/token-hashed-high-entropy` | The token MUST be 256 bits from a CSPRNG and stored only as sha256. | Security | `TestRequestEmailVerification_StoresHash` |
| `email_verification/consume-atomic` | Single use and expiry MUST be enforced in one conditional `UPDATE`, and the consume and the stamp MUST commit together. | Consistency & concurrency | `TestVerifyEmail_ValidToken_MarksVerified`, `TestVerifyEmail_InvalidToken_Rejected`, `TestConsumePaths_TheTokenAndItsWriteDoNotSeparate`. **Unit (mock) only** for the conditional `UPDATE`: a live test would race two redemptions and replay an expired token. |
| `email_verification/opaque-refusal` | An unknown, expired or used token MUST produce one identical `Unauthenticated` answer. | Security | `TestConsumePaths_ABadTokenIsAlwaysTheSameOpaqueRefusal` |
| `email_verification/stamp-and-proof-agree` | A verification MUST set `email_verified_at` and `email_proof = SELF_CONFIRMED` in one statement. | Consistency & concurrency | `TestVerifyEmail_ValidToken_MarksVerified` (asserts that `MarkEmailVerified` is called, not what the DQL writes) |
| `email_verification/derived-never-downgrades` | Marking an address `DERIVED_FROM_INVITE` MUST NOT lower a `SELF_CONFIRMED` address. | Consistency & concurrency | `TestAcceptOrgInvite_BoundRecordsDerivedAndOpenDoesNot` (caller side). The guard sits in the DQL WHERE clause and is **unit (mock) only**. |
| `email_verification/proof-bound-to-address` | A proof MUST certify the address it was delivered to. Changing `User.email` MUST reset both `email_verified_at` and `email_proof`, and MUST void every outstanding verification token. | Security | none (see gaps 1 and 2) |
| `email_verification/floor-enforced` | When `email_proof_required` is `derived` or `full`, an acceptance below the floor MUST be refused with `EMAIL_NOT_VERIFIED`, without revealing whether the invitation exists and without consuming it. | Security | `TestEmailProofGate_FullRefusesAnUnprovenAccount`, `TestEmailProofGate_FullAllowsASelfConfirmedAccount`, `TestEmailProofGate_NoneChangesNothing`, `TestEmailProofGate_RefusalIsActionableAndLeaksNothing`, `TestEmailProofGate_DerivedFloorSeparatesBoundFromOpen`, `TestEmailProofGate_AlreadyDerivedSatisfiesDerivedButNotFull`, `TestAcceptOrgInvite_ARefusedAcceptanceDoesNotConsumeTheInvitation` |
| `email_verification/floor-config-fails-boot` | An `email_proof_required` value other than `none`, `derived` or `full`, or a value above `none` in an activation without this feature, MUST fail boot. | Failure & configuration | none (see gap 3) |

**Gaps / suspected defects**

1. **Tokens are not bound to an address.** `EmailVerificationToken` has no email column, and `MarkEmailVerified` stamps whatever address the user holds at redemption time (`emailverify.go:114`). If the address changes between request and click (an admin edit through `UpdateUser`), a link mailed to the old address verifies the new one. Store the address on the token and require a match at consume, or delete the user's tokens when the address changes.
2. **An address change leaves `email_proof` stale.** `UpdateUser` clears `email_verified_at` (`auth_mutation.proto:2167`) but leaves `email_proof`, so the two columns disagree after every change. `DERIVED_FROM_INVITE` carried over from the old address satisfies the `derived` floor for the new one. A stale `SELF_CONFIRMED` blocks `MarkEmailDerivedFromInvite` (`WHERE email_proof < 2`) indefinitely.
3. **The floor fails open on configuration.** `ValidateConfig` does not check `email_proof_required`. A typo (`"ful"`) happens to fail closed, because anything other than `none` or `derived` demands a timestamp. Setting `derived` or `full` in an activation without `email_verification` leaves the gate at its permissive default, so the configured floor is silently not enforced.
4. **Requests are not limited.** `RequestEmailVerification` is bearer-authenticated, so no public limiter applies. One session can mint unlimited tokens and mails, including for an already-verified address, and every token stays redeemable for its TTL.
5. **Verification tokens on the events channel.** See `password_reset` gap 1.

---

### two_factor

**Purpose.** Adds a second factor to password sign-in. Built-in TOTP (RFC 6238) is on by default. An event-delivered numeric code is the fallback, and one-time recovery codes stand in for a lost authenticator. When a challenge fires, SignIn returns `mfa_required` + `challenge_id` instead of a token, and VerifyMfa completes the sign-in.

**Adds.**
- Tables: `UserTotpSecret` (one per user; `seed` CRYPTED_SECRET; `last_step` replay guard; `stepup_attempts` / `stepup_locked_until`), `UserRecoveryCode` (SHA-256 of the normalised code, `used_at`), `MfaChallenge` (`code_hash` for the fallback path, `attempts`, `consumed_at`; expiry is computed as `created_at + mfa_code_ttl_seconds` and is not stored).
- Business RPCs: `EnrollTotp`, `ConfirmTotp`, `DisableTotp`, `GetMfaStatus`, `GenerateRecoveryCodes`, `VerifyMfa`. Also a SignIn seam (the challenge gate).
- REST (`/auth/mfa`): `POST /verify` (**public, failed_only**), `POST /totp`, `POST /totp/confirm`, `DELETE /totp`, `GET /status`, `POST /recovery-codes`. All endpoints except `/verify` need a bearer.
- Storage RPCs: `GetTotpSecret`, `CountRecoveryCodes`, `GetMfaChallenge`, `LockUserForIssuance` (SELECT … FOR UPDATE on the user row), `CountRecentMfaChallenges`; `CreateTotpSecret`, `ConfirmTotpSecret`, `MoveTotpSeed`, `ClaimTotpStep`, `RecordStepUpAttempt`, `LockStepUp`, `ResetStepUp`, `CreateRecoveryCode`, `DeleteRecoveryCodes`, `ConsumeRecoveryCode`, `DeleteTotpSecret`, `CreateMfaChallenge`, `ConsumeMfaChallenge`, `RecordMfaAttempt`, `SupersedePendingMfaChallenges`.
- Events: `MfaChallengeRequested` (carries `totp_enrolled`, `email`, the **plaintext** fallback `code`, `expires_at`), `MfaVerified`, `TotpEnrolled`, `TotpConfirmed`, `TotpDisabled`, `RecoveryCodeUsed`.
- Env knobs: `two_factor_totp` (default true), `two_factor_scope` (`all_logins` | `new_devices`), `mfa_code_ttl_seconds` (300), `mfa_max_challenges_per_window` (10), `mfa_challenge_window_seconds` (900), `totp_issuer`, `two_factor_secret_key` (legacy; only used to open seeds sealed by earlier releases).
- Constants: 5 attempts per challenge; ±1 time step of skew; 6 digits; 10 recovery codes of 10 characters from a 31-symbol alphabet (about 49.5 bits each); step-up locks for 15 min after 5 wrong codes.

**Requires:** `sign_in_turnkey`. **Conflicts:** none. **Combined files:** none. `two_factor_scope=new_devices` also needs `devices`, which the boot check enforces.

| id | invariant | category | proof |
|---|---|---|---|
| `two_factor/no-session-while-challenged` | When the gate raises a challenge, SignIn MUST return `mfa_required` + `challenge_id` and MUST NOT issue a session token. | Security | TestMfaGate_AllLogins_NoTotp_GeneratesCode, TestMfaGate_TotpEnrolled_NoCode, TestMfaGate_NewDevices_ChallengesUntrusted |
| `two_factor/new-devices-needs-proven-trust` | Under `new_devices`, a challenge MUST be skipped only for a device that presents a valid server-issued trust token. A client-chosen device id or a bare `trusted_at` MUST NOT be enough. | Security | TestMfaGate_NewDevices_SkipsTrusted, TestMfaGate_NewDevices_ChallengesUntrusted, TestResolveSignInDevice_TrustedAtButNoToken_NotTrusted, TestResolveSignInDevice_WrongTrustToken_NotTrusted |
| `two_factor/seed-encrypted-at-rest` | The TOTP seed MUST be stored only encrypted with the project field keyring. It MUST NOT be stored or logged in plaintext. | Security | none. Encryption is done by the storage layer. A live test must read the raw `seed` column and show ciphertext that decrypts only with the keyring. |
| `two_factor/legacy-seed-moved-once` | A seed sealed under `two_factor_secret_key` MUST verify with that key, then be moved into `seed` and cleared from the legacy column. If the key is unusable, verification MUST be refused (FailedPrecondition), never accepted. | Security | TestLegacySeed_VerifiesAndMoves, TestLegacySeed_KeyGone_Refuses |
| `two_factor/totp-step-single-use` | A TOTP code MUST be accepted at most once: only for a time step later than `last_step`, claimed by one conditional UPDATE. When two requests present the same code at once, exactly one MUST succeed. | Security | TestTotp_ACodeIsAcceptedOnce; TestTotp_ConcurrentReuseIsAcceptedOnce is **unit (mock) only**. A live test must fire N parallel VerifyMfa calls with one code against the database and show exactly one `ClaimTotpStep` row returned. |
| `two_factor/challenge-attempt-budget` | A challenge MUST allow at most 5 verification attempts. Each attempt MUST be counted (atomic increment with RETURNING) *before* the code is checked. After the 5th, even the correct code MUST be refused. | Security | TestVerifyMfa_LocksOutAfterMaxAttempts; TestVerifyMfa_ConcurrentGuessesShareOneBudget is **unit (mock) only**. A live test must show that 20 parallel wrong guesses produce attempts 1..20 and at most 5 code checks. |
| `two_factor/issuance-cap` | At most `mfa_max_challenges_per_window` challenges MUST be issued per user per window. The count and the insert MUST be one section serialised by a row lock on the user. | Security | TestMfaIssuance_CapRefusesOnceTheWindowIsSpent, TestMfaIssuance_CountsOverTheConfiguredWindow; TestMfaIssuance_CapHoldsUnderConcurrency is **unit (mock) only**. A live test must send concurrent sign-ins for one user and show no more than the cap of `MfaChallenge` rows (proves the FOR UPDATE plus the distributed transaction). |
| `two_factor/one-live-challenge` | Issuing a challenge MUST retire every pending challenge of the user in the same transaction, so at most one code is live. If retiring fails, nothing MUST be minted. | Security | TestMfaIssuance_NewChallengeRetiresThePendingOnes, TestMfaIssuance_SupersedeAndCreateAreOneSeam, TestMfaIssuance_AFailedSupersedeMintsNothing |
| `two_factor/challenge-single-use` | A consumed or superseded challenge MUST NOT yield a session. When two concurrent verifications both pass the code check, only the one whose conditional consume returns a row MUST get a session. | Security | TestVerifyMfa_Consumed_Unauthenticated; the consume race is **unit (mock) only**. A live test needs two parallel correct fallback-code verifications and must show one session. |
| `two_factor/challenge-expires` | A challenge older than `mfa_code_ttl_seconds` MUST be refused. | Security | TestVerifyMfa_Expired_Unauthenticated |
| `two_factor/fallback-code-hashed` | The fallback code MUST be persisted only as a slow password hash. The plaintext MUST travel only in `MfaChallengeRequested`. A TOTP-path challenge MUST carry no code. | Security | TestMfaGate_AllLogins_NoTotp_GeneratesCode, TestMfaGate_TotpEnrolled_NoCode |
| `two_factor/fallback-code-not-client-visible` | `MfaChallengeRequested` (plaintext code) MUST NOT be delivered to any client-facing event stream. It is for a server-side delivery subscriber only. | Security | none. The event declaration carries no visibility restriction. |
| `two_factor/opaque-verify` | Every VerifyMfa refusal (unknown, expired, consumed, over budget, wrong code) MUST be the same Unauthenticated. | Security | TestVerifyMfa_WrongCode_Unauthenticated, TestVerifyMfa_Expired_Unauthenticated, TestVerifyMfa_Consumed_Unauthenticated, TestVerifyMfa_LocksOutAfterMaxAttempts |
| `two_factor/no-weaker-path-on-read-failure` | A failed read of the enrolment MUST refuse. It MUST NOT skip the challenge, fall back to the fallback-code path, report "not enrolled", or let DisableTotp proceed without a code. | Security | TestMfaGate_ReadFailure_RefusesRatherThanSkipTheChallenge, TestVerifyMfa_ReadFailure_DoesNotFallToTheWeakerPath, TestGetMfaStatus_ReadFailure_Errors, TestDisableTotp_ReadFailure_DoesNotDisableWithoutACode |
| `two_factor/step-up-for-confirmed-changes` | Replacing (EnrollTotp) or removing (DisableTotp) a confirmed authenticator, or regenerating recovery codes, MUST require a current TOTP code or an unused recovery code. A session alone MUST NOT be enough. | Security | TestEnrollTotp_ReplacingAConfirmedAuthenticatorTakesACode, TestDisableTotp_ValidCode_Deletes, TestDisableTotp_WrongCode_Rejected, TestDisableTotp_EmptyCode_Rejected, TestGenerateRecoveryCodes_ReplacesTheSetBehindTheStepUp, TestStepUp_ARecoveryCodeNeedsNoSeed |
| `two_factor/step-up-budget` | After 5 wrong step-up codes, step-up MUST be locked for 15 minutes, and even a correct code MUST be refused while locked. A success MUST reset the count. Counting MUST be one statement. | Security | TestStepUp_FiveWrongCodesLockIt, TestStepUp_ASuccessResetsTheCount; the single-statement race is **unit (mock) only**. |
| `two_factor/pending-cancel-without-code` | An unconfirmed enrolment MUST be cancellable without a code. | Security | TestDisableTotp_Unconfirmed_NoCodeNeeded |
| `two_factor/first-enrolment-reauth` | Enrolling the first authenticator on an account MUST require fresh proof of the primary credential, not only a bearer session. | Security | none. Not enforced (see gaps). |
| `two_factor/recovery-codes-hashed-single-use` | Recovery codes MUST be shown once, stored only as hashes, and each MUST be spendable exactly once (conditional UPDATE on `used_at IS NULL`). | Security | TestConfirmTotp_HandsOutTenRecoveryCodesStoredHashed, TestVerifyMfa_ARecoveryCodeSignsInOnce; the concurrent spend is **unit (mock) only**. |
| `two_factor/recovery-codes-die-with-authenticator` | Disabling the authenticator MUST delete its recovery codes in the same transaction. | Security | TestDisableTotp_TakesARecoveryCodeAndDropsTheSet |
| `two_factor/no-reconfirm` | ConfirmTotp MUST refuse an already-confirmed authenticator, so that new recovery codes cannot be minted without the step-up. | Security | TestConfirmTotp_RefusesAConfirmedAuthenticator |
| `two_factor/unsignable-account-no-session` | A disabled or machine account MUST NOT get a session from VerifyMfa, even with a correct code. | Security | TestVerifyMfa_ADisabledAccountGetsNoSession |
| `two_factor/replace-is-atomic` | Re-enrolment (delete then create the secret) MUST run in one transaction. A failed create MUST leave the previous authenticator in place. | Consistency & concurrency | TestEnrollTotp_AFailedCreateDoesNotLeaveTheUserWithoutAFactor, TestEnrollTotp_BothWritesGoThroughOneSeam (seam only; actual rollback is **unit (mock) only**) |
| `two_factor/confirm-with-codes-atomic` | Confirming an authenticator and storing its recovery-code set MUST commit together, as must a full set replacement (delete plus 10 inserts). | Consistency & concurrency | none for rollback. TestConfirmTotp_HandsOutTenRecoveryCodesStoredHashed covers only the success path. |
| `two_factor/emit-after-commit` | `MfaChallengeRequested` MUST be emitted only after the challenge row commits. A rolled-back issuance MUST NOT deliver a code. | Consistency & concurrency | none. Depends on the transaction-scoped emitter. A live test must force a commit failure and observe no event. |
| `two_factor/one-authenticator-per-user` | A user MUST have at most one `UserTotpSecret` row (unique `user_id`). | Consistency & concurrency | none. Schema property; needs a live insert-twice test. |
| `two_factor/indexed-lookups` | Lookups MUST be indexed: `UserTotpSecret.user_id` (unique), `UserRecoveryCode(user_id, code_hash)` (unique), `MfaChallenge.user_id` (supersede, count). Challenge lookup is by primary key. | Performance | none (schema) |
| `two_factor/recovery-shape-check-before-lookup` | A code that does not have recovery-code shape MUST be refused without a storage lookup. | Performance | none |
| `two_factor/new-devices-requires-devices-at-boot` | `two_factor_scope=new_devices` without `devices` MUST fail plugin boot. | Failure & configuration | TestValidateConfig_NewDevicesRequiresDevices |
| `two_factor/unknown-scope-fails-boot` | An unrecognised `two_factor_scope` value MUST fail boot. | Failure & configuration | none. Not enforced; any other value behaves as `all_logins`. |
| `two_factor/non-positive-knobs-default` | `mfa_code_ttl_seconds`, `mfa_max_challenges_per_window` and `mfa_challenge_window_seconds` ≤ 0 MUST fall back to their defaults and MUST NOT disable the guard. | Failure & configuration | TestMfaIssuance_CountsOverTheConfiguredWindow (configured value only); fallback: none |
| `two_factor/fail-closed-on-unaccounted-guess` | If the attempt counter, the step claim or the issuance count cannot be written or read, the request MUST be refused. | Failure & configuration | TestTotp_AnUnansweredClaimFailsClosed, TestMfaIssuance_CapFailsClosedWhenTheCountIsUnreadable |
| `two_factor/budget-refusal-is-distinct` | A spent issuance budget MUST answer ResourceExhausted with a retry message, not "invalid credentials". | Failure & configuration | TestMfaIssuance_CapRefusalIsNotInvalidCredentials |
| `two_factor/enrol-refused-when-totp-off` | With `two_factor_totp=false`, EnrollTotp and ConfirmTotp MUST be refused (FailedPrecondition). | Failure & configuration | TestEnrollTotp_RefusedWhenTheAuthenticatorIsOff |

**Gaps / suspected defects**

1. `mfa.go:346–363`: **The first enrolment needs only a session.** `EnrollTotp` asks for a step-up only when a *confirmed* authenticator already exists. A stolen bearer can enrol the attacker's authenticator on an account without 2FA, confirm it, and keep the recovery codes. From then on the owner cannot sign in. Password reset does not remove the authenticator, and `reset.go` never touches `UserTotpSecret`.
2. `mfa.go:558`: The expiry check is skipped when `created_at` is absent (`created != nil && …`), which fails open. Neither `RecordMfaAttempt` nor `ConsumeMfaChallenge` has an age predicate in its `WHERE`, so the handler's earlier read is the only expiry enforcement.
3. `MfaChallengeRequested` (events proto, the `code` field) puts the plaintext fallback code on the shared `events` channel. It has no visibility restriction, so any consumer that bridges `events` to clients exposes live codes.
4. `mfa.go:604` and `mfa_recovery.go:66–74`: On the TOTP path, a recovery code is spent inside `verifyMfaCode` *before* `ConsumeMfaChallenge`. If a concurrent supersede or consume wins, the code is burned and no session is issued. `ConsumeMfaChallenge` also emits `MfaVerified` before `refuseUnsignableAccount`/`issueSession`, so a disabled account still logs a "verified" event.
5. `auth_service.go:400`: `two_factor_scope` is validated only for `new_devices`. A typo silently means `all_logins`. The manifest says codegen rejects `new_devices` without `devices`, but the check actually runs at boot.
6. No retention: `MfaChallenge` rows are never purged, and the table grows with every challenged sign-in.

---

### devices

**Purpose.** Tracks the device behind each session, so that a user can list their sessions and log out one device, every other device, or all devices. It also supplies the "trusted device" signal that `two_factor_scope=new_devices` reads, proven by a server-issued trust token.

**Adds.**
- Table `Device`: unique `(user_id, identifier)`, plus `label`, `ip`, `trusted_at`, `last_seen_at` and `trust_token_hash` (SHA-256 of the trust token). Column `UserToken.device_id` (nullable, indexed). Column `User.device_trust_revoked_at` (nullable): trust stamped at or before it no longer counts. It is written by `password_change` and `user_admin` statements through `?feature(devices)` fragments.
- Business RPCs: `ListDevices`, `RevokeDevice`, `RevokeOtherDevices`, `RevokeAllDevices`. Seam overrides: device resolution at sign-in, device-bound session issuance, and trust-token stamping on `SignInResp`/`VerifyMfaResp`/`OAuthExchangeResp`.
- REST (`/auth/devices`, all bearer-authenticated): `GET ""`, `DELETE /{device_id}`, `POST /revoke-others`, `POST /revoke-all`.
- Storage RPCs: `GetDeviceByIdentifier`, `GetDeviceTrustRevokedAt`, `ListUserDevices`; `CreateDevice`, `TrustDevice`, `TouchDevice`, `DeleteUndevicedSessions`, `DeleteDeviceTokens`, `DeleteDevice`, `DeleteAllUserTokens`, `DeleteAllUserDevices`.
- Forwarded headers: `X-Device-Id`, `X-Device-Trust`, `User-Agent` (read from `x-forwarded-user-agent` first), `X-Forwarded-For`.
- Events: none. Env knobs: none.

**Requires:** `sign_in_turnkey`. **Conflicts:** none. **Combined files:** none. Enables `two_factor_scope=new_devices`.

| id | invariant | category | proof |
|---|---|---|---|
| `devices/trust-needs-server-token` | A device MUST count as trusted only when the request presents a trust token whose SHA-256 equals the stored hash (constant-time compare). A missing token, a missing hash or `trusted_at` alone MUST mean untrusted. | Security | TestResolveSignInDevice_ValidTrustToken_Trusted, TestResolveSignInDevice_TrustedAtButNoToken_NotTrusted, TestResolveSignInDevice_WrongTrustToken_NotTrusted, TestResolveSignInDevice_NewDevice_Creates_Untrusted |
| `devices/trust-token-hashed-rotated` | The trust token MUST be 256-bit random, MUST be stored only as a hash, and MUST be rotated on every completed sign-in. | Security | TestIssueSessionWithDevice_IssuesMintsAndTrusts |
| `devices/trust-only-after-all-gates` | A device MUST become trusted only by a sign-in that passed the plugin's second factor (VerifyMfa). A password sign-in that met no second factor MUST only renew the trust of a device that already has it, and an OAuth sign-in MUST NOT trust it. A sign-in that stops at a challenge MUST NOT trust it. | Security | TestSignIn_RenewsDeviceTrustButNeverGrantsIt, TestOAuthExchange_DoesNotTrustTheDevice, TestMfaGate_NewDevices_ChallengesUntrusted |
| `devices/owner-only-revoke` | Every revoke MUST be scoped by the caller's `user_id`. One user MUST NOT be able to delete another user's device or tokens. | Security | TestRevokeDevice_DeletesTokensThenDevice (checks the `user_id` guard argument; enforcement by `WHERE … AND user_id` is **unit (mock) only**) |
| `devices/revoke-all-spares-api-tokens` | RevokeAllDevices and RevokeOtherDevices MUST delete every session token, including sessions with no device (sign-up, OAuth, CLI). They MUST NOT delete API tokens. | Security | TestRevokeAllDevices_PerDeviceSparesApiTokens, TestRevokeDevices_SweepSessionsNoDeviceHolds |
| `devices/revoke-others-keeps-caller` | RevokeOtherDevices MUST keep the caller's own session. If the caller's device cannot be identified, it MUST revoke rather than keep. | Security | TestRevokeOtherDevices_KeepsCurrent |
| `devices/raw-identifier-not-exposed` | ListDevices MUST NOT return the raw device identifier. | Security | TestListDevices_MarksTrustedAndCurrent |
| `devices/authenticated-only` | Every device-management RPC MUST refuse a call with no principal. | Security | TestListDevices_NoCaller_Unauthenticated |
| `devices/credential-change-ends-trust` | A device MUST count as trusted only when its `trusted_at` is later than `User.device_trust_revoked_at` (when set), at sign-in and in `ListDevices`. An equal instant MUST count as revoked. A failed read of the revocation MUST mean untrusted at sign-in, and MUST fail `ListDevices`. A password sign-in MUST NOT renew revoked trust. Trust written by a sign-in MUST NOT outlive a revocation that commits while the sign-in is in flight: `TrustDevice` writes only while no revocation is later than the sign-in's cutoff (the stamp a renewing SignIn read; the challenge's creation for VerifyMfa), checked in the statement itself, and a refused write leaves the session without a trust token. | Security | TestResolveSignInDevice_TrustRevokedByACredentialChange_NotTrusted, TestSignIn_DoesNotRenewRevokedDeviceTrust, TestListDevices_TrustRevokedByACredentialChange_NotShownTrusted, TestSignIn_ARevocationCommittedMidSignInIsNotOverwritten, TestVerifyMfa_TrustIsGuardedFromTheChallengeOn, TestTrustDevice_TheStatementIsGuardedByTheRevocation (the guard's SQL is **unit (mock) only**: a live test would commit a password change between a sign-in's read and its TrustDevice). Residual windows: gap 6. |
| `devices/revoke-ends-trust` | Revoking a device MUST end both its sessions and its trust. A later sign-in from it MUST be treated as new. | Security | TestRevokeDevice_DeletesTokensThenDevice |
| `devices/one-row-per-identifier` | `(user_id, identifier)` MUST be unique. A racing duplicate create MUST resolve to the existing row, not fail the sign-in. | Consistency & concurrency | none. Unique index plus re-read; a live test needs two parallel first sign-ins. |
| `devices/revoke-idempotent` | Revoking a device that is already gone MUST succeed. | Consistency & concurrency | TestRevokeDevice_IdempotentOnMissing |
| `devices/tokens-before-row` | Device revocation MUST delete the tokens before the Device row, so a partial failure leaves a visible, retryable device and never a live token with no device. | Consistency & concurrency | TestRevokeDevice_DeletesTokensThenDevice |
| `devices/trust-failure-does-not-fail-sign-in` | A failure to mint or store a trust token MUST NOT fail the issued session. It MUST only leave the device untrusted. | Failure & configuration | none |
| `devices/header-fallback` | Without `X-Device-Id`, the identifier MUST fall back to a hash of the forwarded User-Agent and the first X-Forwarded-For hop, and the forwarded User-Agent MUST take priority over the gateway's own. | Failure & configuration | TestResolveDeviceIdentity_HeaderWins, TestResolveDeviceIdentity_FingerprintFallback, TestResolveDeviceIdentity_PrefersTheForwardedUserAgent |
| `devices/indexed-lookups` | `Device(user_id, identifier)` (unique), `Device.user_id` and `UserToken.device_id` MUST be indexed. | Performance | none (schema) |
| `devices/bounded-per-user` | The number of Device rows per user MUST be bounded, or stale rows MUST expire. | Performance | none. Not enforced (see gaps). |

**Gaps / suspected defects**

1. `devices.go:109–112, 316`: **The device identity is client-chosen, and "revoke others" keys on it.** Any client that sends the same `X-Device-Id` (or matches the UA+IP fingerprint) shares the victim's Device row. Its session is bound to that row, and RevokeOtherDevices skips the row because it matches "current". The keep decision should use the caller's session token (`callerSessionTokenID`, already available) rather than the resolved identifier. A colliding sign-in also rotates the shared row's trust token, which silently untrusts the real device.
2. `auth_service.go:795` (with `devices.go:196`): A Device row is created after password verification but *before* the 2FA gate, and there is no cap. A password holder without the second factor can create unlimited Device rows, one per new `X-Device-Id`. `ListUserDevices` is unpaged and nothing purges devices.
3. `devices.go:111, 163`: `truncate` cuts by bytes. A header longer than 128 bytes (identifier) or 255 bytes (label) that contains multi-byte characters can become invalid UTF-8. The proto string marshal then fails, and that client's sign-in fails.
4. `TouchDevice` is declared but has no caller. `last_seen_at` is refreshed only by `TrustDevice` (on a completed sign-in), never by use of the session, so "last seen" means "last signed in".
5. Trust has no lifetime of its own. It survives password reset (documented) and enrolling or disabling the authenticator. It ends when the device is revoked, and for every device of the account on a password change or a disable (`devices/credential-change-ends-trust`).
6. **Residual windows of `devices/credential-change-ends-trust`.** The `TrustDevice` guard catches a revocation that commits after the sign-in's cutoff, and the cutoff is taken after the password check, never before it. (a) VerifyMfa's cutoff is the challenge's `created_at`, and SignIn inserts the challenge after the password check, so a password change or disable committing between SignIn's password check and the challenge insert is not caught: VerifyMfa then trusts the device, with the second factor passed. A renewing SignIn has the same window between its password check and its read of the stamp in `resolveSignInDevice`. Both last milliseconds. Closing (a) would mean carrying a stamp read before the password check into the challenge (a column on `MfaChallenge`) for VerifyMfa to use as the earlier cutoff; not done. (b) On Postgres `NOW()` is the transaction's start, so `trusted_at` and `device_trust_revoked_at` are each stamped at their transaction's start rather than at commit: two overlapping transactions can order their stamps against their commit order, a window of the transactions' own length (microseconds for these single statements).

---

### oauth

**Purpose.** Generic OAuth2/OIDC sign-in as a *consumer* of external identity providers. Providers are administrator-managed rows rather than code. The callback finds or creates the local user, links the external subject, and issues a session.

**Adds.**
- Tables: `OAuthProvider` (unique `name`; `secret` CRYPTED_SECRET client secret; legacy plaintext `client_secret` migrated on first use; URLs; `scopes`; `subject_path`/`email_path`; `enabled`; `tenant_id` gated on tenant_scope) and `OAuthIdentity` (unique `(provider_id, external_id)`, indexed `user_id`).
- Table `OAuthLoginCode` (`code_hash` unique SHA-256, `code_challenge` = SHA-256 hex of the browser's challenge, `expires_at` = now + 2 min, `consumed_at`).
- Business RPCs: `OAuthAuthorizeURL` (requires `code_challenge`), `OAuthCallback`, `OAuthExchange`.
- REST (`/auth/oauth`): `GET /{provider}/authorize` (**public**, browser 302 to the provider), `GET /{provider}/callback` (**public, failed_only**, browser 302 to the site-relative `redirect_after` with a single-use login code in the fragment) and `POST /exchange` (**public, failed_only**: code + verifier → session).
- Storage RPCs: `GetProviderByName`, `GetOAuthIdentity`; `CreateOAuthIdentity`, `UpsertOAuthProvider`, `MoveOAuthProviderSecret`, `ClearOAuthProviderLegacySecret`, `CreateOAuthLoginCode`, `ConsumeOAuthLoginCode`.
- Sandbox: a deterministic fake OIDC provider (`sandboxes/fakeidp`).
- Events: none of its own; account creation emits the base `UserCreated`. Env knob: `oauth_redirect_base`.

**Requires:** `email_verification`, needed so the local account's verification can be checked before linking. **Conflicts:** `tenant_scope` (declared on tenant_scope): the create path writes no `tenant_id`. **Combined files:** none.

| id | invariant | category | proof |
|---|---|---|---|
| `oauth/state-signed-and-provider-bound` | `state` MUST be HMAC-signed with the provider's client secret and bound to the provider name. A tampered state, a wrong key or a state for another provider MUST be refused. | Security | TestOAuthState_SignVerifyRoundTrip, TestOAuthCallback_BadState_Unauthenticated |
| `oauth/state-single-use-and-expiring` | A state MUST expire within minutes and MUST be bound to the PKCE challenge of the browser that started the flow (by its digest, see `oauth/state-hides-the-challenge`). A sign-in MUST complete only in that browser: the callback's login code is single-use, short-lived, and redeemable only with that challenge's verifier (login-CSRF defence). | Security | TestOAuthState_Expires, TestOAuthState_WithoutAChallengeIsRefused, TestOAuthAuthorizeURL_RequiresAPKCEChallenge, TestOAuthExchange_OnlyTheStartingBrowsersVerifierRedeems, TestOAuthExchange_ACodeRedeemsOnce (single use is **unit (mock) only**: a live test races two exchanges of one code and asserts exactly one session) |
| `oauth/state-hides-the-challenge` | The state and the stored login code MUST carry only a digest of the browser's challenge, never the challenge itself, so it cannot be lifted from a URL to start a sign-in bound to it. | Security | TestOAuthAuthorizeURL_TheStateDoesNotRevealTheBrowsersChallenge, TestOAuthCallback_HandsOutACodeNotASession, TestOAuth_TheRawChallengeIsAcceptedNowhere |
| `oauth/callback-carries-no-session` | The callback MUST NOT issue a session or put one in its redirect. It MUST hand out only a login code, stored as its hash. | Security | TestOAuthCallback_HandsOutACodeNotASession |
| `oauth/pkce-towards-provider` | The authorize URL MUST carry the plugin's own S256 challenge, distinct from the browser's, and the token request the matching verifier. | Security | TestOAuthCallback_SendsPKCEToTheProvider |
| `oauth/no-empty-hmac-key` | A provider with no client secret MUST be refused at both authorize and callback. It MUST NOT sign a state with an empty key. | Security | TestOAuthAuthorizeURL_EmptyClientSecret_Rejected, TestOAuthCallback_EmptyClientSecret_Rejected |
| `oauth/disabled-provider-refused` | An unknown or disabled provider MUST be refused. | Security | TestOAuthAuthorizeURL_DisabledProvider |
| `oauth/redirect-after-site-relative` | `redirect_after` MUST be a site-relative path (no scheme, no host, no `//`, no backslash or NUL). It MUST be refused at authorize, and an unsafe value inside a validly signed state MUST be dropped at callback. | Security | TestOAuthAuthorizeURL_RejectsUnsafeRedirect, TestOAuthCallback_DropsUnsafeRedirect |
| `oauth/link-needs-idp-verified-email` | Auto-linking to an existing local account MUST require the provider to assert `email_verified=true`. | Security | TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting, TestOAuthCallback_VerifiedEmail_LinksToExisting |
| `oauth/link-needs-locally-verified-email` | Auto-linking MUST also require the existing local account to have verified the address (`email_verified_at`). An unverified local account MUST NOT receive a provider identity. | Security | TestOAuthAutoLink_RefusesAnUnverifiedLocalAccount, TestOAuthAutoLink_LinksIntoAVerifiedLocalAccount |
| `oauth/existing-identity-wins` | A known `(provider, subject)` MUST resolve to its linked user regardless of the email currently asserted. | Security | TestOAuthCallback_ExistingIdentity_ReusesUser |
| `oauth/creation-gated` | Creating an account through OAuth MUST pass the same `sign_up_allowlist` and `invite_only` gates as password sign-up, with the invitation token the exchange carries (an open invitation works by token, and its link is spent by that registration). The account MUST be created in the exchange, never in the callback, so the token never travels through a URL or the provider. | Security | TestOAuthCreate_ConsultsTheInviteGate, TestOAuthCallback_CreatesNoAccount, TestOAuthExchange_SignsUpWithTheInvitationItCarries, TestOAuthExchange_RefusesASignUpWithoutAnInvitation, TestOAuthExchange_AnExistingAccountIgnoresTheInvitation; allowlist: none |
| `oauth/refusals-coded` | Every OAuth refusal MUST carry an `ErrorDetail` code: `OAUTH_ACCOUNT_UNVERIFIED`, `OAUTH_EMAIL_UNVERIFIED`, `ACCOUNT_DISABLED`, the sign-up gate's own code, `AUTH_UNAVAILABLE` for an outage, or `OAUTH_FAILED`. A password sign-in to a disabled account MUST still answer `INVALID_CREDENTIALS`. | Security | TestOAuthRefusal_Codes, TestOAuth_ADisabledAccountSaysAccountDisabled, TestOAuthExchange_ABadCodeSaysOAuthFailed, TestSignupInviteGate_ABoundInvitationForAnotherAddress |
| `oauth/unsignable-account-no-session` | A disabled or machine account MUST NOT get a session through the callback or the exchange. | Security | TestOAuth_ADisabledAccountSaysAccountDisabled (disabled; machine: none) |
| `oauth/client-secret-encrypted` | The client secret MUST be stored encrypted (CRYPTED_SECRET). A legacy plaintext value MUST be moved on first read and cleared once `secret` is set, and MUST NOT override a newer `secret`. | Security | TestOAuthProvider_SecretFromEncryptedColumnOrMovedFromLegacy (handler logic); at-rest encryption: none (needs a raw-column read in a live test) |
| `oauth/id-token-validated` | Claims taken from an `id_token` MUST be checked for `aud` (= client_id), `azp` (= client_id when present), `exp`, and the nonce of this sign-in. | Security | TestCheckIDTokenClaims, TestOAuthCallback_IDTokenPath. `iss` and the signature are not checked (see gaps). |
| `oauth/second-factor-policy` | **Decided.** An OAuth sign-in MUST NOT ask for this plugin's second factor, also for an account with one confirmed: the provider already verified the identity, and a second factor at the provider and again here is not wanted. It MUST NOT make the device trusted either, so a later password sign-in under `new_devices` still asks for the factor. | Security | TestOAuthExchange_DoesNotTrustTheDevice, TestIssueSessionWithDevice_BindsWithoutTrustingWhenNotAllowed (the absence of a challenge is the exchange's design: no test asserts it). |
| `oauth/opaque-failures` | Every callback failure except the unsignable-account refusal MUST be an opaque Unauthenticated. | Security | TestOAuthCallback_BadState_Unauthenticated, TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting |
| `oauth/created-account-is-complete` | An OAuth-created account MUST get its default/first-user roles, and `email_verified` when the provider asserted it, in the same transaction as the user insert. | Consistency & concurrency | TestOAuthCallback_UserinfoPath_CreatesUser, TestOAuthCallback_AProviderVerifiedAddressIsRecorded (transaction rollback is **unit (mock) only**) |
| `oauth/user-and-identity-atomic` | The created user and its `OAuthIdentity` MUST commit together. | Consistency & concurrency | TestOAuthExchange_SignsUpWithTheInvitationItCarries (both written in the exchange's unit of work; rollback is **unit (mock) only**) |
| `oauth/one-link-per-subject` | `(provider_id, external_id)` MUST be unique. Concurrent first sign-ups for one subject (two login codes redeemed by two exchanges) MUST yield one account and one link. The exchange resolves the identity again before creating, so a code redeemed after another one made the account signs in to it. | Consistency & concurrency | TestOAuthExchange_AnAccountMadeSinceTheCallbackIsUsed (sequential). Unique index for a true race; a live test needs parallel exchanges. |
| `oauth/email-canonical` | The asserted email MUST be trimmed and lower-cased before lookup and create. | Consistency & concurrency | TestOAuthCallback_UserinfoPath_CreatesUser (partial) |
| `oauth/provider-mapping` | Subject and email MUST be read via `subject_path`/`email_path` (defaults `sub`/`email`). Numeric ids MUST be coerced to strings. A missing subject or email MUST be refused. | Failure & configuration | TestOAuthCallback_UserinfoPath_CreatesUser, TestOAuthCallback_IDTokenPath, TestOAuthCallback_GitHubNumericId |
| `oauth/outbound-bounded` | Token and userinfo calls MUST time out (15 s) and MUST read at most 1 MiB. | Performance | none |
| `oauth/indexed-lookups` | `OAuthProvider.name` (unique), `OAuthIdentity(provider_id, external_id)` (unique) and `OAuthIdentity.user_id` MUST be indexed. | Performance | none (schema) |
| `oauth/redirect-base-configured` | The callback URL sent to the provider MUST come from configuration, not from a request header. | Failure & configuration | TestOAuthAuthorizeURL_BuildsRedirect (configured path only); not enforced when `oauth_redirect_base` is empty |
| `oauth/provider-secret-encrypted` | A provider configured through `UpsertOAuthProvider` MUST store its secret only in the encrypted `secret` column, on creation and on every rewrite, and MUST leave no plaintext `client_secret`. The same request twice MUST leave one row. | Security | `TestUpsertOAuthProvider_WritesTheSecretEncryptedOnBothBranches` (the declaration). **Unit (mock) only:** a live test would upsert twice and read the row back: one row, ciphertext in `secret`, `client_secret` NULL, the secret decrypting to the second value. |

**Gaps / suspected defects**

1. **Fixed: login CSRF.** See verified finding 1 and the `oauth/state-*`, `oauth/callback-carries-no-session` and `oauth/pkce-towards-provider` invariants.
2. The `id_token` signature and `iss` are not checked. `aud`, `exp` and the nonce are. The token comes straight from the provider's token endpoint over TLS, and the nonce ties it to this sign-in. Checking the signature needs the provider's JWKS, and checking `iss` needs an issuer column on `OAuthProvider`.
3. **Decided: the callback skips the second factor** (`oauth/second-factor-policy`, also the README). Combined with auto-linking, an account that was password + TOTP becomes reachable with the provider login alone once an identity is linked; the provider's own sign-in, and its own second factor, is what protects it. There is no per-account or per-provider switch to require the plugin's factor as well. The exchange does not trust the device, so this cannot spill over into password sign-ins.
4. Fixed: the user (with roles) used to be committed in its own transaction, with `CreateOAuthIdentity` afterwards outside it. A failed link insert then left an account for the address with no identity, and a retry with `email_verified=false` hit `errOAuthEmailUnverified`, locking the person out of the account just created for them. The exchange now writes both, the spent invitation included, in one unit of work, so a failed link insert leaves no account.
5. `DeleteUser` (mutation proto, around line 2183) deletes tokens and the user but not `OAuthIdentity`. With no foreign key, the orphaned link keeps resolving the external subject to the deleted user id. `refuseUnsignableAccount` then refuses forever, so that person can never sign up again through that provider.
6. `oauth.go:198–206`: When `oauth_redirect_base` is empty, `redirect_uri` is built from the request `Host` header. This is not refused at boot, and correctness then depends on the provider matching redirects exactly.
7. Fixed: the manifest text described the client secret as PASSWORD-typed. It is CRYPTED_SECRET (`secret`).
8. No account-linking audit event (e.g. identity linked), although linking an identity grants a new way into the account.

---

### cli_login

**Purpose.** Makes the deployment act as an OAuth authorization server for its own clients: the authorization-code flow with mandatory PKCE (S256). Loopback redirects (RFC 8252) need no registration. Any other redirect must be an exact `(client_id, redirect_uri)` row in the `AuthClient` registry, whose clients are confidential (a secret is required at the token endpoint).

**Adds.**
- Tables: `AuthClient` (unique `(client_id, redirect_uri)`, indexed `client_id`, `client_secret` PASSWORD = argon2 hash, per-row `enabled`) and `CliAuthCode` (`code_hash` unique SHA-256, `code_challenge`, `redirect_uri`, `client_id`, `expires_at` = now + 60 s, `consumed_at`, `session_expires_at` = the approving session's expiry, NULL when it never expires).
- Business RPCs: `CliAuthorize`, `CliToken`, `RegisterClient`, `ListClients`, `SetClientEnabled`, `DeleteClient`.
- REST: `POST /auth/cli/authorize` (bearer), `POST /auth/cli/token` (**public, failed_only**), and `POST|GET /auth/clients`, `PATCH|DELETE /auth/clients/{id}` (bearer; authorization is left to the project's endpoint ACL).
- Storage RPCs: `GetRegisteredRedirect`, `ListAuthClients`, `GetAuthClientSecret`, `GetLiveSessionExpiry`; `RegisterAuthClient`, `SetAuthClientEnabled`, `DeleteAuthClient`, `CreateCliAuthCode`, `ConsumeCliAuthCode`.
- Events: none. Env knobs: none (code TTL fixed at 60 s; the issued token uses `session_token_ttl_seconds`, capped at the approving session's expiry).

**Requires:** none declared (it uses the bearer principal from the gateway envelope). **Conflicts:** none. **Combined files:** none.

| id | invariant | category | proof |
|---|---|---|---|
| `cli_login/authorize-needs-principal` | CliAuthorize MUST refuse a call with no resolved principal, or one that did not authenticate with a live session of its own, and MUST NOT mint a code. | Security | TestCliAuthorize_Rejections, TestCliAuthorize_AnAPITokenCallerIsRefused, TestCliAuthorize_RefusesAnApproverThatIsNotALiveSessionOfTheCaller, TestCliAuthorize_RefusesWhenTheSessionReadFails, TestCliAuthorize_AnEmptySessionAnswerIsNotANonExpiringSession |
| `cli_login/pkce-mandatory` | CliAuthorize MUST refuse an empty `code_challenge`. CliToken MUST refuse a verifier shorter than 43 characters without consuming the code, and MUST issue only when BASE64URL(SHA256(verifier)) equals the stored challenge (constant-time). | Security | TestCliAuthorize_Rejections, TestCliToken_Rejections, TestVerifyPKCES256 |
| `cli_login/redirect-allowlist` | A code MUST be minted only for a loopback `http://127.0.0.1|[::1]|localhost` redirect, or for an `https` redirect registered *exactly* (whole string) and enabled under the presented `client_id`. Prefix, host-only and plaintext matches MUST be refused. | Security | TestIsLoopbackRedirect, TestCliAuthorize_LoopbackStillNeedsNoRegistration, TestCliAuthorize_ARegisteredCallbackIsAccepted, TestCliAuthorize_RefusesEverythingNotRegistered, TestCliAuthorize_RefusesAPlaintextRegisteredCallback, TestCliAuthorize_RefusesARowThatIsNotTheOneItAskedFor, TestGetRegisteredRedirect_MatchesTheWholeStringAndNothingLess |
| `cli_login/registry-lookup-fails-closed` | A registry read error MUST refuse the redirect. | Security | TestCliAuthorize_AFailedRegistryLookupRefuses |
| `cli_login/code-hashed` | Only the SHA-256 of the code MUST be stored. | Security | TestCliLogin_EndToEnd |
| `cli_login/code-single-use-short-lived` | A code MUST be redeemable once, within 60 s, by one conditional UPDATE (`consumed_at IS NULL AND expires_at > NOW()`). A wrong verifier MUST still burn the code. | Security | TestCliLogin_EndToEnd (replay), TestCliToken_Rejections (expired, wrong verifier burns); the concurrent double redemption is **unit (mock) only**. A live test must race two CliToken calls with one code and show one token. |
| `cli_login/redirect-bound-at-exchange` | For a registered (non-loopback) code, CliToken MUST require the same `redirect_uri` the code was issued for. | Security | TestCliToken_RefusesAnExchangeNamingADifferentRedirect, TestCliToken_AcceptsTheRedirectTheCodeWasIssuedFor |
| `cli_login/confidential-client-auth` | A code minted for a registered client MUST be redeemed only with that client's secret. The client MUST still be enabled at exchange time. Unknown client, disabled client and wrong or absent secret MUST be indistinguishable. | Security | TestCliToken_RegisteredClientMustPresentItsSecret, TestCliToken_ClientDisabledAfterAuthorizeCannotRedeem, TestCliToken_ClientAuthFailuresAreIndistinguishable |
| `cli_login/loopback-public-client` | A loopback code MUST NOT be bound to a client or require a secret, even if a `client_id` is sent. | Security | TestCliToken_LoopbackStaysAPublicClient |
| `cli_login/client-secret-hashed-once` | A client secret MUST be random, MUST be stored only as a password hash, and MUST be returned exactly once at registration. | Security | TestRegisterClient_IssuesASecretAndStoresOnlyItsHash |
| `cli_login/registered-redirect-shape` | Registration MUST refuse a non-absolute, non-`https` or fragment-bearing redirect. | Security | TestRegisterClient_RefusesARedirectThatCannotWork |
| `cli_login/state-echoed` | `state` MUST be returned unchanged. | Security | TestCliAuthorize_EchoesStateUnchanged |
| `cli_login/registry-admin-only` | Registering, listing, disabling and deleting clients MUST be restricted to operators. | Security | none. The plugin checks only authentication; the gate is the project's ACL. |
| `cli_login/unsignable-account-no-token` | A disabled or machine account MUST NOT redeem a code. | Security | none |
| `cli_login/no-lifetime-extension` | Redeeming a code MUST NOT produce a credential that outlives, or is broader than, the session that approved it. The minted session expires at min(now + `session_token_ttl_seconds`, the approving session's `expires_at`), with no floor; an approving session that has expired by the exchange mints nothing. Only a session may approve (an API token is refused). | Security | TestCliToken_InheritsTheApprovingSessionsEarlierExpiry, TestCliToken_NeverOutlivesTheNormalTTL, TestCliToken_ANonExpiringApproverGivesTheNormalTTL, TestCliToken_AChainOfLoginsCannotExtendTheFirstSession, TestCliToken_RefusesWhenTheApprovingSessionExpiredMeanwhile, TestCliSessionExpiry, TestCliAuthorize_AnAPITokenCallerIsRefused. **Unit (mock) only:** the liveness and ownership filters of `GetLiveSessionExpiry` are in its SQL. |
| `cli_login/opaque-token-errors` | Refusals MUST be opaque Unauthenticated. Storage failures MUST surface as errors, not as a bad code. | Failure & configuration | TestCliToken_Rejections, TestCliLogin_StorageErrorsPropagate |
| `cli_login/one-registration-per-pair` | `(client_id, redirect_uri)` MUST be unique, and the secret lookup MUST read exactly that row. | Consistency & concurrency | none (schema) |
| `cli_login/indexed-lookups` | `CliAuthCode.code_hash` (unique), `CliAuthCode.user_id`, `AuthClient(client_id, redirect_uri)` (unique) and `AuthClient.client_id` MUST be indexed. | Performance | none (schema) |
| `cli_login/expired-codes-purged` | Expired or consumed codes MUST be purged. | Performance | none. Not enforced. |

**Gaps / suspected defects**

1. **Fixed: a credential could renew itself.** CliAuthorize accepted any resolved principal, and CliToken minted a fresh session with the full `session_token_ttl_seconds`. Since rc.25 only a session may approve; the minted session now inherits the approving session's expiry (`cli_login/no-lifetime-extension`).
2. `cli_login.go:351–425`: **The registry endpoints only check authentication.** Any signed-in account can register a callback (and receive its secret), list every registration, or disable or delete other clients, unless the project's ACL forbids it. A project with the endpoint ACL axis off has no gate at all. The README documents this, but the plugin enforces nothing.
3. `cli_login.go:69`: `code_challenge` is checked only for being non-empty. No length or charset check, and no `code_challenge_method` (S256 is implied). A malformed challenge mints a code that can never be redeemed, instead of being refused up front.
4. Mutation proto, `RegisterAuthClient`: the comment says a repeat registration is a no-op, but the unique index makes it an AlreadyExists error. Rotating a secret requires delete then re-register, and no RPC states this.
5. No retention: `CliAuthCode` rows are never deleted. No events: there is no audit trail for client registration or CLI token issuance.

---

### api_token

**Purpose.** Adds API/MCP credentials that sit alongside browser session bearers. Each token belongs to a user. An API token resolves permissions only from the holder's API-realm roles, and an optional per-token permission subset can narrow that further.

**Adds**
- Tables and columns: `UserToken.token_type` (SESSION=1 default, API=2), `UserToken.name`, `UserToken.last_used_at`, `Role.token_type` (realm), table `TokenPermission` (unique `(token_id, permission_id)`).
- Queries: `GetTokenWithType`, `GetUserRolePermissionsByRealm`, `GetTokenPermissionSubset`, `ListApiTokensByUser`.
- Mutations: `IssueApiToken`, `AddTokenPermission`, `DeleteApiToken`, `DeleteTokenPermissions`.
- Business RPCs: `CreateApiToken`, `ListApiTokens`, `RevokeApiToken`.
- REST: `POST /auth/tokens`, `GET /auth/tokens`, `DELETE /auth/tokens/{token_id}`. All three need a bearer token. None is `public` or `failed_only`.
- The resolver is replaced: `resolvePrincipal` becomes realm-aware (installed by `init()` in `apitoken.go`).
- Events: none. Minting and revoking an API token emit nothing (see gaps).
- Env: `api_token_default_ttl_hours` (default 2160 = 90 days; 0 = never expires; above 100 years the plugin refuses to boot).

**Requires / conflicts / combined files.** Requires `rbac` (`GetUserRolePermissionsByRealm` reads its tables) and declares no `conflicts_with` (an earlier conflict with `org_membership` was lifted once both narrowing axes began intersecting on role IDs). Go file: `handlers/apitoken.go`. `service_account` requires this feature and reuses its minting path.

| id | invariant | category | proof |
|---|---|---|---|
| api_token/realm-separation | A SESSION token MUST resolve only roles whose `token_type` is SESSION, and an API token only roles whose `token_type` is API. | Security | `TestResolvePrincipalRealmAware_Session_NoSubsetLookup`. Unit (mock) only: the realm filter is in the SQL of `GetUserRolePermissionsByRealm`. A live test must show that a user holding only an API-realm role gets an empty permission set with a session token, and the reverse. |
| api_token/subset-narrow-only | An API token's effective permissions MUST be the intersection of its holder's API-realm grants with its subset. A subset entry the holder does not hold MUST NOT grant anything. | Security | `TestResolvePrincipalRealmAware_API_Subset_Intersects`, `TestIntersectInt32` |
| api_token/wildcard-narrowed-by-subset | A wildcard (`all_permissions`) API-realm role MUST become exactly the subset ∩ the deployed lock for a narrowed token, and MUST NOT expand again after the organization axis runs. | Security | `TestResolvePrincipalRealmAware_API_Wildcard_NarrowedBySubset`, `TestResolvePrincipalRealmAware_Wildcard_GrantsAll` |
| api_token/empty-subset-is-holder-ceiling | An API token with no subset rows MUST resolve to exactly its holder's API-realm grants, never more. | Security | `TestResolvePrincipalRealmAware_API_EmptySubset_NoNarrowing` |
| api_token/derived-token-not-wider | A token minted by a caller who authenticated with an API token MUST NOT carry permissions that the calling token does not carry. | Security | `TestCreateApiToken_AnAPITokenCallerIsRefused`, `TestCliAuthorize_AnAPITokenCallerIsRefused` (an API token mints nothing). |
| api_token/not-a-session | An API token MUST NOT appear as `AuthResp.session_token_id`, so `Logout` cannot revoke it and refuses an API-token bearer. | Security | `TestResolvePrincipalRealmAware_ApiTokenHasNoSessionID`, `TestResolvePrincipalRealmAware_ReturnsTokenID`, `TestLogout_NoSessionToken_Refused` |
| api_token/secret-once-hash-only | The plaintext token MUST be returned exactly once, at mint. Only its sha256 MUST be stored, and no list MUST ever return it. | Security | `TestCreateApiToken_StampsAPIRealm_AndSubset`, `TestListApiTokens_ReturnsCallersTokens` (the list projection lacking the secret is a schema property: `ListApiTokensByUser` selects no secret column) |
| api_token/owner-only-management | `ListApiTokens` and `RevokeApiToken` MUST act only on the caller's own API-type tokens. A revoke MUST NOT delete another user's token or any session token, and MUST NOT touch subset rows of a token it did not delete. | Security | `TestRevokeApiToken_NotOwned_SkipsSubsetCleanup`, `TestRevokeApiToken_Owned_ClearsSubset`. Unit (mock) only: ownership sits in the `DeleteApiToken` WHERE clause. A live test must revoke user B's token ID as user A and show B's token still authenticates. |
| api_token/expired-token-refused | A token whose `expires_at` has passed MUST fail authentication with Unauthenticated `SESSION_EXPIRED` (`base/expired-token-says-so`); the API-token sentence names creating a new token. | Security | `TestAuthenticate_ExpiredApiTokenSaysSo`. The `expires_at IS NULL OR expires_at > NOW()` predicate in `GetTokenWithType` is never run by a test. |
| api_token/last-used-throttled | A token that authenticates MUST have `last_used_at` written at most once per minute: skipped in Go when the lookup's value is inside the window, and guarded in `TouchTokenLastUsed`'s WHERE (`last_used_at IS NULL OR last_used_at < :cutoff`) so concurrent requests write once. A refused request MUST write nothing, and a failed write MUST NOT fail the authentication. | Consistency & concurrency | `TestAuthenticate_TouchesLastUsedAtThrottled`, `TestAuthenticate_FailedTouchDoesNotFailAuth`, `TestAuthenticate_RefusedTokenIsNotTouched`, `TestSessionExpiryStatements`. **Unit (mock) only:** the concurrent guard is SQL. |
| api_token/expiry-future-and-valid | A caller-supplied `expires_at` MUST be a valid timestamp in the future, or the call MUST fail with InvalidArgument (`TOKEN_EXPIRY_IN_PAST` / `TOKEN_EXPIRY_INVALID`). | Security | `TestAPITokenExpiry`, `TestAPITokenExpiry_OutOfRange` |
| api_token/default-expiry | A token minted without `expires_at` MUST expire after `api_token_default_ttl_hours`. 0 MUST mean "never expires". | Security | `TestCreateApiToken_DefaultExpiryReachesTheTokenAndTheCaller`, `TestAPITokenExpiry` |
| api_token/mint-atomic | A token and its subset rows MUST commit together. A failed subset write MUST NOT leave a live token behind, because an empty subset reads as "no narrowing". | Consistency & concurrency | `TestCreateApiToken_NarrowingFails_RollsBackTheLiveToken`, `TestCreateApiToken_BeginRefused_MintsNothing`, `TestCreateApiToken_Success_CommitsOnTheHandlersConnection`. Unit (fake distx) only, and only when `DistTx` is wired (gap 3). |
| api_token/revoke-idempotent | Revoking an absent or already-revoked token MUST succeed. Revoking a token that has no subset MUST NOT report NotFound. | Consistency & concurrency | `TestRevokeApiToken_EmptySubsetIsNotAFailure`, `TestRevokeApiToken_OtherCleanupErrorsStillFail` |
| api_token/revoke-immediate | Once `RevokeApiToken` returns, the next `Authenticate` with that token MUST fail. | Consistency & concurrency | none (needs a live test: revoke, then authenticate) |
| api_token/indexed-lookups | Token lookup MUST use the unique `token_hash` index, the subset lookup the `token_id` index, and the list the `user_id` index. | Performance | none (declared in `proto/types/models.proto`; no test asserts a query plan) |
| api_token/bounded-auth-cost | Authenticating an API token MUST cost a fixed number of queries (token, realm grants, subset, plus the organization axis), however many tokens or roles exist. | Performance | none |
| api_token/resolver-fails-closed | Any query error while resolving a token MUST produce the opaque Unauthenticated, never a partial principal. | Failure & configuration | none for the realm-aware resolver (only the organization axis has `TestNarrowGrants_QueryErrorFailsClosed`) |
| api_token/ttl-bounded-at-boot | `api_token_default_ttl_hours` above 100 years MUST fail plugin bootstrap. | Failure & configuration | `TestAPITokenExpiry_OutOfRange` |

**Gaps / suspected defects**
1. **Fixed in rc.25: a narrowed token could mint an unnarrowed one.** `CreateApiToken` read only `callerUserID`, so an API token narrowed to `{view}` could mint a token carrying every API-realm permission its holder has. It now refuses any caller that did not authenticate with a session. Still open: an API token can list and revoke every other API token its holder owns.
2. **No upper bound on a caller-chosen expiry.** `src/handlers/apitoken.go:285-300` accepts any future `expires_at` (up to year 9999), so the default TTL only applies to callers that omit the field. No deployment knob caps it.
3. **Atomicity depends on wiring.** `src/handlers/apitoken.go:135`: when `h.DistTx` is nil, the token and its subset rows are written as separate statements. A failure partway leaves a live token whose subset is partial or empty, and an empty subset reads as unnarrowed. This is the exact state the comment says it prevents.
4. **Fixed: `last_used_at` was never written.** Authenticate now writes it through `TouchTokenLastUsed`, at most once a minute per token (`api_token/last-used-throttled`). Best effort: a failed write is not logged (the package has no logger) and is retried by the next request in a new window.
5. **No events.** `IssueApiToken` and `DeleteApiToken` (`proto/mutations/auth_mutation.proto:1387`, `:1432`) emit neither `TokenIssued` nor `TokenRevoked`, so creating or revoking a long-lived credential is invisible to audit subscribers.
6. **Revoke is two unguarded statements.** `src/handlers/apitoken.go:230-261`: if the subset cleanup fails after the token delete succeeded, the caller gets an error for a token that is already gone. Harmless for security, but it is a non-idempotent answer.
7. **Fixed: the manifest under-declared dependencies.** `GetUserRolePermissionsByRealm` reads `UserRole`, `Role` and `RolePermission`, which `rbac` owns, so `api_token` without `rbac` could not generate. `api_token` now `requires: [rbac]`, and `make check-stage` reports a statement that names another feature's table.
8. **A personal token is not bound to an organization.** With `org_membership`, an API token can select any organization its holder belongs to through `W17-Org`. A token minted "for" one company acts in all of the holder's companies. This is undocumented.

---

### service_account

**Purpose.** Adds machine accounts (`User.kind = BOT`). A machine account has no usable password and acts only through API tokens that an operator mints for it. Creating one and minting a token for one are both held to the operator's role ceiling.

**Adds**
- Column `User.kind` (enum `AccountKind`, HUMAN=0 stored as a value, CHECK-constrained).
- Queries: `ListBotAccounts`, `ListRealmMachineAccounts`, `ListApiRealmRoles`. Mutation: `CreateBotUser` (password hash set to a non-verifiable sentinel).
- Business RPCs: `CreateBot`, `ListBots`, `ListBotRoles`, `IssueBotToken`.
- REST: `POST /auth/bots`, `GET /auth/bots`, `GET /auth/bots/roles`, `POST /auth/bots/{user_id}/token`. All need a bearer token. None is `public` or `failed_only`.
- Admin page `ServiceAccounts` (list, detail, delete, bulk disable/enable).
- A `SignIn` gate (`signInBotGate`) and the `account_kind=bot` principal label.
- Events: none of its own (`CreateBotUser` emits no `UserCreated`).
- Env: `api_token_default_ttl_hours` (shared with `api_token`).

**Requires / conflicts / combined files.** Requires `api_token`, `user_admin`, `rbac` and `authenticate_turnkey`. Go files: `handlers/service_account.go` and `handlers/role_ceiling.go`. Combined files: `[service_account, tenant_scope]` → `handlers/service_account_tenant.go` (the bot is created in the operator's tenant and only that tenant's bots are visible). `[service_account, org_membership]` → `handlers/service_account_org.go` (the bot joins the operator's active organization, its role is granted org-scoped, and listing and minting are restricted to that organization). If organizations are staged without the org scoping file, every machine-account call refuses with Internal.

| id | invariant | category | proof |
|---|---|---|---|
| service_account/no-password-sign-in | Password `SignIn` MUST refuse a BOT account with the same opaque Unauthenticated used for a wrong password, even if a password hash was later set on it. | Security | `TestSignInBotGate`, `TestSignInBotGate_ReasonStaysInternal`, `TestSignIn_RefusesAMachineAccountThatHasAPassword`, `TestBotPasswordSentinel_IsNonEmptyAndCannotVerify` |
| service_account/token-only-for-bots | `IssueBotToken` MUST refuse a human account or a missing account with the same PermissionDenied, and MUST write nothing on refusal. | Security | `TestIssueBotToken_RefusesAPerson`, `TestIssueBotToken_WithoutOrgs_RefusesAPersonAndAMissingAccountAlike` |
| service_account/create-role-ceiling | `CreateBot` MUST refuse a role carrying any permission the operator does not hold. | Security | `TestCreateBot_RefusesARoleAboveTheOperator`, `TestCreateBot_WithoutOrgs_TheRoleCeilingHolds` |
| service_account/mint-ceiling | `IssueBotToken` MUST refuse a bot that holds any role the operator could not grant. | Security | `TestIssueBotToken_RefusesABotAboveTheOperator` |
| service_account/api-realm-role-only | `CreateBot` MUST refuse a role that is not in the API realm. | Security | `TestCreateBot_RefusesARoleFromTheSessionRealm`, `TestCreateBot_AcceptsAnApiRealmRoleAndGrantsIt` |
| service_account/role-required | `CreateBot` MUST refuse a request without `role_id`. | Security | `TestCreateBot_RoleIsRequired` |
| service_account/org-isolation | With organizations, a bot MUST be created in the operator's active organization with an org-scoped grant. Listing and minting MUST see only that organization's bots, and having no active organization MUST be refused. | Security | `TestCreateBot_JoinsTheOrgAndScopesTheGrantToIt`, `TestCreateBot_RefusesWithNoActiveOrg`, `TestListBots_AsksOnlyForTheActiveOrganization`, `TestListBots_RefusesWithNoActiveOrg`, `TestIssueBotToken_RefusesABotFromAnotherOrganization`, `TestListBots_InAnOrg_KeepsOnlyTheMachines` |
| service_account/tenant-isolation | With `tenant_scope`, a bot MUST be created in the operator's tenant, and bots of other tenants MUST be invisible and unmintable. Having no tenant in scope MUST see none. | Security | `TestCreateBot_PutsTheBotIntoTheOperatorsTenant`, `TestCreateBot_RefusesWithNoTenantInScope`, `TestMachineAccounts_WithoutOrgs_StayInTheOperatorsTenant`, `TestMachineAccounts_NoTenantInScopeSeesNone` |
| service_account/no-unscoped-fallback | A build with organizations but without the org scoping file MUST refuse every machine-account call rather than serve all organizations. | Failure & configuration | `TestMachineAccounts_OrgsWithoutTheirScopingRefuse` |
| service_account/disabled-bot-unmintable | `IssueBotToken` MUST refuse a disabled machine account. | Security | `TestIssueBotToken_RefusesADisabledBot` |
| service_account/create-atomic | The account, its membership and its role grant MUST commit together or not at all. | Consistency & concurrency | `TestCreateBot_GrantFails_RollsBackTheAccountAndMembership`, `TestCreateBot_Success_CommitsOnTheHandlersConnection`, `TestCreateBot_BeginRefused_WritesNothing` (fake distx; only when `DistTx` is wired) |
| service_account/mint-atomic | A bot token and its subset MUST commit together. | Consistency & concurrency | `TestIssueBotToken_NarrowingFails_RollsBackTheLiveToken`, `TestIssueBotToken_Success_CommitsOnTheHandlersConnection`, `TestIssueBotToken_BeginRefused_MintsNothing` (fake distx) |
| service_account/ceiling-check-is-current | The ceiling MUST be evaluated against the catalogue as it stands when the grant is written. | Consistency & concurrency | none. The check and the write are separate statements, so a role widened in between is granted unchecked. Unit tests cannot show this. |
| service_account/listing-bounded | Listing machine accounts MUST be bounded (paged or indexed on `kind`). | Performance | none. `ListBotAccounts` and `ListRealmMachineAccounts` scan `User` on unindexed `kind` and return every row. |
| service_account/label-not-authority | The `account_kind=bot` label MUST be informational only. A failure to resolve it MUST NOT fail or widen authentication. | Failure & configuration | none |

**Gaps / suspected defects**
1. **Fixed in rc.25: a disabled machine account could get a fresh, working token.** `IssueBotToken` checked only `kind` and visibility, and `Authenticate` never read `disabled_at`. It now refuses a disabled bot with `FailedPrecondition`, and `Authenticate` refuses a disabled account's token.
2. **The email is not normalized.** `src/handlers/service_account.go:240` stores `CreateBotReq.email` as given. `Bot@X` and `bot@x` can coexist alongside a human `bot@x` that differs only by case, unlike every other account path.
3. **The membership label does not match the grant.** `src/handlers/service_account_org.go` writes `OrgMembership.role = "member"` whatever role was granted, so `ListOrgMembers` reports a label unrelated to the bot's permissions.
4. **Without organizations, every operator manages every bot.** By design the realm is one organization, so any authenticated caller whose ceiling covers a bot's role can mint tokens for it. Only the endpoint ACL limits this, which is the project's job, and nothing in the plugin enforces that an ACL exists.
5. **No audit events.** Bot creation emits no `UserCreated`, and token minting emits nothing.

---

### user_admin

**Purpose.** Adds turnkey administration of accounts: a Users page and a Sessions page on the admin surface, soft-disable and enable, hard-delete, and revocation of single tokens.

**Adds**
- Column `User.disabled_at`.
- With `devices`, `DisableUsers` also stamps `User.device_trust_revoked_at` (that column is `devices`'), so a re-enabled account's devices pass the second factor again.
- Queries: `ListUsers`, `GetUser` (no `password_hash`), `ListUserTokens`, `GetUserToken` (no secret).
- Mutations: `UpdateUser` (email only; clears `email_verified_at`; emits `UserUpdated`), `DeleteUser` (purges tokens, then the user; emits `UserDeleted`), `DisableUsers` (sets `disabled_at` and deletes every token of those users), `EnableUsers`, `RevokeUserToken` (emits `UserTokenRevoked`).
- A `SignIn` gate (`signInDisabledGate`), also applied by `refuseUnsignableAccount` to MFA completion, the OAuth callback and the CLI exchange.
- REST: none. The surface is the admin preset only (pages `Users`, `Sessions`), so authorization is the admin surface's ACL.
- Env: none.

**Requires / conflicts / combined files.** No `requires`, no conflicts. Go file: `handlers/user_admin.go`. `service_account` requires this feature.

| id | invariant | category | proof |
|---|---|---|---|
| user_admin/disabled-cannot-sign-in | Password `SignIn` MUST refuse a disabled account, even with the correct password, using the opaque Unauthenticated. | Security | `TestSignInDisabledGate_SeamRejectsDisabledAllowsActive`, `TestSignIn_RejectsDisabledAccount`, `TestSignIn_TheFourRefusalsAreIndistinguishable` |
| user_admin/disabled-gets-no-session-elsewhere | Every other path that issues a session to an existing account (second factor, OAuth callback, CLI code exchange) MUST refuse a disabled account. | Security | `TestVerifyMfa_ADisabledAccountGetsNoSession` (OAuth and CLI paths: none) |
| user_admin/disable-revokes-all-tokens | Disabling MUST delete every session and API token of the account in the same unit of work. | Security | none. Unit tests cannot reach it: it is the two-leg SQL in `DisableUsers`. A live test must disable an account holding a session and an API token and show both fail `Authenticate`. |
| user_admin/disable-ends-device-trust | With `devices`, disabling MUST end the trust of every device of the account in the same statement as `disabled_at`, so re-enabling does not bring back a device that skips the second factor. | Security | `TestDisableUsers_RevokesDeviceTrustInTheSameStatement` (the statement), `TestResolveSignInDevice_TrustRevokedByACredentialChange_NotTrusted` (the read side). A live test would disable, re-enable, and show a replayed trust token no longer skips the challenge. |
| user_admin/disabled-token-refused-at-auth | A token belonging to a disabled account MUST fail authentication, including a token minted after or concurrently with the disable. | Security | `TestResolvePrincipal_ADisabledAccountIsRefused`. **Unit (mock) only**: a live test must mint a token for an account after disabling it and show `Authenticate` refuses it. |
| user_admin/enable-restores-nothing | Re-enabling MUST NOT restore any revoked token. | Security | none (SQL only) |
| user_admin/delete-revokes-tokens | Deleting an account MUST delete its tokens in the same transaction as the user row. | Security | none (SQL only; a live test must show a token of a deleted user fails) |
| user_admin/no-secret-projection | Admin reads MUST NOT return `password_hash` or any token secret or hash. | Security | `TestEveryUserProjectionFillsTheFieldsItsGatesRead` covers the projections that are present. Absence of secrets: none (schema/DQL only). |
| user_admin/email-change-drops-proof | An email change MUST clear every proof of address ownership recorded for the previous address. | Security | none. Partly violated, see gap 3. |
| user_admin/email-canonical | An email written through the admin MUST be stored in the same canonical (trimmed, lower-cased) form that sign-in looks up. | Consistency & concurrency | none. **Violated**, see gap 2. |
| user_admin/revoke-token-immediate | `RevokeUserToken` MUST make that token fail the next authentication. | Consistency & concurrency | none (live) |
| user_admin/no-self-lockout | An administrator MUST NOT be able to disable or delete the last account able to administer the realm. | Failure & configuration | none. Not enforced, see gap 5. |
| user_admin/listing-bounded | `ListUsers` and `ListUserTokens` MUST be paged. | Performance | none. Both return the whole table. |

**Gaps / suspected defects**
1. **Fixed in rc.25: authentication did not check `disabled_at`.** "Disabled" was enforced only by deleting tokens, so a token minted after the disable (a racing `SignIn`, `IssueBotToken` for a disabled bot) worked. `GetTokenWithType` and `GetUserByTokenWithPermissions` now project the owner's `disabled_at`, and both resolvers refuse a disabled account.
2. **Admin email edits are not normalized.** `proto/mutations/auth_mutation.proto:2149` (`UpdateUser`) writes `:email` verbatim. A mixed-case value makes the account impossible to sign in to (`SignIn` lower-cases the lookup), and it slips past the case-sensitive unique constraint, so two accounts can differ only by case.
3. **The proof survives an email change.** `UpdateUser` clears `email_verified_at` but not `email_proof`. An account holding `DERIVED_FROM_INVITE` keeps it for the new address. With `email_proof_required=derived`, that account can accept an OPEN invitation on an address it never proved.
4. **Deletion leaves dependent rows behind.** `DeleteUser` (`auth_mutation.proto:2183`) leaves `UserRole`, `OrgMembership`, `TokenPermission`, `OrgInvite.invited_by` and `Organization.owner_id` pointing at the deleted ID. It relies on an external `UserDeleted` subscriber, and the plugin itself subscribes to nothing. Concrete effects: an organization keeps a dangling owner, and admin lists show memberships with an empty member.
5. **No last-admin or self guard** on `DisableUsers` or `DeleteUser`. An operator can lock the realm out of its own admin surface.
6. **Disable and enable emit no events** (`auth_mutation.proto:2213`, `:2233`), so downstream systems cannot react to a disable that already revoked tokens.
7. **Fixed in rc.25: a stale comment contradicted the behaviour.** `User.disabled_at` in `proto/types/models.proto` said existing tokens keep working after a disable.

---

### org_membership

**Purpose.** Adds multi-organization membership. One identity belongs to many `Organization`s through `OrgMembership`. Each request acts in one validated active organization, and the caller's grants are narrowed to that organization. Ownership (`Organization.owner_id`) grants root authority inside the owned organization to a session principal.

**Adds**
- Tables: `Organization` (unique `slug`; `owner_id` indexed and nullable), `OrgMembership` (unique `(user_id, org_id)`).
- Columns: `UserRole.org_id` (indexed; partial unique indexes for realm-wide and org-scoped grants), `Role.org_scoped`.
- Queries: `ListUserOrgs`, `ListUserOrgGrants`, `GetUserOrgPermissions`, `GetUserRealmWidePermissions`, `GetUserOwnsOrg`, `GetUserOwnsAnyOrg`, `GetOwnedOrgBySlug`, `GetUserOrgBySlug`, `ListOrgScopedRoles`, `ListOrgMemberAccounts`, `GetOrgMember`, `ListOrganizations`, `GetOrganization`, `ListOrgMemberships`, `GetOrgMembership`, `ListOrgMembersByOrg`.
- Mutations: `CreateOrganization`, `UpdateOrganization`, `DeleteOrganization` (purges memberships and org grants), `AddOrgMembership`, `UpdateOrgMembership` (row-locked; revokes the member's org grants and writes the new one), `DeleteOrgMembership` (row-locked; revokes the org grants).
- Business RPCs: `ListMyOrgs`, `ListOrgMembers`, `UpdateOrgMembershipRole`, `RemoveOrgMembership` (the last two are held to the role ceiling).
- REST: `GET /auth/orgs`, `GET /auth/orgs/{org}/members`. Both need a bearer token, and neither is `public`. The `{org}` group uses `org_from_path`, so the path slug becomes the `W17-Org` selector before authentication.
- Auth header `W17-Org`. Scope keys `org_id` and `org_slug`. `WhoAmI` gains `orgs` and `active_org_id`.
- Admin pages `Organizations` and `OrgMemberships` (update and delete go through the ceiling-checked service methods).
- Events: `OrganizationCreated`, `OrganizationUpdated`, `OrganizationDeleted`, `OrgMembershipAdded`, `OrgMembershipUpdated`, `OrgMembershipRemoved`.
- Env: none.

**Requires / conflicts / combined files.** Requires `authenticate_turnkey` and `rbac`. Go files: `handlers/org_membership.go`, `handlers/role_ceiling.go`, `handlers/org_membership_role.go`. Combined with `service_account`: `handlers/service_account_org.go`. It can coexist with `tenant_scope`, but a project is expected to pick one model.

| id | invariant | category | proof |
|---|---|---|---|
| org_membership/selector-validated | A client-sent organization selector (header or path) MUST resolve to an organization only if the caller is a member or its owner. Otherwise authentication MUST fail with a distinct "not a member" refusal. | Security | `TestResolveOrgScope`, `TestResolveOrgScope_NonMemberNonOwnerStillRefused`, `TestOrgNotMember_SaysWhatIsWrong`, `TestResolveOrgScope_HeaderLookupIsCaseInsensitive`, `TestResolveOrgScope_SlugFromHeadersWithoutMetadata` |
| org_membership/path-header-agree | A request whose `org` field names a different organization from the one authentication resolved MUST be refused. An empty field MUST defer to authentication. | Security | `TestRefuseOtherOrg`, `TestRefuseOtherOrgDefersWhenNoOrgWasResolved` |
| org_membership/sole-org-inference-only | With no selector, the active organization MUST be inferred only when the caller belongs to exactly one. With zero or several it MUST stay unset. | Security | `TestResolveOrgScope_SoleOrgInference`, `TestResolveOrgScope_MultipleOrgsStayAmbiguous`, `TestResolveOrgScope_HeaderWinsOverInference`, `TestResolveOrgScope_NoSelectorFallsBackToInference`, `TestResolveOrgScope_SoleOrgInferenceAlsoStampsTheSlug` |
| org_membership/grants-narrowed-to-active-org | With an active organization, grants MUST be limited to realm-wide non-org-scoped roles plus roles assigned in that organization. With none, they MUST be realm-wide roles only. | Security | `TestNarrowGrants_ActiveOrg`, `TestNarrowGrants_NoActiveOrg`. Unit (mock) only for the role selection itself: the `GetUserOrgPermissions` predicate is SQL. A live test must give a user an org-scoped admin role in A and show that acting in B grants nothing from it. |
| org_membership/intersect-on-roles | A permission MUST survive only if one single role grants it and that role passes both the realm axis and the organization axis. | Security | `TestNarrowGrants_APermissionTwoDifferentRolesGrantDoesNotSurvive`, `TestNarrowGrants_WildcardRoleMustPassTheOrgAxis` |
| org_membership/admin-plane-realm-only | `AuthenticateAdmin` (the admin `user_lookup`) MUST select no organization, from a header, the context or sole-org inference. Only realm-wide roles survive, and ownership grants nothing. `Authenticate` MUST keep selecting one. | Security | `TestResolveOrgScope_TheAdminPlaneSelectsNoOrganization`, `TestAuthenticateAdmin_MarksTheAdminPlaneAndAuthenticateDoesNot`, `TestNarrowGrants_NoActiveOrg` |
| org_membership/ownership-session-only | Ownership MUST widen grants only for a SESSION principal, only in the owned active organization, and never for an API token. | Security | `TestNarrowGrants_OwnershipWidensASession`, `TestNarrowGrants_OwnershipDoesNotWidenAnApiToken` |
| org_membership/owner-not-locked-out | An organization's owner MUST be able to select it even without a membership row, so removing or changing memberships cannot lock the owner out. | Security | `TestResolveOrgScope_OwnerWithoutMembership`, `TestResolveOrgScope_MembershipShortCircuitsTheOwnershipLookup` |
| org_membership/role-change-ceiling | A role change MUST be refused unless the caller holds every permission of the new role and covers every role the member currently holds in that organization. | Security | `TestUpdateOrgMembershipRole_RefusesARoleAboveTheCaller`, `TestMembership_TheMemberAboveTheCallerIsNotTheirsToChange` |
| org_membership/removal-ceiling | A removal MUST be refused unless the caller covers every role the member holds in that organization. | Security | `TestMembership_TheMemberAboveTheCallerIsNotTheirsToChange` |
| org_membership/cross-org-management-refused | A caller acting in organization A MUST NOT change or remove a membership in organization B. | Security | `TestMembership_AnotherOrganizationsMemberIsRefused` |
| org_membership/org-scoped-roles-only | A membership MUST carry only an org-scoped role, with distinct refusals for an unknown name (`UNKNOWN_ORG_ROLE`) and a realm-wide role (`ROLE_NOT_ORG_SCOPED`). The role MUST be applied by the ID that was checked. | Security | `TestRoleIDByName_RefusesARealmRole`, `TestRoleIDByName_AnUnknownNameIsATypoNotAScopingProblem`, `TestRoleIDByName_AcceptsAnOrgScopedRole`, `TestAssignableRolesAndValidatorCannotDisagree`, `TestUpdateOrgMembershipRole_GrantsTheCheckedRoleByID`, `TestUpdateOrgMembershipRole_OtherRefusals` |
| org_membership/ceiling-fails-closed | A grant decision with no resolved permission envelope (a direct gRPC call) MUST be refused. | Failure & configuration | `TestCheckMayGrantRole_NoEnvelopeFailsClosed`, `TestUpdateOrgMembershipRole_OtherRefusals` |
| org_membership/label-and-grant-move-together | A role change MUST replace the member's org-scoped grants and the membership label in one transaction. A removal MUST delete the org-scoped grants with the row. | Consistency & concurrency | none. Unit tests cannot reach it: multi-statement SQL in `UpdateOrgMembership` and `DeleteOrgMembership`. A live test must demote a member and show the old role's permissions are gone. |
| org_membership/concurrent-role-changes-serialize | Two concurrent changes to one membership MUST leave the member holding exactly one org role, matching the label. | Consistency & concurrency | none. The `SELECT … FOR UPDATE` lock is declared in the mutation, but no test runs two transactions. |
| org_membership/ceiling-and-write-consistent | The ceiling check and the grant MUST see the same catalogue and the same member grants. | Consistency & concurrency | none. Not enforced, see gap 4. |
| org_membership/no-orphan-grants | Deleting an organization MUST delete its memberships and org-scoped grants atomically. | Consistency & concurrency | none (SQL only) |
| org_membership/narrowing-fails-closed | A query error in the organization narrower MUST fail authentication. | Failure & configuration | `TestNarrowGrants_QueryErrorFailsClosed`, `TestResolveOrgScope_OwnershipLookupErrorPropagates` |
| org_membership/whoami-degrades | A failure to list the caller's organizations MUST NOT fail `WhoAmI`. It MUST report no organizations instead. | Failure & configuration | `TestWhoAmI_SurvivesAFailingOrgQuery`, `TestWhoAmI_CarriesOrgsAndTheActiveOne`, `TestWhoAmI_NoActiveOrgIsReportedAsEmpty` |
| org_membership/indexed-auth-path | The per-request lookups (membership by `(user_id, org_id)`, organization by `slug`, grants by `user_id` and `org_id`, owner by `owner_id`) MUST be served by indexes. | Performance | none (schema declares them; untested) |
| org_membership/bounded-auth-cost | Organization resolution MUST add a constant number of queries per request. | Performance | none. The current cost is up to 4 extra round trips (slug, then owned slug, then grants, then ownership), uncached. |

**Gaps / suspected defects**
1. **Partly fixed: the admin surface.** The admin preset now authenticates through `AuthenticateAdmin`, which selects no organization, so neither ownership nor an organization-scoped role grants anything there. Still open for app endpoints: **ownership widens to the entire deployed permission lock**, not to "everything inside this organization". `src/handlers/org_membership.go:169` appends `RoleGrant{AllPermissions: true}`, which expands from the whole lock. Any endpoint whose effect is not row-scoped by `org_id` and is reached with the owned organization selected passes its permission check. Examples: realm-wide administration reached through an app surface (`DisableUsers`, `DeleteUser`, `RevokeUserToken`, `ListUsers`, `UpdateOrganization` or `DeleteOrganization` of another organization, client registration). An owner can also pass every role ceiling and hand out realm-level API roles through `CreateBot`. Whether this is exploitable depends on whether those surfaces accept `W17-Org`. The plugin does not restrict the expansion to org-scoped permissions.
2. **No in-plugin ownership lifecycle.** No plugin mutation writes `Organization.owner_id` (`CreateOrganization` at `proto/mutations/auth_mutation.proto:2699` sets only slug, name and kind). There is no transfer, and nothing guarantees an organization has an owner. Organizations without an owner have no "last owner" protection at all: the last member able to manage memberships can demote or remove themselves.
3. **A member with no org roles can be removed or relabelled by anyone allowed to call.** `src/handlers/org_membership_role.go:118` returns success when the target holds no org-scoped grants. This includes an owner's own membership row, which harmlessly leaves ownership in place, and any member whose authority comes from realm-wide roles.
4. **Time-of-check versus time-of-use in role changes.** `checkMayManageMembership` and `checkMayGrantRole` (`org_membership_role.go:59-72`) read the member's grants and the role catalogue on the pool, outside the row lock taken later by `UpdateOrgMembership`. A concurrent promotion of the member, or a widening of the target role, between check and write is applied without a ceiling check.
5. **Sole-organization inference swallows errors.** `src/handlers/org_membership.go:286-289` returns success with no org scope when `ListUserOrgs` fails. This is safe for permissions (narrowing falls back to realm-wide), but a transient failure becomes a hard-to-diagnose "missing required scope" on scoped models.
6. **Unpaged admin lists.** `ListOrganizations`, `ListOrgMemberships` and `ListOrgMembersByOrg` (`proto/queries/auth_query.proto:2142`, `:2235`) return whole tables.
7. **`UpdateOrganization` can change `slug`**, which is the selector clients send in `W17-Org` and in paths, and nothing announces the old-to-new mapping beyond `OrganizationUpdated { org_id }`.

---

### org_invite

**Purpose.** Adds invitations to an organization with a named org-scoped role, delivered as a single-use secret link. An invitation is either bound to one address or open, meaning whoever holds the link picks the address. Accepting writes the membership and the org-scoped role grant together. The same table can gate sign-up (`invite_only`).

**Adds**
- Table `OrgInvite`: `token_hash` unique; nullable `email` (NULL = open); `role` (a Role name); `role_snapshot`; opaque `metadata` (JSON); `expires_at`; `accepted_at`. There is a partial unique index on `(org_id, email) WHERE accepted_at IS NULL`.
- Queries: `GetPendingOrgInviteByToken`, `ListOrgInvitesByOrg`, `ListPendingInvitesForEmail`.
- Mutations: `CreateOrgInvite`, `BindOpenOrgInvite`, `ConsumeOrgInviteByToken`, `ClearExpiredOrgInvite`, `DeleteOrgInvite` (scoped by `org_id`).
- Business RPCs: `ListAssignableRoles`, `InviteToOrg`, `ListOrgInvites`, `RevokeOrgInvite`, `ListMyInvites`, `AcceptOrgInvite`.
- REST: `GET /auth/orgs/{org}/roles`, `GET|POST /auth/orgs/{org}/invites`, `DELETE /auth/orgs/{org}/invites/{invite_id}`, `GET /auth/invites`, `POST /auth/invites/accept` (the token travels in the body, never in the path). All need a bearer token. None is `public` or `failed_only`.
- Sign-up seams: `signupInviteGate` (also consulted by OAuth account creation) and `signupClaimInvite`.
- Events: `OrgInviteCreated`, `OrgInviteAccepted` (emitted after commit), `OrgInviteRevoked`.
- Env: `invite_only` (default true), `email_proof_required` (`none` default, then `derived`, then `full`), `org_invite_ttl_hours` (default 168).

**Requires / conflicts / combined files.** Requires `org_membership` and `rbac`. Go file: `handlers/org_invite.go`. It interacts with `sign_up_turnkey`, `sign_up_confirmation` and `oauth` through the sign-up gate, and with `email_verification`, which provides the real `inviteVerifiedEmailGate` and `markEmailDerived`. Without `email_verification` both are no-ops.

| id | invariant | category | proof |
|---|---|---|---|
| org_invite/invite-role-ceiling | `InviteToOrg` MUST refuse a role carrying any permission the inviter does not hold, and the refusal MUST name the rule. | Security | `TestInviteToOrg_RefusesARoleAboveTheInviter`, `TestInviteToOrg_ARoleAboveTheInviterNamesTheRule`, `TestRoleWithinCeiling`, `TestCheckMayGrantRole_ARoleYouDoNotHoldButCover` |
| org_invite/picker-equals-validator | `ListAssignableRoles` MUST offer exactly the org-scoped roles within the caller's ceiling, the same set `InviteToOrg` accepts. | Security | `TestListAssignableRoles_OffersOnlyRolesWithinTheCeiling`, `TestAssignableRolesAndValidatorCannotDisagree` |
| org_invite/snapshot-holds-at-accept | Acceptance MUST refuse, without spending the invitation, if the role is no longer the one checked at invite time or now carries a permission outside the stored snapshot. An empty snapshot MUST be refused. | Security | `TestCheckMayGrantRole_ReturnsTheSnapshotItChecked`, `TestCheckRoleWithinSnapshot`, `TestAcceptOrgInvite_RefusesARoleWidenedSinceTheInvitation`, `TestRoleSnapshot_AWildcardOverAnEmptyCatalogueRoundTrips` |
| org_invite/secret-link | The invitation token MUST be returned to the inviter exactly once. Only its sha256 MUST be stored, and acceptance MUST look it up by hash. | Security | `TestInviteToOrg_ReturnsThePlaintextOnceAndStoresTheHash`, `TestAcceptOrgInvite_ConsumesTheHashNotThePlaintext` |
| org_invite/bound-to-address | A bound invitation MUST be accepted only by the account whose canonical email equals the invited address, at sign-up and at acceptance. | Security | `TestAcceptOrgInvite_BoundInvitationRefusesAnotherAddressOpaquely`, `TestSignupInviteGate_ABoundTokenDoesNotAdmitAnotherAddress`, `TestSignupInviteGate_ABoundTokenAdmitsItsOwnAddress` |
| org_invite/opaque-refusal | Unknown, expired, spent and wrong-address acceptances MUST all return the same NotFound refusal. | Security | `TestAcceptInvite_NotFoundBecomesTheOpaqueRefusal`, `TestAcceptInvite_EmptyResponseGivesTheSameRefusal`, `TestAcceptOrgInvite_AnUnknownTokenIsOpaque`, `TestAcceptInvite_OtherErrorsAreNotDisguised` |
| org_invite/grant-is-org-scoped | Acceptance MUST write the role grant with the invitation's `org_id`, never as a realm-wide grant. The role MUST come from the claimed row, never from the request. | Security | `TestAcceptOrgInvite_BoundRecordsDerivedAndOpenDoesNot` (indirect). Unit (mock) only: no test asserts `AssignRoleToUserReq.OrgId`. |
| org_invite/invite-only-gate | With `invite_only=true`, sign-up (password, confirmation and OAuth creation) MUST refuse an address that has neither a pending invitation nor a valid open or own bound link, with an opaque refusal. With `invite_only=false`, the gate MUST admit everyone. A query error MUST refuse. | Security | `TestSignupInviteGate_OverrideIsInstalled`, `TestSignupInviteGate_InvitedAddressPasses`, `TestSignupInviteGate_OffAllowsEveryone`, `TestInviteGate_RefusesAnUninvitedAddress`, `TestInviteGate_AdmitsAnInvitedAddress`, `TestInviteGate_OffAdmitsEveryone`, `TestInviteGate_RefusalIsOpaque`, `TestOAuthCreate_ConsultsTheInviteGate`, `TestSignupInviteGate_AnOpenLinkAdmitsAnyAddress`, `TestSignupInviteGate_AStaleTokenFallsBackToTheAddress` |
| org_invite/open-link-registers-once | Under `invite_only`, an open link MUST admit at most one registration: the first sign-up binds it to its address, and a second one with the same link MUST be refused unless its address has its own invitation. | Security | `TestClaimOpenInvite_TheFirstRegistrationSpendsTheLink`, `TestClaimOpenInvite_AnUncommittedBindIsTheClaimantsOwn`, `TestClaimOpenInvite_TheLoserOfARaceKeepsItsOwnInvitation`, `TestClaimOpenInvite_WithoutInviteOnlyNothingIsRefused`. Unit (mock) only: the race is decided by the row lock of `BindOpenOrgInvite`. A live test must run two concurrent sign-ups on one link and show one account was admitted. |
| org_invite/email-proof-floor | With `email_proof_required=full`, acceptance MUST require a self-confirmed address. With `derived`, it MUST accept a bound invitation or an already derived or confirmed address, and refuse an open invitation from an unproven account. A refused acceptance MUST NOT spend the invitation. | Security | `TestEmailProofGate_FullRefusesAnUnprovenAccount`, `TestEmailProofGate_FullAllowsASelfConfirmedAccount`, `TestEmailProofGate_NoneChangesNothing`, `TestEmailProofGate_DerivedFloorSeparatesBoundFromOpen`, `TestEmailProofGate_AlreadyDerivedSatisfiesDerivedButNotFull`, `TestEmailProofGate_RefusalIsActionableAndLeaksNothing`, `TestAcceptOrgInvite_ARefusedAcceptanceDoesNotConsumeTheInvitation` |
| org_invite/bound-accept-derives-proof | Accepting a bound invitation MUST record `DERIVED_FROM_INVITE` in the acceptance transaction and MUST NOT downgrade a self-confirmed address. An open invitation MUST record nothing. | Security | `TestAcceptOrgInvite_BoundRecordsDerivedAndOpenDoesNot` (no-downgrade is SQL only) |
| org_invite/revoke-own-org-only | `RevokeOrgInvite` MUST delete only a pending invitation of the caller's active organization. | Security | none. Unit (mock) only: `org_id` sits in the `DeleteOrgInvite` WHERE clause. A live test must revoke organization B's invitation ID while acting in A and show it survives. |
| org_invite/single-use | An invitation MUST be consumed at most once. Two concurrent acceptances of one token MUST yield exactly one membership. | Consistency & concurrency | none. The guard is `accepted_at IS NULL` in the consuming `UPDATE`. Live only. |
| org_invite/accept-atomic | Consuming the invitation, writing the membership, writing the org-scoped grant and recording the derived proof MUST commit together. Any failure MUST leave the invitation unspent. | Consistency & concurrency | none. No org_invite test wires `DistTx`; `TestAcceptOrgInvite_RefusesARoleWidenedSinceTheInvitation` shows only the snapshot refusal. Only holds when `DistTx` is wired, see gap 2. |
| org_invite/one-pending-per-address | At most one pending bound invitation MUST exist per `(org, email)`. An expired one MUST NOT block a new invitation. Open invitations MUST NOT collide with each other. | Consistency & concurrency | `TestInviteToOrg_ClearsALapsedInviteFirst`, `TestInviteToOrg_NothingExpiredIsNotAFailure`, `TestInviteToOrg_ClearFailureStopsTheWrite`, `TestInviteToOrg_AnOpenInvitationSkipsTheClear`, `TestInviteToOrg_PropagatesTheConstraintDetail` (uniqueness itself: partial index, live only) |
| org_invite/expiry-enforced | An invitation past `expires_at` MUST be refused at sign-up and at acceptance. | Consistency & concurrency | none (SQL predicate `expires_at > NOW()` in three statements) |
| org_invite/address-canonical | Bound invitation addresses MUST be stored in canonical form, and an empty address MUST create an open invitation. | Consistency & concurrency | `TestInviteToOrg_TheAddressMayBeEmptyForAnOpenInvitation`, `TestInviteToOrg_AnOpenInvitationStoresNoAddress` |
| org_invite/metadata-opaque | `metadata` MUST be stored as given (an absent value as `{}`) and returned from the same statement that spends the invitation. | Consistency & concurrency | `TestInviteToOrg_AbsentMetadataBecomesTheEmptyObject` |
| org_invite/indexed-lookups | Token lookup MUST use the unique `token_hash` index. Per-org and per-address listings MUST use the `org_id` and `email` indexes. | Performance | none (schema only) |
| org_invite/proof-knob-effective | A non-`none` `email_proof_required` MUST be enforced or MUST fail boot. It MUST NOT be silently ignored. | Failure & configuration | none. **Violated**, see gap 3. |

**Gaps / suspected defects**
1. **The binding check races with the consume.** `src/handlers/org_invite.go:502-519` decides whether the invitation is bound from an advisory read. `ConsumeOrgInviteByToken` (`proto/mutations/auth_mutation.proto:3049`) is keyed only on `token_hash`, with no email predicate. If an open invitation is bound to address X by a concurrent sign-up (`BindOpenOrgInvite`) between the read and the consume, a different, already registered account that holds the same link still consumes it. The binding is defeated, and X's registrant loses the invitation. Adding `AND (email IS NULL OR email = :email)` to the consuming `UPDATE` would close this.
2. **Acceptance is atomic only with distx.** `src/handlers/org_invite.go:526`: when `h.DistTx` is nil, consume, `AddOrgMembership`, `AssignRoleToUser` and `markEmailDerived` run as separate statements. A failure after the consume (for example, the caller is already a member, so `AddOrgMembership` hits its unique constraint, or the snapshot check fails) spends the invitation and can leave a membership without a grant. The read-before-gate ordering exists precisely to avoid this, and it covers only the email-proof refusal.
3. **The proof floor is silently ignored without `email_verification`.** `inviteVerifiedEmailGate` and `markEmailDerived` default to no-ops (`src/handlers/auth_service.go:528-541`), and only `emailverify.go` installs the real gate. A deployment with `org_invite` and `email_proof_required=full` but without `email_verification` admits every acceptance, and `ValidateConfig` (`auth_service.go:399`) does not refuse the combination. An unknown value is enforced as the strictest floor at call time but is not rejected at boot.
4. **The address-guessing window is open by default.** With `invite_only=true` (default) and `email_proof_required=none` (default), whoever registers an invited address first inherits the membership and role. This is documented, but the documentation points to a removed knob: the `invite_only` description in `plugin.yaml:72` and the `OrgInvite` comment in `proto/types/models.proto:1056` tell operators to set `invite_requires_verified_email`, which `email_proof_required` replaced.
5. **`ListMyInvites` returns invitations the caller cannot accept from the list.** `AcceptOrgInvite` takes only the token (`proto/business/auth_service.proto:813-824`), and `ListMyInvites` returns an `invite_id`, so an invitee who lost the link has no way to accept from their own account.
6. **Invitation management has no ceiling of its own.** `ListOrgInvites` and `RevokeOrgInvite` require only an authenticated member of the active organization (`org_invite.go:392-445`). Any member can read every pending invitation's address and metadata, and can revoke invitations for roles above their own ceiling, unless the project's endpoint ACL restricts it.
7. **`POST /auth/invites/accept` has no `public_limit`.** It is authenticated, but a valid account can enumerate token guesses without the `failed_only` budget that the other secret-consuming endpoints carry. With 256-bit-class random tokens this is low risk, but the rate limiting is inconsistent with the sibling endpoints.
8. **Expiry mixes clocks.** `expires_at` is computed from application time (`org_invite.go:343`), and every check uses database `NOW()`. Skew between them shortens or lengthens the TTL.

## Across features

Every interaction goes through one of these mechanisms:

| Mechanism | Where | Rule |
|---|---|---|
| **Seam variable** (a single `var` replaced in `init()`) | `auth_service.go`: `resolvePrincipal`, `issueSession`, `resolveSignInDevice`, `signInMfaGate`, `signInDisabledGate`, `signInBotGate`, `stampSignInDeviceTrust`, `stampDeviceTrust`, `signupResolveRoleIDs`, `signupAssignRoleIDs`, `signupInviteGate`, `signupClaimInvite`, `inviteVerifiedEmailGate`, `markEmailDerived`, `markEmailConfirmed`, `whoAmIEnrich`; `signup.go`: `signupCreateUser`, `signUpConfirmation`; `signup_confirm.go`: `pendingSignUpTenant`, `confirmCreateUser` | Exactly **one** feature may assign each seam. The default is the behaviour with that feature off. A seam is declared in a file staged for every feature combination that can assign or call it. |
| **Append-only list** | `scopeDecorators` (tenant_scope, org_membership, service_account), `grantNarrowers` (org_membership), `botUserFillers` / `botVisible` (service_account × tenant_scope) | Features add to the list and never replace it. A narrower may only **remove** grants, or add a wildcard it has re-checked itself (org ownership). |
| **Feature marks** | `devicesActive` (devices), `orgMembershipStaged` (org_membership) | Read by boot validation and by fail-closed checks. |
| **Field / RPC gates in DQL** | `?feature(x)` in SET / WHERE / projection lists | A column that belongs to feature X may appear only behind `?feature(X)`, or in an RPC gated on X. |
| **Combined files** | `go_files_combined` | `service_account_tenant.go` (service_account + tenant_scope), `service_account_org.go` (service_account + org_membership), `signup_confirm_tenant.go` (sign_up_confirmation + tenant_scope). |

---

### Feature interaction matrix

Abbreviations: **rb** rbac, **at** authenticate_turnkey, **su** sign_up_turnkey, **sc** sign_up_confirmation, **si** sign_in_turnkey, **ts** tenant_scope, **ap** api_token, **dv** devices, **oa** oauth, **tf** two_factor, **pr** password_reset, **ev** email_verification, **cl** cli_login, **om** org_membership, **oi** org_invite, **pc** password_change, **sa** service_account, **ua** user_admin.

Cell codes (row × column, upper triangle; the relation is symmetric unless the code says which side):
**R** one requires the other (plugin.yaml) · **X** conflicts_with · **C** combined go_files · **H** one overrides or extends the other's seam/hook · **T** shared table or column (one writes or deletes what the other reads) · **Q** shared query/RPC or shared helper · **O** ordering constraint inside one request · **G** one feature's gate applies on the other's path · **·** no interaction found.

|    | rb | at | su | sc | si | ts | ap | dv | oa | tf | pr | ev | cl | om | oi | pc | sa | ua |
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| **rb** | — | R Q | H O | H | · | Q | T Q | · | H | · | · | · | · | R T Q | R T | · | R T | T |
| **at** | | — | · | · | · | H | H | Q | · | · | · | · | G | R H | · | Q | R H | G |
| **su** | | | — | R H | · | R H | · | T | G | · | · | · | · | · | H G | · | · | · |
| **sc** | | | | — | · | C | · | T | G | · | · | H | · | · | G O | · | · | · |
| **si** | | | | | — | · | · | R H | · | R H O | · | · | · | · | · | · | H O | H O |
| **ts** | | | | | | — | · | · | X | · | · | · | · | H | · | · | C | · |
| **ap** | | | | | | | — | Q T | · | · | T | · | G | H O | · | T | R Q | T |
| **dv** | | | | | | | | — | H | H R* | T | · | T | · | · | T | · | T |
| **oa** | | | | | | | | | — | O | · | R T | · | · | G | · | G | G T |
| **tf** | | | | | | | | | | — | O | · | O | · | · | O | G | G |
| **pr** | | | | | | | | | | | — | · | · | · | · | T | G | G |
| **ev** | | | | | | | | | | | | — | · | · | H G | · | · | T |
| **cl** | | | | | | | | | | | | | — | · | · | · | G | G |
| **om** | | | | | | | | | | | | | | — | R T | · | C | T |
| **oi** | | | | | | | | | | | | | | | — | · | · | T |
| **pc** | | | | | | | | | | | | | | | | — | G | · |
| **sa** | | | | | | | | | | | | | | | | | — | R T |

`R*` (dv × tf): not a manifest `requires`. It is the `two_factor_scope=new_devices` requirement, enforced at boot.

Base tier: `sessionTokenExpiry`, `newBearerToken`, `refuseUnsignableAccount`, `callerUserID`, `callerSessionTokenID`, `signUpAllowlistGate`, `notFoundOK`, `intersectInt32` and `normalizeEmail` are always staged, and every feature uses them.

---

### Interaction invariants

Proof column: exact unit-test names in `auth/src/handlers`, or `none`. A unit test that runs against a fake store proves the handler's **sequencing** only. Where the property is enforced by SQL (a conditional update, a constraint, a transaction), that is listed under [How to prove it — live-only coverage](#how-to-prove-it--live-only-coverage).

#### Identity, roles and sign-up

| ID | Features | Mechanism | MUST hold | Proof |
|---|---|---|---|---|
| `interaction/rbac-sign_up-role-decision-before-tx` | rb su (also sc, oa) | H O: `signupResolveRoleIDs` reads `CountUsers` from committed state **before** the write transaction opens. `signupAssignRoleIDs` writes inside it. | The first account receives the `assign_first_user` roles and every later account receives `assign_default`. The count is never read inside the transaction, because the new user is not visible to pooled reads. A zero count only makes the sign-up a candidate: the bootstrap decision is settled inside the transaction by the `BootstrapClaim` write (`interaction/rbac-sign_up-first-user-race`). All three account-creating doors (SignUp, ConfirmSignUp, OAuth create) use the same pair. | TestAssignSignupRoles_FirstUserGetsBootstrapRoles, TestAssignSignupRoles_LaterUserGetsDefaultRoles |
| `interaction/rbac-sign_up-first-user-race` | rb su sc oa | Q: `CountUsers == 0` is not serialised. | Two sign-ups that run concurrently on an empty table MUST NOT both receive bootstrap roles. The first_user set goes only to the sign-up that writes the `BootstrapClaim` row (constant key, `UPSERT … DO NOTHING`) in its transaction; a taken claim is never reopened. | TestAssignSignupRoles_ConcurrentFirstSignUpsGetOneBootstrapAdmin, TestAssignSignupRoles_ATakenClaimIsNotReopened (**unit (mock) only**: a live test runs concurrent first sign-ups and asserts one administrator) |
| `interaction/rbac-tenant_scope-first-user-is-global` | rb ts | Q: `CountUsers` is realm-wide, not per tenant. | Only the first account in the whole deployment gets bootstrap roles. The first account of each later tenant gets default roles. | none |
| `interaction/sign_up-sign_up_confirmation-seam` | su sc | H: `signUpConfirmation` diverts SignUp after the allowlist and invite gates. | With sc on, SignUp creates no User and issues no token. It answers `confirmation_required` and `pending_id`. The allowlist and invite gates run for both paths. | TestSignUpConfirmation_SignUpParksAndConfirmCreates, TestSignUpAllowlist_GatesBothSteps |
| `interaction/sign_up-tenant_scope-create-seam` | su ts | H: `signupCreateUser` is replaced by `createUserWithResolvedTenant`. | Under ts, every self-service account is created with the tenant resolved from `tenant_slug` or the forwarded Host (never from a client-sent tenant id). A request with no resolvable tenant is refused with `TENANT_UNKNOWN` and nothing is written. | TestResolveSignupTenant_ByForwardedHost |
| `interaction/sign_up_confirmation-tenant_scope-pending-carries-tenant` | sc ts | C: `signup_confirm_tenant.go` stamps `PendingSignUp.tenant_id` at SignUp and creates the User in that tenant at ConfirmSignUp. | The tenant is decided when the code is requested and is not re-resolved at confirmation. | none |
| `interaction/tenant_scope-email-global` | ts su sc | T: `User.email` is unique across the table, not per tenant. | One address can hold at most one account in the deployment, whatever its tenant. A second registration in another tenant answers `EMAIL_TAKEN`, or `AlreadyExists` at confirmation. | none |
| `interaction/tenant_scope-oauth-conflict` | ts oa | X | The activation is refused at codegen. Reason: OAuth creates accounts through `CreateUser` with no tenant, and has no request-derived tenant to resolve. Under ts, `User.tenant_id` is NOT NULL, so an OAuth sign-up would fail at runtime with a constraint violation. | codegen (manifest) |
| `interaction/tenant_scope-org_membership-both-scopes` | ts om | H: both append a scope decorator. | Both `scopes[tenant_id]` and `scopes[org_id]` may be stamped. Neither decorator reads the other's scope, and nothing prevents a project from activating both. | none |
| `interaction/sign_up-org_invite-invite-gate` | su oi (also oa) | H G: `signupInviteGate` = `requirePendingInvite`, read at call time from `invite_only`. | With `invite_only=true` (the default), SignUp **and** the OAuth create branch refuse an address that holds no pending, unexpired invitation and presents no matching invite token. The refusal is `PermissionDenied`. It does not say whether an invitation expired or an account exists. Without oi the gate is permissive and `invite_only` has no effect. | TestInviteGate_RefusesAnUninvitedAddress, TestInviteGate_AdmitsAnInvitedAddress, TestInviteGate_OffAdmitsEveryone, TestInviteGate_RefusalIsOpaque, TestSignupInviteGate_OverrideIsInstalled, TestOAuthCreate_ConsultsTheInviteGate, TestSignupInviteGate_ABoundTokenDoesNotAdmitAnotherAddress |
| `interaction/sign_up-org_invite-open-link-claim` | su oi | H: `signupClaimInvite` binds an open invitation to the registering address **inside** the sign-up transaction. | An open link is spent by exactly one registration. A failed registration leaves the link open. The loser of a race keeps its own invitation. | TestClaimOpenInvite_TheFirstRegistrationSpendsTheLink, TestClaimOpenInvite_AnUncommittedBindIsTheClaimantsOwn, TestClaimOpenInvite_TheLoserOfARaceKeepsItsOwnInvitation, TestClaimOpenInvite_WithoutInviteOnlyNothingIsRefused |
| `interaction/sign_up_confirmation-org_invite-gate-timing` | sc oi | G O: the invite gate and the open-link bind run in `startSignUpConfirmation`. ConfirmSignUp re-checks only the allowlist. | An invitation revoked or expired between SignUp and ConfirmSignUp does **not** stop the account from being created. An open link is spent by a pending registration even if it is never confirmed. A specification that wants the gate at confirmation must say so; today it is request-time only. | none |
| `interaction/sign_up_confirmation-email_verification-self-confirmed` | sc ev | H: `markEmailConfirmed` → `MarkEmailVerified` inside the confirmation transaction. | An account created by ConfirmSignUp has `email_verified_at` set and `email_proof = SELF_CONFIRMED`. Without ev the call is a no-op. | none (no test reaches `confirmSignUpTx` with ev staged) |
| `interaction/sign_up_confirmation-oauth-bypass` | sc oa | G | The OAuth create branch does not pass through confirmation. It runs the allowlist and invite gates, and marks the address confirmed only if the provider asserts `email_verified=true`. | TestOAuthCallback_AProviderVerifiedAddressIsRecorded |
| `interaction/sign_up-devices-undeviced` | su sc dv | T: SignUp and ConfirmSignUp call `IssueToken` directly, not `issueSession`. | Sessions from registration carry no `device_id` and mint no device-trust token. `RevokeDevice` cannot end them; `RevokeOtherDevices` and `RevokeAllDevices` can, through the undeviced sweep. | TestRevokeDevices_SweepSessionsNoDeviceHolds |

#### Sign-in gates and the second factor

| ID | Features | Mechanism | MUST hold | Proof |
|---|---|---|---|---|
| `interaction/sign_in-user_admin-disabled-after-password` | si ua | H O: `signInDisabledGate` runs after the password check. | A disabled account is refused with the same opaque `INVALID_CREDENTIALS` as a wrong password. The check runs only after the password verified. `GetUserByEmail` projects `disabled_at`. | TestSignIn_RejectsDisabledAccount, TestSignInDisabledGate_SeamRejectsDisabledAllowsActive, TestSignIn_TheFourRefusalsAreIndistinguishable, TestEveryUserProjectionFillsTheFieldsItsGatesRead |
| `interaction/sign_in-service_account-bot-gate` | si sa | H O: `signInBotGate` runs after the password check, before the disabled gate. | A BOT account never gets a session from SignIn, even if a password hash has been written to it. The refusal is indistinguishable from a wrong password. | TestSignInBotGate, TestSignInBotGate_ReasonStaysInternal, TestSignIn_RefusesAMachineAccountThatHasAPassword, TestBotPasswordSentinel_IsNonEmptyAndCannotVerify |
| `interaction/user_admin-every-session-door-rechecks` | ua sa × tf oa cl | G: `refuseUnsignableAccount` re-reads the account before VerifyMfa, OAuthExchange and CliToken issue a session (and before OAuthCallback mints a login code). | No path that mints a session for an account decided earlier (a challenge, a linked identity, an authorization code) may mint one for an account that is disabled or BOT at mint time. | TestVerifyMfa_ADisabledAccountGetsNoSession (VerifyMfa only; OAuthCallback, OAuthExchange and CliToken: none) |
| `interaction/user_admin-disable-purges-every-token-class` | ua ap dv sa | T: `DisableUsers` sets `disabled_at` and deletes every `UserToken` of the ids (sessions, API, bot, device-bound) in one unit of work. | Authenticate does not read `disabled_at`. Revocation is the only enforcement on a live bearer, so after DisableUsers commits **no** token of that account may resolve, and no later mint may produce one. | none |
| `interaction/user_admin-service_account-disabled-bot-token` | ua sa | G | IssueBotToken MUST refuse a disabled machine account, and Authenticate MUST refuse a token of one. | `TestIssueBotToken_RefusesADisabledBot`, `TestResolvePrincipal_ADisabledAccountIsRefused` |
| `interaction/user_admin-disable-vs-inflight-mint` | ua × si ap cl | T | A sign-in or token mint that read the account before DisableUsers committed, and writes its token afterwards, leaves a live token for a disabled account. The same unguarded window exists for CreateApiToken from a token resolved before the disable. | none (live only, gap) |
| `interaction/sign_in-two_factor-gate` | si tf | H O: `signInMfaGate` runs after the password and account gates, and after device resolution. | When challenged, SignIn returns `mfa_required` and `challenge_id` and issues **no** token. Only VerifyMfa issues the session, through the same `issueSession` seam. If the enrolment status cannot be read, SignIn refuses rather than skipping the challenge. | TestMfaGate_AllLogins_NoTotp_GeneratesCode, TestMfaGate_TotpEnrolled_NoCode, TestMfaGate_ReadFailure_RefusesRatherThanSkipTheChallenge, TestEnrollConfirmVerify_TotpRoundTrip |
| `interaction/two_factor-devices-new_devices-scope` | tf dv | H R*: `resolveSignInDevice` returns `trusted` only for a device presenting the server-issued `X-Device-Trust` token that matches the stored hash. The base default is "trusted". | `two_factor_scope=new_devices` without `devices` fails at boot. With both features on, a device is trusted only by the replayed trust token; a client-chosen `X-Device-Id`, or a non-null `trusted_at` without the token, is not enough. | TestValidateConfig_NewDevicesRequiresDevices, TestMfaGate_NewDevices_SkipsTrusted, TestMfaGate_NewDevices_ChallengesUntrusted, TestResolveSignInDevice_TrustedAtButNoToken_NotTrusted, TestResolveSignInDevice_WrongTrustToken_NotTrusted, TestResolveSignInDevice_ValidTrustToken_Trusted |
| `interaction/devices-issue-session-binds-and-trusts` | dv si tf oa | H: `issueSession` = `issueSessionWithDevice` binds `device_id` and rotates the device-trust token on **every** session it mints. | Every session minted through the seam (SignIn, VerifyMfa, OAuthExchange) is device-bound and returns a fresh trust token. Trust is per device and per most recent session. | TestIssueSessionWithDevice_IssuesMintsAndTrusts, TestSignIn_DevicesSeams_WiredViaInit |
| `interaction/oauth-two_factor-bypass` | oa tf | O: OAuthExchange calls `issueSession` without `signInMfaGate`. | An OAuth sign-in is **not** challenged for the plugin's second factor; the identity provider is treated as the second factor. This is documented behaviour, and a project that needs both must layer its own policy. | none |
| `interaction/oauth-devices-two_factor-trust-laundering` | oa dv tf | H: OAuthExchange issues its session through `issueSessionWithDevice` with trust off. | Under `new_devices`, a device MUST become trusted only by a sign-in that passed the plugin's second factor or was not asked for one. An OAuth sign-in binds its session to the device and does not trust it. | TestOAuthExchange_DoesNotTrustTheDevice, TestIssueSessionWithDevice_BindsWithoutTrustingWhenNotAllowed |
| `interaction/two_factor-password_reset-factor-survives` | tf pr | O: ResetPassword sets the hash and revokes tokens. It issues no session and does not touch `UserTotpSecret`, recovery codes or challenges. | Holding the mailbox never bypasses the second factor: the next sign-in after a reset is challenged as before. A challenge opened before the reset stays redeemable until its TTL runs out. | none |
| `interaction/two_factor-password_change-no-step-up` | tf pc | O | ChangePassword requires the current password only, not a second-factor step-up. A hijacked session that knows the password can rotate it and end every other session. | none |
| `interaction/two_factor-cli_login-inherits` | tf cl | O | CliToken never runs the second factor. It may mint a session only from a code that CliAuthorize created for an already-authenticated principal, so the second factor is inherited from that session. See `interaction/api_token-cli_login-realm-escalation` for the exception. | none |

#### Tokens, realms and organizations

| ID | Features | Mechanism | MUST hold | Proof |
|---|---|---|---|---|
| `interaction/api_token-authenticate-realm-resolver` | ap at rb | H: `resolvePrincipal` = `resolvePrincipalRealmAware`. | A SESSION token counts only session-realm roles and an API token counts only API-realm roles. An API token's non-empty permission subset intersects every role, a wildcard included. An empty subset means no narrowing. An API token carries no `session_token_id`. | TestResolvePrincipalRealmAware_Session_NoSubsetLookup, TestResolvePrincipalRealmAware_API_Subset_Intersects, TestResolvePrincipalRealmAware_API_Wildcard_NarrowedBySubset, TestResolvePrincipalRealmAware_API_EmptySubset_NoNarrowing, TestResolvePrincipalRealmAware_ApiTokenHasNoSessionID |
| `interaction/api_token-org_membership-compose-on-roles` | ap om | H O: the realm resolver runs first, then `narrowGrantsToActiveOrg` keeps a grant only if its **role** is eligible in the active org (or realm-wide when no org is active). Permissions are flattened last. | A permission survives only when a **single** role grants it and that role passes both axes. A wildcard role must pass the org axis. Org **ownership** widens to all permissions for a SESSION token only, never for an API token. A failed narrowing query refuses authentication. | TestNarrowGrants_ActiveOrg, TestNarrowGrants_APermissionTwoDifferentRolesGrantDoesNotSurvive, TestNarrowGrants_WildcardRoleMustPassTheOrgAxis, TestNarrowGrants_OwnershipWidensASession, TestNarrowGrants_OwnershipDoesNotWidenAnApiToken, TestNarrowGrants_QueryErrorFailsClosed, TestNarrowGrants_NoActiveOrg |
| `interaction/org_membership-authenticate-active-org` | om at | H: `resolveOrgScope` decorator + `whoAmIEnrich`. | `scopes[org_id]` is stamped only for an org the caller belongs to or owns, selected by `W17-Org` (header or path); otherwise it is inferred only when the caller has exactly one org. A slug the caller does not belong to is refused with `ORG_NOT_MEMBER`. A path org and a header org that disagree are refused (`ORG_MISMATCH`). | TestResolveOrgScope, TestResolveOrgScope_NonMemberNonOwnerStillRefused, TestResolveOrgScope_SoleOrgInference, TestResolveOrgScope_MultipleOrgsStayAmbiguous, TestRefuseOtherOrg, TestOrgNotMember_SaysWhatIsWrong, TestWhoAmI_CarriesOrgsAndTheActiveOne |
| `interaction/api_token-cli_login-realm-escalation` | ap cl | G: CliToken mints a **SESSION** token; CliAuthorize requires a session caller (`requireSessionCaller`) and binds its expiry. | An API token (API realm, possibly narrowed by a subset) MUST NOT be exchangeable for a session token, which would carry the user's full session-realm roles. Since rc.25 CliAuthorize and CreateApiToken refuse a non-session bearer (`SESSION_REQUIRED`), and the CLI session cannot outlive the session that approved it. | TestCliAuthorize_AnAPITokenCallerIsRefused, TestCreateApiToken_AnAPITokenCallerIsRefused, TestCliToken_AChainOfLoginsCannotExtendTheFirstSession |
| `interaction/api_token-devices-revocation-scope` | ap dv | Q T: `DeleteUndevicedSessions` filters `?feature(api_token) token_type = 1`. | RevokeDevice, RevokeOtherDevices and RevokeAllDevices end sessions only. API tokens survive. | TestRevokeAllDevices_PerDeviceSparesApiTokens, TestRevokeOtherDevices_KeepsCurrent, TestRevokeDevices_SweepSessionsNoDeviceHolds |
| `interaction/api_token-logout` | ap at | Q | Logout from an API-token bearer is refused with `FailedPrecondition`; it is not reported as success. RevokeApiToken is the operation for API tokens. | TestLogout_NoSessionToken_Refused, TestLogout_RevokesCurrentSession, TestLogout_AlreadyRevoked_Idempotent |
| `interaction/api_token-password_change-sessions-only` | ap pc at | T: `DeleteOtherSessionTokens` deletes `token_type = SESSION` rows other than the caller's `session_token_id`, in the same transaction as the conditional password update. | ChangePassword ends every other session and keeps the calling session and all API tokens. If the sign-out fails, the password is not changed. | TestChangePassword_EndsEveryOtherSession, TestChangePassword_AFailedSignOutFailsTheChange |
| `interaction/password_change-without-api_token-build` | pc ap | T: the `DeleteOtherSessionTokens` DQL names `token_type`, a column that exists only with ap. | An activation with `password_change` and without `api_token` must build. The session-realm filter is gated `?feature(api_token)`; `make check-stage` fails a statement that names another feature's column ungated. | TestChangePassword_TheSweepSparesAPITokensOnlyWhereTheyExist |
| `interaction/api_token-password_reset-all-tokens` | ap pr | T: `DeleteUserSessionsForReset` deletes every `UserToken` of the user. | A completed reset revokes sessions **and** API tokens. Sweep failure is reported (`sessions_revoked=false`), not hidden. | TestResetPassword_ValidToken_UpdatesAndRevokes, TestResetPassword_ReportsWhenTheSessionSweepDidNotRun, TestResetPassword_ReportsASweepThatSucceeded |
| `interaction/password_reset-sweep-outside-tx` | pr ap dv | O | The password write and the token sweep are **not** one unit of work: the sweep runs after commit, so a reset can succeed while an attacker's sessions survive. ChangePassword puts both in one transaction; ResetPassword should do the same. | TestResetPassword_ReportsWhenTheSessionSweepDidNotRun (documents the split) |
| `interaction/credential-change-device-trust` | pr pc ua × dv | Q: `UpdateUserPasswordIfUnchanged` (pc) and `DisableUsers` (ua) carry `?feature(devices) device_trust_revoked_at = NOW()`; `resolveSignInDevice` and `ListDevices` compare it with `Device.trusted_at`. | A password change or a disable ends the trust of every device of the account in its own statement; under `new_devices` each of them, the changing caller's included, passes the second factor again. A reset keeps trust by design: the reset link proved the mailbox, which is treated as the second factor. RevokeDevice/Other/All still end trust per device. | TestChangePassword_RevokesDeviceTrustInTheSameStatement, TestDisableUsers_RevokesDeviceTrustInTheSameStatement, TestResolveSignInDevice_TrustRevokedByACredentialChange_NotTrusted, TestSignIn_DoesNotRenewRevokedDeviceTrust, TestListDevices_TrustRevokedByACredentialChange_NotShownTrusted |
| `interaction/service_account-api_token-realm` | sa ap rb | R Q | A machine account holds only API-realm roles (CreateBot refuses a session-realm role). Its tokens go through `issueApiTokenTx` and `apiTokenExpiry`, the same paths as a person's API token. | TestCreateBot_RefusesARoleFromTheSessionRealm, TestCreateBot_AcceptsAnApiRealmRoleAndGrantsIt, TestIssueBotToken_MintsForABot, TestIssueBotToken_RefusesAPerson |
| `interaction/role-ceiling-shared` | om oi sa rb at | Q: `role_ceiling.go` reads the caller's resolved permissions from the AuthResp envelope and the role catalogue. | Granting a role (invite, membership role change, membership removal, bot creation, bot token) requires the caller to hold every permission the role carries. With no envelope, the request is refused. An invitation snapshots the role, and acceptance is refused if the role has widened since. | TestRoleWithinCeiling, TestInviteToOrg_RefusesARoleAboveTheInviter, TestCreateBot_RefusesARoleAboveTheOperator, TestIssueBotToken_RefusesABotAboveTheOperator, TestUpdateOrgMembershipRole_RefusesARoleAboveTheCaller, TestMembership_TheMemberAboveTheCallerIsNotTheirsToChange, TestCheckMayGrantRole_NoEnvelopeFailsClosed, TestAcceptOrgInvite_RefusesARoleWidenedSinceTheInvitation |
| `interaction/org_invite-org_membership-rbac-accept-writes-both` | oi om rb | R T: AcceptOrgInvite writes OrgMembership and an org-scoped UserRole in one transaction. | An accepted invitation always produces both rows or neither. Only org-scoped roles may be invited. Removing a membership revokes the member's UserRoles in that org in the same unit of work. | TestRoleIDByName_RefusesARealmRole, TestAcceptOrgInvite_BoundRecordsDerivedAndOpenDoesNot (rollback on a real store: none) |
| `interaction/service_account-org_membership-scoping` | sa om | C: `service_account_org.go` installs `botOrgs`. | With organizations, a bot is created as a member of the operator's active org with its role scoped there. Bots are listed and minted for only inside that org. A build that has org_membership but lacks the combined file refuses rather than serving every organization's bots. | TestCreateBot_JoinsTheOrgAndScopesTheGrantToIt, TestCreateBot_RefusesWithNoActiveOrg, TestListBots_AsksOnlyForTheActiveOrganization, TestIssueBotToken_RefusesABotFromAnotherOrganization, TestMachineAccounts_OrgsWithoutTheirScopingRefuse |
| `interaction/service_account-tenant_scope-scoping` | sa ts | C: `service_account_tenant.go` appends `fillBotTenant` and `botInCallersTenant`. | A bot is created in the operator's tenant (NOT NULL `tenant_id`). An operator sees and mints only for bots in its own tenant. With no tenant in scope, creation is refused and the list is empty. | TestCreateBot_PutsTheBotIntoTheOperatorsTenant, TestCreateBot_RefusesWithNoTenantInScope, TestMachineAccounts_WithoutOrgs_StayInTheOperatorsTenant, TestMachineAccounts_NoTenantInScopeSeesNone |
| `interaction/service_account-authenticate-label` | sa at ua | H: `labelMachineAccount` decorator (uses `GetUser`, which is gated on user_admin; that gate is why sa requires ua). | A BOT principal carries `labels[account_kind]=bot`. A person carries no such label, so a rule of the form "refuse unless bot" fails closed. | none |
| `interaction/service_account-password-doors` | sa pr pc cl oa | G | A password written to a bot (through ResetPassword, which does not check `kind`) never opens SignIn, and CliToken, OAuthCallback and OAuthExchange refuse a bot through `refuseUnsignableAccount`. | TestSignIn_RefusesAMachineAccountThatHasAPassword (CliToken and OAuth: none) |
| `interaction/cli_login-devices-undeviced` | cl dv | T: CliToken calls `IssueToken`, not `issueSession`. | A CLI session has no `device_id`. It is ended by RevokeOtherDevices or RevokeAllDevices (undeviced sweep), not by RevokeDevice. | TestRevokeDevices_SweepSessionsNoDeviceHolds |

#### Address proof

| ID | Features | Mechanism | MUST hold | Proof |
|---|---|---|---|---|
| `interaction/oauth-email_verification-link-needs-both-proofs` | oa ev | R T | Auto-linking an incoming identity to an existing account requires **both** the provider's `email_verified=true` **and** the local account's `email_verified_at`. Without either, the callback is refused. This is why oa requires ev: the local half needs a column to record it in. | TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting, TestOAuthCallback_VerifiedEmail_LinksToExisting, TestOAuthAutoLink_RefusesAnUnverifiedLocalAccount, TestOAuthAutoLink_LinksIntoAVerifiedLocalAccount |
| `interaction/oauth-email_verification-create-records-provider-proof` | oa ev | T | An account created by OAuth is marked verified only if the provider asserted it. A provider that does not assert it creates an unverified account. | TestOAuthCallback_AProviderVerifiedAddressIsRecorded, TestOAuthCallback_UserinfoPath_CreatesUser |
| `interaction/org_invite-email_verification-proof-floor` | oi ev | H G: `inviteVerifiedEmailGate`, `markEmailDerived`; `email_proof_required` ∈ none / derived / full. | `full`: acceptance requires `email_verified_at`. `derived`: a bound invitation passes, and an open one requires a verified or previously derived address. The gate runs before the invitation is consumed, so a refused acceptance leaves it valid. A bound acceptance records `DERIVED_FROM_INVITE`; an open one records nothing. | TestEmailProofGate_FullRefusesAnUnprovenAccount, TestEmailProofGate_FullAllowsASelfConfirmedAccount, TestEmailProofGate_NoneChangesNothing, TestEmailProofGate_DerivedFloorSeparatesBoundFromOpen, TestEmailProofGate_AlreadyDerivedSatisfiesDerivedButNotFull, TestAcceptOrgInvite_ARefusedAcceptanceDoesNotConsumeTheInvitation, TestEmailProofGate_RefusalIsActionableAndLeaksNothing |
| `interaction/org_invite-email_proof-without-email_verification` | oi ev | H: without ev the gate seam is the permissive default. | `email_proof_required=derived` or `full` with `email_verification` off enforces **nothing**, and boot does not complain. It MUST fail at boot or be documented as inert. | none (gap) |
| `interaction/user_admin-email_verification-address-change` | ua ev oi | T: UpdateUser clears `?feature(email_verification) email_verified_at`. | Changing an account's address drops its verified state, so a verification of one address cannot be carried to another (an invite or OAuth link). **Partial:** `email_proof = DERIVED_FROM_INVITE` is **not** reset, so under the `derived` floor the stale derivation still admits open invitations for the new address. | none (gap for `email_proof`) |
| `interaction/user_admin-oauth-delete-leaves-identity` | ua oa (also om, rb, tf, dv) | T: DeleteUser purges tokens and the User row only. It emits `UserDeleted` for downstream cleanup. | Feature-owned rows (OAuthIdentity, UserRole, OrgMembership, Device, UserTotpSecret) outlive the account. A leftover OAuthIdentity resolves to a missing user, so that provider identity can never sign in or re-register (Unauthenticated) until the row is removed. | none |
| `interaction/password_reset-email_verification-no-proof` | pr ev | · | A completed reset does not mark the address verified, even though the reset link went to that mailbox. | none |

---

### Cross-cutting invariants

#### Bearer tokens

| ID | MUST hold | Proof |
|---|---|---|
| `auth/bearer-hash-only` | Every mint path (SignUp, ConfirmSignUp, `issueSession` used by SignIn, VerifyMfa and OAuthExchange, CliToken, CreateApiToken, IssueBotToken) creates a 64-char random token with `newBearerToken`, stores only `token_hash = sha256 hex`, and returns the plaintext once. No query returns the token, and admin views mark `token_hash` as SECRET. | TestNewBearerToken, TestIssueSessionWithDevice_IssuesMintsAndTrusts, TestCreateApiToken_StampsAPIRealm_AndSubset |
| `auth/bearer-legacy-upgrade` | A row created before hashing (plaintext `token`, NULL `token_hash`) is still found by its value. The first Authenticate that resolves it moves it to `token_hash` and clears `token` with a conditional update (`WHERE token = :legacy AND token_hash IS NULL`). The move is best-effort and never fails the request. `GetUserByToken` called from hand-written code does not upgrade. | TestUpgradeLegacyToken, TestResolvePrincipalSession_LegacyRowIsMovedToTheHash, TestResolvePrincipalRealmAware_LegacyRowIsMovedToTheHash |
| `auth/bearer-expiry-in-sql` | Every live token lookup filters `expires_at IS NULL OR expires_at > NOW()`; only the miss-path expiry probes (`GetExpiredToken*`) read expired rows, and only to answer `SESSION_EXPIRED`. A session expires at `session_token_ttl_seconds` (≤0 → 30 days). An API or bot token expires at the caller's future `expires_at`, or else at `api_token_default_ttl_hours` (0 = never; negative → 90 days). An `expires_at` in the past or invalid is refused. | TestSessionTokenExpiry_ConfiguredTTL, TestSessionTokenExpiry_DefaultWhenUnset, TestIssueSession_StampsExpiry, TestAPITokenExpiry, TestCreateApiToken_DefaultExpiryReachesTheTokenAndTheCaller |
| `auth/authenticate-opaque` | Every Authenticate failure (missing header, wrong scheme, empty, unknown or expired token, failed decorator or narrower) answers the same `Unauthenticated`. The only exception is an org-selection refusal (`ORG_NOT_MEMBER`, `ORG_MISMATCH`), which reveals only the caller's own membership. An outage is reported as `AUTH_UNAVAILABLE`, not as bad credentials. | TestUnauthenticated_WireStatusIsAlwaysOpaque, TestUnauthenticated_TwoCallsWithDifferentCauses_WireResponseIdentical, TestScopeDecorators_UnclassifiedFailureStaysOpaque, TestAuthnError_AnOutageIsNotReportedAsBadCredentials, TestAuthnError_NotFoundNeverBecomesOperational |
| `auth/authenticate-no-disabled-check` | Authenticate does not read `disabled_at` or `kind`. A token's validity depends only on the row existing and not being expired. Every path that disables or deletes an account must therefore delete its tokens. See `interaction/user_admin-*`. | none |

#### Per-address rate limit (REST preset, platform ≥ 1.11)

The gateway limits unauthenticated endpoints per client address (default 30 requests per minute, burst 10). The preset decides what spends a token:

| Endpoint | Mode | Why |
|---|---|---|
| SignIn, ConfirmSignUp, VerifyMfa, ResetPassword, VerifyEmail, CliToken, OAuthCallback, OAuthExchange | `failed_only` | Each checks a guessable secret: wrong guesses spend the limit, correct answers are free. |
| SignUp, RequestPasswordReset, OAuthAuthorizeURL | every request (default) | They do their work, such as sending mail or creating a row, when they **succeed**: a registration from a fresh address never fails, and RequestPasswordReset always answers success. |
| All bearer-authenticated endpoints | not limited by this mechanism | They are attributed to an identity. RequestEmailVerification (mail to the caller's own address) is unbounded per account. |

| ID | MUST hold | Proof |
|---|---|---|
| `auth/public-limit-modes` | The table above is what the preset declares. A project that exposes these RPCs on a transport other than the REST preset must provide its own limit. | none (live only) |
| `auth/in-plugin-guess-budgets` | Independently of the gateway: 5 attempts per MFA challenge (atomic counter); at most `mfa_max_challenges_per_window` challenges per user per window, counted under a row lock, and a new challenge supersedes pending ones; 5 attempts per pending sign-up; the step-up locks for 15 minutes after 5 wrong codes; a TOTP step is accepted once. | TestVerifyMfa_LocksOutAfterMaxAttempts, TestVerifyMfa_ConcurrentGuessesShareOneBudget, TestMfaIssuance_CapRefusesOnceTheWindowIsSpent, TestMfaIssuance_CapHoldsUnderConcurrency, TestMfaIssuance_NewChallengeRetiresThePendingOnes, TestSignUpConfirmation_WrongCodesAreRefusedAndExhaustTheRow, TestStepUp_FiveWrongCodesLockIt, TestTotp_ConcurrentReuseIsAcceptedOnce |
| `auth/cheap-gates-before-hash` | SignUp runs the allowlist and invite gates **before** any password hash, so a refused registration costs no hashing work. | TestSignUpAllowlist_GatesThePlainSignUp |

#### Anti-enumeration

| ID | MUST hold | Proof |
|---|---|---|
| `auth/sign-in-constant` | Unknown address, wrong password, disabled account and BOT account give the same status, code (`INVALID_CREDENTIALS`) and message. The unknown-address path runs a throwaway verify with the configured algorithm, so response time does not reveal whether the account exists. | TestSignIn_TheFourRefusalsAreIndistinguishable, TestUnauthenticatedSignIn_AllGatesRenderIdentically, TestSignIn_UserNotFound_RunsDummyVerify, TestSignIn_EveryRefusalReachesTheWireWithAMessage |
| `auth/sign-up-taken-address` | With `sign_up_confirmation`, SignUp answers a taken address exactly as it answers a new one. Only ConfirmSignUp, with the mailed code, answers `EMAIL_TAKEN`. **Without** it, SignUp answers `EMAIL_TAKEN` directly; this reveals existence, which is accepted behaviour for the plain flow. | TestSignUpConfirmation_ATakenAddressIsNotRevealedBySignUp, TestSignUp_ATakenAddressSaysSignInInstead, TestConfirmSignUp_ATakenAddressSaysSignInInstead |
| `auth/sign-up-gates-constant` | An allowlist refusal is identical whether or not the address has an account or an invitation. An invite-only refusal does not say whether an invitation expired or whether an account exists; it inherently reveals that the address has no pending invitation. | TestSignUpAllowlistGate, TestInviteGate_RefusalIsOpaque |
| `auth/reset-request-constant` | RequestPasswordReset answers success for every address. For an unknown address it writes nothing and emits nothing. **Timing is not equalised:** the known-address path does a write and emits an event. | TestRequestPasswordReset_UnknownEmail_NoOp, TestRequestPasswordReset_KnownEmail_StoresHashEmitsPlaintext |
| `auth/consume-paths-opaque` | A bad, expired or used reset, verification, invitation, CLI or MFA token always gets the same refusal for its flow. An outage is still reported as an outage. Bound-invitation mismatch, unknown token and consumed token cannot be told apart. | TestConsumePaths_ABadTokenIsAlwaysTheSameOpaqueRefusal, TestConsumePaths_AnOutageIsStillAnOutage, TestAcceptInvite_NotFoundBecomesTheOpaqueRefusal, TestAcceptOrgInvite_BoundInvitationRefusesAnotherAddressOpaquely, TestAcceptOrgInvite_AnUnknownTokenIsOpaque, TestCliToken_ClientAuthFailuresAreIndistinguishable, TestIssueBotToken_WithoutOrgs_RefusesAPersonAndAMissingAccountAlike |

#### Events

| ID | MUST hold | Proof |
|---|---|---|
| `auth/events-secret-carriers` | Exactly four events carry a plaintext secret, for a hand-written delivery channel: `PasswordResetRequested.token`, `EmailVerificationRequested.token`, `SignUpConfirmationRequested.code`, `MfaChallengeRequested.code` (event-code path only; blank when TOTP is used). The secret comes from the request and is never persisted; only its hash is stored. The `events` channel those topics are mapped to MUST NOT be bridged to any client-visible event surface. | TestRequestPasswordReset_KnownEmail_StoresHashEmitsPlaintext (others: none) |
| `auth/events-no-credentials` | No event carries a bearer token, a password or password hash, a TOTP seed, a recovery code, an invitation token, a client secret or a device-trust token. Token events carry ids only (`TokenIssued`, `TokenRevoked`, `UserTokenRevoked`). `OrgInviteCreated` carries no token: the invitation link is returned once to the inviter. | TestInviteToOrg_ReturnsThePlaintextOnceAndStoresTheHash (no static check over the event catalogue: gap) |
| `auth/events-after-commit` | An event is emitted only after its row commits. A rolled-back write (for example a failed pending sign-up transaction, a refused MFA issuance or a rolled-back acceptance) emits nothing, and therefore sends no mail. | none (live only) |
| `auth/events-only-real-accounts` | `PasswordResetRequested` is emitted only for an existing account, so a subscriber never mails a non-account address on the plugin's behalf. | TestRequestPasswordReset_UnknownEmail_NoOp |

#### Secrets at rest

| Secret | Stored as | ID / Proof |
|---|---|---|
| Account password, PendingSignUp password | PHC string from `password_hash_algo` (argon2id default; bcrypt, scrypt, pbkdf2). Verify reads the algorithm and parameters from the stored hash, so changing the knob affects new hashes only. There is no rehash on login (the rotate callback is nil). | `auth/password-hash-algo` — TestSignUpThenSignIn_TheSamePasswordWorks |
| Bearer token, password-reset and verification token, invitation token, CLI code, device-trust token | sha256 hex in a unique column | `auth/high-entropy-secrets-sha256` — TestNewBearerToken, TestInviteToOrg_ReturnsThePlaintextOnceAndStoresTheHash, TestAcceptOrgInvite_ConsumesTheHashNotThePlaintext, TestRequestEmailVerification_StoresHash |
| MFA event code (6 digits), sign-up code (8 base32 characters), AuthClient secret | Password hash (slow), because the space is small or the secret is long-lived | `auth/low-entropy-secrets-slow-hash` — TestRegisterClient_IssuesASecretAndStoresOnlyItsHash, TestVerifyMfa_EventCodePath |
| Recovery codes | SHA-256, single use | TestConfirmTotp_HandsOutTenRecoveryCodesStoredHashed, TestVerifyMfa_ARecoveryCodeSignsInOnce |
| TOTP seed | `CRYPTED_SECRET` (project field keyring). A legacy secretbox seed under `two_factor_secret_key` is moved to the new column the first time it is used. If the legacy key is unusable, the refusal is `TOTP_UNAVAILABLE`, not a sign-in. | `auth/totp-seed-crypted` — TestEnrollTotp_NeedsNoPluginKey, TestLegacySeed_VerifiesAndMoves, TestLegacySeed_KeyGone_Refuses |
| OAuth client secret | `CRYPTED_SECRET`. A legacy PASSWORD-typed `client_secret` is moved on first use and the legacy column is cleared. A provider with no secret is refused as misconfigured. | `auth/oauth-secret-crypted` — TestOAuthProvider_SecretFromEncryptedColumnOrMovedFromLegacy, TestOAuthCallback_EmptyClientSecret_Rejected |

#### Configuration that must fail at boot

| ID | Condition | Enforced | Proof |
|---|---|---|---|
| `auth/boot-password-algo` | `password_hash_algo` is not one of argon2id, bcrypt, scrypt, pbkdf2 (or pbkdf2-sha256) | `RegisterPlugin` | none |
| `auth/boot-new-devices` | `two_factor_scope=new_devices` without `devices` | `ValidateConfig` | TestValidateConfig_NewDevicesRequiresDevices |
| `auth/boot-api-ttl` | `api_token_default_ttl_hours` greater than 100 years (would overflow the duration type) | `ValidateConfig` | TestAPITokenExpiry_OutOfRange |
| `auth/boot-allowlist` | A `sign_up_allowlist` entry that is neither `name@domain.tld` nor `@domain.tld` | `ValidateConfig`. At runtime, a malformed list refuses everyone. | TestParseSignUpAllowlist, TestSignUpAllowlistGate |
| `auth/boot-feature-graph` | `requires` / `conflicts_with` violations, such as tenant_scope with oauth | codegen | — |
| **Not** boot-checked (gaps) | an unknown `two_factor_scope` value (treated as `all_logins`, the stricter setting); an unknown `email_proof_required` (treated as `full`, also stricter); `email_proof_required` ≠ none without `email_verification` (inert); `invite_only=true` without `org_invite` (inert); a malformed `two_factor_secret_key` (fails per user, at use); an empty `oauth_redirect_base` (the redirect URI is derived from the request Host) | — | none |

#### Transactions (one unit of work)

When `DistTx` is nil, as in a hand-built test handler, the calls fall back to sequential ones. A wired bundle always uses the transaction coordinator.

| Flow | Writes held together | Proof |
|---|---|---|
| SignUp | CreateUser (+tenant) · signup roles · open-invite bind · IssueToken | none (sequencing only) |
| SignUp under sc | open-invite bind · CreatePendingSignUp (+tenant) | none |
| ConfirmSignUp | ClaimPendingSignUp · CreateUser · roles · mark confirmed · delete the address's other pending rows · IssueToken | none |
| OAuth create | CreateUser · roles · mark confirmed. **CreateOAuthIdentity is outside this transaction.** | none |
| CreateApiToken / IssueBotToken | IssueApiToken · every AddTokenPermission. Without this, a partly written subset would be read as "no subset", which grants every API-realm permission. | TestCreateApiToken_NarrowingFails_RollsBackTheLiveToken, TestIssueBotToken_NarrowingFails_RollsBackTheLiveToken, TestServiceAccount_TheWritesThatMustNotSeparate |
| CreateBot | CreateBotUser (+tenant) · membership · role | TestCreateBot_GrantFails_RollsBackTheAccountAndMembership |
| AcceptOrgInvite | ConsumeOrgInviteByToken · role-snapshot check · AddOrgMembership · AssignRoleToUser · mark derived | none |
| ResetPassword | ConsumePasswordResetToken · UpdateUserPassword. **Token sweep after commit.** | TestConsumePaths_TheTokenAndItsWriteDoNotSeparate, TestResetPassword_FailureAfterConsume_RollsBack |
| VerifyEmail | consume · MarkEmailVerified | TestConsumePaths_TheTokenAndItsWriteDoNotSeparate |
| ChangePassword | UpdateUserPasswordIfUnchanged · DeleteOtherSessionTokens | none (sequencing only: TestChangePassword_AFailedSignOutFailsTheChange asserts the error, not a rollback) |
| MFA issuance | LockUserForIssuance · budget count · supersede pending · CreateMfaChallenge | TestMfaIssuance_SupersedeAndCreateAreOneSeam, TestMfaIssuance_AFailedSupersedeMintsNothing |
| EnrollTotp / ConfirmTotp / DisableTotp | replace seed / confirm + recovery codes / delete seed + codes | TestEnrollTotp_AFailedCreateDoesNotLeaveTheUserWithoutAFactor, TestEnrollTotp_BothWritesGoThroughOneSeam |
| DisableUsers / DeleteUser / membership update and removal | one multi-op statement set (`ops`) | none (live only) |

#### Performance

| ID | MUST hold | Proof |
|---|---|---|
| `auth/lookup-columns-indexed` | Every lookup used on a request path is served by a unique key or an index: `UserToken.token_hash` (and legacy `token`), `UserToken.user_id`, `UserToken.device_id`; `User.email`; `PasswordResetToken.token_hash`; `EmailVerificationToken.token_hash`; `CliAuthCode.code_hash`; `OrgInvite.token_hash` and `(org_id, email)`; `OAuthIdentity(provider_id, external_id)`; `Device(user_id, identifier)`; `UserRecoveryCode(user_id, code_hash)`; `PendingSignUp.email`; `MfaChallenge.user_id`; `OrgMembership(user_id, org_id)`; `Organization.slug`; `Tenant.domain`; `OAuthProvider.name`; `AuthClient(client_id, redirect_uri)`. | none (schema; live only) |
| `auth/authenticate-read-only` | Authenticate performs no write per request. The exceptions are the one-time legacy-token upgrade and, under `api_token`, the `last_used_at` write throttled to once a minute per token (`api_token/last-used-throttled`). A refused token costs one more read: the expiry probe after a miss (`base/expired-token-says-so`). It runs a fixed number of reads: token, then grants, then the API subset (ap); one per decorator (tenant; org slug, ownership or org list; machine label); one or two per narrower. | `TestAuthenticate_TouchesLastUsedAtThrottled`, `TestAuthenticate_LookupOutageIsNotProbedForExpiry` |
| `auth/no-expired-row-sweeper` | Expired SESSION tokens are deleted per user at that user's next session mint (`base/expired-sessions-swept-at-mint`); expired API/bot tokens and the expired session tokens of a user who never signs in again stay. Nothing else deletes expired `PasswordResetToken`, `EmailVerificationToken`, `MfaChallenge` or `CliAuthCode` rows. Expiry is enforced in the read predicate, but the tables grow without bound. Pending sign-ups are purged per address on the next SignUp, and lapsed invitations are cleared on re-invite. | TestInviteToOrg_ClearsALapsedInviteFirst |
| `auth/hash-cost-bounded` | The slow hash runs on: SignIn (always, including the dummy verify), SignUp (1, or 2 under sc), ConfirmSignUp (code verify), VerifyMfa (event code), ChangePassword (2), CliToken with a registered client, and RegisterClient. Every unauthenticated one is behind the per-address limit. | none |

---

### How to prove it — live-only coverage

A unit test against a fake store cannot prove the invariants below. An example project's end-to-end suite, run against a real database, the real gateway and the event bus, should cover them. The `fakeidp` sandbox covers OAuth.

1. **Conditional updates under concurrency** (fire N parallel requests and assert exactly one wins): ConsumePasswordResetToken, ConsumeEmailVerificationToken, ConsumeMfaChallenge, ConsumeCliAuthCode, ConsumeOrgInviteByToken, BindOpenOrgInvite, ClaimPendingSignUp, ClaimTotpStep, RecordMfaAttempt / RecordPendingSignUpAttempt / RecordStepUpAttempt (shared budget), UpdateUserPasswordIfUnchanged, and the LockUserForIssuance cap (`auth/in-plugin-guess-budgets`).
2. **Database constraints**: concurrent SignUp of one address → exactly one account, the rest `EMAIL_TAKEN`. Concurrent first-user sign-ups → **one** bootstrap administrator (`interaction/rbac-sign_up-first-user-race`). Duplicate `(provider_id, external_id)` on parallel OAuth callbacks.
3. **Transactions roll back on a real store**: inject a failure after the first write for SignUp, ConfirmSignUp, AcceptOrgInvite, CreateBot, CreateApiToken (subset), MFA issuance and ChangePassword; assert that no partial row exists and that no event was emitted.
4. **Revocation completeness**: after DisableUsers, every token class of the account (session, device-bound, CLI, API, bot) gets 401 on its next request. After ResetPassword, sessions and API tokens get 401. After ChangePassword, other sessions get 401 while the calling session and API tokens still work. IssueBotToken for a disabled bot must be refused (`interaction/user_admin-service_account-disabled-bot-token`).
5. **Expiry in SQL**: a token or code whose `expires_at` has passed is refused by Authenticate, VerifyMfa, ConfirmSignUp, ResetPassword, VerifyEmail, CliToken and AcceptOrgInvite.
6. **Gateway rate limit**: on one client address, with the limit on, `failed_only` endpoints allow unlimited correct answers and answer 429 after the burst of wrong ones. SignUp, RequestPasswordReset and OAuthAuthorizeURL answer 429 after the burst even when every request succeeds (`auth/public-limit-modes`).
7. **Events on the bus**: the four secret carriers arrive only for committed writes and only on the internal channel. No client-visible event stream ever shows them. No event payload contains a bearer token (scan every payload for the issued token string) (`auth/events-*`).
8. **Forwarded headers reach the handler**: Host (tenant resolution under ts), `X-Device-Id` / `X-Device-Trust` / `User-Agent` / `X-Forwarded-For` (devices), and `W17-Org` header or path (om). Each feature depends on the gateway propagating its header, and the handler-level tests inject it directly.
9. **Cross-feature flows**: the second factor under `new_devices` with a replayed trust token, then the same device after an OAuth sign-in (`interaction/oauth-devices-two_factor-trust-laundering`), and after a password change and after a disable and re-enable (`interaction/credential-change-device-trust`, which also proves the `?feature(devices)` fragments stage and run); an API token driving CliAuthorize → CliToken (`interaction/api_token-cli_login-realm-escalation`, must be refused) and a session approving a CLI login whose session then approves the next (`cli_login/no-lifetime-extension`, every link ends with the first session); an org-scoped API token whose permission is granted only by a realm-wide session role (must not survive); an OAuth link into an unverified and into a verified local account.
10. **Secrets at rest on a real row**: legacy-token upgrade (seed a plaintext `token`, authenticate, assert `token_hash` set and `token` NULL); a TOTP seed and an OAuth client secret round-trip through the field keyring and move from their legacy columns.
11. **Feature-combination builds**: each `go_files_combined` pair with and without its partner feature. A table, column or request field named across a feature boundary is caught statically by `check-stage`.
