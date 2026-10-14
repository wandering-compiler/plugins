# auth plugin

Authored Go business handlers + DQL primitives + proto schema for
email/password authentication and bearer tokens.

Layout:

```
auth/
├── plugin.yaml         ← manifest: env contract, features, presets
├── SPEC.md             ← behaviour reference
├── proto/              ← schema source
│   ├── types/
│   ├── queries/
│   ├── mutations/
│   ├── business/
│   └── events/
├── sandboxes/fakeidp/  ← dev-only fake OIDC provider for exercising `oauth`
└── src/                ← module github.com/wandering-compiler/plugins/auth
    ├── gen/            ← GENERATED (`make gen`), never committed (see below)
    ├── handlers/       ← authored Go business handlers
    └── lib/            ← helpers the handlers share
```

## What a consumer has to know

Behaviour that is deliberate, and easy to build against wrongly.

**Devices: every token is bound to a key**
- **A device is a key pair its client holds; the private key never leaves it.** Its id is the RFC 7638 thumbprint of the public key. The client signs a DPoP proof (RFC 9449) on every request and sends a bound token as `Authorization: DPoP <token>`; the gateway verifies the proof and hands the plugin only the thumbprint (`x-w17-dpop-jkt`, a gateway-owned key no client can set). The generated clients and the SDKs do the key handling; a hand-written client must do it too.
- **Every sign-in needs a proof.** `SignIn`, `SignUp` (when it issues a session), `ConfirmSignUp`, `VerifyMfa`, `OAuthExchange` and `CliToken` refuse a request without one (`UNAUTHENTICATED`, `DEVICE_PROOF_REQUIRED`) before anything else happens: no password is checked, and no single-use code or attempt is spent. The new session is bound to the (account, device) pair.
- **Authenticate checks the binding on every request** and answers it as `AuthResp.device_id`, which the gateway forwards to every service. A request without a proof (or with the token sent as `Bearer`, the `DPoP` scheme is case-insensitive) is refused with `DEVICE_PROOF_REQUIRED` before the token is even looked up. With a proof, only the holder of the bound key learns anything: `DEVICE_REVOKED` (the device was revoked) or `SESSION_EXPIRED`. Everything else — an unknown token, one bound to another key or to none, a revoked or expired one presented with another key — is the same plain `invalid credentials`, so a stolen token without its key tells its holder nothing. Both coded refusals carry an `ErrorDetail` and a `google.rpc.ErrorInfo` (domain `auth.w17`).
- **MCP clients keep their OAuth flow without a proof.** On the surface the MCP gateway marks `x-w17-surface: mcp`, a token minted by the MCP OAuth flow (`UserToken.mcp_only`) is accepted without a proof and carries no device; every other token there needs a proof as anywhere else, and an MCP token is refused on every other surface.
- **The second factor completes the sign-in of the same device.** `VerifyMfa` must be signed by the key the challenged `SignIn` was signed with; another key is refused (and spends one of the challenge's attempts).
- **Sessions minted before device binding are refused once** (as `invalid credentials`: they carry no binding). Their holders sign in again, one time, when this version is deployed. API tokens minted before it are refused the same way.
- **A revoked device is refused for good**, at sign-in and on every request (`DEVICE_REVOKED`). It is never revived: the client generates a new key and signs in as a new device (and passes the second factor like any new device). `RevokeDevice`, `RevokeOtherDevices` and `RevokeAllDevices` (`devices`) revoke; the Device row is kept with `revoked_at`.
- **Trust is per (account, device).** On a shared browser, one account's trust never carries over to another's. `two_factor_scope=new_devices` needs no extra feature.
- **API tokens cannot be issued in this version.** `CreateApiToken` and `IssueBotToken` refuse with `UNIMPLEMENTED` / `DEVICE_KEY_REQUIRED`: an API token's device is the program that will use it, and the request cannot carry that program's public key yet. The next version takes the key and binds the token to it.

**Sign-in history**
- **Every sign-in attempt is recorded, failures included.** `SignIn`, `SignUp` (when it issues a session), `ConfirmSignUp`, `VerifyMfa`, `OAuthExchange` and `CliToken` each append one `SignInEvent` row per call: when, the account it reached (empty when it reached none, as for an unknown address or a request without a proof), the address it named, the device (the Device row and the key thumbprint), the client address and user agent, the method and the outcome (`OK`, `WRONG_PASSWORD`, `UNKNOWN_ACCOUNT`, `MFA_REQUIRED`, `DEVICE_REVOKED`, `WRONG_CODE`, … — the full list is in SPEC.md under device identity). A registration parked by `sign_up_confirmation` signs nobody in and is not recorded; its confirmation is.
- **The row never changes the answer.** The caller gets exactly what it got before; a refusal whose row cannot be written is logged and still refused the same way. A successful sign-in writes its row in the transaction that issues the session, so a session never exists without its row (a failed write fails that sign-in).
- **Append-only, and erased with the account.** Nothing updates or deletes a row, except an erasure (`EraseUsers`), which replaces the address with the account's placeholder and blanks the client address and user agent on the account's rows and on the rows that named its address without reaching an account.
- **An attempt at an erased account** (a code or challenge issued before the erasure) is recorded the same way, pseudonymised. Addresses the person used before an admin changed theirs are not known to the erasure, so account-less attempts under those keep them.
- **`device_id` here is the Device row; `thumbprint` is the key**, the value the events and `AuthResp.device_id` carry.
- **Reading it.** A signed-in person reads their own (`GET /auth/sign-ins`, `AuthService.ListMySignInEvents`: the latest 100, newest first). An operator reads everyone's on the admin `SignIns` page (`user_admin`; paged; failed attempts at no account show the address that was typed).
- **The table grows with every attempt** and nothing prunes it. The mint endpoints are behind the gateway's per-address limit, which charges every refusal.
- **Token, sign-in and MFA events carry `device_id`**: the key thumbprint of the device that caused them, the same value as `AuthResp.device_id` (`TokenIssued`, `TokenRevoked`, `UserTokenRevoked` — the operator's device, `MfaChallengeRequested`, `MfaVerified`, `RecoveryCodeUsed`, `TotpEnrolled`, `TotpConfirmed`, `TotpDisabled`).

**Sessions and tokens**
- **An expired or revoked token says so, to the holder of its key.** A bearer that exists but has ended — past its `expires_at`, or revoked — is refused with `UNAUTHENTICATED` carrying two details: an `ErrorDetail` with code `SESSION_EXPIRED` and a translated sentence ("Your session expired on … Sign in again.", or for an API token "… Create a new token."), and a `google.rpc.ErrorInfo` with reason `SESSION_EXPIRED`, domain `auth.w17` and metadata `expires_at` (RFC 3339, UTC: when the token ended). A revoked token gets exactly the answer an expired one gets, dated when it was revoked; one whose device was revoked answers `DEVICE_REVOKED`. A client branches on either and sends the person to sign in. An unknown token keeps the plain `invalid credentials` with no detail.
- **Nothing in the auth tables is deleted.** Revoking a token (logout, `RevokeApiToken`, a password change or reset, a device revocation, a disable, the admin Sessions page, an erasure) sets `UserToken.revoked_at`, `revoked_by` (who did it; empty when nobody signed in did, as for a reset or a disable) and `revoke_reason`; the row stays. Expired tokens stay too — nothing sweeps them. The admin Sessions page and `ListApiTokens` list revoked tokens with `revoked_at` and `revoke_reason`, so a UI shows them as revoked; filter on `revoked_at` to hide them. The first revocation stands: revoking a revoked token changes nothing and is not an error.
- **The same holds for every other auth table.** Retiring a role (`deleted_at`), revoking a role grant (`revoked_at`, `revoked_by`), removing a permission from a role (`removed_at`, `removed_by`), deleting an organization (`deleted_at`), removing a member (`removed_at`, `removed_by`), withdrawing an invitation or releasing a lapsed one (`closed_at`, `closed_by`), confirming a registration (`claimed_at`; the address's other registrations `superseded_at`), disabling or replacing an authenticator (`revoked_at`, its seed cleared) and replacing recovery codes (`revoked_at`) all keep the row. Every read skips ended rows, so what a caller and every permission check sees is what the delete gave. A name, slug, grant, membership or enrolment that was ended can be taken again: the ended row's `ended_key` holds its own id, releasing the unique key, and the re-add is a new row. A removed permission is revived instead (one row per role and permission, because the role seed upserts on that pair), and every add and removal is logged in `RolePermissionChange`. Adding a permission a role already has is refused (`AlreadyExists`), and so is granting a deleted role or adding a permission to one (`NotFound`). A role declared by the project (a preset) can be deleted at runtime and then stays deleted across re-seeds; to bring it back, declare it under a new key.
- **`last_used_at` is written** (`api_token`) when a token authenticates, at most once a minute per token, in the application server's clock; `ListApiTokens` shows it. A failed write does not fail the request.
- **Disabling an account ends its access.** `DisableUsers` (`user_admin`) revokes every token of the account, sessions and API tokens alike, in the same unit of work. Re-enabling gives nothing back: the person signs in again.
- **Erasing an account (GDPR) is not a delete.** The admin Users page's `Erase` action (`AuthService.EraseUsers`, `user_admin`) keeps the row and replaces what is personal (in one transaction where the deployment has a transaction coordinator; without one, an erasure that fails part-way has already ended the account's access — that step runs first — and running it again completes it): the address becomes `erased-<id>@erased.invalid` (so the old address can sign up again, as a new account), the password becomes unusable, the account is disabled for good (`EnableUsers` leaves it disabled), every token and device is revoked, and the other features' personal data is blanked or spent — OAuth identities and login codes, the authenticator and recovery codes, reset and verification links, invitations sent to the address (their address is cleared; a pending one is ended), and registrations parked for the address (`sign_up_confirmation`: ended, the address replaced, the hashes made unusable). It emits `UserErased` (topic `auth.user.erased`), which replaces `UserDeleted`: a subscriber holding the person's data erases its own copy there. There is no delete for accounts any more. The `erased.invalid` domain is reserved for it: sign-up, OAuth account creation, the admin's address edit and machine accounts refuse it (`EMAIL_INVALID`).
- **A password change signs the person out everywhere else.** `ChangePassword` keeps the session the change came from and revokes every other session of the account, atomically with the new password. API tokens are kept, because they are credentials minted on purpose (CI, scripts). Revoke one with `RevokeApiToken`.
- **A password reset revokes every token, API tokens included**, so CI tokens the person minted stop working. `ResetPasswordResp.sessions_revoked` reports whether the sweep ran.
- **A reset or a password change spends every other reset link of the account.** A link asked for earlier, still in a mailbox, cannot set the password again.
- **A password change or a disable ends device trust.** Every device of the account, the one the change came from included, is untrusted in the same statement, so under `two_factor_scope=new_devices` each passes the second factor again on its next sign-in. The session the change came from keeps working. A re-enabled account's devices start untrusted too.
- **A reset keeps device trust.** Under `two_factor_scope=new_devices`, a device trusted before the reset is still trusted after it. The reset link arrived in the mailbox, and that mailbox is the second factor the reset already proved.
- **`two_factor_scope=all_logins` applies to password sign-ins.** An OAuth sign-in issues a session without this plugin's second factor, also for an account that has one: the provider already verified the identity, and its own second factor is the one that applies.
- **An OAuth sign-in does not make the device trusted.** Its session is bound to the device, but under `two_factor_scope=new_devices` the next password sign-in from that device still asks for the second factor.
- **A device becomes trusted only by passing the second factor.** A password sign-in that is not asked for one (the device is already trusted, or `two_factor` is off) renews existing trust and grants none.

**The first account**
- **The first account to register gets the `first_user` roles**, typically every permission. On a deployment with open sign-up that is whoever registers first, so create the first account (seed it, or register it yourself) before the sign-up endpoint is reachable.
- **Exactly one account is ever the bootstrap administrator.** The account that receives the `first_user` roles writes a `BootstrapClaim` row in its sign-up transaction. Concurrent first sign-ups get the default roles, and deleting every account later does not hand out the `first_user` roles again. Only a sign-up writes the claim: if the first account was seeded, or the deployment had users before rc.25, no claim exists, and deleting every account there makes the next sign-up the administrator again.

**OAuth sign-in**
- **The callback never carries a session.** A browser sign-in runs in three steps:
  1. The page makes a PKCE verifier (43–128 random URL-safe characters), keeps it in `sessionStorage`, and calls `GET /auth/oauth/{provider}/authorize?code_challenge=<BASE64URL(SHA256(verifier))>&redirect_after=/where`.
  2. The provider returns the browser to the callback, which answers with a redirect to `redirect_after#code=<login code>`.
  3. The page calls `POST /auth/oauth/exchange` with `{"code": …, "code_verifier": …}` and receives `{"user_id", "token"}`.
- **A login code is single-use and expires after two minutes.** Only the verifier of the challenge sent in step 1 redeems it, so a callback link opened in any other browser signs nobody in. A wrong verifier spends the code.
- **Make a fresh verifier for every sign-in, and remove it before the exchange.** The `state` carries only a sha256 of the challenge, but the challenge itself still passes through the authorize request. Someone who learned it could start their own sign-in with it and send the resulting callback link to the page that made it. That page would sign in to their account if it still held the matching verifier, for example from a sign-in it abandoned at the provider. So the landing page takes the verifier out of `sessionStorage` (read, then delete) before it calls the exchange, whether the exchange succeeds or not, and step 1 never reuses an old one.
- **`code_challenge` is required.** An authorize request without one, or with anything other than a 43-character S256 challenge, is refused. A sign-in left at the provider for more than ten minutes has to start again.
- **Registering through a provider carries an invitation in the exchange.** The callback creates no account. An identity with no account yet is kept on the login code, and `POST /auth/oauth/exchange` creates the account with `{"invite_token": …}` beside the code and verifier. The same rules apply as for `SignUp`: `invite_only`, a bound invitation's address, an open link spent by its first registration, and a coded refusal without a valid invitation. A refusal spends the code, so the page reads the invitation before step 1 and keeps it until the exchange. The token never travels in a URL or through the provider. An identity that already has an account ignores it; accepting an invitation is a separate step.
- **A provider can be configured from the project's own code.** `AuthMutation.UpsertOAuthProvider` creates or rewrites the provider named `name` (client id, secret, URLs, scopes, claim paths, enabled) and stores the secret encrypted with the project's field key (`W17_FIELD_KEYS`), clearing any plaintext legacy `client_secret`. Call it at service start with values from the deployment's secrets, so changing a provider's secret is a deploy and needs no admin. The same request twice leaves one row. A rewrite replaces every field, so pass them all: a blank one is written blank, and `enabled` left unset turns the provider off. The next call also undoes an edit made on the admin page. The name is unique across tenants and the row keeps the tenant it was created with, so the call is for the project's own code, never with a name a tenant chose.
- **Every OAuth refusal carries a code** in its `ErrorDetail`: `OAUTH_ACCOUNT_UNVERIFIED`, `OAUTH_EMAIL_UNVERIFIED`, `ACCOUNT_DISABLED`, or `OAUTH_FAILED` for the rest, so the page should start again. A refused registration answers with the sign-up gate's code (`SIGNUP_NOT_INVITED`, `INVITE_OTHER_ADDRESS`, `SIGNUP_CLOSED`), as `SignUp` does.
- **Towards the provider** the plugin sends its own PKCE challenge and an OIDC `nonce`. Without a `userinfo_url`, it accepts an `id_token` only if its `aud` names the client id, its `azp` (if present) is the client id, its `exp` is in the future, and its `nonce` matches.

**Invitations**
- **The plugin sends no mail.** `InviteToOrgResp.token` is the link's only copy, returned once to the inviter: the inviter is the delivery channel. `OrgInviteCreated` carries the address, not the link, so a mailer subscribed to it cannot send the invitation; it has to send the link the inviter hands it.
- **An open invitation's link is spent by the first registration through it.** It is bound to that address, and a second account cannot register with the same link (under `invite_only` it is refused). Acceptance by the bound account works as before.
- **Invitation `metadata` comes back as the same JSON value, re-serialised.** It is stored as jsonb, so key order and whitespace are the database's. Compare it parsed.

**CLI-login clients**
- **The client registry (`cli_login`) is one list for the whole deployment.** An `AuthClient` row carries no organization, and `RegisterClient`, `ListClients`, `SetClientEnabled` and `RevokeClient` check only that the caller is signed in. Grant them to an OPERATOR role only. A tenant role that holds them lists, disables and revokes every other tenant's registered clients.
- **Revoking a client is for good, and the row stays.** `RevokeClient` (`DELETE /auth/clients/{id}`, formerly `DeleteClient`) stamps `revoked_at`: the redirect is refused exactly as an unregistered one, `SetClientEnabled` cannot restore it, and `ListClients` still shows it. Its `(client_id, redirect_uri)` stays taken: registering it again is refused with `CLIENT_REVOKED`; register the callback under a new `client_id`.
- **A client that lost its secret keeps its `client_id`.** `RotateClientSecret` (`POST /auth/clients/{id}/rotate-secret`) gives a live registration a new secret, returned once; the old one stops working. A revoked registration cannot be rotated. Loopback CLI login (a `w17ctl`-style client on `127.0.0.1`) needs no registration.

**Errors**
- **The sentence for a person is in `details[0].message`.** The envelope's top-level `message` is the generic sentence for the code: for `EMAIL_TAKEN` it reads "Another change reached this first. Please try again." A client must render the detail.

## Generating `src/gen`

`src/gen` is generated and never committed: the pb, the contract
`RegisterPlugin` takes (`EnvConfig`, `ClientSet`, `HandlerRegistry`) and the
feature constants. After cloning, and after editing `plugin.yaml` or any
`proto/` file:

```
make gen PLUGIN=auth        # or: w17ctl plugin gen auth
```

It needs a reachable console (a w17ctl login): the vocabulary is resolved
server-side, the way every other compile is. A consumer's staging generates
the same package for each activation, so nothing here is published.
`EnvConfig` takes its fields from the `env:` block of `plugin.yaml` — each
entry's `description:` there is its documentation.
