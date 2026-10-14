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

**Sessions and tokens**
- **An expired token says so.** A bearer that exists but is past its `expires_at` is refused with `UNAUTHENTICATED` carrying two details: an `ErrorDetail` with code `SESSION_EXPIRED` and a translated sentence ("Your session expired on … Sign in again.", or for an API token "… Create a new token."), and a `google.rpc.ErrorInfo` with reason `SESSION_EXPIRED`, domain `auth.w17` and metadata `expires_at` (RFC 3339, UTC). A client branches on either and sends the person to sign in. An unknown or revoked token keeps the plain `invalid credentials` with no detail.
- **Expired session tokens are deleted at the person's next sign-in**, in the same transaction as the new session, without a `TokenRevoked` event (every lookup already refused them). API and bot tokens, never-expiring tokens and live sessions are not touched. Nothing sweeps the table on a schedule, so the expired sessions of someone who never signs in again stay until then.
- **`last_used_at` is written** (`api_token`) when a token authenticates, at most once a minute per token, in the application server's clock; `ListApiTokens` shows it. A failed write does not fail the request.
- **Disabling an account ends its access.** `DisableUsers` (`user_admin`) deletes every token of the account, sessions and API tokens alike, in the same unit of work. Re-enabling gives nothing back: the person signs in again.
- **A password change signs the person out everywhere else.** `ChangePassword` keeps the session the change came from and deletes every other session of the account, atomically with the new password. API tokens are kept, because they are credentials minted on purpose (CI, scripts). Revoke one with `RevokeApiToken`.
- **A password reset revokes every token, API tokens included**, so CI tokens the person minted stop working. `ResetPasswordResp.sessions_revoked` reports whether the sweep ran.
- **A reset or a password change spends every other reset link of the account.** A link asked for earlier, still in a mailbox, cannot set the password again.
- **A password change or a disable ends device trust.** With `devices`, every device of the account, the one the change came from included, is untrusted in the same statement, so under `two_factor_scope=new_devices` each passes the second factor again on its next sign-in. The session the change came from keeps working. A re-enabled account's devices start untrusted too.
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
- **The client registry (`cli_login`) is one list for the whole deployment.** An `AuthClient` row carries no organization, and `RegisterClient`, `ListClients`, `SetClientEnabled` and `DeleteClient` check only that the caller is signed in. Grant them to an OPERATOR role only. A tenant role that holds them lists, disables and deletes every other tenant's registered clients. Loopback CLI login (a `w17ctl`-style client on `127.0.0.1`) needs no registration.

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
