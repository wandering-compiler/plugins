# auth plugin (v3 POC)

Authored Go business handlers + DQL primitives + proto schema for
email/password authentication and bearer tokens.

This is the **G3-POC** snapshot — manual rewrite of the v2 auth
plugin to the v3 layout (the plugin source lives here, at
`plugins/auth/`). Coexistence is intentional: w17 storage codegen
still uses the v2 location + emits the F3/G2-F templates today;
G3-D deletes those once the v3 staging pipeline (G3-B/C) lands.

Layout:

```
plugins/auth/
├── go.mod              ← module github.com/wandering-compiler/plugins/auth
├── plugin.yaml         ← manifest (go_module field is v3-new)
├── proto/              ← schema source (same content as v2)
│   ├── types/
│   ├── queries/
│   ├── mutations/
│   ├── services/
│   └── events/
├── pb/                 ← Go pb (POC: hand-written stubs; G3-F regenerates from proto)
└── handlers/           ← authored Go business handlers
    └── auth_service.go ← Authenticate + SignIn (formerly F3/G2-F template emit)
```

## POC scope

- Layout proves compileable in isolation (`go build ./...` green)
- Handler source matches the spec's reference shape
  (`*Handler` struct, SDK-injected deps, opaque
  Unauthenticated failure mode, anti-enumeration)
- pb/ contains hand-written stubs covering only the surface
  the POC handler imports — G3-F (`w17ctl plugin build`) will
  regenerate from proto with full coverage

## Out of scope for POC

- Real protoc-driven pb generation (G3-F)
- Staging + per-activation import rewriting (G3-B)
- Handler discovery + RegisterPlugin codegen (G3-C)
- Deleting v2 templates + old proto location (G3-D)
- SDK auditor (G3-G)

The v2 auth plugin keeps functioning unchanged until G3-D.

## What a consumer has to know

Behaviour that is deliberate, and easy to build against wrongly.

**Sessions and tokens**
- **Disabling an account ends its access.** `DisableUsers` (`user_admin`) deletes every token of the account, sessions and API tokens alike, in the same unit of work. Re-enabling gives nothing back: the person signs in again.
- **A password change signs the person out everywhere else.** `ChangePassword` keeps the session the change came from and deletes every other session of the account, atomically with the new password. API tokens are kept, because they are credentials minted on purpose (CI, scripts). Revoke one with `RevokeApiToken`.
- **A password reset revokes every token, API tokens included**, so CI tokens the person minted stop working. `ResetPasswordResp.sessions_revoked` reports whether the sweep ran.
- **A reset or a password change spends every other reset link of the account.** A link asked for earlier, still in a mailbox, cannot set the password again.
- **A reset keeps device trust.** Under `two_factor_scope=new_devices`, a device trusted before the reset is still trusted after it. The reset link arrived in the mailbox, and that mailbox is the second factor the reset already proved.
- **`two_factor_scope=all_logins` applies to password sign-ins.** An OAuth sign-in issues a session without a second factor; the provider is the factor.
- **An OAuth sign-in does not make the device trusted.** Its session is bound to the device, but it returns no `device_trust_token`, so under `two_factor_scope=new_devices` the next password sign-in from a device that was not trusted before still asks for the second factor. A device that was already trusted stays trusted: keep the token you hold, and overwrite it only with a non-empty one.

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
- **Towards the provider** the plugin sends its own PKCE challenge and an OIDC `nonce`. Without a `userinfo_url`, it accepts an `id_token` only if its `aud` names the client id, its `azp` (if present) is the client id, its `exp` is in the future, and its `nonce` matches.

**Invitations**
- **The plugin sends no mail.** `InviteToOrgResp.token` is the link's only copy, returned once to the inviter: the inviter is the delivery channel. `OrgInviteCreated` carries the address, not the link, so a mailer subscribed to it cannot send the invitation; it has to send the link the inviter hands it.
- **An open invitation's link is spent by the first registration through it.** It is bound to that address, and a second account cannot register with the same link (under `invite_only` it is refused). Acceptance by the bound account works as before.
- **Invitation `metadata` comes back as the same JSON value, re-serialised.** It is stored as jsonb, so key order and whitespace are the database's. Compare it parsed.

**CLI-login clients**
- **The client registry (`cli_login`) is one list for the whole deployment.** An `AuthClient` row carries no organization, and `RegisterClient`, `ListClients`, `SetClientEnabled` and `DeleteClient` check only that the caller is signed in. Grant them to an OPERATOR role only. A tenant role that holds them lists, disables and deletes every other tenant's registered clients. Loopback CLI login (a `w17ctl`-style client on `127.0.0.1`) needs no registration.

**Errors**
- **The sentence for a person is in `details[0].message`.** The envelope's top-level `message` is the generic sentence for the code: for `EMAIL_TAKEN` it reads "Another change reached this first. Please try again." A client must render the detail.

## Regenerating the committed `src/gen/pb`

The `src/gen/pb/*.pb.go` stubs exist only for this plugin's local
dev/test loop (`go test ./src/...`); the project codegen generates
its own per-activation pb at staging time and never uses them.
Regenerate them after editing any `proto/` file with:

```
w17ctl plugin gen-pb plugins/auth
```

It reads `go_module` from `plugin.yaml` and drives the same `bufrun`
pipeline as the project codegen — output is byte-stable across runs.
It needs a reachable CONSOLE: the vocabulary is resolved server-side,
the way every other compile is. (It used to say "from the w17ctl
binary's embedded copy"; that embed is gone.)
(This replaces the old hand-rolled `regen-pb.sh`.)
