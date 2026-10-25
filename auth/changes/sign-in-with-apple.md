### Sign in with Apple

Apple is an OIDC provider like the others, with two differences the plugin could not configure until now. With the address in the scopes, Apple comes back by an HTML form POST rather than a GET. Its client secret is a JWT signed with a key Apple issued, valid at most six months, rather than a string.

- `OAuthProvider` (and `UpsertOAuthProviderReq`) gains `response_mode`, `team_id` and `key_id`. `response_mode` is empty (the query string, as before) or `form_post`, which the authorize URL then asks for. With `team_id` and `key_id`, `secret` holds the `.p8` key Apple issued. Each token exchange then sends a client secret minted from it: an ES256 JWT, `iss` team_id, `sub` client_id, `aud` the token endpoint's origin, `kid` key_id, valid five minutes. There is nothing to rotate before Apple's six months run out, and the key itself is never sent. The state, PKCE and nonce stay keyed by the key, so a sign-in started before a mint finishes after it.
- The new feature `oauth_form_post` publishes `POST /auth/oauth/{provider}/callback` (`OAuthCallbackForm`). It is the same callback with the code and state in the form body, and it answers with the same 302 and login code. It accepts only a `form_post` provider. Without the feature, a `form_post` provider is refused at the authorize step, since nothing would receive its POST.
- Apple's `email_verified` arrives as the string `"true"`, which was already read as verified. A private-relay address (`…@privaterelay.appleid.com`) is an address like any other.
- A migration adds the three columns. A provider configured without them behaves as before.
- The dev-only `fakeidp` sandbox can play Apple for one client (`APPLE_CLIENT_ID`, with `APPLE_TEAM_ID`, `APPLE_KEY_ID` and `APPLE_PUBLIC_KEY_PEM`). It answers `response_mode=form_post` with the form page, accepts only a client secret that verifies with the key and names the team, the client and itself, and sends `email_verified` as Apple does. Every other client is served as before.

### Fields rc.34 made required are as optional as they were in rc.33 (read first)

rc.34 marked credentials `sensitive`, which gave plain fields a `(w17.field)`. A field with one and no `blank` is a field the generated code requires, so rc.34 changed what a request must carry, not only what a log may show. Seen broken:

- `OAuthExchangeReq.invite_token`: every `POST /auth/oauth/exchange` without an invitation, which is almost all of them, was refused 400 `REQUIRED_VIOLATION invite_token`.
- `CreateMfaChallengeReq.code` and `MfaChallengeRequested.code`: empty for a user with a confirmed authenticator under the built-in TOTP verifier, so storage refused the challenge and such a user could not sign in.
- `EnrollTotpReq.code`: required only to re-enrol, so a first enrolment was refused 400.
- `GenerateRecoveryCodesReq.code` and `DisableTotpReq.code`: empty after a recent step-up (and for `DisableTotp` without an authenticator), so they were refused 400 before the handler could answer.

Every field rc.34 turned from a plain field into `(w17.field) = { sensitive: true }` now carries `blank: true` as well: what a request must carry is again exactly what it was in rc.33, and redaction is all `sensitive` changes. Fields that had a `(w17.field)` before rc.34 are unchanged. Upgrade from rc.34 if you use `oauth`, `two_factor` or `step_up`.
