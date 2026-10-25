### Sign in with Apple

Apple is an OIDC provider like the others, with two differences the plugin could not configure until now. With the address in the scopes, Apple comes back by an HTML form POST rather than a GET. Its client secret is a JWT signed with a key Apple issued, valid at most six months, rather than a string.

- `OAuthProvider` (and `UpsertOAuthProviderReq`) gains `response_mode`, `team_id` and `key_id`. `response_mode` is empty (the query string, as before) or `form_post`, which the authorize URL then asks for. With `team_id` and `key_id`, `secret` holds the `.p8` key Apple issued. Each token exchange then sends a client secret minted from it: an ES256 JWT, `iss` team_id, `sub` client_id, `aud` the token endpoint's origin, `kid` key_id, valid five minutes. There is nothing to rotate before Apple's six months run out, and the key itself is never sent. The state, PKCE and nonce stay keyed by the key, so a sign-in started before a mint finishes after it.
- The new feature `oauth_form_post` publishes `POST /auth/oauth/{provider}/callback` (`OAuthCallbackForm`). It is the same callback with the code and state in the form body, and it answers with the same 302 and login code. It accepts only a `form_post` provider. Without the feature, a `form_post` provider is refused at the authorize step, since nothing would receive its POST.
- Apple's `email_verified` arrives as the string `"true"`, which was already read as verified. A private-relay address (`…@privaterelay.appleid.com`) is an address like any other.
- A migration adds the three columns. A provider configured without them behaves as before.
- The dev-only `fakeidp` sandbox can play Apple for one client (`APPLE_CLIENT_ID`, with `APPLE_TEAM_ID`, `APPLE_KEY_ID` and `APPLE_PUBLIC_KEY_PEM`). It answers `response_mode=form_post` with the form page, accepts only a client secret that verifies with the key and names the team, the client and itself, and sends `email_verified` as Apple does. Every other client is served as before.

### Optional fields that rc.34 made required are optional again

rc.34 marked credentials `sensitive`, which gave a few plain fields a `(w17.field)`. A field with one and no `blank` is a field the generated code requires, so four optional fields became required:

- `OAuthExchangeReq.invite_token`: every `POST /auth/oauth/exchange` without an invitation, which is almost all of them, was refused 400 `REQUIRED_VIOLATION invite_token`.
- `CreateMfaChallengeReq.code` and `MfaChallengeRequested.code`: both are empty for a user with a confirmed authenticator under the built-in TOTP verifier, since no code is generated then. Storage refused the challenge, so such a user could not sign in.
- `EnrollTotpReq.code`: it is required only to re-enrol, so a first enrolment (`POST /auth/mfa/enroll` with no code) was refused 400.

All four are `blank` again. The other rc.34 fields are always set by their callers (the `legacy_token` lookups, `UpgradeTokenHashReq`, `CreateEmailVerificationTokenReq.token`) or are validated nowhere on their path: `ExchangeOAuthTokenReq` reaches the business method from the gateway's OAuth endpoint (SDK `lib/oauthas`), not through a REST route, and only REST routes and storage methods carry the generated validation.
