### Each public endpoint has its own rate limit (read first)

- **Requires w17 ≥ 1.18.** Every endpoint that takes no credential now
  declares its `public_limit`, and the gateway gives each limited one its own
  bucket per client address instead of one shared bucket per address. A burst
  of registrations no longer eats the budget of a sign-in from the same
  office.
- Thresholds: the credential checks (SignIn, ConfirmSignUp, VerifyMfa,
  EnrollTotpAtSignIn, ResetPassword, VerifyEmail, CliToken, the OAuth callback
  and exchange) charge only failures, 30 a minute with a burst of 10. SignUp
  charges every request at 20 a minute (burst 20), RequestPasswordReset at 10
  (burst 10), OAuthAuthorizeURL at 60 (burst 30).
- **`GetHostOrg` is no longer limited** (`public_limit: none`): every page of a
  white-label site reads it, and an office behind one address was refused.
- An operator overrides one endpoint alone with
  `<PREFIX>_PUBLIC_RATELIMIT_AUTH_SERVICE_<METHOD>_PER_MINUTE` / `_BURST`; the
  generated `.env` files list the names.
