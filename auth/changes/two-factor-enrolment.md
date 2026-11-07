### Enrolment at sign-in (two_factor_enrolment)

- **New feature `two_factor_enrolment`** (requires `two_factor`, off by default) adds the
  `two_factor_policy` value `enrol`, for the activation and, with `org_two_factor_policy`,
  per organization and kind. Under it every account is challenged, and one without a
  confirmed authenticator sets it up at its next sign-in instead of getting a code by
  message. A project with no SMS/e-mail channel can require a second factor without
  locking out the accounts that have none yet.
- The flow: `SignIn` answers `mfa_required` + `challenge_id` + `enrolment_required` (new
  `SignInResp` field) and sends no code — no `MfaChallengeRequested`;
  `AuthService.EnrollTotpAtSignIn` (`POST /auth/mfa/enrol`, unauthenticated like
  `VerifyMfa`, signed by the key that passed the password) answers the secret, the otpauth
  URI and the QR code; `VerifyMfa` with the authenticator's first code confirms it, answers
  its ten recovery codes (new `VerifyMfaResp.recovery_codes`) and issues the session,
  trusting the device. The challenge carries VerifyMfa's guarantees unchanged: the key
  binding, the TTL, the attempt budget, single use, the issuance cap. Every refusal of
  the enrolment is VerifyMfa's opaque one.
- `enrol` needs `two_factor_totp=true`: without it, or without the feature, the boot refuses
  `two_factor_policy=enrol` and an organization's policy refuses it (`TWO_FACTOR_POLICY_INVALID`).
- `MfaChallenge.enrol` is a new column of `two_factor` (default false): a migration adds it to
  every activation with `two_factor`. Where `two_factor_enrolment` is off, VerifyMfa refuses
  such a challenge.
- New storage RPC `CreateEnrolmentChallenge`; `GetMfaChallenge` reads `enrol`.
