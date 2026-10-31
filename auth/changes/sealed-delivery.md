### Mailed credentials travel sealed to the mailer's key (read first)

- **New setting `delivery_recipient`** — the age public key (`age1…`) of the
  service that mails credentials. `PasswordResetRequested`,
  `EmailVerificationRequested`, `SignUpConfirmationRequested`,
  `StepUpCodeRequested` and `MfaChallengeRequested` now carry their token or
  code **sealed** to it, in the new `sealed_token` / `sealed_code` field, and
  leave `token` / `code` empty. The event bus, its dead-letter queue and its
  backups hold ciphertext only: before, anyone who could read the bus could
  reset any password asked for in the last minutes, or pass a mailed second
  factor.
- **What to do:** make a pair with `age-keygen`, set the public key as
  `delivery_recipient`, give your mailer the identity, and open each sealed
  value with `secret.OpenSealed(identity, value)` (sdk/go/service/secret,
  SDK `go/v0.1.0-rc.51`) or `base64 -d | age -d -i key`.
- **The boot is refused** without a recipient when `password_reset`,
  `email_verification`, `sign_up_confirmation`, `two_factor` or
  `step_up_code` is on — except with `W17_ENV=dev`, where the credential
  still travels in clear in `token` / `code`. A local stack that does not set
  `W17_ENV=dev` must set it, or a recipient.
