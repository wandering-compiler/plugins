### Address changes spend the old address's links; a few refusals say what they are

- An admin address change (`UpdateAccount`) spends every live email-verification and
  password-reset link in the transaction that changes it: a link mailed to the old address
  could verify the new one, or let the old mailbox set the password. Saving the address the
  account already has writes nothing, so it no longer loses its verification.
- `Authenticate` matches the configured scheme case-insensitively (`bearer <token>` works),
  as it already did for `DPoP`.
- `ConfirmSignUp` and `VerifyMfa` answer a store outage as `Unavailable` (`AUTH_UNAVAILABLE`)
  instead of "wrong code"; they still refuse it.
- A password longer than the hash accepts (bcrypt: 72 bytes) is refused on its field with
  `PASSWORD_TOO_LONG` (InvalidArgument) by sign-up, confirmation, reset and change, instead
  of an internal error.
