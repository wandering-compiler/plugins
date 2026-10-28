### Second factor: three fail-open paths closed

- `VerifyMfa` refuses a challenge read without its creation time; it used to never expire.
- The code check, the account check and the consume are one transaction. A recovery code
  is no longer burned by a verification that loses the consume to a concurrent one, and a
  disabled account's correct code no longer consumes the challenge (or announces
  `MfaVerified`).
- An unknown `two_factor_scope` refuses the boot; a typo used to mean `all_logins`.
