### README: switching the authenticator off under `required` needs a code channel

No behaviour change. The README and the `two_factor_totp` description now say that
`two_factor_totp=false` with `two_factor_policy=required` makes a hand-written
`MfaChallengeRequested` subscriber the only way any account signs in, and that the
boot cannot check for one (two_factor gap 7).
