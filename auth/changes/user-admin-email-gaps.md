### Admin address changes: normalized, and the proof goes with the old address

`UpdateAccount` (the admin Users page) and `CreateBot` store the address lower-cased and
trimmed, as sign-up does: a mixed-case address typed in the admin could never sign in.
An address change also resets `email_proof` (as it already reset `email_verified_at`), so
a proof derived from an invitation no longer carries over to an address nobody proved; the
erasure drops it too.

An existing account whose address was stored mixed-case keeps it; normalize it once with
`UPDATE <prefix>_user SET email = lower(email) WHERE email <> lower(email)` after checking
that no lower-case twin exists.
