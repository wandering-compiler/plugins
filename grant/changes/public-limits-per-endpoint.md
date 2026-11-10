### The public envelope is not rate-limited (requires w17 ≥ 1.18)

- `GetOrgEnvelope` declares `public_limit: none`: every invitation and
  co-brand sign-in page reads it, and a limit per address refused an office
  behind one address. The envelope is public by intent.
