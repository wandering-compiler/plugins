### A copy of a processed webhook event costs nothing

- After the signature, the webhook reads its ledger first: an event already
  processed in full — the provider's own redelivery, or a signed request
  replayed inside the signature's 300 s window — is acknowledged
  (`handled=false`) before any store or provider work. A delivery whose
  processing failed recorded nothing and still runs in full.
