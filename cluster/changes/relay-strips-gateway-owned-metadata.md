### The relay no longer forwards gateway-owned metadata to workers (read first)

Behaviour change. The relay's callers port now removes every metadata key only a
gateway may write — `x-w17-*` (the identity envelope and scopes), `w17-label-*`,
`w17-tx-id`, `w17-conn-id` and their grpc-gateway spellings — before a call reaches
the worker, as it already removed the ticket. A ticket holder could send them and
the worker received them as if a gateway had stamped them. Every other header still
travels. A worker that read a principal from those keys gets none now; the caller's
remaining metadata is the caller's word, never a verified identity.
