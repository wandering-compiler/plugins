### An OAuth sign-in reports a store outage instead of reading it as "no account"

The OAuth callback and exchange took any failed `GetOAuthIdentity` /
`GetUserByEmail` read as "no row", and went on to link the identity to the
address's account or to create one. Only NotFound means "no row" now; any other
failure answers `UNAVAILABLE` / `AUTH_UNAVAILABLE`.
