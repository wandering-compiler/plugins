### API tokens: listing and revoking take a session

`ListApiTokens` and `RevokeApiToken` refuse an API-token caller (`PERMISSION_DENIED`,
`SESSION_REQUIRED`), as `CreateApiToken` already did: a leaked token can no longer read
its holder's other tokens or revoke all of them. A script that managed tokens with a
token signs in instead. The README states that a person's API token acts in every
organization of its holder.
