### Added

- **`oauth_server`: an OAuth 2.1 authorization server** for MCP clients (the MCP authorization specification) and for w17ctl's browser login. Clients register themselves (RFC 7591) or name a Client ID Metadata Document; the user approves on the project's consent page (`GET /auth/oauth/authorizations/{request_id}`, `POST …/approve`, `POST …/deny`; with `org_membership` choosing the organization); the code (PKCE S256, single-use, 60 s) yields, for an MCP client, an `mcp_only` access token of the new type `TOKEN_TYPE_MCP` for one resource with a rotating refresh token (a reused one ends the grant), and for w17ctl a session bound to its DPoP key. `Authenticate` accepts an MCP token only on the MCP surface naming its resource (`x-w17-mcp-resource`). Users list and revoke their connected apps (`GET /auth/oauth/connected-apps`, `DELETE /auth/oauth/connected-apps/{grant_id}`); revoking a device, every token or the account reaches them too. The OAuth protocol endpoints are served by the generated REST gateway (SDK `lib/oauthas`). Off by default; requires `api_token` and `authenticate_turnkey`; a migration adds four tables and three `UserToken` columns.

### Changed

- `RevokeDeviceTokens` also ends the OAuth access tokens (type MCP) the revoked device approved, beside the CLI sessions it approved.
- `isLoopbackRedirect` moved to the always-compiled handlers file (cli_login and oauth_server both use it).
