### SPEC: the device revocation rows name the statement as it is

No behaviour change. The devices rows said the "approved" op of `RevokeDeviceTokens`
ends session tokens only; it ends the sessions and the `oauth_server` MCP access
tokens the revoked device approved (`token_type IN (1, 3)`), never API tokens. The
Features table listed `two_factor_enrolment` twice.
