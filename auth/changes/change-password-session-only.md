### ChangePassword takes a session only (read first)

Behaviour change. `ChangePassword` (`POST /auth/password/change`) now refuses an
API-token caller with `PermissionDenied` / `SESSION_REQUIRED` before the account is
read, the guess budget spent or anything written, as `ConfirmPassword`,
`CreateApiToken` and the API-token management methods already do. Before, a token
holder who also knew the password could replace it and sign the person out of every
session. A client that changed passwords through an API token must call it from a
signed-in session instead.
