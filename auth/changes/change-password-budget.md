### A password change's current password is bounded and refused on its field

- `ChangePassword` counts its current password against the account's sign-in guess budget
  before checking it. Past the budget the request is refused with `PASSWORD_ATTEMPTS_SPENT`
  (ResourceExhausted), the right password included; a right password within it starts the
  budget over. A stolen session was an unbounded oracle for the password.
- A wrong current password is `PermissionDenied` with `PASSWORD_NOT_CONFIRMED` on
  `current_password`, as `ConfirmPassword` answers one. It was `Unauthenticated` (HTTP 401),
  which clients answer by signing the person out. A client that branched on 401 here reads
  the 403 and its code instead.
- `CliAuthorize` refuses a `code_challenge` that is not an S256 challenge (43 characters of
  base64url decoding to a SHA-256 digest) up front, instead of minting a code that could
  never be redeemed. The OAuth server's authorization checks the same.
