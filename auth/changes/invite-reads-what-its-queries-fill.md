### Two invitation reads now get the column they check

- `email_proof_required = derived` accepts an account whose address an earlier bound invitation derived. The gate reads `User.email_proof` off `AuthQuery.GetUserById`, which never selected it, so every account read as UNPROVEN (the enum's zero, a real value here) and that floor refused exactly the accounts it exists to accept. `GetUserById` now projects it (`email_verification`).
- `AuthService.InviteToOrg` answers with the invitation's `metadata` echoed from the written row, and `AuthMutation.CreateOrgInvite` did not return the column, so the echo was always empty. It is returned now.
