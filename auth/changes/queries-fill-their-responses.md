### Every query fills the message it answers with (read first)

A generated query now fills every field of its response. In this compiler
release, one that does not is a codegen warning, and in the next it is an
error. Each of auth's queries now satisfies that.

- The User lookups and creates (`GetUserByEmail`, `GetUserById`,
  `GetUserByToken*`, `GetTokenWithType`, `GetOrgMemberAccount`,
  `ListOrgMemberAccounts`, `ListRealmMachineAccounts`, `CreateUser`,
  `CreateBotUser`) select every User column, each under its feature. A gate
  handed one of these Users can no longer read a column that was never
  selected.
- The other writes return their whole row, and the reads select their whole
  row. This covers tokens, roles, memberships, organizations, invitations,
  devices, clients, challenges and pending sign-ups.
- Where a column exists only with a feature and the field always does, the
  statement says what it holds without that feature (`?unless`). That is
  `NULL` for a superadmin row's `disabled_at` and `erased_at`, `FALSE` for a
  token's `bearer`, and empty for its OAuth fields. `ListOrgSuperadmins`
  answers `team_id = ''` for a grant held directly, and `ListUserOrgs`
  answers the deprecated `owner` as `FALSE`.
- **Response types narrowed:**
  - `AuthQuery.ListUsers`, `GetUser` and `ListBotAccounts` answer
    **`UserAccount`**, which is every User column but `password_hash`. They
    feed the admin pages, and a hash never leaves storage into an admin view.
  - `AuthQuery.ListAuthClients` and `AuthService.ListClients` answer
    **`AuthClientRow`**, which has no `client_secret`.
  - `AuthQuery.GetTotpSecret` answers a **`TotpSecretRow`** beside the
    decrypted seed.
  - `AuthMutation.CreateTotpSecret` answers a **`TotpSecretCreated`**.

  On the wire these carry the same field names, minus the secret.
