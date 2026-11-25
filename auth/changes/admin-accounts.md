### The admin creates any account (admin_accounts)

New feature `admin_accounts`, off by default: an operator acting realm-wide
creates accounts from the admin, in whichever organization they name.

- **A person's account** — the Users page's "Create account" (organization,
  address, role; `AuthService.CreateAccount`). The account has no usable
  password: the admin shows a one-time setup link once, and the person sets a
  password through it (`POST /auth/account-setup`, `AuthService.SetUpAccount`,
  the sign-up's password rules). Nobody signs in to the account before that,
  the operator included. "Setup link" on an account's detail replaces a lost or
  lapsed link (`AuthService.IssueAccountSetupLink`). `account_setup_url` (with
  `{token}`) builds the link the admin shows; `account_setup_ttl_hours` (72)
  is how long it works.
- **A machine account**, with `service_account` — the ServiceAccounts page's
  "Create machine account" and, on its detail, "Issue token", shown once
  (`AuthService.CreateServiceAccount`, `IssueServiceAccountToken`): CreateBot
  and IssueBotToken in the organization named, every rule of theirs kept.

Every method acts only under the endpoint ACL, from inside an organization
only for a caller holding it realm-wide, and holds the role to the operator's
ceiling. New events `AccountCreated` and `AccountSetUp`; a migration adds the
`AccountSetup` table. Needs a w17 compiler that knows a preset action's and
picker's own `feature:` (0.2), and SDK v0.2.0-rc.3 (`requires_sdk`): move a project
with `w17ctl codegen-version v0.2` before updating the plugin.
