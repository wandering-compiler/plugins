### Invitation, registration, machine-account and admin refusals speak to the person

Fourteen refusals that sent only the operator's text (so a person read the
generic sentence for the status code) now carry a code and a sentence of
their own, translated through the project's catalog and declared in
`plugin.yaml`'s `msgids:`:

- invitations: `INVITE_INVALID` (one sentence for every cause — expired,
  accepted, another account, unknown), `INVITE_ROLE_CHANGED`;
- registration: `SIGNUP_CONFIRM_INVALID` (one sentence for every cause);
- organizations: `ORGANIZATION_REQUIRED` (no organization chosen),
  `ORGANIZATION_UNKNOWN` (backoffice);
- machine accounts: `MACHINE_ACCOUNT_DISABLED`, `NOT_A_MACHINE_ACCOUNT` (one
  sentence for "a person", "not in your organization" and "no such account"),
  `MACHINE_ACCOUNT_EMAIL_REQUIRED`, `MACHINE_ACCOUNT_ROLE_REQUIRED`,
  `ROLE_NOT_FOR_MACHINE_ACCOUNTS`;
- admin bulk actions: `EMPTY_SELECTION`.

The gRPC codes and the operator messages are unchanged, and code that checks
for these refusals with `errors.Is` still matches them.
