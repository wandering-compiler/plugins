### Second factor: required, optional or disabled — per organization and kind

- `two_factor_policy` (env, `two_factor` feature) says who is challenged at all:
  `required` (the default, as before), `optional` (only an account that confirmed an
  authenticator — how 2FA is offered on a running product where nobody has enrolled
  yet) or `disabled` (nobody, and `EnrollTotp` / `ConfirmTotp` refuse with
  `TWO_FACTOR_DISABLED`). Another value refuses the boot. `two_factor_scope` still says
  when a challenged account is asked.
- `org_two_factor_policy` (new feature, needs `two_factor` + `org_membership`; a
  migration adds `OrgTwoFactorPolicy`): an organization's own policy per kind of
  membership over that default. The backoffice sets it realm-wide
  (`/auth/admin/orgs/{org_id}/two-factor-policies`), the organization its own
  (`/auth/orgs/{org}/two-factor-policies`); both refuse a method the endpoint ACL does
  not gate. A sign-in reads the policy of the organization it arrives for (its host,
  the W17-Org selector, or the person's only organization), for the kind of the
  person's membership there.
- Under `required`, an account without a confirmed authenticator still gets its code
  through `MfaChallengeRequested`: without a delivery channel of your own it cannot
  sign in. Use `optional` until people have enrolled.
