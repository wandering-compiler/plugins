### An open registration policy stores the role it was checked with (read first)

Behaviour change, and a migration. `OrgSignUpPolicy` gains `role_snapshot` (TEXT,
default `''`): `SetOrgSignUpPolicy` now stores an open policy's role as the role
ceiling saw it when the operator set it, and every registration the policy admits
holds the role to that snapshot, under the organization's lock, as accepting an
invitation does. A role widened since the policy was set (`UpdateOrgRole`, or a
redeploy that re-seeds a preset role with more permissions), another role now
answering to the name, or a kind no longer open when a parked registration is
confirmed refuses the registration (`SIGNUP_POLICY_STALE`, 412) and writes no
membership and no grant — it is never granted the wider role.

**After upgrading, set every open sign-up policy again** (`SetOrgSignUpPolicy`,
`PUT /auth/admin/orgs/{org_id}/signup-policies`, listed by `GET …/signup-policies`):
a policy set before this release has an empty snapshot — it was never checked — and
every registration on it is refused until it is set again. Do the same after widening
a policy's role.
