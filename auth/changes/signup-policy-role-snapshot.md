### An open registration policy holds its role to what it was checked with

A migration: `OrgSignUpPolicy` gains `role_snapshot` (TEXT, default `''`).
`SetOrgSignUpPolicy` now stores an open policy's role as the role ceiling saw it
when the operator set it, and every registration the policy admits holds the role
to that snapshot, under the organization's lock, as accepting an invitation does.
A role widened since the policy was set (`UpdateOrgRole`, or a redeploy that
re-seeds a preset role with more permissions), another role now answering to the
name, or a kind no longer open when a parked registration is confirmed refuses the
registration (`SIGNUP_POLICY_STALE`, 412) and writes no membership and no grant —
it is never granted the wider role. After widening a policy's role on purpose, set
the policy again.

A policy without a snapshot — seeded by fixtures, or set before this release — keeps
working: its first registration pins the role as it reads then, and the role is held
to that from the next registration on. Nothing has to be re-set after upgrading.
