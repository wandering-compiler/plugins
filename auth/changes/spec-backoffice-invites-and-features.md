### SPEC covers backoffice_invites, DisallowOrgProducts and every feature

No behaviour change. `SPEC.md` now specifies `backoffice_invites` (`InviteToOrgAdmin`,
`RevokeOrgInvites`, `/auth/admin/invites`, the OrgInvites page) and the bulk
`DisallowOrgProducts`, lists every feature of the manifest in its Features table with
the right requirements, and names the release it covers. The proofs of the
confirmation-time invite gate, the machine-account label and the one bootstrap
administrator per deployment are back in the test suite.
