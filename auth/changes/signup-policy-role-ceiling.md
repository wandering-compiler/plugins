### An open registration policy's role is held to the role ceiling (read first)

Behaviour change. `SetOrgSignUpPolicy` (`PUT /auth/admin/orgs/{org_id}/signup-policies`)
now refuses an open policy whose role carries a permission the operator setting it
does not hold (`ROLE_ABOVE_CALLER`, 403), as an invitation, a membership role change
and a bot's roles already are; a request with no resolved permissions is refused.
Before, any operator allowed to call it could open registration with any role of the
organization's catalogue, the organization's wildcard included, and every
registration on the host was granted it. Policies already set are not re-checked:
review the live policies (`GET …/signup-policies`) and re-set any whose role the
operator who set it could not hand out. A registration whose policy role has been
retired since is refused (no membership, no grant) and never falls back to another
role.
