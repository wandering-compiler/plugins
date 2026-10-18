### A member's role and membership can be managed over REST

- **`OrgMember.membership_id` (6, new):** `ListOrgMembers` now names each membership. Those ids are what `UpdateOrgMembershipRole` and `RemoveOrgMembership` take.
- **New feature `org_members_rest`** (off by default, requires `org_membership` and `org_invite`, whose role list a role picker needs). It publishes two endpoints on the preset, beside the member list:
  - `PUT /auth/orgs/{org}/members/{id}/role` (`UpdateOrgMembershipRole`);
  - `DELETE /auth/orgs/{org}/members/{id}` (`RemoveOrgMembership`).

  Both keep the role ceiling: the caller must cover every role the member holds, plus the role they are given.
- **`UpdateOrgMembershipRoleReq.org` (3) and `RemoveOrgMembershipReq.org` (2):** the organization the path names. A request that names a different organization from the one authentication resolved is refused with `ORG_MISMATCH`, as the other org-path calls already are.
- **The owner's membership can no longer be changed or removed:** `UpdateOrgMembershipRole` and `RemoveOrgMembership` refuse it with `MEMBERSHIP_IS_OWNER` (`FAILED_PRECONDITION`), whatever the caller covers. Ownership outlives the membership, so a demoted or removed owner used to keep root authority while vanishing from the member list.
