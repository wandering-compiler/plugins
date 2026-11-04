### The backoffice invites into an organization and ends plan lines by row

- **Invitations from the backoffice (org_invite).** `InviteToOrg`, `ListOrgInvites` and
  `RevokeOrgInvite` acted only in the caller's active organization, which a realm-wide
  operator does not have — every call answered "no active organization". A caller who holds
  the method realm-wide (the endpoint ACL gates it) now acts in the organization the
  request names by its slug (`org`), from inside an organization of its own or from none,
  as the backoffice's product-role and plan methods do. The role ceiling still
  applies, against what the caller holds realm-wide; a member keeps inviting into their
  active organization as before.
- **New feature `backoffice_invites`** (requires `org_invite`, off by default) publishes the
  admin page `OrgInvites` and `POST /auth/admin/invites`, `POST /auth/admin/invites/withdraw`. The page: every organization's pending
  invitations (`AuthQuery.ListOrgInvitesAdmin`, the org's name beside its id), an
  "Invite to an organization" action with an organization picker that shows the link
  once, and "Withdraw" over picked rows (`AuthService.RevokeOrgInvites`, realm-wide).
  A hand-written page named `OrgInvites` overrides it.
- **`AuthService.DisallowOrgProducts`** (feature `product_plans`) ends plan lines picked by
  their row ids — what an admin row action sends. `DisallowOrgProduct` takes one line by
  (org, product, role), which an admin delete cannot stamp, so a page could not bind it
  and the method never reached the endpoint ACL.
- New queries: `GetOrganizationBySlug`, `GetPendingOrgInvite`, `GetOrgInviteAdmin`,
  `ListOrgInvitesAdmin`, `GetOrgProductAllowance`.
