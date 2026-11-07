### One model of organizations: tenant_scope is retired (read first)

- **The feature `tenant_scope` is gone.** It modelled a user in exactly one organization,
  with its own `Tenant` table, `User.tenant_id` and `tenant_id` data scope, beside
  `org_membership`'s `Organization` + `OrgMembership` and `org_id` scope: two models of one
  thing. An activation that still names it fails code generation. Use `org_membership`: a
  person with one membership acts in it without naming it (`org_from_sole_membership`, on by
  default), and the data scope is `org_id`.
- Gone with it: the `Tenant` table; `User.tenant_id`, `OAuthProvider.tenant_id`,
  `PendingSignUp.tenant_id` and the requests' `tenant_id`; `SignUpReq.tenant_slug`;
  `AuthQuery.GetUserTenant`, `GetTenantBySlug`, `GetTenantByDomain`; the refusal
  `TENANT_UNKNOWN`; the forwarded `Host` header the feature needed. Activations without the
  feature lose no column.
- An audience's source of the organization is read from `x-w17-org-from` (was
  `x-w17-tenant-from`), what the SDK's audience gateways write since the vocabulary says
  `org_from` (`w17/audience.proto`). Regenerate the identity and the products that reach it
  together: a gateway from before this release names the old key, and this plugin no
  longer reads it.
