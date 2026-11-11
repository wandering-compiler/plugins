### Suspend a whole organization (`org_suspension`)

A new feature, off by default. The realm's operators can suspend an organization with `AuthMutation.SuspendOrganizations` and lift it with `ResumeOrganizations`. Both take ids in bulk, and the project's endpoint ACL decides who may call them.

While an organization is suspended, every request that acts in it is refused with `PERMISSION_DENIED` / `ORG_SUSPENDED`. That covers:
- its people's sessions and API tokens;
- its machine accounts' bearer tokens;
- OAuth tokens consented for it.

The check runs once, after the organization is chosen, however the request chose it. A member's other organizations and requests in no organization are not affected. Nothing is revoked or deleted, so resuming restores everything.

Turning the feature on adds `Organization.suspended_at` (a migration) and one read per request that acts in an organization.
