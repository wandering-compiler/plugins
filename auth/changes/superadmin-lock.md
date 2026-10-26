### Role changes in an organization run one at a time (`org_membership`, `teams`, `org_roles`, `org_invite`, `org_signup`, `product_roles`, `product_plans`, `service_account`, `bot_roles`)

- Every change to who holds what in an organization now runs, from its first read, in ONE transaction that first locks the organization's row (new query `AuthQuery.LockOrganization`, SELECT … FOR UPDATE). Its role-ceiling and last-superadmin checks therefore judge the state its write changes. Before, they read the member's grants, the team's roles and the role catalogue outside the write's transaction, and several races got through:
  - two superadmins demoting or removing each other at the same moment both passed the last-superadmin rule and left the organization with none, and with ownership gone nothing inside the organization could restore one;
  - a caller removed a member whom someone else was promoting above the caller at that moment;
  - a role was granted while an edit was widening it;
  - two role changes of one team diffed against the same stale set and failed.
- Two such changes in one organization now run one after the other. The covered calls:
  - `UpdateOrgMembershipRole`, `RemoveOrgMembership`, `RemoveOrganization`;
  - the team methods (`AddOrgTeamMember`, `RemoveOrgTeamMember`, `SetOrgTeamRoles`, `DeleteOrgTeam`);
  - `CreateOrgRole`, `UpdateOrgRole`, `DeleteOrgRole`;
  - `InviteToOrg`, `AcceptOrgInvite`, and an open registration's join;
  - `AssignOrgProductRole`, `RevokeOrgProductRole`, `AssignProductRole`, `RevokeProductRole` (with an organization), and the organization's plan (`AllowOrgProduct`, `DisallowOrgProduct`), which bounds what they may give;
  - `SetBotRoles`, `CreateBot`, `IssueBotToken`. With organizations, the ceiling is re-checked inside the mint's transaction.
- `RemoveOrganization` takes the lock first as well. Its cascades lock team and membership rows before the organization's row, so a member removal running at the same time cannot take them in the other order and deadlock with it.
- Calls that wrote outside a transaction now write inside that one when the bundle has a coordinator. Without one (no `DistTx`), every statement commits on its own, as before, and the lock is held for none of them.
- The caller's own permissions are re-read under the lock too. A ceiling compares against what Authenticate resolved for the request, less every permission whose grants the caller has all lost since (the active organization's and realm-wide roles, and for a session a team's roles): a caller demoted while their request waited for the lock no longer hands out what the demotion took — a machine account's creation and token minting included. The re-read only ever removes, so what Authenticate narrowed away (another organization's roles, the packages, a token's subset) stays away.
- A change to an organization the lock finds no live row for (an unknown or deleted organization) runs as before and answers with its own refusal.
