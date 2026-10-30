# auth — changelog

## 0.1.0-rc.49

### A refused second-factor code says so

`ConfirmTotp`, `VerifyMfa` and the step-up of `EnrollTotp` (replacing an authenticator), `DisableTotp` and `GenerateRecoveryCodes` refuse a code with the same `Unauthenticated` status as before, now with the detail `MFA_CODE_REFUSED` and the sentence "That code is not valid. Check it and try again, or request a new one." It used to render "You are not signed in.", to a caller who on `ConfirmTotp` was. The pair is identical for every cause (wrong, expired, used or unknown code, attempts spent, another device), so it reveals nothing the status did not. An outage still answers `AUTH_UNAVAILABLE`.

## 0.1.0-rc.48

### Sign-in upgrades weak hashes, resets end sessions with the password, and more fail closed

- `SignIn` stores a password whose hash is weaker than the current settings (another algorithm, a lower cost) rehashed, through `AuthMutation.RehashUserPassword`. The write is a compare-and-swap on the verified hash and touches nothing else. A failed write never fails the sign-in.
- `ResetPassword` revokes every token inside its transaction. A sweep that fails rolls the reset back, so a thief's session no longer outlives a reset.
- `RequestPasswordReset` answers registered and unregistered addresses alike, in time and in errors. A registered address's link is minted after the answer.
- Under `tenant_scope`, an account that resolves to no tenant is refused by `Authenticate` (Unauthenticated) instead of being authenticated unscoped.
- New event `BotCreated` when an operator creates a machine account. Its tokens were already `ApiTokenCreated`.

## 0.1.0-rc.47

### The realm keeps an administrator, invitations hold at confirmation, admin actions are events

- The admin's Disable / Enable actions are `AuthService.DisableAccounts` / `EnableAccounts`. With them and with the erasure (`EraseUsers`, `EraseAccount`), an operator can no longer disable or erase their own account (`OWN_ACCOUNT`), nor the last active account holding a wildcard role (`LAST_ADMIN`). The check and the writes run in one transaction that locks those accounts (`LockUsers`). The storage bulk forms `AuthMutation.DisableUsers` / `EnableUsers` remain, without the rule or events.
- New events: `UserDisabled`, `UserEnabled` (per account, with the operator), `ApiTokenRevoked` (a person revoking an API token) and `OAuthIdentityLinked` (a provider identity linked to an account). Each carries the causing device's key thumbprint.
- `ConfirmSignUp` runs the invite gate again: an invitation revoked or expired between SignUp and the confirmation now refuses it, and no account is created.

## 0.1.0-rc.46

### A password change's current password is bounded and refused on its field

- `ChangePassword` counts its current password against the account's sign-in guess budget
  before checking it. Past the budget the request is refused with `PASSWORD_ATTEMPTS_SPENT`
  (ResourceExhausted), the right password included; a right password within it starts the
  budget over. A stolen session was an unbounded oracle for the password.
- A wrong current password is `PermissionDenied` with `PASSWORD_NOT_CONFIRMED` on
  `current_password`, as `ConfirmPassword` answers one. It was `Unauthenticated` (HTTP 401),
  which clients answer by signing the person out. A client that branched on 401 here reads
  the 403 and its code instead.
- `CliAuthorize` refuses a `code_challenge` that is not an S256 challenge (43 characters of
  base64url decoding to a SHA-256 digest) up front, instead of minting a code that could
  never be redeemed. The OAuth server's authorization checks the same.

## 0.1.0-rc.45

### Address changes spend the old address's links; a few refusals say what they are

- An admin address change (`UpdateAccount`) spends every live email-verification and
  password-reset link in the transaction that changes it: a link mailed to the old address
  could verify the new one, or let the old mailbox set the password. Saving the address the
  account already has writes nothing, so it no longer loses its verification.
- `Authenticate` matches the configured scheme case-insensitively (`bearer <token>` works),
  as it already did for `DPoP`.
- `ConfirmSignUp` and `VerifyMfa` answer a store outage as `Unavailable` (`AUTH_UNAVAILABLE`)
  instead of "wrong code"; they still refuse it.
- A password longer than the hash accepts (bcrypt: 72 bytes) is refused on its field with
  `PASSWORD_TOO_LONG` (InvalidArgument) by sign-up, confirmation, reset and change, instead
  of an internal error.

## 0.1.0-rc.44

### Admin address changes: normalized, and the proof goes with the old address

`UpdateAccount` (the admin Users page) and `CreateBot` store the address lower-cased and
trimmed, as sign-up does: a mixed-case address typed in the admin could never sign in.
An address change also resets `email_proof` (as it already reset `email_verified_at`), so
a proof derived from an invitation no longer carries over to an address nobody proved; the
erasure drops it too.

An existing account whose address was stored mixed-case keeps it; normalize it once with
`UPDATE <prefix>_user SET email = lower(email) WHERE email <> lower(email)` after checking
that no lower-case twin exists.

## 0.1.0-rc.43

### API tokens: listing and revoking take a session

`ListApiTokens` and `RevokeApiToken` refuse an API-token caller (`PERMISSION_DENIED`,
`SESSION_REQUIRED`), as `CreateApiToken` already did: a leaked token can no longer read
its holder's other tokens or revoke all of them. A script that managed tokens with a
token signs in instead. The README states that a person's API token acts in every
organization of its holder.

## 0.1.0-rc.42

### Second factor: three fail-open paths closed

- `VerifyMfa` refuses a challenge read without its creation time; it used to never expire.
- The code check, the account check and the consume are one transaction. A recovery code
  is no longer burned by a verification that loses the consume to a concurrent one, and a
  disabled account's correct code no longer consumes the challenge (or announces
  `MfaVerified`).
- An unknown `two_factor_scope` refuses the boot; a typo used to mean `all_logins`.

## 0.1.0-rc.41

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

## 0.1.0-rc.40

### Acting for a person another domain names: `ResolveUser`

- **`AuthService.ResolveUser` (`authenticate_turnkey`)** answers what a person holds — the `AuthResp` `Authenticate` would answer for their session, the organization chosen by the request's `headers` (`w17-org`) — from a user id instead of a credential. It is the same resolution as `Authenticate`'s, not a second one. The identity domain's own code, serving a private method that names the person another domain acts for, stamps the answer as the envelope: `principal.ActAs(ctx, who, who.GetScopes())`. Every check that reads the envelope then judges that person — the role ceiling above all: stamped with a bare user id, they held nothing and could grant no role carrying a permission (`InviteToOrg` and every other grant of a role refused them). It trusts its caller with any user, so no preset surfaces it, and it is marked `(w17.contrib.plugin_internal_rpc)`: codegen refuses it on every surface a project could name it on (a REST endpoint or auth method, an rpc or private group, an admin source, an MCP tool), and a whole-service ref leaves it out. **Requires w17 1.16**: an older platform does not know the option. A disabled or unknown account is refused. The answer carries `AuthResp.acted_for`, which says it was resolved without a credential: the role ceiling's re-read under an organization's lock counts the person's session roles for it.

### Pending invitations to a role of all permissions survive the lock growing

- **Fixed: every pending invitation to a role of `all_permissions` became unacceptable when the project added a method** ("this invitation's role has changed since it was sent"). The invitation stored the lock the role expanded to; it now stores `<role>:*`, accepted while the role still grants all permissions. Invitations sent before this release keep their list and are held to it: one sent while the lock was smaller is refused — send it again.

## 0.1.0-rc.39

### A sign-in without a device proof says the client is outdated

- **`DEVICE_PROOF_REQUIRED` names its cause in the developer text**, which a client that does not know the code prints as it is — and a client too old to sign proofs is exactly such a client. A sign-in without a proof: the client does not sign one, so it is outdated or not this deployment's client — update it. A request without one: the token went as a plain Bearer or from a client that does not sign — send it with a proof by its key. The code and the user-facing message are unchanged.

### Invitations accepted from the caller's own list; invitation and member management within the ceiling

- **`invite_accept_from_list`** (off by default): register first, accept later. `AcceptMyOrgInvite` (`POST /auth/invites/{invite_id}/accept`) accepts a pending invitation bound to the caller's address, by its id from `ListMyInvites`. No link reached the address, so nothing is derived: under `email_proof_required` `derived` or `full` the account must already hold that proof. An open invitation is accepted through its link only.
- **`invite_accept_at_signup`** (off by default): a registration through an invitation's link joins at once — SignUp, an OAuth account's creation and ConfirmSignUp (which takes the link again, `invite_token`) accept it in the transaction that creates the account. It declines, leaving the invitation for AcceptOrgInvite, when the address does not reach `email_proof_required` without a proof of its own.
- **A member's kind changes in place (`membership_kinds`).** `UpdateOrgMembershipKind` (`PUT /auth/orgs/{org}/members/{id}/kind`), under the role ceiling and the kinds the caller may hand out, instead of removing and re-inviting the member.
- **Fixed: a bind racing an acceptance could hand a bound invitation to another account.** The statement that spends an invitation through its link matches only an open one or one bound to the accepting address.
- **Fixed: any member could read and withdraw every pending invitation.** `ListOrgInvites` lists, and `RevokeOrgInvite` withdraws, only invitations whose role the caller could give (`INVITE_ABOVE_CALLER`).
- **Fixed: a member holding the products' roles in an organization could be removed by a member below them** (`product_roles`). Changing or removing them needs every permission of those roles there.
- **`email_proof_required` above `none` without `email_verification`, or an unknown value, refuses to boot.** It was silently ignored.
- **Fixed: under an audience naming no kind, every invitation of a kind was refused (`INVITE_KIND_NOT_ALLOWED`)** (`membership_kinds`). Kinds are gated only when some audience names one; otherwise any kind is handed out, as without audiences.

### An organization's members a page at a time; the new slug in OrganizationUpdated

- **Changed: `ListOrgMembers` (`GET /auth/orgs/{org}/members`) answers one page**, ordered by address: 100 members unless `page_size` asks otherwise, at most 500. `next_page_token` is set while members remain; pass it back as `page_token`. A client that read the whole list in one call reads only its first page for an organization of more than 100 members — walk the tokens.
- **`OrganizationUpdated` carries `slug`, `name` and `kind`** as they are after the change. The slug is the organization's selector (`W17-Org`, `/orgs/{org}/`); a subscriber that keys anything on it learns the new one from the event instead of reading the organization back.

### A product reaches its identity through the identity's private surface (`product_roles`) (read first)

- **`presets.rpc` (requires w17 ≥ 1.15).** The plugin offers other domains' services `AuthService.Authenticate` and `AuthService.AuthenticateAdmin` (`authenticate_turnkey`), `AuthService.SignIn` (`sign_in_turnkey`), `AuthService.OAuthExchange` (`oauth`) and `AuthService.GetHostOrg` (`org_hosts`). Nothing is served until the domain's `(w17.private_api)` confirms a method by name; a product's gateway and admin call them there, over mutual TLS, never the identity's storage tier.
- **Changed: a product is answered only for itself.** `Authenticate` answers a product's roles (`x-w17-product`) only when the identity's private gateway reports that the call comes from that product (`x-w17-caller-domain`); otherwise it refuses with `PERMISSION_DENIED`. A product's gateway or admin generated before this release dials the storage tier directly and is refused: **regenerate the products with the identity**, and declare the identity's private surface (`proto/domains/<identity>/private.proto`, `callers: [<products>]`).

## 0.1.0-rc.38

### The identity composes the products' roles (`product_roles`) (read first)

- **The roles are the identity's.** Besides the presets the products declare (their `(w17.acl_roles)`), the backoffice defines roles from any products' permissions — one may span products — (`DefineProductRole` / `RetireProductRole`, `PUT /auth/admin/product-roles`, `POST …/retire`), and an organization defines its own from what its definer holds there (`DefineOrgProductRole` / `RetireOrgProductRole`, `PUT /auth/orgs/{org}/product-roles`, `POST …/retire`). A grant, a plan line, an invitation, a registration policy and a token name them as product `*`. `ListProductPermissions` (`GET /auth/product-permissions`) lists every product's permissions; `ListProductRoles` lists the presets with what they grant and the identity's own. A migration adds the table `ProductRoleDef`.
- **A product is answered permission codes, not role keys.** `AuthResp.product_roles` now carries the product's permission codes the caller holds there (the union of their roles'). A product's gateway generated by a console from this release on translates both codes and preset keys; **regenerate the products together with the identity** when you take this release.
- **The ceiling is by permission.** Inside an organization a caller hands out, takes and defines only roles every permission of which they hold there (it was a preset another preset covers). Presets that covered each other still do.
- **Plans carry a role or a product.** A role's line (`product: "*"` for the identity's own) carries it in every product it grants in; a whole-product line carries every role's permissions there.
- **Tokens narrow by permission.** A token is answered what its holder holds in the product that a role it names grants there.

### The backoffice is marked inside an organization (`realm_permissions`)

- A request acting inside an organization whose credential holds roles realm-wide (granted with no organization) now carries the scope `realm_permissions`: `*` for a wildcard, otherwise the permission ids those roles grant. It adds no permission. Another plugin's backoffice method reads it to act realm-wide: the grant plugin's envelope decisions (grant 0.1.0-rc.3). This plugin's own backoffice methods already act realm-wide for such a caller.
- Inside an organization Authenticate reads the caller's realm-wide roles once more to decide it (one query).
- **Packages bound the organization's roles, not the backoffice's (`org_packages`).** A role held realm-wide is no longer narrowed by the packages of the organization a request acts in, and a realm-wide wildcard reaches any audience there (no `PACKAGE_AUDIENCE_OFF`); the endpoint ACL still decides what it calls. Before, a backoffice operator who was also a member of a packaged organization lost the backoffice there. Plans already left realm-wide product roles unbounded.

### `org_signup` builds without `oauth`

- rc.37's `signup_host` named `OAuthExchangeReq` in `handlers/org_signup.go`, a message that exists only with `oauth`, so a project activating `org_signup` without `oauth` generated a storage bundle that did not compile (`undefined: pb.OAuthExchangeReq`). The host is now read off any request that carries the field. Projects with `oauth` were not affected.

## 0.1.0-rc.37

### Correction: the `owner_id` drop is not asked for (`org_membership`) (read first)

- The rc.36 notes said the migration that drops `Organization.owner_id` "is lossy and the migrator asks you to confirm it". It does not. A field the proto no longer declares is a decision already made, so `migrate generate` writes the drop and asks nothing. `migrate check` reports nothing to decide, and the generated migration only carries a `-- RISK:` comment for the step (`drop_column`, MEDIUM). Only a local `stack build` stops on it, as on any lossy sync, until `--lossy` says what to do.
- If a deployment set `owner_id` by hand and wants the values, export them before anything applies the migration: the deployed binary when it migrates, or a local `stack build --lossy=apply`. Grant those people a role and a membership first, as the rc.36 notes say.

### A registration on the identity's own host names the host it comes from (`org_signup`)

- `SignUpReq.signup_host` and `OAuthExchangeReq.signup_host` (new, present with `org_signup`). When a person comes from an organization's host to register on the identity's own host, the registration page there sends that host. The identity's host serves several organizations' sign-ups and is bound to none of them.
- With no gateway host, the named host decides exactly as a registration arriving on it would: the organization bound to it (`org_hosts`) and that organization's policies (kind, role, open or closed), and `invite_only` when no policy speaks. An unbound host joins nothing. An invitation still decides its own organization.
- A gateway that takes the tenant from the host still decides by the host the request arrived on when that host is bound to an organization; one bound to none (the identity's own) leaves the named host to decide. A body host naming another host than a bound gateway host is refused with `SIGNUP_HOST_CONFLICT`; one that is not a host name is refused with `HOST_INVALID` on `signup_host`.
- The page shows the organization the same way as on its own host: `GET /auth/hosts/{host}` (with `open_kinds`), then the grant plugin's approved envelope (`GET /grant/envelopes/orgs/{org_id}`).
- Nothing extra is verified. An open policy already admits anyone who reaches that host, so naming the host gains nothing more.

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
- The caller's own permissions are re-read under the lock too. A ceiling compares against what Authenticate resolved for the request, less every permission whose grants the caller has all lost since (the active organization's and realm-wide roles, or realm-wide alone with no active organization, and for a session a team's roles): a caller demoted while their request waited for the lock no longer hands out what the demotion took — a machine account's creation and token minting included. The re-read only ever removes, so what Authenticate narrowed away (another organization's roles, the packages, a token's subset) stays away. It counts the caller's realm on role ids, as Authenticate does: a session's roles for a session, the API and MCP realms' for a token (nothing on the request tells an API token from an MCP one, so for either a role of the other token realm still keeps a permission).
- A change to an organization the lock finds no live row for (an unknown or deleted organization) runs as before and answers with its own refusal.

### An API token names the products' roles it may use (`product_roles` with `api_token`)

- `CreateApiTokenReq.product_roles` and `IssueBotTokenReq.product_roles` name the products' roles a token may use, each one of the catalogue (`PRODUCT_UNKNOWN`, `PRODUCT_ROLE_UNKNOWN` otherwise). A product is answered the roles the token names that a role its holder holds there covers (a holder of alpha's editor may mint a token for alpha's viewer).
- **A token minted narrow stays narrow toward the products.** One with a `permission_subset` and no product role now reaches the products with **no** role; until now it carried every product role of its holder. A token narrowed on neither axis carries them all, as before, and so does a session.
- A migration adds the table `TokenProductRole` (with `product_roles`).

### A backoffice method held realm-wide acts realm-wide from inside an organization

- The backoffice's methods that refuse inside an organization — packages, hosts, sign-up policies, the products' roles and plans — now act realm-wide for a caller who holds them through a realm-wide role, whatever organization the request acts in (named, or the caller's only one inferred). Until now they refused (`PACKAGES_REALM_ONLY`, `HOSTS_REALM_ONLY`, …) and an operator who was also a member of one organization needed a second account or `org_from_sole_membership: false`.
- A member who holds such a method only inside an organization is refused as before. The grant plugin's envelope decisions still need a request acting in no organization.

## 0.1.0-rc.36

### An invitation for someone who is already a member is refused

- `InviteToOrg` (`POST /auth/orgs/{org}/invites`) refuses an address whose account is already a live member of the organization: `AlreadyExists` with the detail `INVITE_ALREADY_MEMBER` on `email` ("This person is already a member of the organization."), and nothing is written. Until now the invitation was written and listed as pending, and only acceptance refused it, on the membership's unique index, so it could never be accepted.
- A removed member can still be invited back, and an address with no account or with a membership of another organization is invited as before. Open invitations (no address) are not affected.

### Organizations have no owner (`org_membership`) (read first)

- **`Organization.owner_id` is dropped.** It was read as root authority — a wildcard grant over the whole deployed permission lock in the owned organization, selecting the organization without a membership, a membership nobody could change or remove (`MEMBERSHIP_IS_OWNER`), an exemption from the last-superadmin rule, and inviting any kind of membership under `membership_kinds` — yet nothing in the plugin ever wrote it. The field is reserved (6, `owner_id`); a project's next generated migration drops the column and its index. **The drop is lossy and the migrator asks you to confirm it.** Nothing the column held should be kept: it granted what a role should grant.
- **Use roles.** Whoever administers an organization holds an org-scoped role there — grant the creator one on their membership when you create the organization. Make it a wildcard (`all_permissions`) org role, or keep one wildcard holder per organization: the last-superadmin rule counts wildcard roles only, so an organization administered only through non-wildcard roles can lose its last administrator, and nothing in the plugin restores one. If a deployment set `owner_id` by hand and gave that person no role, grant them one **before** upgrading, or they lose access to the organization (they also need a live membership to select it).
- Organization selection is by live membership only. A principal without one is refused `ORG_NOT_MEMBER`, whoever created the organization.
- Every membership is managed the same way, its creator's included; `MEMBERSHIP_IS_OWNER` and its message are gone. The last superadmin of an organization (the last member holding a wildcard role there) cannot be demoted or removed — by themselves or by anyone else (`LAST_SUPERADMIN`), with no exception. A wildcard role held through a team (`teams`) now counts: such a member is a superadmin, and one keeps the organization administered. The team methods are held to the rule too: `RemoveOrgTeamMember`, `SetOrgTeamRoles` and `DeleteOrgTeam` refuse `LAST_SUPERADMIN` when they would end the organization's last wildcard. Only a superadmin who can act counts: a disabled or erased account (`user_admin`), a machine account's API-realm wildcard (`api_token`), a revoked grant, a removed membership or a deleted role or team no longer lets the last active superadmin go. An operator's `DisableUsers` / `EraseUsers` is not held to the rule, by design — they are realm-level actions, and an operator may disable the last superadmin deliberately. `AuthQuery.CountOtherOrgSuperadmins` is replaced by `ListOrgSuperadmins`; new `ListOrgTeamSuperadmins` (`teams`).
- `UserOrg.owner` (`ListMyOrgs`) and `OrgMember.owner` (`ListOrgMembers`) stay on the wire, deprecated and always `false`; stop reading them. `OrgMemberRow.owner` is reserved.
- Removed queries: `AuthQuery.GetUserOwnsOrg`, `GetOwnedOrgBySlug`, `GetUserOwnsAnyOrg`. `GetOrganization` no longer projects `owner_id`. A project query that names `Organization.owner_id` stops generating; drop the reference.

### Registration on an organization's own host (`org_signup`)

- New feature `org_signup` (requires `org_hosts`, `rbac`; off by default; a migration adds `OrgSignUpPolicy` and, with `sign_up_confirmation`, three `PendingSignUp` columns). Per organization and kind of membership the backoffice sets whether people may register without an invitation and with which org-scoped role (`PUT` / `GET /auth/admin/orgs/{org_id}/signup-policies`, `POST …/signup-policies/clear`).
- A registration without an invitation — password, OAuth (Google, Apple), or confirmed by code — on a host bound to an organization, through an audience that takes the tenant from the host: an open policy for the audience's kind makes the new account a member of that kind with that role in the same transaction, whatever `invite_only` says; a closed one refuses it (`SIGNUP_NOT_INVITED`); no policy leaves `invite_only` to decide, as before. Two open kinds on one audience are refused (`SIGNUP_KIND_AMBIGUOUS`). An invitation still decides its own organization.
- `GET /auth/hosts/{host}` answers `open_kinds`, so a sign-up page knows whether to show its form.
- Needs a gateway generated by a console that hands the audience's context to every call (SDK `restgw.AudienceContextMiddleware`).

### One identity for several products (`product_roles`, `product_plans`)

- New feature `product_roles` (requires `org_membership`; off by default; a migration adds `ProductRoleGrant`). A domain whose `(w17.domain).identity` names this one is a product: it keeps no users, and its gateway authenticates here with `x-w17-product`. `Authenticate` then answers `product_roles` — the keys of the roles the caller holds in that product, realm-wide and in the active organization — and no permission ids; the product turns the keys into its own ids. The catalogue is the products' `(w17.acl_roles)`, generated into `w17_product_roles` (`GET /auth/product-roles`).
- Grants: inside an organization a member gives and takes the product roles covered by one they hold there (it carries all their permissions), to members (`GET` / `PUT /auth/orgs/{org}/product-role-grants`, `POST …/revoke`); the backoffice any, realm-wide too (`GET` / `PUT /auth/admin/product-role-grants`, `POST …/revoke`). Leaving an organization ends the roles held there.
- New feature `product_plans` (requires `product_roles`; a migration adds `OrgProductAllowance`): an organization's plan — a product's roles or the whole product — bounds what its members hold on every request and what anyone can hand out (`GET` / `PUT /auth/admin/orgs/{org_id}/product-plan`, `POST …/product-plan/remove`; `GET /auth/orgs/{org}/product-plan`).
- Needs a console that generates products (SDK `(w17.domain).identity`) and fills `w17_product_roles`.

### Product roles on joining (`product_roles` with `org_invite` / `org_signup`)

- Invitations and open registration carry product roles: `InviteToOrgReq.product_roles` (with `org_invite`) names the products' roles accepting gives — each covered by one the inviter holds there and carried by the plan, checked again at acceptance (`PRODUCT_ROLE_NOT_IN_PLAN`, `PRODUCT_ROLE_UNKNOWN` leave the invitation unspent); the invitation lists, `ListMyInvites` and `AcceptOrgInviteResp` show them. `SetOrgSignUpPolicyReq.product_roles` (with `org_signup`) names those an open registration is given; one that left the catalogue or the plan since is passed over. Migrations add `OrgInvite.product_roles` and `OrgSignUpPolicy.product_roles`.

## 0.1.0-rc.35

### The organization comes from the host, or only from the request

- **`org_hosts`** (new, off by default): the backoffice binds a white-label or co-brand host to the organization it serves (`PUT` / `DELETE /auth/admin/hosts/{host}`, `GET /auth/admin/hosts`; realm-wide, `HOSTS_REALM_ONLY` from inside an organization, `HOST_TAKEN` for a host another organization holds), and anyone may ask which organization a host serves (`GET /auth/hosts/{host}`, unauthenticated, limited per address). A migration adds the `OrgHost` table.
- **Audiences that take the tenant from the host.** An audience declaring `membership.tenant_from` (w17/audience.proto) now has its order followed: on a request arriving on a bound host, `TENANT_SOURCE_HOST` acts in that organization (the caller still needs a membership there, of an admitted kind), and a `W17-Org` selector naming another organization is refused with `ORG_HOST_CONFLICT`, never followed. `TENANT_SOURCE_DEFAULT` is the selector, then the sole membership. An audience whose sources omit `DEFAULT` refuses a selector (`ORG_SELECTOR_NOT_ACCEPTED`) and never infers. An audience naming the host without `org_hosts` activated fails every request with `FailedPrecondition`.
- **`org_from_sole_membership`** (new setting, default `true`, today's behaviour): `false` stops a request that names no organization from acting in the caller's only one, so an organization only ever comes from the request — the selector, the path, the host.

### Sign in with Apple

Apple is an OIDC provider like the others, with two differences the plugin could not configure until now. With the address in the scopes, Apple comes back by an HTML form POST rather than a GET. Its client secret is a JWT signed with a key Apple issued, valid at most six months, rather than a string.

- `OAuthProvider` (and `UpsertOAuthProviderReq`) gains `response_mode`, `team_id` and `key_id`. `response_mode` is empty (the query string, as before) or `form_post`, which the authorize URL then asks for. With `team_id` and `key_id`, `secret` holds the `.p8` key Apple issued. Each token exchange then sends a client secret minted from it: an ES256 JWT, `iss` team_id, `sub` client_id, `aud` the token endpoint's origin, `kid` key_id, valid five minutes. There is nothing to rotate before Apple's six months run out, and the key itself is never sent. The state, PKCE and nonce stay keyed by the key, so a sign-in started before a mint finishes after it.
- The new feature `oauth_form_post` publishes `POST /auth/oauth/{provider}/callback` (`OAuthCallbackForm`). It is the same callback with the code and state in the form body, and it answers with the same 302 and login code. It accepts only a `form_post` provider. Without the feature, a `form_post` provider is refused at the authorize step, since nothing would receive its POST.
- Apple's `email_verified` arrives as the string `"true"`, which was already read as verified. A private-relay address (`…@privaterelay.appleid.com`) is an address like any other.
- A migration adds the three columns. A provider configured without them behaves as before.
- The dev-only `fakeidp` sandbox can play Apple for one client (`APPLE_CLIENT_ID`, with `APPLE_TEAM_ID`, `APPLE_KEY_ID` and `APPLE_PUBLIC_KEY_PEM`). It answers `response_mode=form_post` with the form page, accepts only a client secret that verifies with the key and names the team, the client and itself, and sends `email_verified` as Apple does. Every other client is served as before.

### Fields rc.34 made required are as optional as they were in rc.33 (read first)

rc.34 marked credentials `sensitive`, which gave plain fields a `(w17.field)`. A field with one and no `blank` is a field the generated code requires, so rc.34 changed what a request must carry, not only what a log may show. Seen broken:

- `OAuthExchangeReq.invite_token`: every `POST /auth/oauth/exchange` without an invitation, which is almost all of them, was refused 400 `REQUIRED_VIOLATION invite_token`.
- `CreateMfaChallengeReq.code` and `MfaChallengeRequested.code`: empty for a user with a confirmed authenticator under the built-in TOTP verifier, so storage refused the challenge and such a user could not sign in.
- `EnrollTotpReq.code`: required only to re-enrol, so a first enrolment was refused 400.
- `GenerateRecoveryCodesReq.code` and `DisableTotpReq.code`: empty after a recent step-up (and for `DisableTotp` without an authenticator), so they were refused 400 before the handler could answer.

Every field rc.34 turned from a plain field into `(w17.field) = { sensitive: true }` now carries `blank: true` as well: what a request must carry is again exactly what it was in rc.33, and redaction is all `sensitive` changes. Fields that had a `(w17.field)` before rc.34 are unchanged. Upgrade from rc.34 if you use `oauth`, `two_factor` or `step_up`.

## 0.1.0-rc.34

### Tokens, codes and secrets stay out of every sink

Telemetry and the request event stream write each request message without its `sensitive` fields (the redaction plan beside each `.pb.go`). Only the fields the type marks were left out until now: `PASSWORD`, `SECRET`, `CRYPTED_SECRET`. Most credentials the plugin hands out or takes in were plain strings, so they were written. That included `AuthReq.headers`, which carries the caller's `Authorization` header and goes to the error report whenever `Authenticate` fails on the backend.

- 70 fields are now marked `sensitive`. They cover what the plugin issues (session, API, bot and OAuth access/refresh tokens; `client_secret`; the TOTP secret, its `otpauth://` URI and recovery codes) and what it takes in (`AuthReq.headers`; sign-up, MFA, step-up and OAuth codes; `code_verifier`; reset, verification and invite tokens; a legacy plaintext token). They include the decrypted TOTP seed and the hashes of the short codes (MFA, step-up, sign-up, recovery), which a brute force over the code space reverses. The plaintext codes and tokens on the `*Requested` events are marked too.
- Nothing changes on the wire. The responses still carry the token, and the events still carry the code the mail is built from. Only what a sink writes changes.
- The hashes of the long random tokens and the token ids stay visible. They identify a token, and nobody can authenticate with them.

## 0.1.0-rc.33

### The account type rides the identity

- With `membership_kinds`, `Authenticate` answers `AuthResp.membership_kind`: the kind of the caller's membership (`staff`, `client`, …) in the organization the request acts in, however that organization was resolved (the `W17-Org` selector, the sole membership, an OAuth token's organization, an audience's kinds). Like the organization it is the request's context, so the same person in two organizations at once gets one kind per request. Empty when the request acts in no organization, or in one the caller only owns.
- A gateway generated by a console that knows the field copies it into every request record (`RequestEventMeta.membership_kind`), where the `marketing` plugin sends it as the event's `w17_account_type`. Without `membership_kinds` the field does not exist and nothing changes.
- The memberships an audience gateway reads to resolve the organization are read once per `Authenticate` and reused for the kind.

## 0.1.0-rc.32

### Added

- **`oauth_server`: w17ctl signs in with a code** when it runs on another machine than the browser (an ssh session, a remote workspace), where the redirect to its loopback cannot reach it. The new setting `oauth_code_redirect` names the authorization server's code page (the REST gateway serves it at `<issuer>/oauth/code`, SDK `lib/oauthas`); w17ctl may then ask for a session with that page as its redirect, the consent page says the answer is a code to type into w17ctl, and the page shows it as `code#state`. Such a code lasts 5 minutes instead of 1, still single-use and worth nothing without w17ctl's PKCE verifier and DPoP key. The page is allowed as a redirect whatever `oauth_redirect_hosts` lists. Empty (the default) = not offered, and w17ctl is told so instead of "a resource is required". A value that is not an https URL (http only on a loopback host) without query or fragment fails the boot.

## 0.1.0-rc.31

### Added

- **`membership_kinds`: memberships of several kinds** — the auth half of audience surfaces (a domain publishing one REST / MCP / gRPC surface per audience, each on its own gateway). `OrgMembership` and `OrgInvite` gain a kind (`staff`, `client`, …); a membership has one kind, so a person is an organization's staff or its client (and may be staff of one organization, client of another). An audience gateway names the kinds it admits in every `Authenticate` (`x-w17-membership-kinds`, gateway-owned): the organization a request acts in is resolved among the memberships of an admitted kind, a caller holding none is refused 403 `MEMBERSHIP_NOT_ADMITTED` before any handler, and ownership does not widen. `InviteToOrg` takes the kind of membership accepting creates (with `org_invite`), held to the kinds the inviter's audiences may invite (`INVITE_KIND_NOT_ALLOWED`). With `oauth_server`, the consent page offers an MCP client only the organizations of a kind its audience admits. The domain's audience table, `w17_audiences`, is generated by codegen and checked at boot. A gateway that names no kinds admits every membership, so nothing changes without audiences. Off by default; requires `org_membership`; a migration adds the columns.

### Added

- **`oauth_server`: an OAuth 2.1 authorization server** for MCP clients (the MCP authorization specification) and for w17ctl's browser login. Clients register themselves (RFC 7591) or name a Client ID Metadata Document; the user approves on the project's consent page (`GET /auth/oauth/authorizations/{request_id}`, `POST …/approve`, `POST …/deny`; with `org_membership` choosing the organization); the code (PKCE S256, single-use, 60 s) yields, for an MCP client, an `mcp_only` access token of the new type `TOKEN_TYPE_MCP` for one resource with a rotating refresh token (a reused one ends the grant), and for w17ctl a session bound to its DPoP key (a key the account cannot use is refused with the extension error `w17_device_key_refused`; a replayed code ends the session it minted, `RevokeReason.CODE_REPLAYED`). `Authenticate` accepts an MCP token only on the MCP surface naming its resource (`x-w17-mcp-resource`). Users list and revoke their connected apps (`GET /auth/oauth/connected-apps`, `DELETE /auth/oauth/connected-apps/{grant_id}`); revoking a device, every token or the account reaches them too. The OAuth protocol endpoints are served by the generated REST gateway (SDK `lib/oauthas`). Off by default; requires `api_token` and `authenticate_turnkey`; a migration adds four tables and three `UserToken` columns. A code is spent and redeemed in one transaction, so a replay racing the redemption still ends what it issued.

### Changed

- `bot_roles` and `org_roles` declare `rbac`, whose role writes their handlers make (they held it only through `service_account` / `org_membership`).

- `RevokeDeviceTokens` also ends the OAuth access tokens (type MCP) the revoked device approved, beside the CLI sessions it approved.
- `isLoopbackRedirect` moved to the always-compiled handlers file (cli_login and oauth_server both use it).

### Added

- **`org_packages`: what an organization can hold is bounded by its packages.** A project names packages — sets of its methods and audiences — in the domain's protos (`(w17.packages)`, w17/packages.proto); the backoffice gives and takes them per organization, realm-wide (`AddOrgPackage` / `RemoveOrgPackage` / `ListPackagesOfOrg`), and an organization reads its own (`ListMyOrgPackages`). On every `Authenticate` in an organization a project method's permission survives only when one of its packages grants it — the owner's wildcard included — so a method no package grants is held by nobody (default deny), and the role ceiling keeps anyone from handing out a role above the packages. An audience a package names admits a member only when one of the organization's packages names it (`PACKAGE_AUDIENCE_OFF`); a `default` package is every organization's without being given — the floor for existing and new organizations. The backoffice's methods need the endpoint ACL. Plugin methods and realm-wide requests are not narrowed; taking a package applies on the next request; nothing is deleted. The table, `w17_packages`, is generated by codegen. Off by default; requires `org_membership`; a migration adds the table.

### Added

- **`org_roles`: an organization's own roles.** `ListOrgRoles` / `CreateOrgRole` / `UpdateOrgRole` / `DeleteOrgRole` (`GET` / `POST /auth/orgs/{org}/org-roles`, `PUT` / `DELETE /auth/orgs/{org}/org-roles/{role_id}`): an organization composes roles from the deployed lock's permissions, stored as ordinary org-scoped roles with `RolePermission` rows (each change logged in `RolePermissionChange`), seen, granted and edited only in that organization (`Role.org_id`). With the feature on, the catalogue every org-role grant reads — invitation, acceptance, role change, `ListAssignableRoles` — is the organization's: the shared org roles plus its own. The role ceiling applies to composing as to granting: a role carries only permissions its author holds, and is changed or deleted only by someone who covers it. A role still held is not deleted. Off by default; requires `org_membership`; a migration adds `Role.org_id`.
- **`bot_roles`: any combination of the bot roles.** `SetBotRoles` (`PUT /auth/bots/{user_id}/roles`) replaces the API-realm roles a machine account holds, in one transaction, under the operator rules of `IssueBotToken`; `ListBots` carries each bot's `role_ids`. Off by default; requires `service_account` and `org_membership`.

### Fixed

- **A machine account's role is no longer offered to a person.** An org-scoped API-realm role (a bot's) was listed by `ListAssignableRoles` and accepted by an invitation and a membership's role change, replacing the person's session role with one their browser cannot use. It is now filtered out of the org-role catalogue and refused by name (`ROLE_IS_FOR_BOTS`). With it, a person in an organization holds no API-realm role at all, so a personal API token (`CreateApiToken`) authenticates and is granted nothing: automation — CI, scripts, integrations — runs as a machine account (`CreateBot`, `IssueBotToken`).
- **An organization keeps its last superadmin.** A member holding a wildcard (`all_permissions`) role who is the organization's last — no other member holds one and the organization has no owner — can no longer be removed or moved to a lesser role (`LAST_SUPERADMIN`).
- `AssignableRole` and `OrgScopedRole` carry `display_name`; `GetOrganization` projects `owner_id`.

### Personal API tokens in an organization (read first)

- A person in an organization no longer holds an API-realm role (see `ROLE_IS_FOR_BOTS` under Fixed), so a personal API token (`CreateApiToken`) used in an organization authenticates and is granted nothing. Before upgrading, move every script, CI job and integration that calls with a person's API token to a machine account: `CreateBot`, give it its roles (`SetBotRoles` with `bot_roles`), and mint its token with `IssueBotToken` (`service_account`). A project that issues no personal API tokens has nothing to do.

### Added

- **SignIn has a per-account guess budget.** Every password attempt at an account is counted before its password is checked, in one statement, so concurrent guesses cannot share a budget. Past `sign_in_failure_budget` attempts (default 20) in `sign_in_failure_window_seconds` (default 900), the account is not locked: only a device that has signed in to it before may still try, within `sign_in_device_failure_budget` attempts (default 10). The owner keeps signing in on every device they have used while someone guesses; a new device waits for the window. A refusal answers exactly as a wrong password does (same code, message and timing), and the sign-in history records it as `THROTTLED`. A correct password resets both counts. Guessing spread over many addresses — or collapsed into one behind a misconfigured proxy — is now bounded per account. A migration adds `User.sign_in_failures` / `sign_in_window_at` and `Device.sign_in_failures` / `sign_in_window_at`.
- README: **Behind a proxy** — what `<PREFIX>_PUBLIC_RATELIMIT_TRUSTED_PROXIES` must be for the per-address limit to mean anything.

### Added

- **`step_up_code`: step up with the second factor instead of the password.** `RequestStepUpCode` (`POST /auth/step-up/code`) names the proof a session must give — the person's authenticator when one is confirmed, otherwise a six-digit code it mails through a hand-written channel (`StepUpCodeRequested`, topic `auth.step_up.code_requested`; only the hash is kept, on the caller's own session, and a new code goes out at most once a minute). `ConfirmStepUp` (`POST /auth/step-up/confirm`) takes an authenticator code, a recovery code or the mailed code and stamps `UserToken.stepped_up_at` like `ConfirmPassword`, under the same per-session guess budget. `step_up_password=false` turns `ConfirmPassword` off (`STEP_UP_PASSWORD_OFF`), so the second factor is the only step-up. Sessions only. Off by default; requires `step_up` and `two_factor`; a migration adds `UserToken.step_up_code_hash` and `step_up_code_sent_at`.
- **`admin_mfa`: reset a person's authenticator.** The `Authenticators` admin page lists every enrolment, and its `Reset` action (`ResetAuthenticators`) ends the selected live authenticators and their unused recovery codes — the way back for a person who lost the phone and the codes; the next sign-in falls back to the mailed code. Off by default; requires `user_admin` and `two_factor`.
- **`api_token_max_ttl_hours`**: a cap on how long a person's API token may live. With it set, a later expiry is refused (`TOKEN_EXPIRY_TOO_LATE`) and a token minted without one never outlives the cap — so every person's token expires. Default 0 = no cap.
- **`api_token_step_up_seconds`**: `CreateApiToken` asks for a step-up that recent in the caller's session (`API_TOKEN_NEEDS_STEP_UP`). Default 0 = not asked; a value > 0 needs `step_up`.
- **`two_factor_scope=off`**: no sign-in is challenged — for a development stack whose scripts sign in with a password. Honoured only with `W17_ENV=dev`; anywhere else the plugin refuses to boot, and a sign-in is challenged regardless.

### Added

- **`teams`: groups of an organization's members that hold roles.** `ListOrgTeams` / `CreateOrgTeam` / `UpdateOrgTeam` / `DeleteOrgTeam` / `AddOrgTeamMember` / `RemoveOrgTeamMember` / `SetOrgTeamRoles` (`GET` / `POST /auth/orgs/{org}/teams`, `PUT` / `DELETE /auth/orgs/{org}/teams/{team_id}`, `POST /auth/orgs/{org}/teams/{team_id}/members`, `DELETE /auth/orgs/{org}/teams/{team_id}/members/{user_id}`, `PUT /auth/orgs/{org}/teams/{team_id}/roles`). A team belongs to one organization, its members are people of that organization (a machine account holds its roles directly), and it holds org-scoped session-realm roles of the organization's catalogue, which every member holds for a session acting in that organization — never realm-wide, in another organization or for an API token. The role ceiling holds wherever someone gains or loses a role through a team: giving or taking a team's role, adding or removing a member, deleting the team, and removing someone from the organization, which also ends their team memberships. A role a team holds is in use (`DeleteOrgRole`). Nothing is deleted. Off by default; requires `rbac` and `org_membership`; a migration adds `Team`, `TeamMember` and `TeamRole`.

## 0.1.0-rc.30

### Added

- **`bot_token_guard`: an address allowlist and a use summary for machine accounts' bearer tokens.** `SetBotAllowlist` (`PUT /auth/bots/{user_id}/allowlist`) holds a bot's bearer tokens to CIDRs: from any other client address they are refused like an unknown token. The address is the one the gateway resolved through its trusted proxies (`x-w17-client-addr`), never one the client wrote; a gateway that sends none fails closed while a list is set. A change is announced as `BotAllowlistChanged`, with the operator who made it. `GetBotGuard` (`GET /auth/bots/{user_id}/guard`) answers the list and where the bot's tokens were used: one row per token, address, surface and method, with the first and the latest use. Off by default; requires `service_account`; a migration adds `User.allowed_cidrs` and the `BotTokenUse` table.

## 0.1.0-rc.29

### The user's consent to marketing messages (`marketing_consent`, new, off by default)

- **New feature `marketing_consent`** (requires `authenticate_turnkey`). The user reads and sets their own consent on the REST preset: `GET /auth/marketing-consent` and `PUT /auth/marketing-consent` with `{"consent": true|false}` (`GetMarketingConsent`, `SetMarketingConsent`). Both act on the caller only.
- **Stored on the user:** `User.marketing_consent` (FALSE until given) and `User.marketing_consent_at`, the time of the latest decision (NULL = never asked, which a UI reads to know whether to ask). A withdrawal is recorded like a consent.
- **`AuthResp.marketing_consent` (7):** the gateway copies it into every request record, so the tool that sends the messages has it. Nothing in w17 acts on it; what is recorded does not depend on it.
- **New event `MarketingConsentChanged`** (`auth.user.marketing_consent_changed`: `user_id`, `consent`, `decided_at`, `device_id` of the device the user decided from), for a subscriber that keeps a copy (a marketing tool's contact).
- **Migration** (only with the feature): two new columns on `User`, nothing changed or removed.

### A session's password confirmation (`step_up`, new, off by default)

- **New feature `step_up`.** `ConfirmPassword` (`POST /auth/password/confirm` with `{"password": "…"}`) verifies the caller's password and stamps their session: `UserToken.stepped_up_at`. A consumer that guards a sensitive action reads the caller's own token row and asks for a recent confirmation. A stolen token and its device key do not carry the password, so they cannot pass.
- **A session only.** An API token is refused (`SESSION_REQUIRED`).
- **Guess budget.** Every guess is counted on the session in one statement. After five wrong passwords in a row the step-up is locked for fifteen minutes (`PASSWORD_STEP_UP_LOCKED`), and a confirmation resets the count. A wrong password is `PASSWORD_NOT_CONFIRMED`.
- **Migration** (only with the feature): three new columns on `UserToken`, nothing changed or removed.

## 0.1.0-rc.28

### `devices` requires `authenticate_turnkey`

- **The `devices` feature now declares `requires: [authenticate_turnkey]`.** Its handlers read the caller's device from the turnkey identity answer (`AuthResp`), which only `authenticate_turnkey` stages. An activation that enabled `devices` without it got a bundle that did not compile (`undefined: pb.AuthResp`, in a file the project never wrote); it is now refused at activation with the missing feature named.
- An activation that already enables both (every known one) changes nothing: the same tables, env variables and endpoints, no migration.

### A member's role and membership can be managed over REST

- **`OrgMember.membership_id` (6, new):** `ListOrgMembers` now names each membership. Those ids are what `UpdateOrgMembershipRole` and `RemoveOrgMembership` take.
- **New feature `org_members_rest`** (off by default, requires `org_membership` and `org_invite`, whose role list a role picker needs). It publishes two endpoints on the preset, beside the member list:
  - `PUT /auth/orgs/{org}/members/{id}/role` (`UpdateOrgMembershipRole`);
  - `DELETE /auth/orgs/{org}/members/{id}` (`RemoveOrgMembership`).

  Both keep the role ceiling: the caller must cover every role the member holds, plus the role they are given.
- **`UpdateOrgMembershipRoleReq.org` (3) and `RemoveOrgMembershipReq.org` (2):** the organization the path names. A request that names a different organization from the one authentication resolved is refused with `ORG_MISMATCH`, as the other org-path calls already are.
- **The owner's membership can no longer be changed or removed:** `UpdateOrgMembershipRole` and `RemoveOrgMembership` refuse it with `MEMBERSHIP_IS_OWNER` (`FAILED_PRECONDITION`), whatever the caller covers. Ownership outlives the membership, so a demoted or removed owner used to keep root authority while vanishing from the member list.

### Built on SDK go/v0.1.0-rc.24

- **The plugin's module requires `github.com/wandering-compiler/sdk/go` v0.1.0-rc.24.** A w17ctl that knows the request data annotations (`gdpr`, `sensitive`) generates a redaction plan next to every pb file of the plugin's `src/gen`, and that plan imports the SDK's `lib/redact`, which rc.24 is the first to have. The plugin's own code does not change.
- Nothing in your project changes: the same activation, the same env variables, no migration. Your project's own `go.mod` moves to rc.24 with the same w17ctl.

## 0.1.0-rc.27

### A bearer token is written by IssueApiToken; IssueBotBearerToken is gone

In rc.26, `ApiTokenCreated` had two emit sites: `IssueApiToken`, and `IssueBotBearerToken` for a machine account's bearer token. A consumer that enabled `service_account` could not generate code, because an event has exactly one emit site.

- **`AuthMutation.IssueBotBearerToken` is removed.** The bearer token is written by `AuthMutation.IssueApiToken`, using a new `IssueApiTokenReq.bearer` (11, field-gated `service_account`, set only by the machine-account path).
- **`IssueApiTokenReq.device_id` may be empty**, but only for a bearer token. The handler still refuses any other API token without a device.
- Nothing changes on the wire or in the schema compared with rc.26: the same column and the same `ApiTokenCreated` event, with an empty `key_thumbprint` for a bearer token.

## 0.1.0-rc.26

### Machine accounts can get a bearer token with no key

A machine account's token no longer has to be bound to a key. `IssueBotToken` without `public_key` mints a **bearer token**: there is no JWK to make and paste. The program sends `Authorization: Bearer <token>` and signs nothing. People's sessions and API tokens stay bound to their device key; nothing changes for them.

- **`IssueBotTokenReq.public_key` (5) is optional.**
  - Present: the token is bound to that key, as before.
  - Absent: the token starts with `w17bot_` and is bound to no device. `IssueBotTokenResp.bearer` (5, new) is true and `device_id` is empty. The program must not send a DPoP proof with it: a proof beside a bearer token is refused.
- **A bearer token always expires.**
  - The expiry is the request's `expires_at`. Without one, it is the deployment's `api_token_default_ttl_hours`, or 90 days when that is 0. "Never" is not offered.
  - It lies at most 366 days ahead. A later `expires_at` is refused with `TOKEN_EXPIRY_TOO_FAR` (`INVALID_ARGUMENT`, on `expires_at`), and a longer default is cut to 366 days.
- **Authenticate still refuses every proofless request** with `DEVICE_PROOF_REQUIRED` before the lookup, with one exception: where `service_account` is on, a token sent as `Bearer` (the configured scheme) with the `w17bot_` prefix, outside the MCP surface and the admin plane. A bearer token never opens the admin console.
  - That token passes only when its row is flagged `bearer`, belongs to a machine account and is bound to no device. Anything else gets the plain `invalid credentials`.
  - An ended bearer token answers `SESSION_EXPIRED`.
  - `AuthResp.device_id` is empty for it.
- **Migration** (`service_account`): new column `UserToken.bearer` (17, `FALSE` by default). Existing rows are unchanged, so every existing token keeps working exactly as it did.
- **API additions:**
  - New mutation `AuthMutation.IssueBotBearerToken` (`service_account`). It emits `ApiTokenCreated` with an empty `key_thumbprint`.
  - New fields `GetTokenWithTypeResp.bearer` (12) and `GetExpiredTokenWithTypeResp.bearer` (6).
- **Ending a bearer token:** revoke it on the admin `Sessions` page (`user_admin`, which `service_account` requires), or disable the machine account. A bound bot token also ends when its key's device is revoked; a bearer token has no device.

## 0.1.0-rc.25

### Upgrading to device identity (read first)

This release binds every token to a device key and stops deleting rows from the auth tables. The entries below give the details; this is the order to upgrade in.

1. **Platform and clients first.**
   - Move to platform 1.12 or newer and the w17ctl that comes with it. The console refuses this plugin on an older platform: its gateway does not verify the proofs, and every sign-in would be refused.
   - Regenerate the project, so the gateway verifies DPoP proofs and the admin, the generated clients and the e2e runner sign their requests.
   - Hand-written clients must send DPoP too: SDK `ts/dpop` in TypeScript, `dpopclient` in Go. A bound token goes as `Authorization: DPoP <token>` with a `DPoP` proof header, and every sign-in request needs a proof.
2. **Configure the gateway** (`<P>` is the surface's env prefix):
   - `<P>_DPOP_ORIGIN` is required: the public URL clients reach the REST surface (or the admin) at, with the base path when a proxy serves it under one. `<P>_RPC_DPOP_ORIGIN` is required with an rpc surface. The binary refuses to boot without them, and a wrong value refuses every proof.
   - `<P>_DPOP_NONCE_KEY` (base64, at least 32 bytes, the same on every replica) and `<P>_DPOP_REDIS_DSN` (the replay store every replica shares) are required in production.
   - `<P>_DPOP_SINGLE_REPLICA=true` (one replica, a per-boot nonce key, an in-memory replay store) is honoured only with `W17_ENV=dev`.
3. **Generate and apply the migration.** No row is deleted or rewritten: every existing row stays live, and old Device rows stay as history.
   - Base tier: new tables `Device` (where `devices` was off) and `SignInEvent`. New columns: `UserToken.device_id`, `mcp_only`, `revoked_at`, `revoked_by`, `revoke_reason`, `public_computer`, `approved_by_device_id`, and `User.device_trust_revoked_at`. Where `devices` was on, `Device` gains `thumbprint`, `revoked_at` and `api_key`, and loses `identifier` and `trust_token_hash`.
   - `two_factor`: `MfaChallenge.thumbprint`, `public_computer`; `UserTotpSecret.revoked_at`, `ended_key`; `UserRecoveryCode.revoked_at`.
   - `cli_login`: `CliAuthCode.session_expires_at`, `approved_by_device_id`; `AuthClient.revoked_at`.
   - `user_admin`: `User.erased_at`.
   - `rbac`: `Role.deleted_at`, `ended_key`; `RolePermission.removed_at`, `removed_by`; `UserRole.revoked_at`, `revoked_by`, `ended_key`; new table `RolePermissionChange`.
   - `org_membership`: `Organization.deleted_at`, `ended_key`; `OrgMembership.removed_at`, `removed_by`, `ended_key`.
   - `org_invite`: `OrgInvite.closed_at`, `closed_by`.
   - `sign_up_confirmation`: `PendingSignUp.claimed_at`, `superseded_at`.
   - Unique indexes: `ended_key` joins the unique keys of `Role`, `Organization`, `OrgMembership`, `UserRole` and `UserTotpSecret`. `Role.name` and `Organization.slug` are unique among live rows only. The pending-invitation index also skips closed rows.
   - An upsert keyed on one of those columns alone now fails with "there is no unique or exclusion constraint matching the ON CONFLICT specification". That covers a fixture with `upsert_on: ["slug"]` (or `["name"]` on a role) and a hand-written `ON CONFLICT (slug)`. Key it on the new index instead: `["slug", "ended_key"]`, with `ended_key: ""` on the row. Codegen does not catch this; the seed fails at `stack build`.
4. **Sign in again and re-issue tokens.**
   - Every existing session is refused once, so everyone signs in again, one time. A pending second-factor challenge has to be started over.
   - API tokens and machine-account tokens issued before this release are refused. Issue them again with the public JWK of the program that uses them: `w17ctl key public`, or the SDKs' keygen helper. The program then signs every request with that key.
5. **Update project code that calls the plugin's storage directly.**
   - Renamed: `DeleteToken` → `RevokeToken`, `DeleteSessionToken` → `RevokeSessionToken`, `DeleteApiToken` → `MarkApiTokenRevoked`, `DeleteOtherSessionTokens` → `RevokeOtherSessionTokens`, `DeleteUserSessionsForReset` → `RevokeTokensForReset`, `DeleteDeviceTokens` → `RevokeDeviceTokens`, `DeleteUndevicedSessions` → `RevokeUndevicedSessions`, `DeleteAllUserTokens` → `RevokeAllUserTokens`, `DeleteAuthClient` → `RevokeAuthClient`, and `DeleteUser` → `BeginUserErasure` + `EraseUser` (through `AuthService.EraseAccount`, or `AuthService.EraseUsers` for several).
   - Also renamed: `DeleteOrgMembership` → `MarkOrgMembershipRemoved`, `DeleteOrgInvite` → `CloseOrgInvite`, `ClearExpiredOrgInvite` → `CloseExpiredOrgInvite`, `DeletePendingSignUpsForEmail` → `SupersedePendingSignUpsForEmail`, `DeleteTotpSecret` → `RevokeTotpSecret`, and `DeleteRecoveryCodes` → `RevokeRecoveryCodes`. `AuthService.DeleteClient` keeps its name and route and now revokes the registration.
   - Removed: `DeleteTokenPermissions`, `PurgeExpiredPendingSignUps`, and the device rpcs `GetDeviceByIdentifier`, `CreateDevice`, `TouchDevice`, `DeleteDevice` and `DeleteAllUserDevices` (now `RegisterDevice` and `MarkDeviceRevoked`). The `X-Device-Id` and `X-Device-Trust` headers and `device_trust_token` are gone too.
   - Changed requests and responses:
     - `IssueToken` requires `device_id`.
     - `RevokeDeviceTokensReq` requires `revoked_by` and `keep_token_id` (the nil UUID keeps none).
     - `CreateApiTokenReq` and `IssueBotTokenReq` require `public_key`.
     - `AuthQuery.GetUserToken` returns `UserTokenAdminDetail`.
     - Several revoke responses are empty now.
   - Roles: `AddPermissionToRole` revives a removed pair and still refuses one the role holds (`ALREADY_EXISTS`). It and `AssignRoleToUser` refuse a deleted or unknown role (`NOT_FOUND` / `ROLE_NOT_FOUND`). A preset role deleted at runtime stays deleted across re-seeds; declare it under a new key to bring it back.
   - Events: `UserDeleted` (`auth.user.deleted`) keeps its name and topic; the erasure emits it (erasure is the plugin's deletion). New `ApiTokenCreated`. The token and MFA events carry `device_id`.
6. **The admin changes.**
   - The `delete` on the Users, ServiceAccounts and Sessions pages stays, with its button, its permission (the model's `delete`) and its response, so hand-written admin tests (`admin.Users.Delete` → `user_id`, `admin.Sessions.Delete` → `token_id`) keep passing. It no longer deletes: on Users and ServiceAccounts it erases the account (`AuthService.EraseAccount`), on Sessions it revokes the token (`AuthService.RevokeSession`), the operator recorded either way. Revoked and erased rows stay listed.
   - New pages, opt-in: `Devices` (feature `admin_devices`) and `SignIns` (feature `admin_sign_ins`), both requiring `user_admin`. The upgrade adds no page to an existing activation. To get them, enable the features and, if your admin declares `nav` groups, add the pages to one: an admin with nav groups must list every page, and the build refuses one it does not list.
   - The Sessions page shows each session's device by its label, without a link to the Devices page.
   - The admin's sign-in form has a "This is a public computer" box, and the app's sign-in requests take `public_computer`. Such a session never trusts the device, is kept in session storage only, and expires after `public_session_ttl_seconds`.
   - Federated (OAuth) sign-in to the admin needs `oauth` enabled on the admin's realm. Without it the sign-in returns a token bound to no key, and the admin refuses it.
7. **Opt-in features.** Everything this release adds to a published surface is behind a feature that is off by default, so an upgrade adds no page, endpoint, admin action, permission or scaffolded e2e test to an existing activation:
   - `admin_sign_ins` — the admin `SignIns` page (requires `user_admin`).
   - `admin_devices` — the admin `Devices` page and its `Revoke` action (requires `user_admin`).
   - `my_sign_ins` — `GET /auth/sign-ins`, the caller's own sign-in history (requires `authenticate_turnkey`).
   - `client_secret_rotation` — `POST /auth/clients/{id}/rotate-secret` (requires `cli_login`).

   One addition is not optional: with `oauth`, `POST /auth/oauth/exchange` is published, because the callback now hands the browser a login code instead of a session and the exchange is the only way to redeem it. A project with `oauth` gets a scaffolded e2e test for it on the next generation and should write it (or keep its own test of the OAuth flow).
8. **Known limits.**
   - MCP clients keep their OAuth flow without DPoP. Their tokens (`mcp_only`) are accepted only on the MCP surface.
   - On a surface that binds devices, the e2e runner skips MCP scenarios and counts the skips.

### A CLI login lasts only as long as the session that approved it (`cli_login`)

`CliToken` used to mint a session with the full `session_token_ttl_seconds`, so a browser session could renew itself indefinitely: approve a CLI login shortly before it expired, receive a fresh full-lifetime session, repeat.

- **The CLI session now inherits the approving session's expiry.** It expires at the earlier of the normal session TTL from now and the expiry of the browser session that approved it, with no minimum. An approving session that never expires gives the normal TTL. A CLI login therefore ends when the browser session that approved it would have, and signing in again in the browser is what starts a new lifetime.
- **`CliAuthorize` refuses an approving session that is no longer live** (revoked, expired) with the opaque `UNAUTHENTICATED`, and `CliToken` refuses a code whose approving session expired before the exchange.
- **New column `CliAuthCode.session_expires_at`** (nullable `DATETIME`) and new query `AuthQuery.GetLiveSessionExpiry`, both under `cli_login`. Generate a migration for the new column.

### Every token is bound to a device key (breaking)

A session used to be a bearer token that worked from anywhere until it expired. Now every token is bound to the device that signed in: a key pair its client holds, identified by the RFC 7638 thumbprint of its public key. The client proves it holds the key on every request with a DPoP proof (RFC 9449); the gateway verifies the proof and passes the plugin only the thumbprint.

- **Every existing session is refused once.** Sessions issued before this version carry no binding, so the next request with one is refused (`DEVICE_PROOF_REQUIRED` without a proof, `invalid credentials` with one) and the person signs in again, one time. API tokens issued before it are refused the same way. Later upgrades do not sign anybody out.
- **Clients must send DPoP proofs.** A bound token goes as `Authorization: DPoP <token>` with a `DPoP` proof header; every sign-in request (`SignIn`, `SignUp` when it issues a session, `ConfirmSignUp`, `VerifyMfa`, `OAuthExchange`, `CliToken`) needs a proof too, and is refused without one before anything else happens. The gateway verifies the proofs from platform 1.12 on, which this version requires; the generated TypeScript client, the SDKs and w17ctl sign for you once updated. Deploy them together.
- **New refusals** (`UNAUTHENTICATED`, with an `ErrorDetail` and a `google.rpc.ErrorInfo` in domain `auth.w17`): `DEVICE_PROOF_REQUIRED` (no proof — decided before the token is looked up, so it says nothing about the token) and `DEVICE_REVOKED` (said only to the holder of the bound key; the client generates a new key and signs in as a new device). `SESSION_EXPIRED` is now also said only to the holder of the bound key. A token proved by another key, bound to none, or unknown is the same plain `invalid credentials`: a stolen token without its key tells its holder nothing. The `DPoP` scheme is matched case-insensitively.
- **MCP keeps its OAuth flow without DPoP.** New column `UserToken.mcp_only` (default false): a token minted by the MCP OAuth flow is accepted without a proof, only on the surface the gateway marks `x-w17-surface: mcp`, and refused everywhere else.
- **VerifyMfa must be signed by the key of the SignIn it completes.** New column `MfaChallenge.thumbprint` (nullable); a challenge raised before this version cannot be completed (sign in again).
- **`AuthResp.device_id`** carries the verified device of every authenticated request.
- **Device identity is base tier.** The `Device` table, `UserToken.device_id` and `User.device_trust_revoked_at` exist in every activation. The `devices` feature is now only the management endpoints (`ListDevices`, `RevokeDevice`, `RevokeOtherDevices`, `RevokeAllDevices`); revoking a device stamps `Device.revoked_at` instead of deleting the row, so the key stays refused for good (what else a revocation ends: see the Devices page entry). `two_factor_scope=new_devices` works without `devices`, and trust belongs to the (account, device) pair.
- **Removed:** the `X-Device-Id` and `X-Device-Trust` headers, the device trust token (`device_trust_token` on `SignInResp`, `VerifyMfaResp` and `OAuthExchangeResp`), `Device.identifier`, `Device.trust_token_hash`, and the storage rpcs `GetDeviceByIdentifier`, `CreateDevice`, `TouchDevice`, `DeleteDevice` and `DeleteAllUserDevices` (replaced by `RegisterDevice` and `MarkDeviceRevoked`; no statement deletes a Device row). `IssueToken` now requires `device_id`.
- **API tokens and machine-account tokens are bound to the key of the program that uses them**, never to the browser that created them: `CreateApiToken` and `IssueBotToken` take that key (see "API tokens and machine-account tokens are bound to the program's key").
- **Migration.** Generate and apply a migration: new table `Device` (unique `(user_id, thumbprint)`) and columns `UserToken.device_id`, `UserToken.mcp_only`, `MfaChallenge.thumbprint` (with `two_factor`) and `User.device_trust_revoked_at` where the `devices` feature was off; where it was on, `Device` loses `identifier` and `trust_token_hash` and gains `thumbprint` (nullable) and `revoked_at`. **No data is cleared:** existing Device rows stay as history with a NULL `thumbprint`. They name no key, so nothing can sign in with them, a token bound to one is refused like any unbound token, and `ListDevices` leaves them out; they remain in the table for audit. Every device signs in once more and is registered as new.

### Operators see and revoke devices; "this is a public computer"; a CLI login records its approver

An operator could revoke a session but not a device, and could not see which device a session belonged to. A sign-in at a shared computer was treated like any other: the device could become trusted and the session lasted the full lifetime. A CLI session did not say which browser had approved it.

- **New admin page `Devices`**, opt-in: enable the new feature `admin_devices` (requires `user_admin`) and, if your admin declares `nav` groups, add `Devices` to one — an admin with nav groups must list every page. It is not part of `user_admin`, so upgrading adds no page to an existing activation. The page lists every device of every account — the owner, label, key thumbprint, address, first and last seen, `trusted_at`, the account's last trust revocation, whether the trust still stands (`trusted`), and `revoked_at`. Revoked devices and legacy ones (recorded before device binding, no key) are listed too. New queries `AuthQuery.ListAllDevices` (cursor-paged, the newest first by `created_at`) and `GetDevice`, projection `DeviceAdminRow`.
- **Its `Revoke` action** (`AuthService.RevokeDevices`) revokes each selected device for good and every token bound to it — reason `DEVICE_REVOKED`, the operator as `revoked_by` — in one transaction per device. The key can never sign in to that account again (`DEVICE_REVOKED`). A device already revoked keeps its first revocation; revoking it again only ends the API tokens it created (see the machine keys entry). An empty selection is refused. A legacy device can be revoked like any other.
- **Revoking a device also ends the CLI sessions it approved** (`UserToken.approved_by_device_id`), from the Devices page and from the owner's own `RevokeDevice` / `RevokeOtherDevices` / `RevokeAllDevices`: a stolen browser session could otherwise approve the thief's own CLI key, and that CLI session would outlive the revoked device. `RevokeDeviceTokens` runs a second statement for them (same reason, actor and account) that spares `keep_token_id` (new, 4; required — pass the nil UUID to keep none): `RevokeOtherDevices` keeps the caller's own session, even when the caller is a CLI session one of those devices approved. A CLI code approved by a device revoked before the CLI redeems it mints nothing (new query `AuthQuery.GetCliApproverRevocation`, `cli_login`); the refusal is the opaque one, recorded as `REFUSED`. Ending the approving browser *session* (Logout, the admin Sessions revoke) leaves the CLI sessions it approved alive, by design: revoke the device, or the CLI session itself.
- **`AuthMutation.RevokeDeviceTokens` and `MarkDeviceRevoked` are base tier now** (they were `devices` only), and `RevokeDeviceTokensReq` has a new required `revoked_by` (3). Project code calling `RevokeDeviceTokens` directly must pass it — the device's owner, as the `devices` calls do.
- **The `Sessions` page shows each session's device**: its label (`device_label`; not a link, since the Devices page is opt-in), its key thumbprint, and `public_computer`. The detail (`AuthQuery.GetUserToken`, which now returns `UserTokenAdminDetail` instead of `UserToken`) adds the device, whether it is a public-computer session and, for a CLI session, the device that approved it.
- **"This is a public computer."** `SignInReq` (3), `OAuthExchangeReq` (4), `SignUpReq` (5) and `ConfirmSignUpReq` (3) take `public_computer`; `VerifyMfa` takes the choice from its challenge (`MfaChallenge.public_computer`, `two_factor`), never from its own request. Such a session never makes the device trusted, even after a passed second factor, and does not use trust the device already had, so `two_factor_scope=new_devices` asks the second factor at every sign-in from it. It expires after the new **`public_session_ttl_seconds`** (default 0 = 8 hours, capped at the session lifetime, so a deployment with sessions shorter than 8 hours boots unchanged); only an explicit value longer than `session_token_ttl_seconds` fails the boot. The responses (`SignInResp` 6, `VerifyMfaResp` 4, `OAuthExchangeResp` 4, `SignUpResp` 5, `ConfirmSignUpResp` 3) echo it, so the client keeps the token in session storage only (the clients' part comes with the SDK release). `CliToken` has no such option.
- **New columns** `UserToken.public_computer` (15) and `SignInEvent.public_computer` (11), both `FALSE` by default; the admin `SignIns` detail and `ListMySignInEvents` show it.
- **A CLI login records the browser that approved it.** `CliAuthorize` reads the Device row the approving session is bound to (`GetLiveSessionExpiry` now also returns `device_id`) onto the code (`CliAuthCode.approved_by_device_id`, 11), and `CliToken` writes it on the CLI session (`UserToken.approved_by_device_id`, 16). The CLI session stays bound to the CLI's own key.
- **Erasure:** nothing new to erase. The new columns are a flag and references to Device rows, whose label and address an erasure already blanks.
- **Migration.** Generate and apply a migration: new columns `UserToken.public_computer`, `UserToken.approved_by_device_id`, `SignInEvent.public_computer`, and with `two_factor` `MfaChallenge.public_computer`, with `cli_login` `CliAuthCode.approved_by_device_id`. Existing rows take the defaults (`FALSE`, NULL).

### A password change or a disable ends device trust

With `devices`, a trusted device used to stay trusted after the account's password was changed or the account was disabled, so under `two_factor_scope=new_devices` it kept skipping the second factor, also for whoever had signed in from it with the old password.

- **`ChangePassword` (`password_change`) and `DisableUsers` (`user_admin`) now end the trust of every device of the account**, in the same statement that writes the new password or `disabled_at`. The session a change came from keeps working, but its device passes the second factor again on the next sign-in; so does every device of a re-enabled account. `ListDevices` shows these devices as untrusted. A sign-in already in flight when the change commits cannot trust the device after it.
- **A password reset still keeps device trust**, unchanged.
- **New column `User.device_trust_revoked_at`** (nullable, base tier with device binding) and query `AuthQuery.GetDeviceTrustRevokedAt`; it is part of the device-binding migration.
- **OAuth sign-in does not ask for the plugin's second factor**, also for an account that has one confirmed. This is now a recorded decision, not an open question: the provider already verified the identity. An OAuth sign-in still never makes the device trusted.

### `src/gen` is generated, not shipped

- **Needs w17ctl v0.1.0-rc.75 or newer.** The release no longer carries `src/gen` (the pb, the `EnvConfig` / `ClientSet` / `HandlerRegistry` contract and the feature constants). A consumer's staging generates all of it for each activation from `plugin.yaml` and the protos, and w17ctl does that from rc.75 on. An older w17ctl expects the release to carry the contract; upgrade it before you take this release.
- Nothing in your project changes: the same activation, the same env variables, the same configuration, no migration.

### API tokens and machine-account tokens are bound to the program's key (breaking)

An API token's device is the program that uses it — a CI job, a script, a machine account — not the browser that created it, and a token bound to that browser would be useless to the program. The request carries the program's public key and the token is bound to it. An API token issued before this version is refused like any unbound token: issue it again with the program's key.

- **`CreateApiTokenReq.public_key` (4) and `IssueBotTokenReq.public_key` (5) are required**: the JSON of a PUBLIC JWK, `{"kty":"EC","crv":"P-256","x":…,"y":…}` or `{"kty":"OKP","crv":"Ed25519","x":…}`. The plugin computes its RFC 7638 thumbprint, registers it as a device of the token's owner (labelled `API token: <name>` or `Machine account key`) and binds the token to it. `CreateApiTokenResp.device_id` (4) and `IssueBotTokenResp.device_id` (4) return the thumbprint. The program sends `Authorization: DPoP <token>` with a DPoP proof signed by its key on every request; without one, or signed by another key, the token is refused exactly like a session.
- **The key is read strictly.** One JSON object of at most 1024 bytes, no duplicate member; base64url coordinates of 32 bytes in their canonical spelling (no line breaks); a P-256 point on the curve; only the members a key export carries (`alg`, `use`, `key_ops`, `kid`, `ext`) beside the key's own, none of them `null`. **A JWK with any private member is refused** before anything else is read, and nothing of it is stored, logged or repeated back.
- **New refusals**, on the `public_key` field with an `ErrorDetail` only (never `UNAUTHENTICATED`): `DEVICE_KEY_REQUIRED` and `DEVICE_KEY_INVALID` (`INVALID_ARGUMENT`; a request with no `public_key` at all is refused earlier by the gateway's field validation, `INVALID_ARGUMENT` with `REQUIRED_VIOLATION` on `public_key`, so `DEVICE_KEY_REQUIRED` reaches only callers that bypass it, such as in-process project code), `DEVICE_KEY_REVOKED` (`FAILED_PRECONDITION`: the key's device was revoked for good — generate a new key), `BOT_KEY_MISMATCH` (`FAILED_PRECONDITION`).
- **`IssueBotToken` needs a signed-in session**, as `CreateApiToken` does (`PERMISSION_DENIED`, `SESSION_REQUIRED`): an API token — a machine account's own, or an operator's — no longer mints machine tokens.
- **A machine account has exactly one key.** Its first token registers it; later tokens must name the same key (its replicas share it), another is refused with `BOT_KEY_MISMATCH`. To replace it, revoke the account's device on the admin `Devices` page, then issue with the new key. New queries `AuthQuery.LockMachineAccount` and `ListMachineKeys` (`service_account`).
- **A key is a program's or a signed-in device's, never both.** New column `Device.api_key` (12, `FALSE` by default; `RegisterDeviceReq.api_key`, 5, written when the row is created). A program's key never signs in, the key of a device that signs in is refused for an API token (`DEVICE_KEY_INVALID`), and `ListDevices`, `RevokeOtherDevices` and `RevokeAllDevices` (`devices`) list and revoke signed-in devices only — API tokens keep surviving them. The admin `Devices` page lists every key, so an operator can end an API token by revoking its key.
- **The creator is recorded.** The creating caller's device (the operator's, for a machine account) is stored as `UserToken.approved_by_device_id` (new `IssueApiTokenReq.device_id` 6, required, and `approved_by_device_id` 7; new query `AuthQuery.GetUserDeviceByThumbprint`, `api_token`). Revoking that ONE device on purpose — the owner's `RevokeDevice`, the admin `Devices` revoke — ends the API tokens it created too (new mutation `AuthMutation.RevokeApprovedApiTokens`, `api_token`): a stolen browser session could have created one bound to the thief's key. `RevokeOtherDevices` and `RevokeAllDevices` keep sparing API tokens (`RevokeDeviceTokens`' second statement now matches session tokens only). A machine account's tokens are the account's, not the operator's, so revoking the operator's device leaves them.
- **The creator recorded is the ROOT approver**: for a token created from a CLI session, the browser that approved the CLI login (new query `AuthQuery.GetSessionApprover`), so revoking that browser ends the CLI session and the token. The admin `Devices` page revokes an already revoked device again only to end the API tokens it created.
- **New event `ApiTokenCreated`** (`auth.api_token.created`, `api_token`), emitted for every new API token, a machine account's included: `token_id`, `user_id` (the owner), `created_at`, `name`, `device_id` (the creating request's key — a CLI's own), `key_thumbprint` (the program's key), `created_by`. No secret. `IssueApiTokenReq` takes the event-only `thumbprint` (8), `key_thumbprint` (9) and `created_by` (10).
- **After a compromise**: "sign out everywhere else" and a password change keep API tokens; review `ListApiTokens` and revoke the stolen device itself (see README).
- **Issuance is in the sign-in history**: methods `API_TOKEN` (7) and `BOT_TOKEN` (8) and outcome `KEY_REFUSED` (19); one row per call, the success row in the transaction that mints the token.
- **`ListApiTokens` shows each token's key**: `ApiTokenInfo.device_thumbprint` (8) and `device_revoked_at` (9).
- **Migration.** Generate and apply a migration: new column `Device.api_key` (`FALSE` on existing rows — every existing device signed in). Callers of `CreateApiToken` and `IssueBotToken` must send `public_key`; the SDKs' key helper comes with the client release.

### Nothing in the auth tables is deleted, in any table (breaking)

Tokens, accounts, devices and clients are kept (see "Tokens, accounts and clients are revoked, not deleted" and the device binding); the remaining sixteen `DELETE` statements — roles, role grants, role permissions, organizations, memberships, invitations, pending sign-ups, authenticators and recovery codes — are now state changes too. The rows stay as the history, and every read skips ended rows, so what callers and permission checks see is what the delete gave. A test now refuses any `DELETE` in any auth proto or in the plugin's Go.

- **How a removed key is reused.** A table whose key must be reusable after a removal gets an `ended_key` column (`''` while live, the row's own id once ended) inside its unique index: `Role (name, ended_key)`, `Organization (slug, ended_key)`, `OrgMembership (user_id, org_id, ended_key)`, `UserRole (user_id, role_id[, org_id], ended_key)` (all three variants), `UserTotpSecret (user_id, ended_key)`. Re-adding is the same INSERT and creates a new row; the ended row is never rewritten. `Role.name` and `Organization.slug` are no longer unique on their own (a deleted role's name and a deleted organization's slug can be taken again, as before). `RolePermission` keeps its `(role_id, permission_id)` index — the platform's role seed upserts on it — and revives instead: see below.
- **rbac.** `DeleteRole` stamps `Role.deleted_at`, revokes every grant of the role and frees its name; its permission rows stay. **A preset role deleted at runtime now stays deleted**: it keeps its `preset_key`, and the role seed (which matches on that key and never writes `deleted_at`) leaves it deleted on every re-seed, where it used to re-create it. To bring it back, declare it under a new key. `RevokeRoleFromUser` stamps `UserRole.revoked_at` and takes an optional `revoked_by`. `RemovePermissionFromRole` stamps `RolePermission.removed_at` and takes an optional `removed_by`. `AddPermissionToRole` is an UPSERT that revives a removed pair, behind two guards: a deleted or unknown role is refused with `NOT_FOUND` / `ROLE_NOT_FOUND` (by a no-op UPDATE that locks the role row, so concurrent writes naming one role run one after another), and a permission the role already carries with `ALREADY_EXISTS` / `PERMISSION_ALREADY_GRANTED` (as before); so `RolePermissionAdded` and the log row come only from a real change. It takes an optional `added_by`. **`AssignRoleToUser` refuses a deleted or unknown role** (`NOT_FOUND` / `ROLE_NOT_FOUND`; it used to insert a grant for any id), and `ListUserOrgGrants` skips grants of deleted roles. Both permission calls append to the new append-only table `RolePermissionChange` (`role_id`, `permission_id`, `kind` ADDED/REMOVED — new enum `RolePermissionChangeKind` — `changed_by`). `UpdateRole` refuses a deleted role (NotFound). Every role and permission query skips deleted roles, revoked grants and removed permissions; **`GetUserPermissions` now joins `Role`**, so a deleted role's permissions are no longer reported (it used to keep granting them).
- **org_membership.** `DeleteOrganization` stamps `Organization.deleted_at`, removes the organization's memberships and revokes its org-scoped grants, and frees its slug. The admin Organizations page now deletes through the new **`AuthService.RemoveOrganization`**, which first closes the organization's pending invitations (with `org_invite`: new mutation `CloseOrgInvitesOfOrg`, the caller as `closed_by`) and then calls `DeleteOrganization`, in one transaction. **`DeleteOrgMembership` is renamed `MarkOrgMembershipRemoved`** (optional `removed_by`; `AuthService.RemoveOrgMembership` passes the caller): it stamps `removed_at` / `removed_by` and revokes the member's org grants with the same actor. `UpdateOrgMembership` takes an optional `changed_by` (passed by `UpdateOrgMembershipRole`), recorded as `revoked_by` on the grants a role change replaces. `UpdateOrganization` refuses a deleted organization. Every organization and membership query skips ended rows, so a deleted organization's `owner_id` grants nothing.
- **org_invite.** **`DeleteOrgInvite` is renamed `CloseOrgInvite`** (optional `closed_by`; `RevokeOrgInvite` passes the caller) and **`ClearExpiredOrgInvite` `CloseExpiredOrgInvite`**: both stamp `OrgInvite.closed_at`. The pending index becomes `(org_id, email) WHERE accepted_at IS NULL AND closed_at IS NULL`. A closed invitation is refused like a spent one and is not listed. `GetPendingOrgInviteByToken`, `BindOpenOrgInvite`, `ConsumeOrgInviteByToken` and `ListPendingInvitesForEmail` also require the invitation's organization to be live, so a deleted organization's invitations cannot be used even when it was deleted through `AuthMutation.DeleteOrganization` directly.
- **sign_up_confirmation.** `ClaimPendingSignUp` is `UPDATE … SET claimed_at = NOW() … RETURNING` (still exactly-once). **`DeletePendingSignUpsForEmail` is renamed `SupersedePendingSignUpsForEmail`** (stamps `superseded_at`), and **`PurgeExpiredPendingSignUps` is removed** — SignUp no longer purges; an expired registration stays, refused by its `expires_at`. New eraser `ErasePendingSignUpAddress`: an erasure (`EraseUsers`) now also ends the address's pending registrations and replaces their address and hashes, since they are no longer deleted at confirmation.
- **two_factor.** **`DeleteTotpSecret` is renamed `RevokeTotpSecret`**: it stamps `UserTotpSecret.revoked_at` and clears `seed` and `secret`; **`DeleteRecoveryCodes` is renamed `RevokeRecoveryCodes`**: it stamps `UserRecoveryCode.revoked_at` on the unused codes. A revoked authenticator verifies nothing and a revoked code is refused like a used one. `TotpDisabled` still fires on both disable and re-enrolment.
- **Events** keep their names and payloads.
- **Migration.** Generate and apply a migration: new columns `Role.deleted_at`, `Role.ended_key`, `RolePermission.removed_at` / `removed_by`, `UserRole.revoked_at` / `revoked_by` / `ended_key` (rbac); table `RolePermissionChange` (rbac); `Organization.deleted_at` / `ended_key`, `OrgMembership.removed_at` / `removed_by` / `ended_key` (org_membership); `OrgInvite.closed_at` / `closed_by` (org_invite); `PendingSignUp.claimed_at` / `superseded_at` (sign_up_confirmation); `UserTotpSecret.revoked_at` / `ended_key`, `UserRecoveryCode.revoked_at` (two_factor). The unique indexes listed above are replaced. No data changes: every existing row is live (`ended_key` `''`, every new state column NULL).
- **The platform's role seed** of a release that knows `RolePermission.removed_at` ends the rows a declaration drops instead of deleting them, revives a declared permission removed at runtime (only a change to the declaration removes a seeded permission for good), and logs its changes in `RolePermissionChange`; it leaves a deleted role's permissions alone. An older platform still prunes with a `DELETE`: update both together.

### Tokens, accounts and clients are revoked, not deleted (breaking)

Revoking a token, erasing an account and revoking a registered client used to delete rows, so afterwards nobody could say which credential had existed, who ended it or why. Every one of those paths now writes a state instead, and the rows stay as the history.

- **Tokens are revoked, not deleted.** New base-tier columns `UserToken.revoked_at` (nullable), `UserToken.revoked_by` (nullable UUID: the holder for a logout, an API-token revoke, a password change and the devices calls; the operator for an admin revoke or an erasure; NULL for a reset, a disable and `RevokeToken`) and `UserToken.revoke_reason` (new enum `RevokeReason`, default `REVOKE_REASON_NONE`). The first revocation stands: every revoking statement is guarded on `revoked_at IS NULL`, so revoking a revoked token changes nothing and is not an error.
- **A revoked token is refused exactly as an expired one.** Every token lookup filters `revoked_at IS NULL` beside the expiry. The holder of the bound key hears `SESSION_EXPIRED`, dated when the token ended, or `DEVICE_REVOKED` when its device was revoked; anyone else the plain `invalid credentials`. Until now a revoked token, being gone, always answered `invalid credentials`. `GetExpiredToken` / `GetExpiredTokenWithType` read revoked rows too and return `revoked_at` and `device_revoked_at`; their `expires_at` is now nullable.
- **Expired tokens stay**, refused by their `expires_at`; nothing sweeps them.
- **Storage mutations renamed** to say what they do: `DeleteToken` → `RevokeToken`, `DeleteSessionToken` → `RevokeSessionToken`, `DeleteApiToken` → `MarkApiTokenRevoked`, `DeleteOtherSessionTokens` → `RevokeOtherSessionTokens`, `DeleteUserSessionsForReset` → `RevokeTokensForReset`, `DeleteDeviceTokens` → `RevokeDeviceTokens`, `DeleteUndevicedSessions` → `RevokeUndevicedSessions`, `DeleteAllUserTokens` → `RevokeAllUserTokens`, `DeleteAuthClient` → `RevokeAuthClient`, `DeleteUser` → `EraseUser`. `DeleteTokenPermissions` is removed: a revoked API token keeps its subset rows. `RevokeUserToken` keeps its name, revokes instead of deleting and takes `revoked_by`. Several responses lost the ids of the rows they deleted (`RevokeTokensForResetResp`, `RevokeDeviceTokensResp`, `RevokeUndevicedSessionsResp`, `RevokeAllUserTokensResp` are empty). Project code calling any of them by the old name must be updated.
- **`DeleteUser` is now erasure (GDPR) by pseudonymisation** (`user_admin`). New column `User.erased_at`, new service methods `AuthService.EraseAccount` (one account) and `AuthService.EraseUsers` (the bulk form) and storage mutations `AuthMutation.BeginUserErasure` (first: access ends) and `AuthMutation.EraseUser` (last: the address and `erased_at`). The row stays (one transaction with a transaction coordinator; without one a partial erasure has already ended the account's access and retrying completes it); its address becomes `erased-<id>@erased.invalid` (the old address can sign up again; the `erased.invalid` domain is now refused with `INVALID_ARGUMENT` / `EMAIL_INVALID` at SignUp, ConfirmSignUp, OAuth account creation, CreateBot and the admin Users page's update, which now goes through the new `AuthService.UpdateAccount`), the password hash becomes the unusable `!`, the account is disabled, every token is revoked (`REVOKE_REASON_USER_ERASED`) and every device revoked with its label and IP blanked. With the matching features on, the same transaction blanks OAuth identities (the provider subject is replaced, so the person can sign up through the provider again) and login codes (including those of the sign-in that created the account), clears the authenticator seed and spends recovery codes and pending challenges, spends reset and verification links, and clears the address on invitations sent to it (a pending one is ended) (new mutations `EraseOAuthData`, `EraseTwoFactorData`, `SpendEmailVerificationTokens`, `EraseOrgInviteAddress`). `EnableUsers` leaves an erased account disabled and `UpdateUser` refuses it. A second erase is a no-op.
- **Event `UserDeleted` (`auth.user.deleted`) keeps its name, topic and fields**; the erasure emits it. Erasure is the plugin's deletion, so a subscriber that cleaned up on a delete erases its copy of the person's data there. Nothing to re-subscribe, and a project's events lock is unchanged.
- **Admin pages: `delete` erases or revokes; nothing is deleted.** The Users and ServiceAccounts pages keep their `delete` (same button, same model `delete` permission, same response `user_id`), now bound to `AuthService.EraseAccount`, which erases the account with the operator recorded. The Sessions page keeps its `delete` (response `token_id`), now bound to `AuthService.RevokeSession`, which revokes the token with the operator recorded as `revoked_by`; revoked sessions stay listed with `revoked_at` and `revoke_reason`. No page action is added, so an existing admin gets no new permission and no new scaffolded e2e test. Users lists `erased_at`. The bulk forms `AuthService.EraseUsers` and `AuthService.RevokeSessions` are for project code and refuse an empty selection.
- **Registered clients are revoked, not deleted** (`cli_login`). New column `AuthClient.revoked_at`. The unique `(client_id, redirect_uri)` index is unchanged, so a revoked pair stays taken: `RegisterClient` refuses it with `FAILED_PRECONDITION` / `CLIENT_REVOKED`; register the callback under a new `client_id`. A client that lost its secret keeps its `client_id` through the new `AuthService.RotateClientSecret` (`POST /auth/clients/{id}/rotate-secret`, published by the new opt-in feature `client_secret_rotation`, which requires `cli_login`; storage `RotateAuthClientSecret`), which refuses a revoked registration. `AuthService.DeleteClient` keeps its name, request and route (`DELETE /auth/clients/{id}`) and now revokes; a revoked registration is refused exactly as an unregistered one, `SetClientEnabled` cannot restore it, and `ListClients` shows it with `revoked_at`.
- **`ListApiTokens`** lists revoked tokens too, with `revoked_at` and `revoke_reason` (new `ApiTokenInfo` fields).
- **`ResetPasswordResp.sessions_revoked`** is now true for an account that held no live token (the revocation no longer answers NotFound for nothing to do).
- **Migration.** Generate and apply a migration: new columns `UserToken.revoked_at`, `revoked_by`, `revoke_reason` (default 0), `User.erased_at` (with `user_admin`) and `AuthClient.revoked_at` (with `cli_login`). No data changes: every existing token is live (`revoke_reason` 0), every existing registration live.

### An expired session says so, with its date

An expired bearer used to answer the same `UNAUTHENTICATED: invalid credentials` as an unknown one, so a client could not tell that signing in again would fix it.

- **An expired token now answers `SESSION_EXPIRED`.** A token that exists and is past its `expires_at` is refused with `UNAUTHENTICATED` carrying an `ErrorDetail` (code `SESSION_EXPIRED`, a translated sentence naming the expiry date) and a `google.rpc.ErrorInfo` (reason `SESSION_EXPIRED`, domain `auth.w17`, metadata `expires_at` in RFC 3339 UTC). An expired API token answers the same code, with a sentence that says to create a new token. With device binding (same release) the code is said only to the holder of the token's key, and a revoked token answers it too; anyone else, and an unknown token, gets `invalid credentials`, no detail. New queries `AuthQuery.GetExpiredToken` and `GetExpiredTokenWithType` (`api_token`); they run only when the normal lookup found nothing. Two new msgids reach the project catalog.
- **`last_used_at` is now written** (`api_token`) when a token authenticates, at most once a minute per token (application clock), by the new mutation `AuthMutation.TouchTokenLastUsed`. A failed write does not fail the request.
- **No migration** for this change: no column, table or index is added.

### Every sign-in attempt is recorded, and events name the device

The plugin kept no record of sign-in attempts: a failed password, a refused device or a burst of guesses at one address left nothing behind, and the token and MFA events did not say which device caused them.

- **New table `SignInEvent`** (base tier, append-only): `created_at`, `user_id` (NULL when the attempt reached no account), `address` (the address named, normalised), `device_id` (the Device row) and `thumbprint` (the proof's key, also when no Device row exists), `ip`, `user_agent`, `method` (new enum `SignInMethod`: PASSWORD, MFA, SIGN_UP, SIGN_UP_CONFIRM, OAUTH, CLI, API_TOKEN, BOT_TOKEN) and `outcome` (new enum `SignInOutcome`: OK, MFA_REQUIRED, UNKNOWN_ACCOUNT, WRONG_PASSWORD, ACCOUNT_DISABLED, MACHINE_ACCOUNT, DEVICE_PROOF_REQUIRED, DEVICE_REVOKED, WRONG_CODE, TOO_MANY_ATTEMPTS, OTHER_DEVICE, RATE_LIMITED, EMAIL_TAKEN, SIGN_UP_REFUSED, UNVERIFIED_EMAIL, CLIENT_REFUSED, ERROR, REFUSED, KEY_REFUSED). Indexes `(user_id, created_at)`, `(address, created_at)` and `created_at`.
- **Every attempt on every mint path writes exactly one row**: `SignIn` (the admin's sign-in too), `SignUp` when it issues a session, `ConfirmSignUp`, `VerifyMfa`, `OAuthExchange`, `CliToken`, `CreateApiToken` and `IssueBotToken`, whatever the outcome — a request without a proof and an unknown address included. A parked registration (`sign_up_confirmation`) records nothing. New mutation `AuthMutation.RecordSignInEvent`.
- **Nothing a caller gets changes.** A success writes its row in the transaction that issues the session (`SignIn`, `VerifyMfa`, `OAuthExchange` and `CliToken` now mint in one: IssueToken and the row; device trust is renewed after it commits), so a failed history write fails that sign-in. A refusal writes its row on its own; a failed write is logged and the refusal is unchanged.
- **A refusal's row is bounded**: written synchronously on a context the caller's cancellation does not end, for at most 2 seconds (plus half a second for the account read an erased-account check may need). A byte that is not UTF-8 in the address, user agent or client address is stored as U+FFFD (also in `Device.label` / `ip`).
- **An attempt at an erased account** (a challenge or an OAuth / CLI code issued before the erasure, the placeholder typed at SignIn) is written with the placeholder address and without `ip` / `user_agent`. `GetUserByEmail` now also projects `erased_at` (`user_admin`). When the account cannot be read, the row keeps no `ip` / `user_agent`.
- **`SignInEvent.device_id` is the Device row's UUID**; the key thumbprint the events call `device_id` is the `thumbprint` column, which the admin list shows.
- **`CliToken` reports a failed mint as its other refusals do** (opaque, or `AUTH_UNAVAILABLE` for an outage) instead of passing the store's error through.
- **The person's own history:** `AuthService.ListMySignInEvents`, REST `GET /auth/sign-ins`, published by the new opt-in feature `my_sign_ins` (requires `authenticate_turnkey`; off by default, so an upgrade adds no endpoint and no scaffolded e2e test): the caller's latest 100 rows, newest first. New query `AuthQuery.ListUserSignInEvents`.
- **The operator's:** a new admin page `SignIns`, opt-in: enable the new feature `admin_sign_ins` (requires `user_admin`) and, if your admin declares `nav` groups, add `SignIns` to one. It is not part of `user_admin`, so upgrading adds no page to an existing activation. Queries `ListSignInEvents` (cursor-paged) and `GetSignInEvent` (`user_admin`).
- **Erasure** (`EraseUsers`) also pseudonymises the history: the account's rows and the rows that reached no account but named its address get the placeholder address, and lose `ip` and `user_agent` (new mutation `EraseSignInEvents`, `user_admin`).
- **Events carry `device_id`** — the key thumbprint, the value of `AuthResp.device_id`: `TokenIssued` (4), `TokenRevoked` (3), `UserTokenRevoked` (2, the operator's device), `MfaChallengeRequested` (7), `MfaVerified` (3), `RecoveryCodeUsed` (2), `TotpEnrolled` (3), `TotpConfirmed` (2), `TotpDisabled` (2). Their mutations take an event-only `thumbprint` (`IssueTokenReq` 5, `RevokeSessionTokenReq` 4, `RevokeUserTokenReq` 3, `ConsumeMfaChallengeReq` 2, `ConsumeRecoveryCodeReq` 3, `CreateTotpSecretReq` 4, `ConfirmTotpSecretReq` 2, `RevokeTotpSecretReq` 2); project code calling them directly may pass one.
- **Migration.** Generate and apply a migration: the new table `SignInEvent`. No existing row changes.

### A provider can be configured outside the admin

`OAuthProvider` could only be created or edited on the generated admin page, and a fixture could set only the plaintext legacy `client_secret`, which the plugin moves to the encrypted `secret` and clears. A deployment that does not expose the admin had no way to put a provider's secret in place.

- **New mutation `AuthMutation.UpsertOAuthProvider`** (`oauth`) creates or rewrites a provider by `name`, writes `secret` encrypted with the project's field key and clears `client_secret`. Call it from the project's own code, for example at start with values from the deployment's secrets.
- **The provider's `name` is unique across tenants**; under `tenant_scope` the tenant is set when the provider is created.
- **A rewrite replaces every field.** A blank field clears it, and `enabled` left out turns the provider off, so send the whole configuration each time. It is meant for the project's own code, never for a name a tenant chose.

### The admin counts only realm-wide roles

The admin preset authenticated through `Authenticate`, which selects an organization (from the request, or the caller's only one) and lets that organization's roles grant permissions. A role scoped to one organization, a wildcard one above all, therefore passed every admin page for every organization. The same was true of organization ownership.

- **New `AuthService.AuthenticateAdmin`**, which the admin preset now uses as its `user_lookup`. It is `Authenticate` with no organization selected, so only realm-wide roles survive the narrowing, and ownership grants nothing. The admin is one console across every organization.
- **App endpoints are unchanged.** They keep `Authenticate` and its organization scoping.
- **A project that wires `user_lookup` by hand** should point it at `AuthenticateAdmin`.
- **An admin page over an `org_id`-scoped model now refuses** with `missing required scope: org_id`, for every caller. No organization means no `org_id` scope on the admin's storage calls. Such a page used to serve whichever single organization the caller belonged to, which was never the whole console.
- **`tenant_scope` is unchanged.** The admin still stamps the caller's `tenant_id`, so it stays inside the caller's tenant.

### OAuth and sign-up refusals carry a code

An OAuth refusal used to be the bare opaque `invalid credentials`, so a page could not tell a person what to do. Every OAuth handler now answers with an `ErrorDetail` code. The status code and message stay as they were.

| Code | When |
|---|---|
| `OAUTH_ACCOUNT_UNVERIFIED` | An account exists for the provider's address and never verified it, so it is not linked. |
| `OAUTH_EMAIL_UNVERIFIED` | An account exists for the address and the provider did not verify it. |
| `ACCOUNT_DISABLED` | The sign-in resolved to a disabled account. Only OAuth says this; a password sign-in still answers `INVALID_CREDENTIALS`. |
| `OAUTH_FAILED` | Everything else: the state, the login code, the verifier, the provider's answer. |

Saying these plainly tells an attacker nothing new. `OAUTH_ACCOUNT_UNVERIFIED` and `ACCOUNT_DISABLED` are reached only after the provider proved that the caller owns the address. `OAUTH_EMAIL_UNVERIFIED` is not, because the provider did not verify the address. It says only what the refusal already said: the callback succeeds when no account holds the address and refuses when one does.

Only refusals this plugin made pass through as they are. A storage answer that carries its own detail (not found, a timeout) is still classified, as an outage or as `OAUTH_FAILED`.

The sign-up gates gain codes too, on `SignUp` and the OAuth exchange alike. Outages still answer `AUTH_UNAVAILABLE`.

| Code | When |
|---|---|
| `SIGNUP_NOT_INVITED` | `invite_only`, and nothing invites the address. |
| `INVITE_OTHER_ADDRESS` | The invitation link is bound to another address (or an open link was already used by another registration), and nothing invites this one. The other address is not revealed. |
| `SIGNUP_CLOSED` | The address is outside `sign_up_allowlist`. |

### Registering through a provider can carry an invitation

Under `invite_only`, an OPEN invitation (one that names no address, for example sent by SMS) could not be used to register through a provider. The callback created the account and had no way to receive the token. Only a bound invitation whose address matched the provider's worked.

- **The callback no longer creates an account.** For an identity that has none, the login code keeps the provider-verified identity (subject, address, whether the provider verified it). `OAuthLoginCode` gains `provider_id`, `external_id`, `email` and `email_verified`, and `user_id` is now nullable.
- **`OAuthExchange` creates it, with the new `invite_token`.** The rules are the same as `SignUp`: the allowlist, `invite_only`, a bound invitation's address, and an open link spent by its first registration. Without a valid invitation the exchange refuses with the gate's coded refusal. The token travels only in the page's own exchange request, never in a URL or through the provider.
- **The user, its roles, the verified address, the spent invitation and the identity link commit together.** Before, the identity link was written after the user's transaction.
- **An identity that already has an account ignores the token.** The exchange resolves the identity again before creating, so a second login code for the same subject (another tab) signs in to the account the first one made instead of failing.
- **A refused registration spends the login code.** The page has to start the sign-in again, with the invitation, to retry.
- **Generate a migration.** `OAuthLoginCode` gains four columns and `user_id` becomes nullable; the new text columns default to empty, so existing rows migrate.

### One bootstrap administrator, even under concurrent first sign-ups

The `first_user` roles (typically every permission) were decided by reading "no users yet" before the sign-up transaction. Two sign-ups racing on an empty deployment both read zero, and both became administrators.

- **New table `BootstrapClaim` (rbac)** with one row on a constant key. Generate a migration as usual.
- **The sign-up that receives the `first_user` roles writes the claim** in its own transaction (`AuthMutation.ClaimBootstrapAdmin`, `UPSERT … ON CONFLICT DO NOTHING`). A concurrent sign-up waits on the key, conflicts, and gets the default roles. A rolled-back sign-up leaves the claim free.
- **The claim is never reopened.** Once an administrator was handed out, an empty user table does not hand out another. A deployment that already has users never writes the claim, and a seeded first account writes none either. Accounts are no longer deleted (an erased one stays as a pseudonymised row), so the user table never empties again and the bootstrap does not reopen there.

### An invitation to a role with a long name can be accepted

`OrgMembership.role` held 32 characters, while a role name holds 100. An invitation to a role whose name was longer than 32 characters was created, and then every acceptance failed when it wrote the membership. Changing a member to such a role on the admin's OrgMemberships page failed the same way.

- **`OrgMembership.role`, `AddOrgMembershipReq.role` and `UpdateOrgMembershipRoleReq.role` hold 100 characters**, as wide as `Role.name` (org_membership). Generate a migration as usual; it widens one column.

### A reset or a password change spends every other reset link

Each reset request inserts a new link, and a successful reset consumed only the link it used. Any other link the person had asked for, or one intercepted from their mailbox earlier, could set the password again until it expired. A password change left them all alive too.

- **`ResetPassword` and `ChangePassword` spend every live link of the account** in the same transaction as the new password. They use the new `AuthMutation.SpendPasswordResetTokens` (password_reset).
- **`password_change` without `password_reset`** builds and behaves as before: there are no links to spend.

### `password_change` builds without `api_token`

`DeleteOtherSessionTokens` filtered on `UserToken.token_type`, a column only `api_token` adds. An activation with `password_change` and without `api_token` failed code generation.

- **The filter is now `?feature(api_token) token_type = 1`.** Without `api_token`, every token is a session, and the sweep deletes the other ones.
- **`DeleteOtherSessionTokensReq` drops `token_type`** (field 3, now reserved). The statement names the session realm itself.

### `api_token` requires `rbac`

`GetUserRolePermissionsByRealm` reads `UserRole`, `Role` and `RolePermission`, the tables `rbac` adds. An activation with `api_token` and without `rbac` failed code generation; it is now refused by the manifest instead. `rbac` is on by default, so only an activation that turned it off is affected.

### An OAuth sign-in no longer makes the device trusted

An OAuth sign-in skips the plugin's second factor, and with `devices` it still marked the device trusted. Under `two_factor_scope=new_devices` a trusted device skips the second factor, so after one OAuth sign-in, password sign-ins from that device skipped it too.

- **`OAuthExchange` binds the session to the device and does not trust it.** It returns no `device_trust_token`.
- **A device becomes trusted only by passing the second factor (`VerifyMfa`).** A password sign-in that met no second factor renews the trust of a device that already has it and grants none. Before, with `devices` on and `two_factor` off, every password sign-in trusted its device, so switching on `two_factor_scope=new_devices` later let every device that had ever signed in skip the new factor. Such a deployment should clear existing trust (`trusted_at`, `trust_token_hash` on `Device`) when it turns `two_factor` on.

### OAuth: the callback hands out a single-use code, not a session (breaking)

The OAuth callback used to redirect the browser with the session token in the URL fragment, and its `state` was valid forever, reusable, and tied to no browser. Anyone could start a sign-in with their own provider account and send the callback link to someone else. Whoever opened it was signed in to the sender's account and kept working there (login CSRF).

The browser that starts a sign-in now proves it is the one finishing it:

- **`OAuthAuthorizeURL` requires `code_challenge`**, the PKCE S256 challenge (RFC 7636) of a verifier the page keeps. The signed `state` carries a sha256 of it, never the challenge itself, and now expires after ten minutes.
- **`OAuthCallback` returns `code`, not `token`.** It is a single-use login code, stored as its hash, valid for two minutes and bound to that challenge. The REST callback redirects to `redirect_after#code=…`. `OAuthCallbackResp` drops `user_id`, `token` and `device_trust_token`.
- **New `OAuthExchange` (`POST /auth/oauth/exchange`, public, failed_only)** redeems the code with `code_verifier` and returns `user_id`, `token` and, under `devices`, `device_trust_token`. A wrong verifier spends the code. The device is resolved from this request, which comes from the page itself.
- **New table `OAuthLoginCode`.** Generate a migration as usual.
- **Towards the provider:** the authorize URL carries the plugin's own PKCE challenge (`code_challenge`, `code_challenge_method=S256`) and an OIDC `nonce`, and the token request carries the matching `code_verifier`. Both derive from the state under the client secret, so nothing is stored. A provider that supports neither ignores them. On the `id_token` path (no `userinfo_url`), a token whose `aud` does not name the client id, whose `azp` names another client, whose `exp` has passed, or whose `nonce` is not this sign-in's is refused.
- **The `fakeidp` sandbox** checks PKCE and echoes the nonce for codes it issued from `/authorize`, and sets the `id_token`'s `aud` to the requesting client id. Rebuild its image.

**Migrating a frontend:**

1. Before redirecting to `/auth/oauth/{provider}/authorize`, generate a fresh verifier for this sign-in (never reuse one), store it in `sessionStorage`, and add `code_challenge` to the request.
2. On the landing page, read `code` from the fragment (not `token`), take the verifier out of `sessionStorage` (read, then delete), and `POST` both to `/auth/oauth/exchange`. Delete the verifier before the call, so a failed exchange leaves none behind: a leftover verifier would redeem a code someone else started with its challenge.
3. Store the returned token as before.

A state signed by an older release has no challenge and is refused, so a sign-in in flight during the upgrade has to start again.

### A disabled account holds no working credential

`Authenticate` now refuses every token of a disabled account, session or API, and `IssueBotToken` refuses a disabled machine account with `FAILED_PRECONDITION`.

`DisableUsers` deletes the account's tokens, but nothing checked the flag afterwards. A token minted after the disable worked: one issued by `IssueBotToken` for a disabled bot, or a session from a sign-in racing the disable.

What changes:

- **`GetUserByTokenWithPermissions` projects `user.disabled_at`** (under `user_admin`), and **`GetTokenWithType` joins the owner** and returns it as `user` (`GetTokenWithTypeResp.user`, field 7). Both are the lookups `Authenticate` already runs, so this adds no round trip.
- **Re-enabling an account gives nothing back,** as before: its tokens were deleted when it was disabled.

### An API token can no longer mint credentials

`CreateApiToken`, `CliAuthorize`, `RegisterClient`, `SetClientEnabled`, `EnrollTotp` and `GenerateRecoveryCodes` now answer `PERMISSION_DENIED` (detail `SESSION_REQUIRED`) unless the caller authenticated with a session token.

`CreateApiToken` and `CliAuthorize` mint a new credential from the holder's roles, not from the caller's narrowed permissions. So an API token limited to one permission, given access to `POST /auth/tokens`, could mint a token carrying every API-realm permission of its holder, and through the CLI exchange (`CliAuthorize` → `CliToken`) it could become a full session. The others create credentials of their own: `RegisterClient` a client secret and a callback that `CliAuthorize` sends a session's code to (`SetClientEnabled` restores a retired one), and `EnrollTotp` / `GenerateRecoveryCodes` the account's second factor, which a token could otherwise take over and lock the person out with.

What changes:

- **Creating a credential needs a signed-in session.** A user does it from the app. Automation that minted API tokens with a token has to use a session or, for a machine account, `IssueBotToken`, which stays open to tokens because it is held to the caller's own resolved permissions.
- **The caller is told apart by `AuthResp.session_token_id`,** which `Authenticate` now sets only for a session-realm token (sign-in, device, CLI) and leaves empty for any other, an API or bot token included. A deployment that authenticates through something other than this plugin's `Authenticate` gets no `session_token_id` and is refused, as `Logout` already is.

## 0.1.0-rc.24

### Bearer tokens are stored as a hash

Session and API tokens (`UserToken`) used to be stored as they are handed out, so whoever could read the table or a backup of it held every live token. A token is now stored only as `token_hash`, the sha256 of the token. The handler that mints a token generates it, stores the hash, and returns the token to the caller once. A lookup hashes the bearer it is presented and compares.

What changes:

- **New column `UserToken.token_hash`.** Generate a migration as usual (`w17ctl migrate generate`). `UserToken.token` becomes nullable and nothing writes it any more.
- **Existing tokens keep working.** A token minted before this release is still found by its value. The first request that `Authenticate` resolves with it moves the row to `token_hash` and clears `token` (`AuthMutation.UpgradeTokenHash`). Nobody is signed out by the upgrade. Hand-written code that resolves a token through `GetUserByToken` does not move the row; it runs `UpgradeTokenHash` itself if it should.
- **A token that is never used stays in the clear** until a later release drops the `token` column, which ends every such token. To close it sooner, revoke the tokens that are still unhashed (`token_hash IS NULL`): their owners sign in again or reissue an API token.
- **Storage callers:** `IssueToken` and `IssueApiToken` take the hash (`token_hash`) and no longer return the token. `GetUserByToken`, `GetUserByTokenWithPermissions`, `GetTokenWithType` and `DeleteToken` take `token_hash`, plus `legacy_token`, the token itself, which finds only a row minted before this release. The old `token` field is gone, so code that set only the token does not compile: a lookup by the token alone would miss every hashed row. Hash the token with sha256, hex-encode it, and pass both.
- **No rollback past this release.** A token minted by this release exists only as its hash, so going back to rc.23, which looks tokens up by `token` alone, signs out every session and invalidates every API token issued since the upgrade.
- **Fixtures** that seed a `UserToken` with a known `token` keep working through the legacy path. A fixture may instead seed `token_hash` with the sha256 of the token.

## 0.1.0-rc.23

### A successful OAuth sign-in no longer spends the per-address limit twice

`OAuthCallback` is `public_limit: failed_only`. A callback with a forged or replayed code or state fails and spends a token. A real one comes back from the provider and redirects the browser, and that is free. Before this, an OAuth sign-in spent two tokens: the authorize hop and the callback. With the defaults (burst 10) an office behind one address could get only about five people through in a burst before a 429.

`OAuthAuthorizeURL` still spends a token on every request. It builds a signed redirect and checks no secret.

## 0.1.0-rc.22

Needs w17 platform 1.11 (`requires_w17: ">=1.11"`): `public_limit` on a REST preset endpoint.

### Registration and reset requests count against the per-address limit

The gateway limits the endpoints that take no credential per client address (`*_RATELIMIT_PER_MINUTE`, default 30 a minute with a burst of 10). Until now every such endpoint spent a token only when it failed. That is right for a sign-in, where an attacker's guesses fail and a legitimate user's sign-in succeeds. It is wrong for an endpoint that does its work when it succeeds:

- `SignUp` creates an account and sends a mail. A registration from a fresh address never fails, so one address could register without limit.
- `RequestPasswordReset` sends a mail and answers success whether or not the address exists, so it never spent a token and could mail any address without limit.

From platform 1.11 an endpoint spends a token on every request unless it says otherwise. This release marks the endpoints that check a guessable secret `public_limit: failed_only`, so a correct answer stays free:

- `SignIn`
- `ConfirmSignUp`
- `VerifyMfa`
- `ResetPassword`
- `VerifyEmail`
- `CliToken`

`SignUp`, `RequestPasswordReset` and the two OAuth hops now spend a token on every request.

If a test suite registers many accounts from one address, turn the limit off in the test stack. `w17ctl test` does this itself from v0.1.0-rc.70, through the generated `compose.test.yaml`. For your own runs, use `docker compose -f compose.yaml -f compose.test.yaml` or set `<DOMAIN>_GATEWAY_RATELIMIT_PER_MINUTE=0`.

## 0.1.0-rc.21

### Recovery codes

Confirming an authenticator (`ConfirmTotp`) now returns ten one-time recovery codes, shown once. The codes are stored as SHA-256 hashes in the new `UserRecoveryCode` table.

- A recovery code works wherever the authenticator's code does: `VerifyMfa`, and the step-up of `EnrollTotp`, `DisableTotp` and `GenerateRecoveryCodes`. Each code works once. It may be typed in any case, with or without the dash.
- `GenerateRecoveryCodes` (`POST /auth/mfa/recovery-codes`) replaces the set. It needs a confirmed authenticator, plus a current code or a recovery code. Without an authenticator it is refused with `TOTP_NOT_ENROLLED`.
- `GetMfaStatus` reports `recovery_codes_remaining`.
- `DisableTotp` deletes the codes together with the authenticator.
- Spending a code emits `RecoveryCodeUsed` (`auth.mfa.recovery_code_used`), so a consumer can tell the person.

### A TOTP code is accepted once

`UserTotpSecret.last_step` records the highest time step accepted. A code is taken only for a later step, through one conditional `UPDATE` (`ClaimTotpStep`). Before this, a code worked for its whole window of about 90 seconds, so a code read over someone's shoulder or captured by a phishing page could sign in a second time (RFC 6238 §5.2). The code that confirms an authenticator counts too. A client that verified twice with the same code now needs the next one.

### Re-enrolling over a confirmed authenticator needs a code

`EnrollTotpReq.code` is now required when the caller already has a confirmed authenticator. It takes a current code or a recovery code. Re-enrolling replaces the authenticator, which turns the second factor off until the new one is confirmed. Before this, a hijacked session could do through `EnrollTotp` what `DisableTotp`'s code requirement prevents. A lost phone is now: sign in with a recovery code, then enrol with another one.

### The step-up has a guess budget

The step-up is the code that `EnrollTotp`, `DisableTotp` and `GenerateRecoveryCodes` ask for. Five wrong codes lock it for 15 minutes, refused with `STEP_UP_LOCKED` (ResourceExhausted) even for the right code, and a success resets the count. The counter is `UserTotpSecret.stepup_attempts` and `stepup_locked_until`, updated in one statement (`RecordStepUpAttempt`), so concurrent guesses cannot race past the lock.

The step-up comes from a session, outside any sign-in challenge's budget. Without this limit a stolen session could keep trying six-digit codes until one of the three valid ones came up. `DisableTotp` had no limit before this release.

A recovery-shaped code is checked as a recovery code without reading the seed. This way a legacy authenticator whose `two_factor_secret_key` is gone can still be replaced with a recovery code.

### `ConfirmTotp` refuses an authenticator that is already confirmed

It answers `TOTP_ALREADY_CONFIRMED`. Re-confirming used to be a harmless no-op. With recovery codes it would hand a fresh set to whoever holds the session, with no step-up budget. Use `GenerateRecoveryCodes` for a new set.

### The QR code comes with the enrolment

`EnrollTotpResp.qr_svg` is `otpauth_uri` as a QR code: a self-contained SVG with black modules on white and the quiet zone included. Render it as it is. Encoding is done by `rsc.io/qr`, the SVG rendering by `lib/qrsvg`. The client no longer needs a QR library, and the seed is never handed to one.

New storage methods:
- `AuthMutation`: `ClaimTotpStep`, `RecordStepUpAttempt`, `LockStepUp`, `ResetStepUp`, `CreateRecoveryCode`, `DeleteRecoveryCodes`, `ConsumeRecoveryCode`;
- `AuthQuery`: `CountRecoveryCodes`.

## 0.1.0-rc.20

Needs w17 platform 1.10 (`requires_w17: ">=1.10"`): a project with a `CRYPTED_SECRET` column may now use `RETURNING` on mutations, as long as no encrypted column is returned.

### TOTP seeds and OAuth client secrets are encrypted with the project's field key

Two stored secrets are read back as plain values and are now `CRYPTED_SECRET` columns, encrypted with the project's field keyring (`W17_FIELD_KEYS`):

- `UserTotpSecret.seed` holds the TOTP seed.
- `OAuthProvider.secret` holds the OAuth client secret.

`W17_FIELD_KEYS` is the one key for every encrypted column of a project: the local stack gets a development key from `.env.defaults`, and a deployment gets its own key from `w17ctl secrets field-key`. Before this release, the TOTP seed was encrypted by the plugin's own cipher under the `two_factor_secret_key` knob, and the client secret was stored in the clear.

Nothing has to be migrated by hand. Existing values move the first time they are used:

- A seed enrolled by rc.19 or earlier is still in `UserTotpSecret.secret`. On its next verification it is decrypted with `two_factor_secret_key` and moved into `seed`. Keep the knob set until every authenticator has moved.
- A client secret in `OAuthProvider.client_secret` moves into `secret` at the provider's next sign-in. That happens only while `secret` is empty. Once `secret` is set, it wins and the plaintext copy is cleared, so a rotation made in the admin before the first sign-in is kept. Rotate the secret in `secret`. A fixture cannot seed an encrypted column, so a dev sandbox keeps seeding `client_secret`.

New deployments leave `two_factor_secret_key` empty, and enrolling no longer needs it. A later release removes the knob and both legacy columns.

New storage methods: `AuthMutation.MoveTotpSeed`, `AuthMutation.MoveOAuthProviderSecret` and `AuthMutation.ClearOAuthProviderLegacySecret`. A move is keyed by the row it read: a TOTP seed by the enrolment row's id, so a re-enrolment in between keeps its new seed, and a client secret by the legacy value still being there.

`GetTotpSecretResp.seed` and `GetProviderByNameResp.secret` carry the decrypted values. A decrypted value is returned as a top-level field, not inside the row message.

`CreateTotpSecretReq.secret` (field 2) is replaced by `seed`. Hand-written code that called `CreateTotpSecret` now passes the plaintext seed.

## 0.1.0-rc.19

Needs w17 platform 1.9 (`requires_w17: ">=1.9"`): `DisableUsers` acts on one id set in two statements.

### Disabling an account ends its sessions and tokens

`DisableUsers` (`user_admin`) now also deletes every token of the disabled accounts, sessions and API tokens alike. Before this release they kept working until they expired (30 days for a session), so disabling a departing person did not end their access. Re-enabling an account gives no token back.

### A password change signs the person out everywhere else

`ChangePassword` (`password_change`) deletes every other session of the account in the same unit of work as the new password, and keeps the session the change came from. API tokens are kept. If the sign-out fails, the password is not changed.

New storage method: `AuthMutation.DeleteOtherSessionTokens`.

### An open invitation's link is spent at registration

Registering through an open invitation's link binds the invitation to the registering address. One open link used to register any number of accounts until somebody accepted it; under `invite_only` that was a way to create accounts. Now a second registration through the same link is refused under `invite_only`, and without it the second account simply does not get the invitation. Acceptance is unchanged.

New storage method: `AuthMutation.BindOpenOrgInvite`.

### Removed

`AuthMutation.MarkOrgInviteAccepted`. Nothing called it: acceptance is `ConsumeOrgInviteByToken`. Hand-written code that called it should call that instead.

### Documented

The README now has a section on what a consumer has to know: sessions and tokens, invitations (the plugin sends no mail, the link is returned once to the inviter), the CLI-login client registry (one list for the deployment — grant its four RPCs to an operator role only), and where a refusal's sentence for a person is.

## 0.1.0-rc.18

### Machine accounts in a realm without organizations

`service_account` no longer requires `org_membership`. A realm without organizations is one organization (a platform's own backoffice, say): there a machine account holds a realm-wide role, the bot directory lists the realm's machine accounts, and any operator who may mint tokens may mint one for it. With `org_membership` on, nothing changes: a machine account still joins the operator's active organization and is listed and minted for only there.

With `tenant_scope` on (with or without organizations) an operator now sees, and mints for, only the machine accounts of their own tenant.

### Minting is held to the operator's role ceiling

`IssueBotToken` now refuses a machine account that holds a role the operator could not grant (`PERMISSION_DENIED`, detail `ROLE_ABOVE_CALLER`). `CreateBot` already held the role to that ceiling; a bot created by someone with more could still be minted for by someone with less, and the token acts with the bot's roles. If your operators mint for bots created by others, check the operators' roles.

### Breaking for hand-written code that calls these storage methods

- `AuthQuery.GetBotInOrg` → `GetOrgMember`, gated `org_membership`; it no longer filters on the account's kind.
- `AuthQuery.ListBotUsers` → `ListOrgMemberAccounts`, gated `org_membership`; it returns every member, and the caller keeps the machine accounts.
- `ListApiRealmRolesResp.roles` is `ApiRealmRole` (was `OrgScopedRole`, which needs `org_membership`).
- New `AuthQuery.ListRealmMachineAccounts` (gated `service_account`), unpaged.

Generated code needs nothing beyond `w17ctl plugin update` and `codegen`. `service_account` now requires `authenticate_turnkey` (it already came with `api_token`'s activations in practice).

## 0.1.0-rc.17

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
- A generated `go.mod` may keep a `replace` line for the old path beside the new one. It is harmless, and you may delete it.
- Hand-written code that imports the plugin's packages directly (a `lib/…` package, say) must change its import paths. It must also change any `replace` directive in its own `go.mod` that names the old module path.

No behaviour change since 0.1.0-rc.16. This release carries the module path and comment edits only.
