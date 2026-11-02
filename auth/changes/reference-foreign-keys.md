### Every reference between the plugin's own tables is a foreign key

A row naming another row of the same activation now carries a foreign key to it (`fk: "@module.<Model>"`, which staging expands to the activation's own table), so a reference to a row that does not exist is refused by the store instead of stored silently — `RolePermission.role_id` naming no role was the case that showed it. Every key is `ON DELETE RESTRICT` (`deletion_rule: BLOCK`): the plugin deletes nothing (an account is erased, a role, an organization or a grant is ended), so a delete that would strand a reference is refused, never cascaded. A write that names a missing row answers `InvalidArgument` (`INVALID_VALUE`, "referenced record does not exist") on that field.

Keyed: `user_id` everywhere it names an account (UserToken, Device, SignInEvent, BotTokenUse, OAuthIdentity, UserTotpSecret, UserRecoveryCode, MfaChallenge, PasswordResetToken, EmailVerificationToken, UserRole, BootstrapClaim, OAuthLoginCode, CliAuthCode, OAuthAuthorization, OAuthGrant, OrgMembership, TeamMember, ProductRoleGrant); `role_id` (RolePermission, RolePermissionChange, UserRole, TeamRole); `org_id` where the table stages with Organization (Role, UserRole, OrgMembership, OrgInvite, Team, TeamMember, TeamRole, OrgPackage, OrgHost, OrgSignUpPolicy, OrgTwoFactorPolicy, ProductRoleDef, ProductRoleGrant, OrgProductAllowance, PendingSignUp.join_org_id); `tenant_id` (User, OAuthProvider, PendingSignUp); the device columns (UserToken.device_id, every `approved_by_device_id`, SignInEvent.device_id); `token_id` (BotTokenUse, TokenPermission, TokenProductRole); `provider_id` (OAuthIdentity, OAuthLoginCode); `client_row_id`, `authorization_id`, `grant_id` and `UserToken.oauth_grant_id` under `oauth_server`; `team_id`.

Not keyed, on purpose: the actor columns (`revoked_by`, `removed_by`, `invited_by`, `granted_by`, `ended_by`, …), which may name an operator of another activation; and `UserToken.oauth_org_id`, `OAuthAuthorization.org_id`, `OAuthGrant.org_id`, because `oauth_server` stages without `org_membership` and then there is no Organization table.

**Before you deploy it: a database may hold rows the keys refuse.** A user deleted before erasure replaced deletion left its tokens, devices and grants behind, and the platform's role seed wrote RolePermission rows for roles that did not exist until it resolved them by `preset_key`. Adding a key over such a row fails the migration. The migration carries one pre-apply check per key, so:

1. Apply with the checks on — `migrate apply --checks`, or `W17_MIGRATE_CHECKS=1` in the deploy environment. A database with orphans then refuses the migration by the check's name and row count before any of it runs (a local `stack build` runs the checks anyway). Each check is the probe `SELECT count(*) FROM <child> WHERE <col> IS NOT NULL AND <col> NOT IN (SELECT id FROM <parent>)`, which you can also run by hand first.
2. Repair without deleting: give each missing parent a row that is already ended, so the history keeps its reference. For orphan grants of missing roles (table names are `<registered_as>_<model>`; `auth` here):

   ```sql
   INSERT INTO auth_role (id, name, description, display_name, deleted_at, ended_key)
   SELECT DISTINCT o.role_id, 'missing-' || o.role_id, '', '', NOW(), o.role_id
   FROM (SELECT role_id FROM auth_rolepermission UNION SELECT role_id FROM auth_rolepermissionchange
         UNION SELECT role_id FROM auth_userrole) o
   WHERE NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.id = o.role_id);
   ```

   A missing account is restored the way an erasure leaves one (`erased_at` and `disabled_at` set, the placeholder address); a missing organization as a deleted one (`deleted_at`).
3. Apply again.
