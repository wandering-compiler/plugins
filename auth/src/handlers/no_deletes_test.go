package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Nothing in the auth tables is deleted (device/revocation-is-a-state, extended
// to every table by auth/nothing-is-deleted). The statements are pinned here —
// a fake store cannot run SQL — and orgTables below proves what the handlers
// do with them: every former delete path leaves its row, with the state that
// ended it, and the behaviour a caller sees is the one the delete gave.

// The guard: no statement of any auth proto deletes, from any table, and no
// hand-written Go carries a DELETE statement of its own.
func TestNoStatementDeletesAnything(t *testing.T) {
	re := regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)
	for rel, src := range authProtos(t) {
		for _, m := range re.FindAllString(dqlText(src), -1) {
			t.Errorf("%s: %q — nothing in the auth tables is deleted; end the row with a state column instead", rel, m)
		}
	}
	// Raw SQL in the plugin's own Go would bypass the protos: none may delete.
	// Comments are dropped first; they may mention what the statements used
	// to do.
	goCode := func(src string) string {
		var b strings.Builder
		for _, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if i := strings.Index(line, " //"); i >= 0 {
				line = line[:i]
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
		return b.String()
	}
	var scanned int
	for _, dir := range []string{".", filepath.Join("..", "lib")} {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			if m := re.FindString(goCode(string(raw))); m != "" {
				t.Errorf("%s carries a DELETE statement: %q", path, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d Go files — the guard is not looking at the handlers", scanned)
	}
	// The matchers, against the shapes they must catch and must not.
	for s, want := range map[string]bool{
		`"DELETE FROM @module.UserRole WHERE user_id = :id"`:   true,
		`"delete from @module.OrgInvite where id = :id"`:       true,
		`"DELETE  FROM @module.PendingSignUp WHERE email = x"`: true,
		`"UPDATE @module.UserRole SET revoked_at = NOW()"`:     false,
		`"SELECT deleted_at FROM @module.Role r"`:              false,
	} {
		if re.MatchString(s) != want {
			t.Errorf("proto matcher on %s = %v, want %v", s, !want, want)
		}
	}
	for src, want := range map[string]bool{
		"const q = `DELETE FROM auth_userrole`\n":     true,
		"\tq := \"delete from x\" // purge\n":         true,
		"// claim the row (DELETE … RETURNING)\n":     false,
		"\tx := 1 // used to DELETE FROM the table\n": false,
	} {
		if re.MatchString(goCode(src)) != want {
			t.Errorf("Go matcher on %q = %v, want %v", src, !want, want)
		}
	}
}

// Every former DELETE, as the UPDATE (or UPSERT) that replaced it. Each ending
// is guarded on its state column being NULL, so the first ending stands and a
// second one matches nothing, as a delete of a missing row did.
func TestEveryFormerDeleteIsAGuardedStateChange(t *testing.T) {
	m := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))
	for name, wants := range map[string][]string{
		// two_factor
		"RevokeTotpSecret":    {"UPDATE @module.UserTotpSecret SET revoked_at = NOW(), ended_key = id, seed = NULL, secret = NULL WHERE user_id = :user_id AND revoked_at IS NULL RETURNING user_id"},
		"RevokeRecoveryCodes": {"UPDATE @module.UserRecoveryCode SET revoked_at = NOW() WHERE user_id = :user_id AND used_at IS NULL AND revoked_at IS NULL"},
		// sign_up_confirmation
		"ClaimPendingSignUp":              {"UPDATE @module.PendingSignUp SET claimed_at = NOW() WHERE id = :pending_id AND claimed_at IS NULL AND superseded_at IS NULL AND expires_at > NOW() RETURNING email AS email, password_hash AS password_hash"},
		"SupersedePendingSignUpsForEmail": {"UPDATE @module.PendingSignUp SET superseded_at = NOW() WHERE email = :email AND claimed_at IS NULL AND superseded_at IS NULL"},
		// The registrations are kept now, so an erasure reaches them.
		"ErasePendingSignUpAddress": {
			"UPDATE @module.PendingSignUp SET superseded_at = NOW() WHERE email = :email AND claimed_at IS NULL AND superseded_at IS NULL",
			`UPDATE @module.PendingSignUp SET email = :placeholder, password_hash = \'!\', code_hash = \'!\' WHERE email = :email`,
		},
		// rbac
		"DeleteRole": {
			"UPDATE @module.UserRole SET revoked_at = NOW(), ended_key = id WHERE role_id = :role_id AND revoked_at IS NULL",
			"UPDATE @module.Role SET deleted_at = NOW(), ended_key = id WHERE id = :role_id AND deleted_at IS NULL RETURNING id AS role_id",
		},
		"RevokeRoleFromUser": {"UPDATE @module.UserRole SET revoked_at = NOW(), revoked_by = :revoked_by, ended_key = id WHERE user_id = :user_id AND role_id = :role_id AND ?feature(org_membership) org_id IS NOT DISTINCT FROM :org_id AND revoked_at IS NULL RETURNING user_id, role_id, ?feature(org_membership) org_id"},
		"RemovePermissionFromRole": {
			"INSERT INTO @module.RolePermissionChange SET role_id = :role_id, permission_id = :permission_id, kind = 2, changed_by = :removed_by",
			"UPDATE @module.RolePermission SET removed_at = NOW(), removed_by = :removed_by WHERE role_id = :role_id AND permission_id = :permission_id AND removed_at IS NULL RETURNING role_id, permission_id",
		},
		"AddPermissionToRole": {
			"INSERT INTO @module.RolePermissionChange SET role_id = :role.id, permission_id = :permission_id, kind = 1, changed_by = :added_by",
			"UPSERT INTO @module.RolePermission SET role_id = :role.id, permission_id = :permission_id ON CONFLICT (role_id, permission_id) DO UPDATE SET removed_at = NULL, removed_by = NULL RETURNING",
		},
		// org_membership
		"DeleteOrganization": {
			"UPDATE @module.OrgMembership SET removed_at = NOW(), ended_key = id WHERE org_id = :id AND removed_at IS NULL",
			"UPDATE @module.UserRole SET revoked_at = NOW(), ended_key = id WHERE org_id = :id AND revoked_at IS NULL",
			"UPDATE @module.Organization SET deleted_at = NOW(), ended_key = id WHERE id = :id AND deleted_at IS NULL RETURNING id AS org_id",
		},
		"MarkOrgMembershipRemoved": {
			"FROM @module.OrgMembership m WHERE m.id = :id AND m.removed_at IS NULL",
			"UPDATE @module.UserRole SET revoked_at = NOW(), revoked_by = :removed_by, ended_key = id WHERE user_id = :m.user_id AND org_id = :m.org_id AND revoked_at IS NULL",
			"UPDATE @module.OrgMembership SET removed_at = NOW(), removed_by = :removed_by, ended_key = id WHERE id = :id AND removed_at IS NULL RETURNING id AS membership_id",
		},
		"UpdateOrgMembership": {
			"FROM @module.OrgMembership m WHERE m.id = :id AND m.removed_at IS NULL",
			"WHERE r.id = :role_id AND r.org_scoped = TRUE AND r.deleted_at IS NULL",
			"UPDATE @module.UserRole SET revoked_at = NOW(), revoked_by = :changed_by, ended_key = id WHERE user_id = :m.user_id AND org_id = :m.org_id AND revoked_at IS NULL",
			"INSERT INTO @module.UserRole SET user_id = :m.user_id, role_id = :r.id, org_id = :m.org_id",
			"WHERE id = :id AND removed_at IS NULL RETURNING id AS membership_id",
		},
		// org_invite
		"CloseExpiredOrgInvite": {"UPDATE @module.OrgInvite SET closed_at = NOW() WHERE org_id = :org_id AND email = :email AND accepted_at IS NULL AND closed_at IS NULL AND expires_at <= NOW() RETURNING id"},
		"CloseOrgInvite":        {"UPDATE @module.OrgInvite SET closed_at = NOW(), closed_by = :closed_by WHERE id = :invite_id AND org_id = :org_id AND accepted_at IS NULL AND closed_at IS NULL RETURNING id AS invite_id"},
		"CloseOrgInvitesOfOrg":  {"UPDATE @module.OrgInvite SET closed_at = NOW(), closed_by = :closed_by WHERE org_id = :org_id AND accepted_at IS NULL AND closed_at IS NULL"},
	} {
		body, ok := m[name]
		if !ok {
			t.Errorf("no mutation %s", name)
			continue
		}
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, body)
			}
		}
	}
	// The change log is written BEFORE the change, in the same statement list:
	// a removal that matches nothing (NotFound) rolls its log row back.
	for _, name := range []string{"AddPermissionToRole", "RemovePermissionFromRole"} {
		if a, b := strings.Index(m[name], `name: "log"`), strings.Index(m[name], `name: "main"`); a < 0 || b < a {
			t.Errorf("%s does not log the change ahead of it:\n%s", name, m[name])
		}
	}
	// The renamed paths are gone under their old names.
	for _, old := range []string{"DeleteTotpSecret", "DeleteRecoveryCodes", "DeletePendingSignUpsForEmail", "PurgeExpiredPendingSignUps", "DeleteOrgMembership", "ClearExpiredOrgInvite", "DeleteOrgInvite"} {
		if _, ok := m[old]; ok {
			t.Errorf("mutation %s still exists", old)
		}
	}
}

// The statements that USE a row the way the delete used to remove it refuse
// an ended one: a revoked authenticator verifies nothing, a revoked recovery
// code is refused like a used one, an ended registration cannot be guessed at
// or claimed, a closed invitation cannot be bound or accepted, a deleted role
// or organization cannot be edited.
func TestEveryWriteThatUsesARowSkipsAnEndedOne(t *testing.T) {
	m := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))
	for name, want := range map[string]string{
		"ConfirmTotpSecret":          "WHERE user_id = :user_id AND revoked_at IS NULL",
		"MoveTotpSeed":               "WHERE id = :id AND user_id = :user_id AND revoked_at IS NULL",
		"ClaimTotpStep":              "WHERE id = :id AND last_step < :step AND revoked_at IS NULL",
		"RecordStepUpAttempt":        "AND revoked_at IS NULL",
		"ConsumeRecoveryCode":        "AND used_at IS NULL AND revoked_at IS NULL",
		"RecordPendingSignUpAttempt": "WHERE id = :pending_id AND claimed_at IS NULL AND superseded_at IS NULL AND expires_at > NOW()",
		"BindOpenOrgInvite":          "WHERE i.token_hash = :token_hash AND i.email IS NULL AND i.accepted_at IS NULL AND i.closed_at IS NULL AND i.expires_at > NOW() AND EXISTS (SELECT o.id FROM @module.Organization o WHERE o.id = i.org_id AND o.deleted_at IS NULL)",
		"ConsumeOrgInviteByToken":    "WHERE i.token_hash = :token_hash AND i.accepted_at IS NULL AND i.closed_at IS NULL AND i.expires_at > NOW() AND EXISTS (SELECT o.id FROM @module.Organization o WHERE o.id = i.org_id AND o.deleted_at IS NULL)",
		"UpdateRole":                 "WHERE id = :role_id AND deleted_at IS NULL",
		"UpdateOrganization":         "WHERE id = :id AND deleted_at IS NULL",
	} {
		if !strings.Contains(m[name], want) {
			t.Errorf("%s lacks %q:\n%s", name, want, m[name])
		}
	}
}

// Every read of a table whose rows can now end skips the ended ones, so what
// a caller and every ACL check sees is what it saw when the rows were deleted:
// for each alias of such a table in each query, the alias's state column is
// tested. The one exception is listed with its reason.
func TestEveryReaderSkipsEndedRows(t *testing.T) {
	state := map[string]string{
		"Role":             "deleted_at",
		"UserRole":         "revoked_at",
		"RolePermission":   "removed_at",
		"Organization":     "deleted_at",
		"OrgMembership":    "removed_at",
		"OrgInvite":        "closed_at",
		"UserTotpSecret":   "revoked_at",
		"UserRecoveryCode": "revoked_at",
	}
	// ListOrgMemberships LEFT JOINs the organization only for its display
	// name; a deleted organization's memberships are removed with it, and the
	// membership's own removed_at is tested.
	//
	// The admin Authenticators page (admin_mfa) lists every enrolment, ended
	// ones included, on purpose — as the Devices page lists revoked devices —
	// and shows revoked_at; Reset skips an ended one.
	exempt := map[string]bool{
		"ListOrgMemberships/Organization":   true,
		"ListAuthenticators/UserTotpSecret": true,
		"GetAuthenticator/UserTotpSecret":   true,
	}
	aliasRe := regexp.MustCompile(`@module\.(\w+)\s+(\w+)`)
	readers := 0
	for name, body := range rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"])) {
		for _, a := range aliasRe.FindAllStringSubmatch(body, -1) {
			table, alias := a[1], a[2]
			col, ok := state[table]
			if !ok || exempt[name+"/"+table] {
				continue
			}
			readers++
			if !strings.Contains(body, alias+"."+col+" IS NULL") {
				t.Errorf("%s reads %s (%s) without `%s.%s IS NULL`:\n%s", name, table, alias, alias, col, body)
			}
		}
	}
	if readers < 40 {
		t.Fatalf("checked only %d reads — the test is not looking at the queries", readers)
	}
	// A LEFT JOIN's filter belongs in its ON: in the WHERE it would drop the
	// role itself once its only permission was removed.
	q := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	for _, name := range []string{"GetUserRoleGrants", "ListRoleGrants", "GetUserRolePermissionsByRealm", "GetUserOrgPermissions", "GetUserRealmWidePermissions"} {
		if !strings.Contains(q[name], "LEFT JOIN @module.RolePermission rp ON rp.role_id = r.id AND rp.removed_at IS NULL") {
			t.Errorf("%s does not skip removed permissions in its LEFT JOIN:\n%s", name, q[name])
		}
	}
	// GetUserPermissions joined no Role, so a deleted role's grants kept
	// granting through it (rbac gap 2). It joins the role now.
	if !strings.Contains(q["GetUserPermissions"], "JOIN @module.Role r ON r.id = rp.role_id") {
		t.Errorf("GetUserPermissions does not join the role:\n%s", q["GetUserPermissions"])
	}
}

// The unique indexes. A table whose key must be reusable after a removal puts
// ended_key into the index (full, so every dialect builds it); RolePermission
// keeps its (role_id, permission_id) index exactly, because the platform's role
// seed conflicts on it, and revives instead; the invitation index, partial
// already, also excludes closed rows. No index of a feature that can build on
// MySQL gains a `where:`.
func TestUniqueIndexesLetAnEndedKeyBeReused(t *testing.T) {
	models := authProtos(t)["types/models.proto"]
	block := func(msg string) string {
		i := strings.Index(models, "message "+msg+" {")
		if i < 0 {
			t.Fatalf("no message %s", msg)
		}
		return models[i : i+strings.Index(models[i:], "\n}\n")]
	}
	for msg, wants := range map[string][]string{
		"Role":           {`{ unique: true, fields: [{ name: "name" }, { name: "ended_key" }] }`},
		"Organization":   {`{ unique: true, fields: [{ name: "slug" }, { name: "ended_key" }] }`},
		"OrgMembership":  {`{ unique: true, fields: [{ name: "user_id" }, { name: "org_id" }, { name: "ended_key" }] }`},
		"UserTotpSecret": {`{ unique: true, fields: [{ name: "user_id" }, { name: "ended_key" }] }`},
		"UserRole": {
			`{ unique: true, fields: [{ name: "user_id" }, { name: "role_id" }, { name: "ended_key" }],
        plugin_feature_unless: "org_membership" }`,
			`{ unique: true, fields: [{ name: "user_id" }, { name: "role_id" }, { name: "ended_key" }],
        where: "org_id IS NULL", plugin_feature: "org_membership" }`,
			`{ unique: true, fields: [{ name: "user_id" }, { name: "role_id" }, { name: "org_id" }, { name: "ended_key" }],
        where: "org_id IS NOT NULL", plugin_feature: "org_membership" }`,
		},
		"RolePermission": {`{ unique: true, fields: [{ name: "role_id" }, { name: "permission_id" }] }`},
		"OrgInvite":      {`where: "accepted_at IS NULL AND closed_at IS NULL"`},
	} {
		b := block(msg)
		for _, want := range wants {
			if !strings.Contains(b, want) {
				t.Errorf("%s lacks index %s", msg, want)
			}
		}
		if msg != "RolePermission" && msg != "OrgInvite" && !strings.Contains(b, `string ended_key`) {
			t.Errorf("%s has no ended_key column", msg)
		}
	}
	// The old single-key uniques are gone: they would keep an ended key taken.
	for msg, gone := range map[string]string{
		"Role":         `max_len: 100, unique: true }`,
		"Organization": `max_len: 64, unique: true }`,
	} {
		if strings.Contains(block(msg), gone) {
			t.Errorf("%s still declares its key unique on its own (%s)", msg, gone)
		}
	}
	for _, msg := range []string{"Role", "RolePermission", "UserTotpSecret", "UserRecoveryCode", "PendingSignUp", "RolePermissionChange"} {
		if strings.Contains(block(msg), "where:") {
			t.Errorf("%s (a feature that can build on MySQL) gained a partial index", msg)
		}
	}
	if strings.Contains(block("UserRole"), `where: "revoked_at`) {
		t.Error("UserRole gained a partial index on its state")
	}
}

// ── the org tables, as the statements keep them ──────────────────────────────

type memRow struct {
	id, userID, orgID, role string
	removedAt               *timestamppb.Timestamp
	removedBy, endedKey     string
}

type grantRow struct {
	id, userID, roleID, orgID string
	revokedAt                 *timestamppb.Timestamp
	revokedBy, endedKey       string
}

type inviteRow struct {
	id, orgID, email, role, tokenHash, snapshot string
	expiresAt                                   time.Time
	acceptedAt, closedAt                        *timestamppb.Timestamp
	closedBy                                    string
}

// orgTables is OrgMembership, UserRole (org-scoped) and OrgInvite. Each fake
// method applies its statement's predicates and writes what its SET writes;
// the unique indexes are enforced as declared — (user, org, ended_key),
// (user, role, org, ended_key) and the pending-invite (org, email) WHERE
// accepted_at IS NULL AND closed_at IS NULL — so a row ended without
// releasing its key would block the re-add exactly as the database would.
type orgTables struct {
	*roleCatalogueMock
	users       map[string]string // id → email
	memberships []*memRow
	grants      []*grantRow
	invites     []*inviteRow
	deletedOrgs map[string]bool
	ops         []string
	next        int
}

func newOrgTables() *orgTables {
	o := &orgTables{roleCatalogueMock: newRoleCatalogue(), users: map[string]string{"u1": "owner@example.com", "u2": "member@example.com"}}
	o.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}, "r-worker": {1, 2}, "r-viewer": {1}}
	return o
}

func (o *orgTables) id(prefix string) string {
	o.next++
	return fmt.Sprintf("%s-%d", prefix, o.next)
}

var errUnique = status.Error(codes.InvalidArgument, "unique violation")

func (o *orgTables) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), Email: o.users[in.GetUserId()]}}, nil
}

func (o *orgTables) MarkEmailDerivedFromInvite(_ context.Context, in *pb.MarkEmailDerivedFromInviteReq, _ ...grpc.CallOption) (*pb.MarkEmailDerivedFromInviteResp, error) {
	return &pb.MarkEmailDerivedFromInviteResp{UserId: in.GetUserId()}, nil
}

func (o *orgTables) liveMembership(id string) *memRow {
	for _, m := range o.memberships {
		if m.id == id && m.removedAt == nil {
			return m
		}
	}
	return nil
}

func (o *orgTables) GetOrgMembership(_ context.Context, in *pb.GetOrgMembershipReq, _ ...grpc.CallOption) (*pb.OrgMembership, error) {
	m := o.liveMembership(in.GetId())
	if m == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.OrgMembership{Id: m.id, UserId: m.userID, OrgId: m.orgID, Role: m.role}, nil
}

func (o *orgTables) ListUserOrgGrants(_ context.Context, in *pb.ListUserOrgGrantsReq, _ ...grpc.CallOption) (*pb.ListUserOrgGrantsResp, error) {
	out := &pb.ListUserOrgGrantsResp{}
	for _, g := range o.grants {
		if g.userID == in.GetUserId() && g.orgID == in.GetOrgId() && g.revokedAt == nil {
			out.RoleIds = append(out.RoleIds, g.roleID)
		}
	}
	return out, nil
}

func (o *orgTables) AddOrgMembership(_ context.Context, in *pb.AddOrgMembershipReq, _ ...grpc.CallOption) (*pb.AddOrgMembershipResp, error) {
	for _, m := range o.memberships {
		if m.userID == in.GetUserId() && m.orgID == in.GetOrgId() && m.endedKey == "" {
			return nil, errUnique
		}
	}
	m := &memRow{id: o.id("mem"), userID: in.GetUserId(), orgID: in.GetOrgId(), role: in.GetRole()}
	o.memberships = append(o.memberships, m)
	return &pb.AddOrgMembershipResp{Membership: &pb.OrgMembership{Id: m.id}}, nil
}

func (o *orgTables) insertGrant(userID, roleID, orgID string) error {
	for _, g := range o.grants {
		if g.userID == userID && g.roleID == roleID && g.orgID == orgID && g.endedKey == "" {
			return errUnique
		}
	}
	o.grants = append(o.grants, &grantRow{id: o.id("ur"), userID: userID, roleID: roleID, orgID: orgID})
	return nil
}

func (o *orgTables) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	if err := o.insertGrant(in.GetUserId(), in.GetRoleId(), in.GetOrgId()); err != nil {
		return nil, err
	}
	return &pb.AssignRoleToUserResp{}, nil
}

// revokeOrgGrants is the "revoke" op both membership mutations share.
func (o *orgTables) revokeOrgGrants(userID, orgID, by string) {
	for _, g := range o.grants {
		if g.userID == userID && g.orgID == orgID && g.revokedAt == nil {
			g.revokedAt, g.revokedBy, g.endedKey = timestamppb.Now(), by, g.id
		}
	}
}

func (o *orgTables) MarkOrgMembershipRemoved(_ context.Context, in *pb.MarkOrgMembershipRemovedReq, _ ...grpc.CallOption) (*pb.MarkOrgMembershipRemovedResp, error) {
	m := o.liveMembership(in.GetId())
	if m == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	o.revokeOrgGrants(m.userID, m.orgID, in.GetRemovedBy())
	m.removedAt, m.removedBy, m.endedKey = timestamppb.Now(), in.GetRemovedBy(), m.id
	return &pb.MarkOrgMembershipRemovedResp{MembershipId: m.id}, nil
}

func (o *orgTables) UpdateOrgMembership(_ context.Context, in *pb.UpdateOrgMembershipReq, _ ...grpc.CallOption) (*pb.UpdateOrgMembershipResp, error) {
	m := o.liveMembership(in.GetId())
	if m == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	var name string
	for _, r := range o.orgScoped {
		if r.GetId() == in.GetRoleId() {
			name = r.GetName()
		}
	}
	if name == "" {
		return nil, status.Error(codes.FailedPrecondition, "ORG_ROLE_NOT_ASSIGNABLE")
	}
	o.revokeOrgGrants(m.userID, m.orgID, in.GetChangedBy())
	if err := o.insertGrant(m.userID, in.GetRoleId(), m.orgID); err != nil {
		return nil, err
	}
	m.role = name
	return &pb.UpdateOrgMembershipResp{MembershipId: m.id}, nil
}

func (o *orgTables) pendingByToken(hash string) *inviteRow {
	for _, i := range o.invites {
		if i.tokenHash == hash && i.acceptedAt == nil && i.closedAt == nil && i.expiresAt.After(time.Now()) && !o.deletedOrgs[i.orgID] {
			return i
		}
	}
	return nil
}

func (o *orgTables) GetPendingOrgInviteByToken(_ context.Context, in *pb.GetPendingOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.GetPendingOrgInviteByTokenResp, error) {
	i := o.pendingByToken(in.GetTokenHash())
	if i == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetPendingOrgInviteByTokenResp{OrgId: i.orgID, Role: i.role, Email: i.email}, nil
}

func (o *orgTables) ConsumeOrgInviteByToken(_ context.Context, in *pb.ConsumeOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.ConsumeOrgInviteByTokenResp, error) {
	i := o.pendingByToken(in.GetTokenHash())
	if i == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	i.acceptedAt = timestamppb.Now()
	return &pb.ConsumeOrgInviteByTokenResp{InviteId: i.id, OrgId: i.orgID, Role: i.role, Email: i.email, RoleSnapshot: i.snapshot}, nil
}

func (o *orgTables) CreateOrgInvite(_ context.Context, in *pb.CreateOrgInviteReq, _ ...grpc.CallOption) (*pb.CreateOrgInviteResp, error) {
	for _, i := range o.invites {
		if in.GetEmail() != "" && i.orgID == in.GetOrgId() && i.email == in.GetEmail() && i.acceptedAt == nil && i.closedAt == nil {
			return nil, errUnique
		}
	}
	i := &inviteRow{id: o.id("inv"), orgID: in.GetOrgId(), email: in.GetEmail(), role: in.GetRole(), tokenHash: in.GetTokenHash(), snapshot: in.GetRoleSnapshot(), expiresAt: in.GetExpiresAt().AsTime()}
	o.invites = append(o.invites, i)
	return &pb.CreateOrgInviteResp{Invite: &pb.OrgInvite{Id: i.id, OrgId: i.orgID, Email: i.email, Role: i.role}}, nil
}

func (o *orgTables) CloseExpiredOrgInvite(_ context.Context, in *pb.CloseExpiredOrgInviteReq, _ ...grpc.CallOption) (*pb.CloseExpiredOrgInviteResp, error) {
	var hit *inviteRow
	for _, i := range o.invites {
		if i.orgID == in.GetOrgId() && i.email == in.GetEmail() && i.acceptedAt == nil && i.closedAt == nil && !i.expiresAt.After(time.Now()) {
			i.closedAt, hit = timestamppb.Now(), i
		}
	}
	if hit == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.CloseExpiredOrgInviteResp{Id: hit.id}, nil
}

func (o *orgTables) CloseOrgInvite(_ context.Context, in *pb.CloseOrgInviteReq, _ ...grpc.CallOption) (*pb.CloseOrgInviteResp, error) {
	for _, i := range o.invites {
		if i.id == in.GetInviteId() && i.orgID == in.GetOrgId() && i.acceptedAt == nil && i.closedAt == nil {
			i.closedAt, i.closedBy = timestamppb.Now(), in.GetClosedBy()
			return &pb.CloseOrgInviteResp{InviteId: i.id}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (o *orgTables) ListOrgInvitesByOrg(_ context.Context, in *pb.ListOrgInvitesByOrgReq, _ ...grpc.CallOption) (*pb.ListOrgInvitesByOrgResp, error) {
	out := &pb.ListOrgInvitesByOrgResp{}
	for _, i := range o.invites {
		if i.orgID == in.GetOrgId() && i.acceptedAt == nil && i.closedAt == nil {
			out.Invites = append(out.Invites, &pb.OrgInvite{Id: i.id, OrgId: i.orgID, Email: i.email, Role: i.role})
		}
	}
	return out, nil
}

// adminInOrg is u1 acting in org-1, holding every permission the catalogue's
// roles carry.
func adminInOrg() context.Context {
	return withHeldPermissions(whoAmICtx("u1", "org-1"), "u1", 1, 2, 3)
}

func (o *orgTables) inviteAndAccept(t *testing.T, h *AuthServiceHandler, role string) {
	t.Helper()
	inv, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: role})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if _, err := h.AcceptOrgInvite(ctxWithCaller("u2"), &pb.AcceptOrgInviteReq{Token: inv.GetToken()}); err != nil {
		t.Fatalf("accept: %v", err)
	}
}

// org_membership/removal-is-a-state: removing a member keeps the membership
// (removed_at, removed_by = the caller) and revokes their org grants
// (revoked_at, revoked_by) without deleting either; the member is gone from
// every read; and they can be invited back and accept, the removed rows
// staying beside the new ones.
func TestRemoveOrgMembership_KeepsTheRowsAndTheMemberCanComeBack(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	o.inviteAndAccept(t, h, "org-worker")
	first := o.memberships[0]

	if _, err := h.RemoveOrgMembership(adminInOrg(), &pb.RemoveOrgMembershipReq{Id: first.id}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if first.removedAt == nil || first.removedBy != "u1" || first.endedKey != first.id {
		t.Fatalf("the membership is not kept as removed by the caller: %+v", first)
	}
	if g := o.grants[0]; g.revokedAt == nil || g.revokedBy != "u1" || g.endedKey != g.id {
		t.Fatalf("the org grant is not kept as revoked by the caller: %+v", g)
	}
	held, _ := o.ListUserOrgGrants(context.Background(), &pb.ListUserOrgGrantsReq{UserId: "u2", OrgId: "org-1"})
	if len(held.GetRoleIds()) != 0 {
		t.Errorf("the removed member still holds %v in the organization", held.GetRoleIds())
	}
	if _, err := h.RemoveOrgMembership(adminInOrg(), &pb.RemoveOrgMembershipReq{Id: first.id}); status.Code(err) != codes.NotFound {
		t.Errorf("removing a removed membership again: %v, want NotFound", err)
	}

	// Back in: a new membership and a new grant, the old rows untouched.
	o.inviteAndAccept(t, h, "org-worker")
	if len(o.memberships) != 2 || len(o.grants) != 2 {
		t.Fatalf("%d memberships, %d grants — want the removed and the new of each", len(o.memberships), len(o.grants))
	}
	if first.removedAt == nil || o.memberships[1].removedAt != nil || o.grants[1].revokedAt != nil {
		t.Errorf("the re-add changed the history or is not live: %+v %+v", first, o.memberships[1])
	}
}

// A role change revokes the grants it replaces (revoked_by = the caller) and
// writes the new one as a new row; changing back to a role held before is
// not blocked by the revoked grant.
func TestUpdateOrgMembershipRole_KeepsTheReplacedGrantsAndCanGoBack(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	o.inviteAndAccept(t, h, "org-worker")
	mem := o.memberships[0].id
	for _, role := range []string{"org-viewer", "org-worker"} {
		if _, err := h.UpdateOrgMembershipRole(inOrg(adminInOrg(), "org-1"), &pb.UpdateOrgMembershipRoleReq{Id: mem, Role: role}); err != nil {
			t.Fatalf("change to %s: %v", role, err)
		}
	}
	if len(o.grants) != 3 {
		t.Fatalf("%d grant rows, want 3 (worker, viewer, worker again)", len(o.grants))
	}
	for i, g := range o.grants[:2] {
		if g.revokedAt == nil || g.revokedBy != "u1" || g.endedKey != g.id {
			t.Errorf("replaced grant %d is not kept revoked by the caller: %+v", i, g)
		}
	}
	held, _ := o.ListUserOrgGrants(context.Background(), &pb.ListUserOrgGrantsReq{UserId: "u2", OrgId: "org-1"})
	if strings.Join(held.GetRoleIds(), ",") != "r-worker" {
		t.Errorf("the member holds %v, want exactly r-worker", held.GetRoleIds())
	}
}

// org_invite/withdrawal-is-a-state: a withdrawn invitation stays (closed_at,
// closed_by = the caller), its link no longer accepts, it is off the pending
// list, and the address can be invited again.
func TestRevokeOrgInvite_ClosesTheRowAndTheLinkIsDead(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	inv, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if _, err := h.RevokeOrgInvite(adminInOrg(), &pb.RevokeOrgInviteReq{InviteId: inv.GetInvite().GetInviteId()}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	row := o.invites[0]
	if row.closedAt == nil || row.closedBy != "u1" || row.acceptedAt != nil {
		t.Fatalf("the invitation is not kept as closed by the caller: %+v", row)
	}
	if _, err := h.AcceptOrgInvite(ctxWithCaller("u2"), &pb.AcceptOrgInviteReq{Token: inv.GetToken()}); err == nil || err.Error() != errInviteInvalid.Error() {
		t.Fatalf("a withdrawn invitation's link: %v, want the opaque invalid-invitation refusal", err)
	}
	if len(o.memberships) != 0 {
		t.Fatal("a withdrawn invitation made a membership")
	}
	if l, _ := h.ListOrgInvites(adminInOrg(), &pb.ListOrgInvitesReq{}); len(l.GetInvites()) != 0 {
		t.Errorf("the withdrawn invitation is still listed as pending: %v", l.GetInvites())
	}
	if _, err := h.RevokeOrgInvite(adminInOrg(), &pb.RevokeOrgInviteReq{InviteId: row.id}); status.Code(err) != codes.NotFound {
		t.Errorf("withdrawing it again: %v, want NotFound", err)
	}
	if _, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"}); err != nil {
		t.Fatalf("the address could not be invited again: %v", err)
	}
	if len(o.invites) != 2 {
		t.Errorf("%d invitation rows, want the closed one and the new one", len(o.invites))
	}
}

// A lapsed invitation is closed, not deleted, when the address is invited
// again: it stays, closed by nobody, and the new one is the pending one.
func TestInviteToOrg_ClosesALapsedInvitationAndKeepsIt(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	if _, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	o.invites[0].expiresAt = time.Now().Add(-time.Minute)
	if _, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"}); err != nil {
		t.Fatalf("re-invite over a lapsed invitation: %v", err)
	}
	if len(o.invites) != 2 || o.invites[0].closedAt == nil || o.invites[0].closedBy != "" || o.invites[1].closedAt != nil {
		t.Fatalf("want the lapsed row kept closed by nobody and a live new one: %+v %+v", o.invites[0], o.invites[1])
	}
}

// The guards that keep a role write from changing nothing, or the wrong
// thing: a deleted or unknown role takes no grant and no permission, and a
// permission the role already carries is refused rather than logged and
// announced again. The role guard is the FIRST op and a no-op UPDATE: it
// locks the live role row, so two adds of one pair serialise (the second sees
// the first's row and is refused) and an add serialises with DeleteRole. Every
// guard runs ahead of the real writes, so a refusal writes nothing.
func TestRoleWritesRefuseADeletedRoleAndANoOp(t *testing.T) {
	m := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))
	const lock = `dql:  "UPDATE @module.Role SET id = id WHERE id = :role_id AND deleted_at IS NULL RETURNING id AS id"`
	roleGuard := []string{lock, "code:       ON_EMPTY_NOT_FOUND", `error_code: "ROLE_NOT_FOUND"`}
	for name, guards := range map[string][][]string{
		"AssignRoleToUser": {roleGuard},
		"AddPermissionToRole": {roleGuard, {
			`dql:  "SELECT rp.id AS id FROM @module.RolePermission rp WHERE rp.role_id = :role.id AND rp.permission_id = :permission_id AND rp.removed_at IS NULL"`,
			"code:       ON_PRESENT_ALREADY_EXISTS",
			`error_code: "PERMISSION_ALREADY_GRANTED"`,
		}},
	} {
		body := m[name]
		if !strings.Contains(body, `name: "role"`) || strings.Index(body, "ops:") != strings.Index(body, `ops: {
        name: "role"`) {
			t.Errorf("%s does not lock the role in its first op:\n%s", name, body)
		}
		// The lock is the first write; the real writes come after every guard.
		firstWrite := len(body)
		for _, w := range []string{"INSERT INTO @module.", "UPSERT INTO @module."} {
			if i := strings.Index(body, w); i >= 0 && i < firstWrite {
				firstWrite = i
			}
		}
		for _, g := range guards {
			at := strings.Index(body, g[0])
			if at < 0 {
				t.Errorf("%s lacks the guard %s:\n%s", name, g[0], body)
				continue
			}
			if at > firstWrite {
				t.Errorf("%s runs the guard %s after a write", name, g[0])
			}
			for _, want := range g[1:] {
				if !strings.Contains(body[at:], want) {
					t.Errorf("%s: the guard %s does not answer %s", name, g[0], want)
				}
			}
		}
	}
	// The writes use the role the lock found.
	for name, want := range map[string]string{
		"AssignRoleToUser":    "role_id = :role.id, ",
		"AddPermissionToRole": "UPSERT INTO @module.RolePermission SET role_id = :role.id, ",
	} {
		if !strings.Contains(m[name], want) {
			t.Errorf("%s does not write the locked role (%q):\n%s", name, want, m[name])
		}
	}
	// A deleted role's grants are not the member's org roles.
	q := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	if !strings.Contains(q["ListUserOrgGrants"], "JOIN @module.Role r ON r.id = ur.role_id") || !strings.Contains(q["ListUserOrgGrants"], "r.deleted_at IS NULL") {
		t.Errorf("ListUserOrgGrants counts grants of deleted roles:\n%s", q["ListUserOrgGrants"])
	}
	// An invitation of a deleted organization is not pending.
	if !strings.Contains(q["GetPendingOrgInviteByToken"], "JOIN @module.Organization o ON o.id = i.org_id") || !strings.Contains(q["GetPendingOrgInviteByToken"], "o.deleted_at IS NULL") {
		t.Errorf("GetPendingOrgInviteByToken reads an invitation of a deleted organization:\n%s", q["GetPendingOrgInviteByToken"])
	}
	// The admin page deletes an organization through the service method that
	// closes its invitations.
	raw, err := os.ReadFile(filepath.Join("..", "..", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "delete: AuthMutation.DeleteOrganization") || !strings.Contains(string(raw), "delete: AuthService.RemoveOrganization") {
		t.Error("the Organizations page does not delete through AuthService.RemoveOrganization")
	}
}

func (o *orgTables) CloseOrgInvitesOfOrg(_ context.Context, in *pb.CloseOrgInvitesOfOrgReq, _ ...grpc.CallOption) (*pb.CloseOrgInvitesOfOrgResp, error) {
	o.ops = append(o.ops, "close-invites")
	for _, i := range o.invites {
		if i.orgID == in.GetOrgId() && i.acceptedAt == nil && i.closedAt == nil {
			i.closedAt, i.closedBy = timestamppb.Now(), in.GetClosedBy()
		}
	}
	return &pb.CloseOrgInvitesOfOrgResp{}, nil
}

// DeleteOrganization: memberships removed, org grants revoked, the org stamped.
func (o *orgTables) DeleteOrganization(_ context.Context, in *pb.DeleteOrganizationReq, _ ...grpc.CallOption) (*pb.DeleteOrganizationResp, error) {
	o.ops = append(o.ops, "delete-org")
	if o.deletedOrgs[in.GetId()] {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	for _, m := range o.memberships {
		if m.orgID == in.GetId() && m.removedAt == nil {
			m.removedAt, m.endedKey = timestamppb.Now(), m.id
		}
	}
	for _, g := range o.grants {
		if g.orgID == in.GetId() && g.revokedAt == nil {
			g.revokedAt, g.endedKey = timestamppb.Now(), g.id
		}
	}
	if o.deletedOrgs == nil {
		o.deletedOrgs = map[string]bool{}
	}
	o.deletedOrgs[in.GetId()] = true
	return &pb.DeleteOrganizationResp{OrgId: in.GetId()}, nil
}

// org_invite/withdrawal-is-a-state: deleting an organization through the
// admin page's service method closes its pending invitations first, by the
// caller, in the same unit of work; their links accept nothing afterwards.
func TestRemoveOrganization_ClosesItsInvitationsAndTheLinksAreDead(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	inv, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	o.ops = nil
	resp, err := h.RemoveOrganization(adminInOrg(), &pb.RemoveOrganizationReq{Id: "org-1"})
	if err != nil || resp.GetOrgId() != "org-1" {
		t.Fatalf("remove: %v %v", resp, err)
	}
	if strings.Join(o.ops, ",") != "close-invites,delete-org" {
		t.Errorf("ran %v — the invitations must be closed before the organization is deleted", o.ops)
	}
	if row := o.invites[0]; row.closedAt == nil || row.closedBy != "u1" {
		t.Fatalf("the invitation is not kept as closed by the caller: %+v", row)
	}
	if _, err := h.AcceptOrgInvite(ctxWithCaller("u2"), &pb.AcceptOrgInviteReq{Token: inv.GetToken()}); err == nil || err.Error() != errInviteInvalid.Error() {
		t.Fatalf("an invitation of a deleted organization: %v, want the opaque invalid-invitation refusal", err)
	}
	if len(o.memberships) != 0 {
		t.Fatal("an invitation of a deleted organization made a membership")
	}
}

// rbac/removal-is-a-state: DeleteRole retires a preset role like any other and
// KEEPS its preset_key — the role seed matches the row by that key and never
// writes deleted_at, so the preset stays deleted across re-seeds; clearing
// the key would make the seed insert its deterministic id again and collide
// with the kept row. Nothing refuses a preset: the seed never retires a role
// the project stopped declaring, so this is the only way to end one.
func TestDeleteRoleKeepsAPresetsKey(t *testing.T) {
	body := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))["DeleteRole"]
	if !strings.Contains(body, "UPDATE @module.Role SET deleted_at = NOW(), ended_key = id WHERE id = :role_id AND deleted_at IS NULL RETURNING id AS role_id") {
		t.Errorf("DeleteRole does not stamp deleted_at and ended_key on any live role:\n%s", body)
	}
	for _, banned := range []string{"preset_key = NULL", "preset_key IS NULL", "preset_key IS NOT NULL", "on_present"} {
		if strings.Contains(body, banned) {
			t.Errorf("DeleteRole treats a preset differently (%q):\n%s", banned, body)
		}
	}
	// The seed's conflict target stays the bare preset_key unique.
	models := authProtos(t)["types/models.proto"]
	i := strings.Index(models, "message Role {")
	role := models[i : i+strings.Index(models[i:], "\n}\n")]
	if !strings.Contains(role, `string preset_key = 9 [(w17.field) = { type: SLUG, max_len: 100, null: true, unique: true }];`) {
		t.Errorf("Role.preset_key is no longer the seed's unique upsert key:\n%s", role)
	}
}

// A request with no caller is refused before anything is written.
func TestRemoveOrganization_RefusesWithoutACaller(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	if _, err := h.RemoveOrganization(context.Background(), &pb.RemoveOrganizationReq{Id: "org-1"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no caller: %v, want Unauthenticated", err)
	}
	if len(o.ops) != 0 {
		t.Fatalf("wrote %v without a caller", o.ops)
	}
}
