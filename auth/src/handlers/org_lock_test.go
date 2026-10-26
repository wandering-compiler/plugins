package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// lockRecorder records every LockOrganization, marked with whether the one
// transaction was open, and answers NotFound for the organizations in missing.
type lockRecorder struct {
	pb.AuthQueryClient
	tx      *recordingDistTx
	locks   []string
	missing map[string]bool
}

func (q *lockRecorder) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	step := in.GetOrgId()
	if len(q.tx.begun) == 1 && len(q.tx.committed) == 0 && len(q.tx.rolledBack) == 0 {
		step += " in tx"
	}
	q.locks = append(q.locks, step)
	if q.missing[in.GetOrgId()] {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func newLockRecorder() (*AuthServiceHandler, *lockRecorder) {
	q := &lockRecorder{tx: &recordingDistTx{}}
	return &AuthServiceHandler{Query: q, DistTx: q.tx, Connection: "main"}, q
}

// withOrgLock takes the organization's lock first, in one transaction, and
// once: a change composed into another one under the same lock joins it. A
// failure rolls the transaction back; an organization with no live row has
// nothing to lock, and the change answers for itself.
func TestWithOrgLock(t *testing.T) {
	t.Run("once, in one transaction", func(t *testing.T) {
		h, q := newLockRecorder()
		inner := 0
		err := h.withOrgLock(context.Background(), "org-1", func(txCtx context.Context) error {
			return h.withOrgLock(txCtx, "org-1", func(context.Context) error {
				inner++
				return nil
			})
		})
		if err != nil || inner != 1 {
			t.Fatalf("err %v, inner ran %d times", err, inner)
		}
		if !reflect.DeepEqual(q.locks, []string{"org-1 in tx"}) || len(q.tx.begun) != 1 || q.tx.settled() != "committed" {
			t.Fatalf("locks %q, begun %d, %s; want one lock in one committed transaction", q.locks, len(q.tx.begun), q.tx.settled())
		}
	})
	t.Run("a refusal rolls back", func(t *testing.T) {
		h, q := newLockRecorder()
		refused := errors.New("refused")
		if err := h.withOrgLock(context.Background(), "org-1", func(context.Context) error { return refused }); !errors.Is(err, refused) {
			t.Fatalf("err %v", err)
		}
		if q.tx.settled() != "rolled back" {
			t.Fatalf("transaction %s", q.tx.settled())
		}
	})
	t.Run("no live organization", func(t *testing.T) {
		h, q := newLockRecorder()
		q.missing = map[string]bool{"gone": true}
		ran := false
		if err := h.withOrgLock(context.Background(), "gone", func(context.Context) error { ran = true; return nil }); err != nil || !ran {
			t.Fatalf("err %v, ran %v: the change must answer for an organization the lock finds no row for", err, ran)
		}
	})
	t.Run("no coordinator: no transaction to hold a lock, none sent", func(t *testing.T) {
		h, q := newLockRecorder()
		h.DistTx = nil
		ran := false
		if err := h.withOrgLock(context.Background(), "org-1", func(context.Context) error { ran = true; return nil }); err != nil || !ran || len(q.locks) != 0 {
			t.Fatalf("err %v, ran %v, locks %q", err, ran, q.locks)
		}
	})
	t.Run("a storage failure of the lock refuses", func(t *testing.T) {
		h, q := newLockRecorder()
		h.Query = failingLock{q}
		ran := false
		if err := h.withOrgLock(context.Background(), "org-1", func(context.Context) error { ran = true; return nil }); status.Code(err) != codes.Unavailable || ran {
			t.Fatalf("err %v, ran %v", err, ran)
		}
	})
}

type failingLock struct{ *lockRecorder }

func (failingLock) LockOrganization(context.Context, *pb.LockOrganizationReq, ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return nil, status.Error(codes.Unavailable, "down")
}

// underOrgLock runs a method again under its organization's lock, once; with
// no organization it lets the method go on as it did.
func TestUnderOrgLock(t *testing.T) {
	h, q := newLockRecorder()
	calls := 0
	var m func(context.Context, string) (string, error)
	m = func(ctx context.Context, req string) (string, error) {
		if resp, done, err := underOrgLock(ctx, h, "org-1", req, m); done {
			return resp, err
		}
		calls++
		return "ran " + req, nil
	}
	if resp, err := m(context.Background(), "x"); err != nil || resp != "ran x" || calls != 1 {
		t.Fatalf("resp %q, err %v, body ran %d times", resp, err, calls)
	}
	if !reflect.DeepEqual(q.locks, []string{"org-1 in tx"}) {
		t.Fatalf("locks %q", q.locks)
	}
	if _, done, _ := underOrgLock(context.Background(), h, "", "x", m); done {
		t.Fatal("no organization: nothing to lock, the method goes on")
	}
}

// Every change to who holds what in an organization — and so every ceiling or
// last-superadmin check that judges it — runs under the organization's lock,
// from its first read. Read off the source: a new method that grants, revokes
// or composes a role there belongs on this list.
func TestRoleChanges_RunUnderTheOrganizationsLock(t *testing.T) {
	whole := map[string][]string{
		"org_membership_role.go": {"UpdateOrgMembershipRole", "RemoveOrgMembership"},
		"teams.go":               {"AddOrgTeamMember", "RemoveOrgTeamMember", "SetOrgTeamRoles", "DeleteOrgTeam"},
		"org_roles.go":           {"CreateOrgRole", "UpdateOrgRole", "DeleteOrgRole"},
		"org_invite.go":          {"InviteToOrg"},
		"product_roles.go":       {"AssignOrgProductRole", "RevokeOrgProductRole", "AssignProductRole", "RevokeProductRole"},
		"bot_roles.go":           {"SetBotRoles"},
		// The plan bounds what a product role grant may give
		// (checkProductRoleInPlan, read under the lock).
		"product_plans.go": {"AllowOrgProduct", "DisallowOrgProduct"},
	}
	for file, methods := range whole {
		src := handlerSource(t, file)
		for _, name := range methods {
			body := funcBody(t, src, "func (h *AuthServiceHandler) "+name+"(")
			first := strings.TrimSpace(strings.SplitN(body, "\n", 2)[0])
			if !strings.HasPrefix(first, "if resp, done, err := underOrgLock(ctx, h, ") || !strings.Contains(first, "h."+name+")") {
				t.Errorf("%s: %s does not begin under the organization's lock (first line %q)", file, name, first)
			}
		}
	}
	inside := []struct{ file, fn, before, after string }{
		{"org_invite.go", "func (h *AuthServiceHandler) AcceptOrgInvite(", "h.withOrgLock(ctx, pending.GetOrgId()", "h.acceptInviteTx("},
		{"service_account.go", "func (h *AuthServiceHandler) IssueBotToken(", "h.underBotOrgLock(txCtx)", "h.machineKeyDevice("},
		{"service_account.go", "func (h *AuthServiceHandler) issueBotBearerToken(", "h.underBotOrgLock(txCtx)", "h.Mutation.IssueApiToken("},
		{"service_account.go", "func (h *AuthServiceHandler) CreateBot(", "h.underBotOrgLock(txCtx)", "h.createBotUserTx("},
		{"org_signup.go", "func writeSignUpJoin(", "h.lockOrgRow(txCtx", "h.Mutation.AssignRoleToUser("},
	}
	for _, c := range inside {
		body := funcBody(t, handlerSource(t, c.file), c.fn)
		i, j := strings.Index(body, c.before), strings.Index(body, c.after)
		if i < 0 || j < 0 || i > j {
			t.Errorf("%s: %s does not take the organization's lock (%s) before %s", c.file, c.fn, c.before, c.after)
		}
	}
	for _, c := range inside[1:3] {
		body := funcBody(t, handlerSource(t, c.file), c.fn)
		if i, j := strings.Index(body, c.before), strings.Index(body, "h.checkMayActAsBot(txCtx"); j < 0 || j < i {
			t.Errorf("%s: %s does not re-check the ceiling under the lock", c.file, c.fn)
		}
	}
}

func handlerSource(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

// funcBody is the body of the function whose declaration starts with decl.
func funcBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("no %s", decl)
	}
	open := strings.Index(src[i:], "{\n")
	end := strings.Index(src[i:], "\n}\n")
	if open < 0 || end < 0 {
		t.Fatalf("no body for %s", decl)
	}
	return src[i+open+2 : i+end]
}

// callerGrantsStore is a membership store that also answers the caller's own
// grants: org — what the caller holds in the active organization (and
// realm-wide), realm — realm-wide alone; asked records which was read.
type callerGrantsStore struct {
	*membershipRoleMock
	org, realm []*pb.RoleGrant
	asked      []string
}

func (callerGrantsStore) keepsCallerGrants() {}

func (s *callerGrantsStore) GetUserOrgPermissions(_ context.Context, in *pb.GetUserOrgPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserOrgPermissionsResp, error) {
	s.asked = append(s.asked, "org "+in.GetUserId()+" "+in.GetOrgId())
	return &pb.GetUserOrgPermissionsResp{Grants: s.org}, nil
}

func (s *callerGrantsStore) GetUserRealmWidePermissions(_ context.Context, in *pb.GetUserRealmWidePermissionsReq, _ ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	s.asked = append(s.asked, "realm "+in.GetUserId())
	return &pb.GetUserRealmWidePermissionsResp{Grants: s.realm}, nil
}

// Under the organization's lock the ceiling judges what the caller holds NOW:
// the permissions Authenticate resolved, less those whose every grant the
// caller has lost since. A caller demoted while their request waited for the
// lock no longer hands out what the demotion took — and one whose grants
// still carry the role does, so the re-read only ever removes.
func TestCeiling_UnderTheLockJudgesTheCallersGrantsNow(t *testing.T) {
	ctx := inOrg(withHeldPermissions(context.Background(), "u1", 1, 2), "org-1")
	for _, c := range []struct {
		name    string
		now     []*pb.RoleGrant
		refused bool
	}{
		{"still holds it", []*pb.RoleGrant{{RoleId: "r-worker", PermissionIds: []int32{1, 2}}}, false},
		{"demoted meanwhile", []*pb.RoleGrant{{RoleId: "r-viewer", PermissionIds: []int32{1}}}, true},
		{"removed meanwhile", nil, true},
		// More now than the request resolved: the envelope still bounds it.
		{"promoted meanwhile", []*pb.RoleGrant{{RoleId: "r-admin", PermissionIds: []int32{1, 2, 3}}}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, mm := newMembershipRoleHandler("r-viewer")
			s := &callerGrantsStore{membershipRoleMock: mm, org: c.now}
			h := &AuthServiceHandler{Query: s, Mutation: s}
			_, err := h.UpdateOrgMembershipRole(ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-worker"})
			if c.refused {
				// Either ceiling may be the one that refuses: the role handed
				// out, or the member's role the change takes away.
				if code := detailOf(t, err).GetCode(); (code != CodeRoleAboveCaller && code != CodeMemberAboveCaller) || mm.updated != nil {
					t.Fatalf("err %v, written %v: a caller who lost the role handed it out", err, mm.updated)
				}
			} else if err != nil {
				t.Fatalf("refused a caller whose grants carry the role: %v", err)
			}
			if len(s.asked) == 0 {
				t.Fatal("the caller's grants were not read under the lock")
			}
			for _, a := range s.asked {
				if a != "org u1 org-1" {
					t.Fatalf("asked %q, want the caller's grants in the active organization", s.asked)
				}
			}
		})
	}

	// Never more than the envelope: a permission the request did not resolve
	// (narrowed away, a token's subset) stays out whatever the grants carry.
	h := &AuthServiceHandler{}
	held := map[int32]bool{1: true}
	s := &callerGrantsStore{org: []*pb.RoleGrant{{RoleId: "r-admin", PermissionIds: []int32{1, 2, 3}}}}
	h.Query = s
	locked := context.WithValue(ctx, orgLockKey{}, "org-1")
	if got, err := heldUnderOrgLock(locked, h, held); err != nil || !reflect.DeepEqual(got, map[int32]bool{1: true}) {
		t.Fatalf("got %v, %v; want only what the request resolved", got, err)
	}
	// A realm-wide caller (no active organization) is judged by their
	// realm-wide grants, as Authenticate narrowed them.
	realm := context.WithValue(withHeldPermissions(context.Background(), "u1", 1, 2), orgLockKey{}, "org-1")
	s = &callerGrantsStore{realm: []*pb.RoleGrant{{RoleId: "r-viewer", PermissionIds: []int32{1}}}}
	h.Query = s
	if got, err := heldUnderOrgLock(realm, h, map[int32]bool{1: true, 2: true}); err != nil || !reflect.DeepEqual(got, map[int32]bool{1: true}) || !reflect.DeepEqual(s.asked, []string{"realm u1"}) {
		t.Fatalf("got %v, %v, asked %q", got, err, s.asked)
	}
	// Outside a lock the request's permissions stand as resolved.
	if got, _ := heldUnderOrgLock(ctx, h, held); !reflect.DeepEqual(got, held) {
		t.Fatalf("outside the lock: %v", got)
	}
}

// A machine account's transaction is under the organization's lock the way
// withOrgLock's is: the context it goes on in says so, so the ceiling it
// re-checks there (checkMayGrantRole, checkMayActAsBot) reads the caller's
// grants now rather than as the request resolved them.
func TestBotOrgLock_MarksTheTransactionAsUnderTheLock(t *testing.T) {
	h := &AuthServiceHandler{}
	ctx, err := lockBotOrg(h, context.Background(), "org-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ctx.Value(orgLockKey{}).(string); got != "org-1" {
		t.Fatalf("lockBotOrg left the transaction unmarked (%q): the ceiling there re-reads nothing", got)
	}
}

// A team's roles count for a session only (narrowGrantsToActiveOrg): an API
// token whose own role was taken while it waited keeps nothing because a team
// still carries the permission.
func TestCeiling_UnderTheLockCountsTeamsForASessionOnly(t *testing.T) {
	saved := orgGrantSources
	t.Cleanup(func() { orgGrantSources = saved })
	orgGrantSources = []func(context.Context, *AuthServiceHandler, string, string) ([]*pb.RoleGrant, error){
		func(context.Context, *AuthServiceHandler, string, string) ([]*pb.RoleGrant, error) {
			return []*pb.RoleGrant{{RoleId: "r-team", PermissionIds: []int32{2}}}, nil
		},
	}
	held := map[int32]bool{1: true, 2: true}
	h := &AuthServiceHandler{Query: &callerGrantsStore{org: []*pb.RoleGrant{{RoleId: "r-viewer", PermissionIds: []int32{1}}}}}

	session := context.WithValue(inOrg(withHeldPermissions(context.Background(), "u1", 1, 2), "org-1"), orgLockKey{}, "org-1")
	if got, err := heldUnderOrgLock(session, h, held); err != nil || !reflect.DeepEqual(got, held) {
		t.Fatalf("session: got %v, %v; want the team's permission kept", got, err)
	}

	raw, err := proto.Marshal(&pb.AuthResp{UserId: "u1", PermissionIds: []int32{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	md := metadata.Pairs(userMetadataKey, base64.StdEncoding.EncodeToString(raw), "x-w17-scope-org_id", "org-1")
	token := context.WithValue(metadata.NewIncomingContext(context.Background(), md), orgLockKey{}, "org-1")
	if got, err := heldUnderOrgLock(token, h, held); err != nil || !reflect.DeepEqual(got, map[int32]bool{1: true}) {
		t.Fatalf("API token: got %v, %v; want the team's permission gone", got, err)
	}
}
