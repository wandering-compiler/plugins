package handlers

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
