package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// suspensionMock answers GetOrgSuspension from a table, and counts the reads.
type suspensionMock struct {
	resolveUserMock

	suspended map[string]bool // org id → suspended
	readErr   error
	reads     []string
}

func (m *suspensionMock) GetOrgSuspension(_ context.Context, in *pb.GetOrgSuspensionReq, _ ...grpc.CallOption) (*pb.GetOrgSuspensionResp, error) {
	m.reads = append(m.reads, in.GetOrgId())
	if m.readErr != nil {
		return nil, m.readErr
	}
	resp := &pb.GetOrgSuspensionResp{OrgId: in.GetOrgId()}
	if m.suspended[in.GetOrgId()] {
		resp.SuspendedAt = timestamppb.Now()
	}
	return resp, nil
}

// withSuspension installs the check, behind decorators that choose the
// organization. The order of the decorators' files does not matter: the
// check runs after all of them.
func withSuspension(t *testing.T, m *suspensionMock, decorators ...scopeDecorator) *AuthServiceHandler {
	t.Helper()
	noFeatureSeams(t, decorators...)
	scopeChecks = []scopeDecorator{refuseSuspendedOrg}
	m.user = &pb.User{Id: "u1"}
	return &AuthServiceHandler{Query: m, Lock: &acllock.Lock{Version: 1}}
}

// selects stamps the organization the way a decorator does.
func selects(orgID string) scopeDecorator {
	return func(_ context.Context, _ *AuthServiceHandler, _ string, _, scopes, _ map[string]string) error {
		scopes["org_id"] = orgID
		return nil
	}
}

// A request resolved to a suspended organization is refused ORG_SUSPENDED,
// as a PERMISSION_DENIED: the session is fine.
func TestOrgSuspension_ARequestInASuspendedOrganizationIsRefused(t *testing.T) {
	m := &suspensionMock{suspended: map[string]bool{"org-a": true}}
	h := withSuspension(t, m, selects("org-a"))

	_, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"})
	if !errors.Is(err, errOrgSuspended) {
		t.Fatalf("err = %v, want errOrgSuspended underneath", err)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied, never Unauthenticated", status.Code(err))
	}
	d := errorDetailOf(t, err)
	if d == nil || d.GetCode() != CodeOrgSuspended || d.GetMessage() != MsgOrgSuspended {
		t.Errorf("detail = %v, want %s / %q", d, CodeOrgSuspended, MsgOrgSuspended)
	}
	if st, _ := status.FromError(err); st.Message() == orgNotMemberMessage {
		t.Errorf("status message %q is ORG_NOT_MEMBER's", st.Message())
	}
}

// The same person in another organization is not touched, and one resumed
// works again with nothing else changed.
func TestOrgSuspension_OnlyTheSuspendedOrganizationIsStopped(t *testing.T) {
	m := &suspensionMock{suspended: map[string]bool{"org-a": true}}
	h := withSuspension(t, m, selects("org-b"))
	who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"})
	if err != nil || who.GetScopes()["org_id"] != "org-b" {
		t.Fatalf("another organization: scopes %v, err %v", who.GetScopes(), err)
	}

	h = withSuspension(t, m, selects("org-a"))
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("suspended: %v", err)
	}
	delete(m.suspended, "org-a")
	if who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); err != nil || who.GetScopes()["org_id"] != "org-a" {
		t.Errorf("resumed: scopes %v, err %v", who.GetScopes(), err)
	}
}

// The check sees the organization whichever decorator chose it, also one
// that runs last.
func TestOrgSuspension_TheCheckRunsAfterEveryDecorator(t *testing.T) {
	m := &suspensionMock{suspended: map[string]bool{"org-late": true}}
	nothing := func(context.Context, *AuthServiceHandler, string, map[string]string, map[string]string, map[string]string) error {
		return nil
	}
	h := withSuspension(t, m, nothing, selects("org-late"))
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); !errors.Is(err, errOrgSuspended) {
		t.Errorf("err = %v, want the suspension of the organization the last decorator chose", err)
	}
}

// A request in no organization (signing in, listing one's own) reads nothing
// and is not refused.
func TestOrgSuspension_NoOrganizationNoRead(t *testing.T) {
	m := &suspensionMock{suspended: map[string]bool{"org-a": true}}
	h := withSuspension(t, m)
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if len(m.reads) != 0 {
		t.Errorf("read the suspension of %v for a request in no organization", m.reads)
	}
}

// A read that fails refuses the request, as an outage — never lets it through
// and never calls it a suspension. A row gone since the membership was read
// is not a suspension.
func TestOrgSuspension_AFailedReadIsAnOutageNotAPass(t *testing.T) {
	m := &suspensionMock{readErr: status.Error(codes.Unavailable, "db down")}
	h := withSuspension(t, m, selects("org-a"))
	_, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable (AUTH_UNAVAILABLE)", status.Code(err))
	}
	if errors.Is(err, errOrgSuspended) {
		t.Error("an outage was reported as a suspension")
	}

	m.readErr = status.Error(codes.PermissionDenied, "refused downstream")
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); err == nil {
		t.Error("a refused read let the request through")
	}

	m.readErr = status.Error(codes.NotFound, "no row")
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); err != nil {
		t.Errorf("a vanished row: %v, want no suspension", err)
	}
}
