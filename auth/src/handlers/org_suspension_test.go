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

	for _, cause := range []error{status.Error(codes.PermissionDenied, "refused downstream"), context.Canceled} {
		m.readErr = cause
		_, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"})
		if err == nil {
			t.Errorf("%v: a failed read let the request through", cause)
		} else if status.Code(err) != codes.Unavailable {
			t.Errorf("%v: code = %v, want Unavailable — never the 401 that signs a session out", cause, status.Code(err))
		}
	}

	m.readErr = status.Error(codes.NotFound, "no row")
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); err != nil {
		t.Errorf("a vanished row: %v, want no suspension", err)
	}
}

// infers stamps the organization the way the sole-membership inference does.
func infers(orgID string) scopeDecorator {
	return func(ctx context.Context, _ *AuthServiceHandler, _ string, _, scopes, labels map[string]string) error {
		scopes["org_id"], scopes["org_slug"], labels["org_id"] = orgID, "slug-"+orgID, orgID
		markOrgInferred(ctx)
		return nil
	}
}

// The caller's only organization, suspended and chosen for them, is dropped:
// the request goes on in no organization, so the account itself (sign out,
// password, second factor, its organizations) keeps working.
func TestOrgSuspension_AnInferredSuspendedOrganizationIsDropped(t *testing.T) {
	m := &suspensionMock{suspended: map[string]bool{"org-a": true}}
	h := withSuspension(t, m, infers("org-a"))
	who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"})
	if err != nil {
		t.Fatalf("ResolveUser: %v, want the request to go on in no organization", err)
	}
	if _, ok := who.GetScopes()["org_id"]; ok {
		t.Errorf("scopes %v still name the suspended organization", who.GetScopes())
	}
	if _, ok := who.GetScopes()["org_slug"]; ok {
		t.Errorf("scopes %v still carry its slug", who.GetScopes())
	}
	if _, ok := who.GetLabels()["org_id"]; ok {
		t.Errorf("labels %v still route its events", who.GetLabels())
	}

	// Inferred and live: kept.
	m.suspended = nil
	if who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"}); err != nil || who.GetScopes()["org_id"] != "org-a" {
		t.Errorf("a live inferred organization: scopes %v, err %v", who.GetScopes(), err)
	}
}

// Nobody enters a suspended organization: the entry check refuses it
// ORG_SUSPENDED, lets a live one through, and fails closed on a read error.
func TestOrgSuspension_NobodyEntersASuspendedOrganization(t *testing.T) {
	m := &suspensionMock{suspended: map[string]bool{"org-a": true}}
	h := &AuthServiceHandler{Query: m}

	err := refuseEntryToSuspendedOrg(context.Background(), h, "org-a")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("suspended: %v, want PermissionDenied", err)
	}
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeOrgSuspended {
		t.Errorf("detail = %v, want %s", d, CodeOrgSuspended)
	}
	if err := refuseEntryToSuspendedOrg(context.Background(), h, "org-b"); err != nil {
		t.Errorf("a live organization: %v", err)
	}
	m.readErr = status.Error(codes.Internal, "db down")
	if err := refuseEntryToSuspendedOrg(context.Background(), h, "org-b"); status.Code(err) != codes.Unavailable {
		t.Errorf("a failed read: %v, want Unavailable", err)
	}
}

// Without the feature nothing checks an entry.
func TestOrgSuspension_NoFeatureNoEntryCheck(t *testing.T) {
	prev := orgEntryCheck
	t.Cleanup(func() { orgEntryCheck = prev })
	orgEntryCheck = nil
	if err := checkOrgEntry(context.Background(), &AuthServiceHandler{}, "org-a"); err != nil {
		t.Errorf("checkOrgEntry with no hook: %v", err)
	}
}
