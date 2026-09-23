package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// inviteMock records the clear-then-create sequence InviteToOrg performs.
type inviteMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	clearErr    error
	clearCalls  int
	createCalls int
	createErr   error
}

func (m *inviteMock) ListOrgScopedRoles(ctx context.Context, in *pb.ListOrgScopedRolesReq, _ ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	return &pb.ListOrgScopedRolesResp{Roles: []*pb.OrgScopedRole{{Id: "r1", Name: "org-worker"}}}, nil
}

func (m *inviteMock) ClearExpiredOrgInvite(ctx context.Context, in *pb.ClearExpiredOrgInviteReq, _ ...grpc.CallOption) (*pb.ClearExpiredOrgInviteResp, error) {
	m.clearCalls++
	if m.clearErr != nil {
		return nil, m.clearErr
	}
	return &pb.ClearExpiredOrgInviteResp{Id: "old"}, nil
}

func (m *inviteMock) CreateOrgInvite(ctx context.Context, in *pb.CreateOrgInviteReq, _ ...grpc.CallOption) (*pb.CreateOrgInviteResp, error) {
	m.createCalls++
	if m.createErr != nil {
		return nil, m.createErr
	}
	return &pb.CreateOrgInviteResp{Invite: &pb.OrgInvite{Id: "new", OrgId: in.GetOrgId(), Email: in.GetEmail()}}, nil
}

func inviterCtx(userID, orgID string) context.Context {
	return whoAmICtx(userID, orgID)
}

// A lapsed invitation must not hold the address hostage.
//
// The pending index is unique on (org, email) WHERE accepted_at IS NULL and
// cannot exclude expired rows — a partial index predicate must be IMMUTABLE
// and NOW() is not — so without this the re-invite fails on a unique
// violation that reads like two inviters racing. Nobody is racing: the
// blocker is a dead row the inviter can see and cannot get past.
func TestInviteToOrg_ClearsALapsedInviteFirst(t *testing.T) {
	m := &inviteMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.InviteToOrg(inviterCtx("u1", "org-1"), &pb.InviteToOrgReq{
		Email: "someone@example.com", Role: "org-worker",
	}); err != nil {
		t.Fatalf("InviteToOrg: %v", err)
	}
	if m.clearCalls != 1 {
		t.Fatalf("the lapsed-invite clear ran %d time(s), want exactly one before the write", m.clearCalls)
	}
	if m.createCalls != 1 {
		t.Fatalf("create ran %d time(s)", m.createCalls)
	}
}

// Nothing lapsed is the ORDINARY case and arrives as NOT_FOUND because of the
// RETURNING. Treating it as a failure would refuse every FIRST invitation to
// an address — the same unreachable-branch shape D13-7 shipped one function
// away.
func TestInviteToOrg_NothingExpiredIsNotAFailure(t *testing.T) {
	m := &inviteMock{clearErr: status.Error(codes.NotFound, "no rows")}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.InviteToOrg(inviterCtx("u1", "org-1"), &pb.InviteToOrgReq{
		Email: "first@example.com", Role: "org-worker",
	}); err != nil {
		t.Fatalf("a first invitation was refused because nothing had expired: %v", err)
	}
	if m.createCalls != 1 {
		t.Fatal("the invitation was never written")
	}
}

// A real failure of the clear stops the write. Carrying on would write a
// second pending invitation for an address that already has one, which is
// exactly what the index exists to prevent.
func TestInviteToOrg_ClearFailureStopsTheWrite(t *testing.T) {
	m := &inviteMock{clearErr: status.Error(codes.Unavailable, "db down")}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.InviteToOrg(inviterCtx("u1", "org-1"), &pb.InviteToOrgReq{
		Email: "someone@example.com", Role: "org-worker",
	}); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if m.createCalls != 0 {
		t.Fatal("the invitation was written after the clear failed")
	}
}
