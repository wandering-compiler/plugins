package handlers

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// realmInviteMock is mintMock plus what the backoffice's invitations read:
// an organization by its slug, the caller's realm-wide grants, and the
// pending invitations a withdrawal picks.
type realmInviteMock struct {
	mintMock
	realmWide bool // the caller holds every permission realm-wide
	storedOrg string
	pending   map[string]*pb.PendingOrgInviteRef
	closed    []string
}

func (m *realmInviteMock) GetUserRealmWidePermissions(context.Context, *pb.GetUserRealmWidePermissionsReq, ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	if !m.realmWide {
		return &pb.GetUserRealmWidePermissionsResp{}, nil
	}
	return &pb.GetUserRealmWidePermissionsResp{Grants: []*pb.RoleGrant{{RoleId: "platform-admin", AllPermissions: true}}}, nil
}

func (m *realmInviteMock) GetOrganizationBySlug(_ context.Context, in *pb.GetOrganizationBySlugReq, _ ...grpc.CallOption) (*pb.Organization, error) {
	if in.GetSlug() != "acme" {
		return nil, status.Error(codes.NotFound, "no org")
	}
	return &pb.Organization{Id: "org-acme", Slug: "acme"}, nil
}

func (m *realmInviteMock) CreateOrgInvite(ctx context.Context, in *pb.CreateOrgInviteReq, opts ...grpc.CallOption) (*pb.CreateOrgInviteResp, error) {
	m.storedOrg = in.GetOrgId()
	return m.mintMock.CreateOrgInvite(ctx, in, opts...)
}

func (m *realmInviteMock) GetPendingOrgInvite(_ context.Context, in *pb.GetPendingOrgInviteReq, _ ...grpc.CallOption) (*pb.PendingOrgInviteRef, error) {
	if ref, ok := m.pending[in.GetId()]; ok {
		return ref, nil
	}
	return nil, status.Error(codes.NotFound, "not pending")
}

func (m *realmInviteMock) CloseOrgInvite(_ context.Context, in *pb.CloseOrgInviteReq, _ ...grpc.CallOption) (*pb.CloseOrgInviteResp, error) {
	ref, ok := m.pending[in.GetInviteId()]
	if !ok || ref.GetOrgId() != in.GetOrgId() {
		return nil, status.Error(codes.NotFound, "nothing closed")
	}
	delete(m.pending, in.GetInviteId())
	m.closed = append(m.closed, in.GetOrgId()+"/"+in.GetInviteId())
	return &pb.CloseOrgInviteResp{InviteId: in.GetInviteId()}, nil
}

func realmInviteHandler(realmWide bool) (*AuthServiceHandler, *realmInviteMock) {
	m := &realmInviteMock{realmWide: realmWide, pending: map[string]*pb.PendingOrgInviteRef{
		"inv-a": {Id: "inv-a", OrgId: "org-acme", Role: "member"},
		"inv-b": {Id: "inv-b", OrgId: "org-globex", Role: "member"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, Lock: &acllock.Lock{Permissions: map[string]int{
		"AUTH_AUTH_SERVICE_INVITE_TO_ORG_ADMIN": 1, "AUTH_AUTH_SERVICE_REVOKE_ORG_INVITES": 2,
	}}}
	return h, m
}

// The backoffice invites into the organization the request names: its
// operator is a member of none. A method of its own — gated by the endpoint
// ACL — and refused when nothing gates it; nothing is written on a refusal.
func TestInviteToOrgAdmin_TheBackofficeInvitesIntoTheNamedOrganization(t *testing.T) {
	h, m := realmInviteHandler(true)
	resp, err := h.InviteToOrgAdmin(ctxWithCaller("ops"), &pb.InviteToOrgReq{Org: "acme", Email: "new@acme.example", Role: "member"})
	if err != nil || m.storedOrg != "org-acme" || resp.GetToken() == "" {
		t.Fatalf("the backoffice: err = %v, stored in %q, token %q — want org-acme and a link", err, m.storedOrg, resp.GetToken())
	}
	if _, err := h.InviteToOrgAdmin(ctxWithCaller("ops"), &pb.InviteToOrgReq{Org: "nope", Role: "member"}); status.Code(err) != codes.NotFound {
		t.Errorf("an organization that does not exist: err = %v, want NotFound", err)
	}
	if _, err := h.InviteToOrgAdmin(ctxWithCaller("ops"), &pb.InviteToOrgReq{Role: "member"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no organization named: err = %v, want InvalidArgument", err)
	}

	// From inside an organization: only holding it realm-wide.
	h, m = realmInviteHandler(false)
	if _, err := h.InviteToOrgAdmin(ctxWithCallerInOrg("u1", "org-1"), &pb.InviteToOrgReq{Org: "acme", Role: "member"}); status.Code(err) != codes.PermissionDenied || m.storedOrg != "" {
		t.Errorf("a member, not realm-wide: err = %v, stored in %q — want PermissionDenied and nothing", err, m.storedOrg)
	}
	h, m = realmInviteHandler(true)
	if _, err := h.InviteToOrgAdmin(ctxWithCallerInOrg("ops", "org-1"), &pb.InviteToOrgReq{Org: "acme", Email: "x@acme.example", Role: "member"}); err != nil || m.storedOrg != "org-acme" {
		t.Errorf("the backoffice from inside org-1: err = %v, stored in %q, want org-acme", err, m.storedOrg)
	}

	// Not in the lock: no endpoint ACL says who may call it, so nobody does.
	h, m = realmInviteHandler(true)
	h.Lock = &acllock.Lock{Permissions: map[string]int{"AUTH_AUTH_SERVICE_SIGN_IN": 1}}
	if _, err := h.InviteToOrgAdmin(ctxWithCaller("ops"), &pb.InviteToOrgReq{Org: "acme", Role: "member"}); status.Code(err) != codes.PermissionDenied || m.storedOrg != "" {
		t.Errorf("InviteToOrgAdmin not in the lock: err = %v, stored in %q — want PermissionDenied and nothing", err, m.storedOrg)
	}
}

// InviteToOrg is every member's and stays in the active organization: `org`
// naming another is refused even for a caller holding everything
// realm-wide — a project's default role commonly grants AuthService.* to
// every account, so a realm path here would let anyone invite themselves
// anywhere.
func TestInviteToOrg_StaysInTheActiveOrganization(t *testing.T) {
	h, m := realmInviteHandler(true)
	if _, err := h.InviteToOrg(ctxWithCaller("ops"), &pb.InviteToOrgReq{Org: "acme", Role: "member"}); err != errNoActiveOrg || m.storedOrg != "" {
		t.Errorf("no active organization, naming acme: err = %v, stored in %q — want the no-active-organization refusal", err, m.storedOrg)
	}
	if _, err := h.InviteToOrg(ctxWithCallerInOrg("u1", "org-1"), &pb.InviteToOrgReq{Email: "x@corp.example", Role: "member"}); err != nil || m.storedOrg != "org-1" {
		t.Errorf("a member: err = %v, stored in %q, want org-1", err, m.storedOrg)
	}
}

// The backoffice withdraws the invitations it picked, in whatever
// organizations they are; one no longer pending is skipped.
func TestRevokeOrgInvites_TheBackofficeWithdrawsAcrossOrganizations(t *testing.T) {
	req := &pb.RevokeOrgInvitesReq{Ids: []string{"inv-a", "inv-b", "gone"}}
	h, m := realmInviteHandler(false)
	if _, err := h.RevokeOrgInvites(ctxWithCallerInOrg("u1", "org-1"), req); status.Code(err) != codes.PermissionDenied || len(m.closed) != 0 {
		t.Errorf("from inside an organization, not realm-wide: err = %v, closed %v — want PermissionDenied and nothing", err, m.closed)
	}
	h, m = realmInviteHandler(true)
	h.Lock = &acllock.Lock{Permissions: map[string]int{"AUTH_AUTH_SERVICE_SIGN_IN": 1}}
	if _, err := h.RevokeOrgInvites(ctxWithCaller("ops"), req); status.Code(err) != codes.PermissionDenied || len(m.closed) != 0 {
		t.Errorf("not in the lock: err = %v, closed %v — want PermissionDenied and nothing", err, m.closed)
	}

	h, m = realmInviteHandler(true)
	resp, err := h.RevokeOrgInvites(ctxWithCaller("ops"), req)
	slices.Sort(m.closed)
	if err != nil || resp.GetRevoked() != 2 || !slices.Equal(m.closed, []string{"org-acme/inv-a", "org-globex/inv-b"}) {
		t.Errorf("the backoffice: err = %v, revoked %d, closed %v — want both, each in its organization", err, resp.GetRevoked(), m.closed)
	}
}
