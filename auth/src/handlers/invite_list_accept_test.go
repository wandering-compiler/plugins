package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// listAcceptMock adds the caller's own invitations by id to inviteTokenMock.
type listAcceptMock struct {
	*inviteTokenMock
	mine []*pb.PendingInviteRow

	consumedID    string
	consumedEmail string
}

func (m *listAcceptMock) GetPendingOrgInviteForEmail(_ context.Context, in *pb.GetPendingOrgInviteForEmailReq, _ ...grpc.CallOption) (*pb.GetPendingOrgInviteForEmailResp, error) {
	if in.GetEmail() == m.accountEmail {
		for _, i := range m.mine {
			if i.GetInviteId() == in.GetInviteId() {
				return &pb.GetPendingOrgInviteForEmailResp{OrgId: i.GetOrgId(), TokenHash: "hash-of-" + i.GetInviteId()}, nil
			}
		}
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (m *listAcceptMock) ConsumeOrgInviteByToken(ctx context.Context, in *pb.ConsumeOrgInviteByTokenReq, opts ...grpc.CallOption) (*pb.ConsumeOrgInviteByTokenResp, error) {
	m.consumedEmail = in.GetEmail()
	if id, ok := strings.CutPrefix(in.GetTokenHash(), "hash-of-"); ok {
		m.consumedID = id
	}
	return m.inviteTokenMock.ConsumeOrgInviteByToken(ctx, in, opts...)
}

func listAcceptHandler(proof pb.EmailProof, floor string) (*AuthServiceHandler, *listAcceptMock) {
	m := &listAcceptMock{
		inviteTokenMock: &inviteTokenMock{accountEmail: "her@corp.example", accountProof: proof},
		mine:            []*pb.PendingInviteRow{{InviteId: "inv-1", OrgId: "org-1", Role: "member"}},
	}
	return &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: floor}, m
}

// Registered without the link, a person accepts an invitation bound to their
// address from their own list — the GitHub way — and it is spent by its id
// AND their address, in the statement that spends it. Nothing about the
// address is derived: no link reached them.
func TestAcceptMyOrgInvite_FromTheCallersOwnList(t *testing.T) {
	withRealSeams(t)
	h, m := listAcceptHandler(pb.EmailProof_UNPROVEN, emailProofNone)
	resp, err := h.AcceptMyOrgInvite(ctxWithCaller("u1"), &pb.AcceptMyOrgInviteReq{InviteId: "inv-1"})
	if err != nil {
		t.Fatalf("AcceptMyOrgInvite: %v", err)
	}
	if resp.GetOrgId() != "org-1" || !m.addedMembership || m.assignedOrg != "org-1" {
		t.Errorf("resp %v, membership %v, grant in %q: want a member of org-1 with the role there", resp, m.addedMembership, m.assignedOrg)
	}
	if m.consumedID != "inv-1" || m.consumedEmail != "her@corp.example" {
		t.Errorf("claimed %q for %q, want inv-1 for the caller's own address", m.consumedID, m.consumedEmail)
	}
	if m.derivedFor != "" {
		t.Errorf("accepting from the list derived a proof for %q — no link reached the address", m.derivedFor)
	}
}

// An id that is not in the caller's own list — another person's invitation,
// an open one, a guess — is the same opaque refusal as a bad link, and spends
// nothing.
func TestAcceptMyOrgInvite_AnIdOutsideTheCallersListIsOpaque(t *testing.T) {
	withRealSeams(t)
	h, m := listAcceptHandler(pb.EmailProof_UNPROVEN, emailProofNone)
	_, err := h.AcceptMyOrgInvite(ctxWithCaller("u1"), &pb.AcceptMyOrgInviteReq{InviteId: "inv-somebody-elses"})
	if err == nil || !strings.Contains(err.Error(), "invitation invalid") {
		t.Fatalf("err = %v, want the opaque refusal", err)
	}
	if m.consumedID != "" || m.addedMembership {
		t.Errorf("a refused id spent %q / wrote a membership", m.consumedID)
	}
}

// Without the link only the address speaks for the caller, so the
// deployment's floor asks the ACCOUNT for its proof: at `derived` an unproven
// account is refused (the address-guessing window) and a derived or
// confirmed one passes; at `full` only a confirmed one.
func TestAcceptMyOrgInvite_TheFloorAsksTheAccountForItsProof(t *testing.T) {
	withRealSeams(t)
	for _, c := range []struct {
		floor string
		proof pb.EmailProof
		ok    bool
	}{
		{emailProofNone, pb.EmailProof_UNPROVEN, true},
		{emailProofDerived, pb.EmailProof_UNPROVEN, false},
		{emailProofDerived, pb.EmailProof_DERIVED_FROM_INVITE, true},
		{emailProofFull, pb.EmailProof_DERIVED_FROM_INVITE, false},
	} {
		h, m := listAcceptHandler(c.proof, c.floor)
		_, err := h.AcceptMyOrgInvite(ctxWithCaller("u1"), &pb.AcceptMyOrgInviteReq{InviteId: "inv-1"})
		if c.ok && err != nil {
			t.Errorf("floor %s, account %s: %v, want accepted", c.floor, c.proof, err)
		}
		if !c.ok {
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("floor %s, account %s: %v, want FailedPrecondition", c.floor, c.proof, err)
			}
			if m.consumedID != "" {
				t.Errorf("floor %s, account %s: a refusal spent the invitation", c.floor, c.proof)
			}
		}
	}
}

// The link's claim carries the caller's address, so the statement that
// spends it matches only an open invitation or one bound to that address: a
// bind racing the acceptance cannot hand a bound invitation to another
// account.
func TestAcceptOrgInvite_TheClaimNamesTheCallersAddress(t *testing.T) {
	withRealSeams(t)
	h, m := listAcceptHandler(pb.EmailProof_UNPROVEN, emailProofNone)
	if _, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	if m.consumedEmail != "her@corp.example" {
		t.Errorf("the claim named %q, want the caller's address", m.consumedEmail)
	}
}

// A floor that would not be enforced refuses to boot: a typo, or a floor
// above none without email_verification, whose gate is then a no-op.
func TestEmailProofFloor_RefusedAtBootWhenItWouldNotHold(t *testing.T) {
	was := emailProofEnforced
	t.Cleanup(func() { emailProofEnforced = was })
	for _, c := range []struct {
		floor    string
		enforced bool
		ok       bool
	}{
		{"", false, true},
		{"none", false, true},
		{"derived", false, false},
		{"full", false, false},
		{"derived", true, true},
		{"full", true, true},
		{"strict", true, false},
	} {
		emailProofEnforced = c.enforced
		err := checkEmailProofFloor(&AuthServiceHandler{EmailProofRequired: c.floor})
		if (err == nil) != c.ok {
			t.Errorf("floor %q, email_verification %v: err = %v, want ok=%v", c.floor, c.enforced, err, c.ok)
		}
	}
}

// inviteListMock is an organization's pending invitations over the role
// catalogue.
type inviteListMock struct {
	*roleCatalogueMock
	invites []*pb.OrgInvite
	closed  string
}

func (m *inviteListMock) ListOrgInvitesByOrg(_ context.Context, _ *pb.ListOrgInvitesByOrgReq, _ ...grpc.CallOption) (*pb.ListOrgInvitesByOrgResp, error) {
	return &pb.ListOrgInvitesByOrgResp{Invites: m.invites}, nil
}

func (m *inviteListMock) CloseOrgInvite(_ context.Context, in *pb.CloseOrgInviteReq, _ ...grpc.CallOption) (*pb.CloseOrgInviteResp, error) {
	m.closed = in.GetInviteId()
	return &pb.CloseOrgInviteResp{InviteId: in.GetInviteId()}, nil
}

// An organization's invitations are shown to, and withdrawn by, only those
// who could have made them: a member below an invitation's role sees neither
// its address nor its metadata, and cannot withdraw it.
func TestOrgInvites_ListedAndWithdrawnWithinTheCeiling(t *testing.T) {
	cat := newRoleCatalogue()
	cat.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}, "r-viewer": {1}}
	m := &inviteListMock{roleCatalogueMock: cat, invites: []*pb.OrgInvite{
		{Id: "inv-admin", Email: "boss@example.com", Role: "org-admin"},
		{Id: "inv-viewer", Email: "pal@example.com", Role: "org-viewer"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	viewer := withHeldPermissions(whoAmICtx("u1", "org-1"), "u1", 1)

	list, err := h.ListOrgInvites(viewer, &pb.ListOrgInvitesReq{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetInvites()) != 1 || list.GetInvites()[0].GetInviteId() != "inv-viewer" {
		t.Errorf("a viewer was shown %v, want only the viewer's invitation", list.GetInvites())
	}
	if _, err := h.RevokeOrgInvite(viewer, &pb.RevokeOrgInviteReq{InviteId: "inv-admin"}); refusalCodeOf(err) != CodeInviteAboveCaller {
		t.Errorf("a viewer withdrawing the admin's invitation: %v, want %s", err, CodeInviteAboveCaller)
	}
	if m.closed != "" {
		t.Errorf("a refused withdrawal closed %q", m.closed)
	}
	if _, err := h.RevokeOrgInvite(viewer, &pb.RevokeOrgInviteReq{InviteId: "inv-viewer"}); err != nil || m.closed != "inv-viewer" {
		t.Errorf("a viewer withdrawing a viewer's invitation: %v, closed %q", err, m.closed)
	}

	admin := withHeldPermissions(whoAmICtx("u2", "org-1"), "u2", 1, 2, 3)
	if list, _ := h.ListOrgInvites(admin, &pb.ListOrgInvitesReq{}); len(list.GetInvites()) != 2 {
		t.Errorf("an admin was shown %v, want both", list.GetInvites())
	}
}
