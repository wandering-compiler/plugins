package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// org_invite/no-invite-for-a-member: an address whose account is already a
// live member of the organization is refused at invite time, before anything
// is written. Without it the invitation was written and listed as pending,
// and acceptance — the membership's unique index — was the first place that
// refused it, so it could never be accepted.
//
// Over orgTables (no_deletes_test.go), whose reads apply the statements'
// predicates: GetOrgMember finds live memberships only.
func TestInviteToOrg_RefusesAnAddressThatIsAlreadyAMember(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	o.inviteAndAccept(t, h, "org-worker") // u2, member@example.com, joins org-1

	// The address as typed: the check matches the normalised one, as the
	// invitation and sign-in do.
	_, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: " Member@Example.com ", Role: "org-viewer"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("inviting a live member: %v, want AlreadyExists", err)
	}
	if d := detailOf(t, err); d.GetCode() != CodeInviteAlreadyMember || d.GetField() != "email" || d.GetMessage() != MsgInviteAlreadyMember {
		t.Errorf("detail = %v, want %s on email with %q", d, CodeInviteAlreadyMember, MsgInviteAlreadyMember)
	}
	if len(o.invites) != 1 {
		t.Errorf("%d invitation rows, want only the accepted one — a refused invitation wrote a row", len(o.invites))
	}
}

// The other side of the same rule: a REMOVED member is not a member
// (org_membership/removal-is-a-state) and may be invited back, and the new
// invitation can be accepted.
func TestInviteToOrg_ARemovedMemberCanBeInvitedBack(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	o.inviteAndAccept(t, h, "org-worker")
	if _, err := h.RemoveOrgMembership(adminInOrg(), &pb.RemoveOrgMembershipReq{Id: o.memberships[0].id}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	inv, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"})
	if err != nil {
		t.Fatalf("inviting a removed member back was refused: %v", err)
	}
	if _, err := h.AcceptOrgInvite(ctxWithCaller("u2"), &pb.AcceptOrgInviteReq{Token: inv.GetToken()}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if len(o.memberships) != 2 || o.memberships[1].removedAt != nil {
		t.Fatalf("want the removed membership and a live new one: %+v", o.memberships)
	}
}

// A member of ANOTHER organization, and an address with no account at all, are
// invited as before: the rule is about this organization's live members only.
func TestInviteToOrg_AnAddressWithNoMembershipHereIsInvited(t *testing.T) {
	o := newOrgTables()
	h := &AuthServiceHandler{Query: o, Mutation: o}
	o.memberships = append(o.memberships, &memRow{id: "mem-other", userID: "u2", orgID: "org-2", role: "org-worker"})

	for _, email := range []string{"member@example.com", "nobody@example.com"} {
		if _, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: email, Role: "org-worker"}); err != nil {
			t.Fatalf("inviting %s: %v", email, err)
		}
	}
	if len(o.invites) != 2 {
		t.Fatalf("%d invitation rows, want 2", len(o.invites))
	}
}

// failingMemberLookup fails one of the check's two reads with a store error.
type failingMemberLookup struct {
	*orgTables
	userErr, memberErr error
}

func (f *failingMemberLookup) GetUserByEmail(ctx context.Context, in *pb.GetUserByEmailReq, opts ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	if f.userErr != nil {
		return nil, f.userErr
	}
	return f.orgTables.GetUserByEmail(ctx, in, opts...)
}

func (f *failingMemberLookup) GetOrgMember(ctx context.Context, in *pb.GetOrgMemberReq, opts ...grpc.CallOption) (*pb.GetOrgMemberResp, error) {
	if f.memberErr != nil {
		return nil, f.memberErr
	}
	return f.orgTables.GetOrgMember(ctx, in, opts...)
}

// A store failure in either read is the request's failure, not "not a
// member": only NotFound means nobody is there. Read as "no", a failing
// lookup would let through exactly the invitation this rule refuses.
func TestInviteToOrg_AFailedMemberLookupStopsTheWrite(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "store down")
	for _, tc := range []struct {
		name string
		f    failingMemberLookup
	}{
		{"GetUserByEmail", failingMemberLookup{userErr: unavailable}},
		{"GetOrgMember", failingMemberLookup{memberErr: unavailable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOrgTables()
			f := tc.f
			f.orgTables = o
			h := &AuthServiceHandler{Query: &f, Mutation: o}
			_, err := h.InviteToOrg(adminInOrg(), &pb.InviteToOrgReq{Email: "member@example.com", Role: "org-worker"})
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v, want the store's Unavailable", err)
			}
			if len(o.invites) != 0 {
				t.Errorf("%d invitation rows written past a failed check", len(o.invites))
			}
		})
	}
}
