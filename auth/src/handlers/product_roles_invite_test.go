package handlers

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

func refs(pairs ...string) []*pb.ProductRoleRef {
	out := make([]*pb.ProductRoleRef, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, &pb.ProductRoleRef{Product: pairs[i], RoleKey: pairs[i+1]})
	}
	return out
}

func refPairs(rs []*pb.ProductRoleRef) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.GetProduct()+":"+r.GetRoleKey())
	}
	return out
}

func TestProductRoleRefsColumn(t *testing.T) {
	col := encodeProductRoleRefs(refs("beta", "viewer", "alpha", "viewer", "alpha", "viewer"))
	if col != "alpha:viewer,beta:viewer" {
		t.Errorf("encoded %q, want sorted and deduplicated", col)
	}
	if got := refPairs(decodeProductRoleRefs(col)); !slices.Equal(got, []string{"alpha:viewer", "beta:viewer"}) {
		t.Errorf("decoded %v", got)
	}
	if got := decodeProductRoleRefs(""); len(got) != 0 {
		t.Errorf("an empty column decodes to %v, want none", got)
	}
}

// An invitation carries only the product roles the inviter could hand out in
// the organization then: the catalogue's, held in an organization, carried
// by the plan and covered by one the inviter holds there.
func TestInviteProductRoles(t *testing.T) {
	if inviteProductRoles == nil {
		t.Fatal("product_roles_invite.go installs no hooks")
	}
	h, m := prodHandler(t)
	ctx := context.Background()
	check := func(inviter string, rs ...*pb.ProductRoleRef) (string, error) {
		write, err := inviteProductRoles.check(ctx, h, inviter, "org-a", &pb.InviteToOrgReq{ProductRoles: rs})
		if err != nil {
			return "", err
		}
		create := &pb.CreateOrgInviteReq{}
		write(create)
		return create.GetProductRoles(), nil
	}
	if col, err := check("alice", refs("alpha", "viewer", "alpha", "editor")...); err != nil || col != "alpha:editor,alpha:viewer" {
		t.Errorf("alice (alpha admin) inviting with alpha's viewer and editor: %q, %v", col, err)
	}
	if col, err := check("alice"); err != nil || col != "" {
		t.Errorf("an invitation with no product roles: %q, %v", col, err)
	}
	for _, c := range []struct {
		name    string
		inviter string
		rs      []*pb.ProductRoleRef
		code    string
	}{
		{"a role above the inviter", "bob", refs("alpha", "viewer"), CodeProductRoleAbove},
		{"a product the catalogue does not name", "alice", refs("gamma", "viewer"), CodeProductUnknown},
		{"a role the product does not declare", "alice", refs("alpha", "owner"), CodeProductRoleUnknown},
		{"a role held realm-wide", "alice", refs("alpha", "auditor"), CodeProductRoleRealmHeld},
		{"a product outside the plan", "alice", refs("beta", "viewer"), CodeProductRoleNotInPlan},
	} {
		if _, err := check(c.inviter, c.rs...); refusalCodeOf(err) != c.code {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	if len(m.written) != 0 {
		t.Errorf("checking an invitation wrote %v", m.written)
	}

	// Acceptance: held to the catalogue and the plan as they are then, and
	// granted by the inviter.
	claimed := &pb.ConsumeOrgInviteByTokenResp{OrgId: "org-a", InvitedBy: "alice", ProductRoles: "alpha:viewer"}
	if err := inviteProductRoles.verify(ctx, h, "org-a", claimed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// dave's membership is the acceptance's own write, in its transaction: a
	// read of it from outside does not see it, so the grant must not ask.
	resp := &pb.AcceptOrgInviteResp{}
	if err := inviteProductRoles.grant(ctx, h, "dave", "org-a", claimed, resp); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !slices.Equal(m.written, []string{"dave/org-a/alpha:viewer"}) || m.grants[len(m.grants)-1].GetGrantedBy() != "alice" {
		t.Errorf("accepting wrote %v (giver %q), want dave's alpha viewer from alice", m.written, m.grants[len(m.grants)-1].GetGrantedBy())
	}
	if got := refPairs(resp.GetProductRoles()); !slices.Equal(got, []string{"alpha:viewer"}) {
		t.Errorf("the acceptance reports %v", got)
	}
	// The plan took alpha since: refused before anything is written.
	m.plan = nil
	if err := inviteProductRoles.verify(ctx, h, "org-a", claimed); refusalCodeOf(err) != CodeProductRoleNotInPlan {
		t.Errorf("accepting after the plan took alpha: %v, want %s", err, CodeProductRoleNotInPlan)
	}
	// A product deploy retired the role since.
	if err := inviteProductRoles.verify(ctx, h, "org-a", &pb.ConsumeOrgInviteByTokenResp{ProductRoles: "alpha:retired"}); refusalCodeOf(err) != CodeProductRoleUnknown {
		t.Errorf("accepting a retired role: %v, want %s", err, CodeProductRoleUnknown)
	}

	// The lists show them.
	sum := &pb.OrgInviteSummary{}
	inviteProductRoles.summary(&pb.OrgInvite{ProductRoles: "alpha:viewer"}, sum)
	mine := &pb.MyInvite{}
	inviteProductRoles.mine(&pb.PendingInviteRow{ProductRoles: "alpha:viewer"}, mine)
	if !slices.Equal(refPairs(sum.GetProductRoles()), []string{"alpha:viewer"}) || !slices.Equal(refPairs(mine.GetProductRoles()), []string{"alpha:viewer"}) {
		t.Errorf("summary %v, mine %v", sum.GetProductRoles(), mine.GetProductRoles())
	}
}

// signupMock adds an organization's registration policies to prodMock.
type signupMock struct {
	*prodMock
	policies []*pb.OrgSignUpPolicyRow
}

func (m *signupMock) ListOrgSignUpPolicyRows(_ context.Context, _ *pb.ListOrgSignUpPolicyRowsReq, _ ...grpc.CallOption) (*pb.ListOrgSignUpPolicyRowsResp, error) {
	if len(m.policies) == 0 {
		return nil, status.Error(codes.NotFound, "none")
	}
	return &pb.ListOrgSignUpPolicyRowsResp{Policies: m.policies}, nil
}

// An open registration policy names only roles the catalogue holds in an
// organization and the plan carries; a registration gives those still
// carried when it joins, and passes over the rest.
func TestSignUpPolicyProductRoles(t *testing.T) {
	if signupPolicyProductRoles == nil {
		t.Fatal("product_roles_signup.go installs no hooks")
	}
	h, pm := prodHandler(t)
	m := &signupMock{prodMock: pm}
	h.Query, h.Mutation = m, m
	ctx := context.Background()
	set := func(rs ...*pb.ProductRoleRef) (string, error) {
		write, err := signupPolicyProductRoles.check(ctx, h, &pb.SetOrgSignUpPolicyReq{OrgId: "org-a", Open: true, Role: "member", ProductRoles: rs})
		if err != nil {
			return "", err
		}
		row := &pb.SetOrgSignUpPolicyRowReq{}
		write(row)
		return row.GetProductRoles(), nil
	}
	// No ceiling: the backoffice sets policies.
	if col, err := set(refs("alpha", "admin")...); err != nil || col != "alpha:admin" {
		t.Errorf("a policy giving alpha's admin: %q, %v", col, err)
	}
	if _, err := set(refs("beta", "viewer")...); refusalCodeOf(err) != CodeProductRoleNotInPlan {
		t.Errorf("a policy giving beta, outside org-a's plan: %v, want %s", err, CodeProductRoleNotInPlan)
	}
	if _, err := set(refs("alpha", "auditor")...); refusalCodeOf(err) != CodeProductRoleRealmHeld {
		t.Errorf("a policy giving a realm-held role: %v, want %s", err, CodeProductRoleRealmHeld)
	}

	info := &pb.OrgSignUpPolicyInfo{}
	signupPolicyProductRoles.info(&pb.OrgSignUpPolicyRow{ProductRoles: "alpha:viewer"}, info)
	if !slices.Equal(refPairs(info.GetProductRoles()), []string{"alpha:viewer"}) {
		t.Errorf("the policy list shows %v", info.GetProductRoles())
	}

	// A registration joins with the live policy of its kind: alpha's viewer
	// is given; alpha's editor left the plan and beta was never in it.
	m.policies = []*pb.OrgSignUpPolicyRow{
		{Kind: "client", Open: true, ProductRoles: "alpha:admin"},
		{Kind: "", Open: true, ProductRoles: "alpha:retired,alpha:viewer,beta:viewer"},
	}
	// frank's membership is the registration's own write (not readable here).
	if err := signupPolicyProductRoles.grant(ctx, h, "frank", &orgJoin{orgID: "org-a", role: "member"}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !slices.Equal(pm.written, []string{"frank/org-a/alpha:viewer"}) {
		t.Errorf("the registration wrote %v, want only frank's alpha viewer", pm.written)
	}
	// No policy speaks for the organization any more: nothing is given.
	m.policies = nil
	pm.written = nil
	if err := signupPolicyProductRoles.grant(ctx, h, "gina", &orgJoin{orgID: "org-a", role: "member"}); err != nil || len(pm.written) != 0 {
		t.Errorf("no live policy: err %v, wrote %v", err, pm.written)
	}
}
