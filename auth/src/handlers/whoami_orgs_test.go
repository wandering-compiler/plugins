package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// whoAmIMock answers the one query the enrichment makes.
type whoAmIMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	orgs    []*pb.UserOrg
	listErr error
	calls   int
}

func (m *whoAmIMock) ListUserOrgs(ctx context.Context, in *pb.ListUserOrgsReq, _ ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	m.calls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &pb.ListUserOrgsResp{Orgs: m.orgs}, nil
}

// whoAmICtx carries what the gateway threads in: the resolved principal and
// the VERIFIED org scope.
func whoAmICtx(userID, orgID string) context.Context {
	pairs := []string{scopeUserIDKey, userID}
	if orgID != "" {
		pairs = append(pairs, "x-w17-scope-org_id", orgID)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

// WhoAmI answers "who am I and WHERE am I".
//
// Asserted through the RPC, not through whoAmIEnrich: the enrichment is
// installed by an init() in this file's org_membership sibling, and a test
// that calls the seam directly passes even if nothing installs it — which is
// the failure mode this plugin has hit before (an init that moved and took a
// security gate with it, everything green).
func TestWhoAmI_CarriesOrgsAndTheActiveOne(t *testing.T) {
	m := &whoAmIMock{orgs: []*pb.UserOrg{
		{OrgId: "o1", Slug: "marb", Role: "org-admin"},
		{OrgId: "o2", Slug: "deinvo", Role: "org-admin"},
	}}
	h := &AuthServiceHandler{Query: m}

	resp, err := h.WhoAmI(whoAmICtx("u1", "o2"), &pb.WhoAmIReq{})
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if resp.GetUserId() != "u1" {
		t.Fatalf("user_id = %q", resp.GetUserId())
	}
	if len(resp.GetOrgs()) != 2 {
		t.Fatalf("orgs = %d, want both memberships — every screen rebuilt this from further calls", len(resp.GetOrgs()))
	}
	if resp.GetActiveOrgId() != "o2" {
		t.Fatalf("active_org_id = %q, want the org THIS request resolved to", resp.GetActiveOrgId())
	}
}

// No active org is a REAL state — a caller in several who named none — and the
// UI has to tell it from "one, and it is this": the difference decides whether
// to show a picker or a workspace.
func TestWhoAmI_NoActiveOrgIsReportedAsEmpty(t *testing.T) {
	m := &whoAmIMock{orgs: []*pb.UserOrg{{OrgId: "o1", Slug: "marb"}, {OrgId: "o2", Slug: "deinvo"}}}
	h := &AuthServiceHandler{Query: m}

	resp, err := h.WhoAmI(whoAmICtx("u1", ""), &pb.WhoAmIReq{})
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if resp.GetActiveOrgId() != "" {
		t.Fatalf("active_org_id = %q, want empty when the request resolved none", resp.GetActiveOrgId())
	}
	if len(resp.GetOrgs()) != 2 {
		t.Error("the choices must still be listed — that is what makes the empty active org actionable")
	}
}

// The org half is ENRICHMENT. WhoAmI's job is to answer who the caller is, and
// sign-in checks and session probes lean on it; failing the whole call because
// a second query was unavailable would take those down with it.
func TestWhoAmI_SurvivesAFailingOrgQuery(t *testing.T) {
	m := &whoAmIMock{listErr: context.DeadlineExceeded}
	h := &AuthServiceHandler{Query: m}

	resp, err := h.WhoAmI(whoAmICtx("u1", "o2"), &pb.WhoAmIReq{})
	if err != nil {
		t.Fatalf("a failed org lookup must not fail WhoAmI: %v", err)
	}
	if resp.GetUserId() != "u1" {
		t.Error("identity was lost with the enrichment")
	}
	if len(resp.GetOrgs()) != 0 {
		t.Error("orgs were invented despite the query failing")
	}
}
