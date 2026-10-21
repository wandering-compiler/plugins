package handlers

import (
	"context"
	"testing"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

func TestOAuthConsent_OffersOnlyTheOrganizationsTheResourcesAudienceAdmits(t *testing.T) {
	t.Setenv("APP_GATEWAY_CLIENT_MCP_PUBLIC_URL", "https://client.mcp.example.com/mcp")
	t.Setenv("APP_GATEWAY_STAFF_MCP_PUBLIC_URL", "https://staff.mcp.example.com/mcp")
	h := kindsHandler()
	h.Audiences = "client:client:APP_GATEWAY_CLIENT_MCP_PUBLIC_URL;staff:staff:APP_GATEWAY_STAFF_MCP_PUBLIC_URL;web:client:"
	all := []*pb.OAuthConsentOrg{{Id: "org-acme", Slug: "acme"}, {Id: "org-acme", Slug: "acme"}, {Id: "org-beta", Slug: "beta"}}
	ids := func(os []*pb.OAuthConsentOrg) []string {
		var out []string
		for _, o := range os {
			out = append(out, o.GetId())
		}
		return out
	}

	// u1 is staff of acme and a client of acme and beta: the staff MCP offers
	// acme alone, once.
	got, err := orgsForResource(context.Background(), h, "u1", "https://staff.mcp.example.com/mcp/", all)
	if err != nil {
		t.Fatal(err)
	}
	if g := ids(got); len(g) != 1 || g[0] != "org-acme" {
		t.Errorf("staff MCP offers %v, want [org-acme]", g)
	}
	// The client MCP offers both of u1's client organizations.
	got, err = orgsForResource(context.Background(), h, "u1", "https://client.mcp.example.com/mcp", all)
	if err != nil {
		t.Fatal(err)
	}
	if g := ids(got); len(g) != 2 {
		t.Errorf("client MCP offers %v, want acme and beta", g)
	}
	// u2 is a client of nothing: refused at once, not offered a dead choice.
	if _, err := orgsForResource(context.Background(), h, "u2", "https://client.mcp.example.com/mcp", all); err == nil {
		t.Error("a user with no client membership was offered the client MCP")
	} else {
		wantNotAdmitted(t, err)
	}
	// Approval holds the choice to the same rule.
	wantNotAdmitted(t, checkOrgForResource(context.Background(), h, "u2", "org-acme", "https://client.mcp.example.com/mcp"))
	if err := checkOrgForResource(context.Background(), h, "u1", "org-beta", "https://client.mcp.example.com/mcp"); err != nil {
		t.Errorf("u1, a client of beta, refused beta on the client MCP: %v", err)
	}
	// A resource the table does not name is not filtered (deduplicated only).
	got, err = orgsForResource(context.Background(), h, "u2", "https://elsewhere.example.com/mcp", all)
	if err != nil || len(got) != 2 {
		t.Errorf("an unknown resource: %v %v, want both organizations, unfiltered", ids(got), err)
	}
}
