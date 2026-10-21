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

// One membership per organization, of one kind: u1 is staff of acme and a
// client of beta and of gamma; u2 is staff of acme only.
func kindsHandler() *AuthServiceHandler {
	return &AuthServiceHandler{Query: &orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"u1": {
			{OrgId: "org-acme", Slug: "acme", MembershipKind: "staff"},
			{OrgId: "org-beta", Slug: "beta", MembershipKind: "client"},
			{OrgId: "org-gamma", Slug: "gamma", MembershipKind: "client"},
		},
		"u2": {{OrgId: "org-acme", Slug: "acme", MembershipKind: "staff"}},
	}}}
}

func admits(kinds string) map[string]string {
	return map[string]string{membershipKindsHeader: kinds}
}

func wantNotAdmitted(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied (403 before any handler)", err)
	}
}

func TestResolveOrgScopeByKind(t *testing.T) {
	h := kindsHandler()

	t.Run("the slug resolves through an admitted membership", func(t *testing.T) {
		sc, lb := map[string]string{}, map[string]string{}
		hd := admits("client")
		hd[orgScopeMetadataKey] = "beta"
		if err := resolveOrgScope(context.Background(), h, "u1", hd, sc, lb); err != nil {
			t.Fatal(err)
		}
		if sc["org_id"] != "org-beta" || lb["org_id"] != "org-beta" {
			t.Errorf("scopes %v labels %v, want org-beta", sc, lb)
		}
	})

	t.Run("a membership of another kind in the named org is 403, not 'not a member'", func(t *testing.T) {
		hd := admits("client")
		hd[orgScopeMetadataKey] = "acme"
		wantNotAdmitted(t, resolveOrgScope(context.Background(), h, "u1", hd, map[string]string{}, map[string]string{}))
	})

	t.Run("no membership of the named org at all is 'not a member'", func(t *testing.T) {
		hd := admits("client")
		hd[orgScopeMetadataKey] = "delta"
		err := resolveOrgScope(context.Background(), h, "u1", hd, map[string]string{}, map[string]string{})
		if err == nil || status.Code(err) == codes.PermissionDenied {
			t.Fatalf("err = %v, want the not-a-member refusal", err)
		}
	})

	t.Run("no selector: the one admitted organization", func(t *testing.T) {
		sc := map[string]string{}
		if err := resolveOrgScope(context.Background(), h, "u1", admits("staff"), sc, map[string]string{}); err != nil {
			t.Fatal(err)
		}
		if sc["org_id"] != "org-acme" {
			t.Errorf("org_id = %q, want org-acme — u1's only staff membership", sc["org_id"])
		}
	})

	t.Run("no selector and several admitted: ambiguous, no scope", func(t *testing.T) {
		sc := map[string]string{}
		if err := resolveOrgScope(context.Background(), h, "u1", admits("client"), sc, map[string]string{}); err != nil {
			t.Fatal(err)
		}
		if _, ok := sc["org_id"]; ok {
			t.Errorf("stamped %q though u1 is a client of two organizations", sc["org_id"])
		}
	})

	t.Run("no admitted membership at all is 403", func(t *testing.T) {
		wantNotAdmitted(t, resolveOrgScope(context.Background(), h, "u2", admits("client"), map[string]string{}, map[string]string{}))
	})

	t.Run("a gateway that names no kinds resolves as before", func(t *testing.T) {
		m := &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{"u1|acme": {OrgId: "org-acme"}}}
		sc := map[string]string{}
		hd := map[string]string{orgScopeMetadataKey: "acme"}
		if err := resolveOrgScope(context.Background(), &AuthServiceHandler{Query: m}, "u1", hd, sc, map[string]string{}); err != nil {
			t.Fatal(err)
		}
		if sc["org_id"] != "org-acme" {
			t.Errorf("org_id = %q", sc["org_id"])
		}
	})
}

// Ownership is root authority its staff exercise: through an audience that
// admits only some kinds, it does not widen.
func TestOwnershipDoesNotWidenThroughAKindFilter(t *testing.T) {
	q := &ownsMock{owner: true}
	p := &authPrincipal{userID: "u1", realm: pb.TokenType_TOKEN_TYPE_SESSION}
	ctx := context.WithValue(context.Background(), authHeadersKey{}, admits("client"))
	if err := narrowGrantsToActiveOrg(ctx, &AuthServiceHandler{Query: q}, p, map[string]string{"org_id": "org-acme"}); err != nil {
		t.Fatal(err)
	}
	for _, g := range p.grants {
		if g.GetAllPermissions() {
			t.Fatal("an owner reached the client's surface with the owner's wildcard")
		}
	}
}

// ownsMock answers the queries narrowGrantsToActiveOrg and the invite check
// make.
type ownsMock struct {
	pb.AuthQueryClient
	owner bool
	orgs  []*pb.UserOrg
}

func (m *ownsMock) GetUserOrgPermissions(context.Context, *pb.GetUserOrgPermissionsReq, ...grpc.CallOption) (*pb.GetUserOrgPermissionsResp, error) {
	return &pb.GetUserOrgPermissionsResp{}, nil
}

func (m *ownsMock) GetUserOwnsOrg(context.Context, *pb.GetUserOwnsOrgReq, ...grpc.CallOption) (*pb.GetUserOwnsOrgResp, error) {
	return &pb.GetUserOwnsOrgResp{Owner: m.owner}, nil
}

func (m *ownsMock) ListUserOrgs(context.Context, *pb.ListUserOrgsReq, ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	return &pb.ListUserOrgsResp{Orgs: m.orgs}, nil
}

// The refusal survives Authenticate's folding of decorator errors into the
// opaque Unauthenticated: an admitted credential at the wrong door is 403.
func TestNotAdmittedSurvivesTheDecoratorFold(t *testing.T) {
	prev := scopeDecorators
	defer func() { scopeDecorators = prev }()
	scopeDecorators = []scopeDecorator{func(ctx context.Context, _ *AuthServiceHandler, _ string, _, _, _ map[string]string) error {
		return membershipNotAdmitted(ctx)
	}}
	err := runScopeDecorators(context.Background(), nil, "u1", nil, map[string]string{}, map[string]string{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v (%s), want PermissionDenied", err, status.Code(err))
	}
}

func TestParseAudienceTable(t *testing.T) {
	t.Setenv("APP_GATEWAY_CLIENT_MCP_PUBLIC_URL", "https://client.mcp.example.com/mcp/")
	h := &AuthServiceHandler{Audiences: " client:client:APP_GATEWAY_CLIENT_MCP_PUBLIC_URL:client ;staff:staff::client|staff;\n"}
	if err := parseAudienceTable(h); err != nil {
		t.Fatal(err)
	}
	if len(h.audiences) != 2 || h.audiences[0].url != "https://client.mcp.example.com/mcp" || strings.Join(h.audiences[1].invites, ",") != "client,staff" {
		t.Errorf("audiences = %+v", h.audiences)
	}
	prev := audienceURLsNeeded
	defer func() { audienceURLsNeeded = prev }()
	audienceURLsNeeded = true // as with oauth_server, which reads the URLs
	for name, table := range map[string]string{
		"malformed":          "client:client",
		"unset MCP URL":      "client:client:APP_GATEWAY_NOWHERE_MCP_PUBLIC_URL:client",
		"one URL, two":       "client:client:APP_GATEWAY_CLIENT_MCP_PUBLIC_URL:;other:client:APP_GATEWAY_CLIENT_MCP_PUBLIC_URL:",
		"no audience name":   ":client::client",
		"one audience twice": "client:client::;client:client::",
	} {
		if err := parseAudienceTable(&AuthServiceHandler{Audiences: table}); err == nil {
			t.Errorf("%s: %q booted", name, table)
		}
	}
	// Without the consent page nothing reads the URLs: an unset one boots.
	audienceURLsNeeded = false
	if err := parseAudienceTable(&AuthServiceHandler{Audiences: "client:client:APP_GATEWAY_NOWHERE_MCP_PUBLIC_URL:client"}); err != nil {
		t.Errorf("without oauth_server an unset MCP URL refused to boot: %v", err)
	}
}

// A member invites only the kinds their audiences may invite; the owner and
// an inviter from outside the organization (backoffice) may invite any kind
// the table knows; a kind no audience admits is refused to everyone.
func TestCheckInviteKind(t *testing.T) {
	table := []audienceEntry{
		{name: "staff", kinds: []string{"staff"}, invites: []string{"staff", "client"}},
		{name: "client", kinds: []string{"client"}}, // names none: invites its own
	}
	invite := func(q *ownsMock, kind string) error {
		h := &AuthServiceHandler{Query: q, audiences: table, audiencesRead: true}
		_, err := checkInviteKind(context.Background(), h, "u1", "org-acme", &pb.InviteToOrgReq{Kind: kind})
		return err
	}
	staff := []*pb.UserOrg{{OrgId: "org-acme", MembershipKind: "staff"}}
	client := []*pb.UserOrg{{OrgId: "org-acme", MembershipKind: "client"}}
	for name, tc := range map[string]struct {
		q    *ownsMock
		kind string
		ok   bool
	}{
		"staff invite a client":           {&ownsMock{orgs: staff}, "client", true},
		"a client invites a client":       {&ownsMock{orgs: client}, "client", true},
		"a client invites staff":          {&ownsMock{orgs: client}, "staff", false},
		"the owner invites staff":         {&ownsMock{orgs: client, owner: true}, "staff", true},
		"an outsider invites staff":       {&ownsMock{}, "staff", true},
		"a kind no audience admits":       {&ownsMock{owner: true}, "staf", false},
		"no kind (no audience admits it)": {&ownsMock{orgs: client}, "", true},
	} {
		err := invite(tc.q, tc.kind)
		if tc.ok && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !tc.ok && status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: err = %v, want PermissionDenied", name, err)
		}
	}
	if _, err := checkInviteKind(context.Background(), &AuthServiceHandler{Query: &ownsMock{orgs: client}}, "u1", "org-acme",
		&pb.InviteToOrgReq{Kind: "staff"}); err != nil {
		t.Errorf("no audiences, no rule: %v", err)
	}
	// A handler that skipped ValidateConfig reads the table itself.
	h := &AuthServiceHandler{Query: &ownsMock{orgs: client}, Audiences: "staff:staff::staff|client;client:client::"}
	if _, err := checkInviteKind(context.Background(), h, "u1", "org-acme", &pb.InviteToOrgReq{Kind: "staff"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("without ValidateConfig the check fell open: %v", err)
	}
}
