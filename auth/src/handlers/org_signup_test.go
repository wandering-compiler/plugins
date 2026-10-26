package handlers

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

func (m *hostMock) ListOrgSignUpPolicyRows(_ context.Context, in *pb.ListOrgSignUpPolicyRowsReq, _ ...grpc.CallOption) (*pb.ListOrgSignUpPolicyRowsResp, error) {
	return &pb.ListOrgSignUpPolicyRowsResp{Policies: m.policies[in.GetOrgId()]}, nil
}

func (m *hostMock) ListOrgRoleRows(context.Context, *pb.ListOrgRoleRowsReq, ...grpc.CallOption) (*pb.ListOrgRoleRowsResp, error) {
	return &pb.ListOrgRoleRowsResp{Roles: m.roles}, nil
}

func (m *hostMock) ListOrgScopedRoles(context.Context, *pb.ListOrgScopedRolesReq, ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	out := &pb.ListOrgScopedRolesResp{}
	for _, r := range m.roles {
		out.Roles = append(out.Roles, &pb.OrgScopedRole{Id: r.GetId(), Name: r.GetName()})
	}
	return out, nil
}

func (m *hostMock) ListRoles(context.Context, *pb.ListRolesReq, ...grpc.CallOption) (*pb.ListRolesResp, error) {
	return &pb.ListRolesResp{}, nil
}

func (m *hostMock) AddOrgMembership(_ context.Context, in *pb.AddOrgMembershipReq, _ ...grpc.CallOption) (*pb.AddOrgMembershipResp, error) {
	m.joined = append(m.joined, fmt.Sprintf("%s/%s/%s/%s", in.GetUserId(), in.GetOrgId(), in.GetKind(), in.GetRole()))
	return &pb.AddOrgMembershipResp{}, nil
}

func (m *hostMock) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.granted = append(m.granted, in.GetUserId()+"/"+in.GetOrgId()+"/"+in.GetRoleId())
	return &pb.AssignRoleToUserResp{}, nil
}

func (m *hostMock) SetOrgSignUpPolicyRow(_ context.Context, in *pb.SetOrgSignUpPolicyRowReq, _ ...grpc.CallOption) (*pb.SetOrgSignUpPolicyRowResp, error) {
	m.policySet = append(m.policySet, fmt.Sprintf("%s/%s/%v/%s", in.GetOrgId(), in.GetKind(), in.GetOpen(), in.GetRole()))
	return &pb.SetOrgSignUpPolicyRowResp{}, nil
}

func (m *hostMock) EndOrgSignUpPolicyRow(_ context.Context, in *pb.EndOrgSignUpPolicyRowReq, _ ...grpc.CallOption) (*pb.EndOrgSignUpPolicyRowResp, error) {
	m.policyEnded = append(m.policyEnded, in.GetOrgId()+"/"+in.GetKind())
	return nil, status.Error(codes.NotFound, "no rows")
}

// signupFixture: acme.example.com serves acme; acme takes clients openly as
// "member" and staff by invitation only.
func signupFixture() *hostMock {
	m := hostFixture()
	m.policies = map[string][]*pb.OrgSignUpPolicyRow{"org-acme": {
		{Kind: "client", Open: true, Role: "member"},
		{Kind: "staff", Open: false},
	}}
	m.roles = []*pb.OrgRoleRow{{Id: "role-member", Name: "member"}, {Id: "role-admin", Name: "org-admin"}}
	return m
}

// registrationVia is a registration's context as an audience gateway leaves
// it (restgw.AudienceContextMiddleware): its sources, kinds and the host.
func registrationVia(from, kinds, host string) context.Context {
	md := metadata.MD{}
	if from != "" {
		md.Set(tenantFromHeader, from)
	}
	if kinds != "" {
		md.Set(membershipKindsHeader, kinds)
	}
	if host != "" {
		md.Set(hostHeader, host)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

// A registration without an invitation on the organization's host: an open
// policy for the audience's kind joins it, a closed one refuses it, no
// policy says nothing (invite_only decides), two open kinds are refused.
func TestDecideSignUpJoin(t *testing.T) {
	for _, c := range []struct {
		name, from, kinds, host string
		extra                   []*pb.OrgSignUpPolicyRow
		want                    *orgJoin
		code                    string
	}{
		{name: "the client audience on acme's host joins acme as a client", from: "host,default", kinds: "client", host: "acme.example.com",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "the staff audience: by invitation only", from: "host,default", kinds: "staff", host: "acme.example.com", code: CodeSignUpNotInvited},
		{name: "a kind no policy names says nothing", from: "host,default", kinds: "partner", host: "acme.example.com"},
		{name: "an unbound host says nothing", from: "host,default", kinds: "client", host: "other.example.com"},
		{name: "an audience that does not read the host says nothing", from: "default", kinds: "client", host: "acme.example.com"},
		{name: "no host says nothing", from: "host,default", kinds: "client"},
		{name: "two open kinds for one audience", from: "host", kinds: "client,guest", host: "acme.example.com",
			extra: []*pb.OrgSignUpPolicyRow{{Kind: "guest", Open: true, Role: "member"}}, code: CodeSignUpKindAmbiguous},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := signupFixture()
			m.policies["org-acme"] = append(m.policies["org-acme"], c.extra...)
			got, err := decideSignUpJoin(registrationVia(c.from, c.kinds, c.host), &AuthServiceHandler{Query: m}, "")
			if c.code != "" {
				if _, code := detailCode(t, err); code != c.code {
					t.Fatalf("err = %v, want %s", err, c.code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Errorf("join = %+v, want %+v", got, c.want)
			}
		})
	}
}

// An open policy lets a registration through whatever invite_only says, and
// an invitation is never second-guessed by the host.
func TestSignUpGates_OpenPolicyAndInvitation(t *testing.T) {
	m := signupFixture()
	h := &AuthServiceHandler{Query: m, InviteOnly: true}
	ctx := registrationVia("host,default", "client", "acme.example.com")
	join, err := signupGates(ctx, h, "new@example.com", "", "")
	if err != nil || join == nil || join.orgID != "org-acme" {
		t.Fatalf("open policy under invite_only: join %+v, err %v", join, err)
	}
	called := false
	saved := signupInviteGate
	signupInviteGate = func(context.Context, *AuthServiceHandler, string, string) error { called = true; return nil }
	defer func() { signupInviteGate = saved }()
	if join, err := signupGates(ctx, h, "new@example.com", "invite-token", ""); err != nil || join != nil || !called {
		t.Errorf("with an invitation: join %+v, err %v, invite gate called %v", join, err, called)
	}
	called = false
	if join, err := signupGates(registrationVia("host,default", "partner", "acme.example.com"), h, "new@example.com", "", ""); err != nil || join != nil || !called {
		t.Errorf("no policy: join %+v, err %v, invite gate called %v — invite_only must decide", join, err, called)
	}
}

// The join writes a membership of the policy's kind and its role, scoped to
// the organization — as accepting an invitation does.
func TestWriteSignUpJoin(t *testing.T) {
	m := signupFixture()
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if err := writeSignUpJoin(context.Background(), h, "u-new", &orgJoin{orgID: "org-acme", kind: "client", role: "member"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.joined, []string{"u-new/org-acme/client/member"}) || !slices.Equal(m.granted, []string{"u-new/org-acme/role-member"}) {
		t.Errorf("joined %v, granted %v", m.joined, m.granted)
	}
	if err := writeSignUpJoin(context.Background(), h, "u-new", &orgJoin{orgID: "org-acme", kind: "client", role: "retired"}); err == nil {
		t.Error("a role gone from the catalogue was written")
	}
}

// The backoffice sets policies realm-wide; a policy needs a kind (memberships
// have kinds here), an open one a role the organization can hand out.
func TestSetOrgSignUpPolicy(t *testing.T) {
	m := signupFixture()
	h := &AuthServiceHandler{Query: m, Mutation: m, Lock: &acllock.Lock{Permissions: map[string]int{
		"AUTH_AUTH_SERVICE_SET_ORG_SIGN_UP_POLICY": 1, "AUTH_AUTH_SERVICE_CLEAR_ORG_SIGN_UP_POLICY": 2, "AUTH_AUTH_SERVICE_LIST_ORG_SIGN_UP_POLICIES": 3,
	}}}
	inOrg := whoAmICtx("admin", "org-acme")
	if _, err := h.SetOrgSignUpPolicy(inOrg, &pb.SetOrgSignUpPolicyReq{OrgId: "org-acme", Kind: "client", Open: true, Role: "member"}); refusalCodeOf(err) != CodeSignUpPoliciesRealmOnly {
		t.Errorf("from inside an organization: %v", err)
	}
	realm := whoAmICtx("ops", "")
	for name, req := range map[string]*pb.SetOrgSignUpPolicyReq{
		"no kind":           {OrgId: "org-acme", Open: true, Role: "member"},
		"open without role": {OrgId: "org-acme", Kind: "client", Open: true},
		"a role it lacks":   {OrgId: "org-acme", Kind: "client", Open: true, Role: "owner-of-everything"},
	} {
		if _, err := h.SetOrgSignUpPolicy(realm, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if len(m.policySet) != 0 {
		t.Fatalf("a refused policy was written: %v", m.policySet)
	}
	if _, err := h.SetOrgSignUpPolicy(realm, &pb.SetOrgSignUpPolicyReq{OrgId: "org-acme", Kind: "client", Open: true, Role: "member"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetOrgSignUpPolicy(realm, &pb.SetOrgSignUpPolicyReq{OrgId: "org-acme", Kind: "staff", Role: "ignored"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.policySet, []string{"org-acme/client/true/member", "org-acme/staff/false/"}) ||
		!slices.Equal(m.policyEnded, []string{"org-acme/client", "org-acme/staff"}) {
		t.Errorf("set %v, ended %v — each set ends the live row first; a closed one keeps no role", m.policySet, m.policyEnded)
	}
	resp, err := h.ListOrgSignUpPolicies(realm, &pb.ListOrgSignUpPoliciesReq{OrgId: "org-acme"})
	if err != nil || len(resp.GetPolicies()) != 2 {
		t.Errorf("list: %v, %v", resp, err)
	}
}

// GetHostOrg tells a sign-up page which kinds may register on the host.
func TestGetHostOrg_OpenKinds(t *testing.T) {
	h := &AuthServiceHandler{Query: signupFixture()}
	resp, err := h.GetHostOrg(context.Background(), &pb.GetHostOrgReq{Host: "acme.example.com"})
	if err != nil || !slices.Equal(resp.GetOpenKinds(), []string{"client"}) {
		t.Errorf("open kinds = %v, err %v", resp.GetOpenKinds(), err)
	}
}

// A registration parked for its code carries the join decided when it was
// requested, and gives it back at confirmation.
func TestPendingSignUpCarriesTheJoin(t *testing.T) {
	create := &pb.CreatePendingSignUpReq{}
	stampPendingSignUpJoin(create, &orgJoin{orgID: "org-acme", kind: "client", role: "member"})
	got := readClaimedSignUpJoin(&pb.ClaimPendingSignUpResp{JoinOrgId: create.GetJoinOrgId(), JoinKind: create.GetJoinKind(), JoinRole: create.GetJoinRole()})
	if got == nil || *got != (orgJoin{orgID: "org-acme", kind: "client", role: "member"}) {
		t.Errorf("round trip = %+v", got)
	}
	if readClaimedSignUpJoin(&pb.ClaimPendingSignUpResp{}) != nil {
		t.Error("a registration that joins nothing came back joining something")
	}
}

// A registration page on the identity's own host names the host the person
// comes from: with no gateway host, that host decides exactly as a
// registration arriving on it would — the bound organization and its
// policies, with the audience's kinds when it names some and none otherwise.
// A gateway host bound to an organization is the request's own and wins over
// a body host naming another; one bound to none leaves the body host to
// decide; an invitation is still never second-guessed.
func TestDecideSignUpJoin_ABodyHost(t *testing.T) {
	for _, c := range []struct {
		name, from, kinds, host, body string
		extra                         []*pb.OrgSignUpPolicyRow
		want                          *orgJoin
		code                          string
	}{
		{name: "the identity's own page names acme's host: acme's one open kind joins", body: "acme.example.com",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "normalised like a gateway host", body: " ACME.example.com. ",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "an unbound host joins nothing", body: "other.example.com"},
		{name: "the audience's kinds still filter: staff is by invitation only", kinds: "staff", body: "acme.example.com", code: CodeSignUpNotInvited},
		{name: "no audience kinds and two open kinds is ambiguous", body: "acme.example.com",
			extra: []*pb.OrgSignUpPolicyRow{{Kind: "guest", Open: true, Role: "member"}}, code: CodeSignUpKindAmbiguous},
		{name: "only closed policies refuse", body: "closed.example.com", code: CodeSignUpNotInvited},
		{name: "a gateway host and the same body host", from: "host", kinds: "client", host: "acme.example.com", body: "acme.example.com",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "a body host equal to the gateway's once normalised is no conflict", from: "host", kinds: "client", host: "acme.example.com", body: " ACME.example.com. ",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "a body host naming another than the gateway's bound host is refused", from: "host", kinds: "client", host: "acme.example.com", body: "other.example.com",
			code: CodeSignUpHostConflict},
		{name: "an audience that does not read the host leaves the body host to decide", from: "default", host: "x.example.com", body: "acme.example.com",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "the identity's own unbound host behind a host-reading audience leaves the body host to decide", from: "host,default", host: "id.example.com", body: "acme.example.com",
			want: &orgJoin{orgID: "org-acme", kind: "client", role: "member"}},
		{name: "not a host name", body: "https://acme.example.com/x", code: CodeHostInvalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := signupFixture()
			m.policies["org-acme"] = append(m.policies["org-acme"], c.extra...)
			m.policies["org-closed"] = []*pb.OrgSignUpPolicyRow{{Kind: "client", Open: false}}
			m.hosts["closed.example.com"] = &pb.OrgHostRow{Host: "closed.example.com", OrgId: "org-closed", Slug: "closed"}
			got, err := decideSignUpJoin(registrationVia(c.from, c.kinds, c.host), &AuthServiceHandler{Query: m}, c.body)
			if c.code != "" {
				if _, code := detailCode(t, err); code != c.code {
					t.Fatalf("err = %v, want %s", err, c.code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Errorf("join = %+v, want %+v", got, c.want)
			}
		})
	}
}

// The body host reaches the decision from both registration requests that
// create an account, and an invitation still decides its own organization.
func TestSignUpGates_ABodyHostFromEachRequest(t *testing.T) {
	if got := signupHost(&pb.SignUpReq{SignupHost: "acme.example.com"}); got != "acme.example.com" {
		t.Errorf("SignUpReq: %q", got)
	}
	if got := signupHost(&pb.OAuthExchangeReq{SignupHost: "acme.example.com"}); got != "acme.example.com" {
		t.Errorf("OAuthExchangeReq: %q", got)
	}
	m := signupFixture()
	h := &AuthServiceHandler{Query: m, InviteOnly: true}
	join, err := signupGates(context.Background(), h, "new@example.com", "", "acme.example.com")
	if err != nil || join == nil || join.orgID != "org-acme" {
		t.Fatalf("body host under invite_only: join %+v, err %v", join, err)
	}
	saved := signupInviteGate
	signupInviteGate = func(context.Context, *AuthServiceHandler, string, string) error { return nil }
	defer func() { signupInviteGate = saved }()
	if join, err := signupGates(context.Background(), h, "new@example.com", "invite-token", "acme.example.com"); err != nil || join != nil {
		t.Errorf("an invitation with a body host: join %+v, err %v — the invitation decides", join, err)
	}
}
