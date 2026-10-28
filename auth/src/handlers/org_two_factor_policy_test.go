package handlers

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// policyMock is the MFA store with organizations and their second-factor
// policies: u1 is staff at acme and a client at globex; acme.example.com
// serves acme.
type policyMock struct {
	*mfaMock
	orgs     []*pb.UserOrg
	policies map[string][]*pb.OrgTwoFactorPolicyRow // org id → live rows
	hosts    map[string]*pb.OrgHostRow
	set      []string
	ended    []string
}

func (*policyMock) keepsTwoFactorPolicies() {}

func (m *policyMock) ListUserOrgs(context.Context, *pb.ListUserOrgsReq, ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	return &pb.ListUserOrgsResp{Orgs: m.orgs}, nil
}

func (m *policyMock) ListOrgTwoFactorPolicyRows(_ context.Context, in *pb.ListOrgTwoFactorPolicyRowsReq, _ ...grpc.CallOption) (*pb.ListOrgTwoFactorPolicyRowsResp, error) {
	return &pb.ListOrgTwoFactorPolicyRowsResp{Policies: m.policies[in.GetOrgId()]}, nil
}

func (m *policyMock) GetOrgOfHost(_ context.Context, in *pb.GetOrgOfHostReq, _ ...grpc.CallOption) (*pb.OrgHostRow, error) {
	if r := m.hosts[in.GetHost()]; r != nil {
		return r, nil
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (m *policyMock) SetOrgTwoFactorPolicyRow(_ context.Context, in *pb.SetOrgTwoFactorPolicyRowReq, _ ...grpc.CallOption) (*pb.SetOrgTwoFactorPolicyRowResp, error) {
	m.set = append(m.set, fmt.Sprintf("%s/%s/%s/%s", in.GetOrgId(), in.GetKind(), in.GetPolicy(), in.GetSetBy()))
	return &pb.SetOrgTwoFactorPolicyRowResp{}, nil
}

func (m *policyMock) EndOrgTwoFactorPolicyRow(_ context.Context, in *pb.EndOrgTwoFactorPolicyRowReq, _ ...grpc.CallOption) (*pb.EndOrgTwoFactorPolicyRowResp, error) {
	m.ended = append(m.ended, in.GetOrgId()+"/"+in.GetKind())
	return nil, status.Error(codes.NotFound, "no rows")
}

// Nobody holds the backoffice's methods realm-wide here.
func (m *policyMock) GetUserRealmWidePermissions(context.Context, *pb.GetUserRealmWidePermissionsReq, ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	return &pb.GetUserRealmWidePermissionsResp{}, nil
}

func policyFixture() (*policyMock, *AuthServiceHandler) {
	m := &policyMock{
		mfaMock: &mfaMock{userEmail: "a@b.c"},
		orgs: []*pb.UserOrg{
			{OrgId: "org-acme", Slug: "acme", MembershipKind: "staff"},
			{OrgId: "org-globex", Slug: "globex", MembershipKind: "client"},
		},
		policies: map[string][]*pb.OrgTwoFactorPolicyRow{},
		hosts:    map[string]*pb.OrgHostRow{"acme.example.com": {OrgId: "org-acme", Slug: "acme", Host: "acme.example.com"}},
	}
	h := newMfaHandler(m.mfaMock)
	h.Query, h.Mutation = m, m
	return m, h
}

// enrol gives u1 a confirmed authenticator.
func (m *policyMock) enrol() {
	m.totpSeed, m.totpConfirmed = "JBSWY3DPEHPK3PXP", true
}

// signInFor is a sign-in's context: the W17-Org selector, or the host an
// audience that takes the tenant from it reports.
func signInFor(selector, host string) context.Context {
	md := metadata.MD{}
	if selector != "" {
		md.Set(orgScopeMetadataKey, selector)
	}
	if host != "" {
		md.Set(tenantFromHeader, tenantFromHost)
		md.Set(hostHeader, host)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

func challenged(t *testing.T, h *AuthServiceHandler, ctx context.Context) bool {
	t.Helper()
	_, ok, err := mfaSignInGate(ctx, h, gateUser(), testJKT, false, false)
	if err != nil {
		t.Fatalf("sign-in gate: %v", err)
	}
	return ok
}

// The three policies, with no organization in play: the activation's default.
// optional is the one deinvo needs — 2FA offered on a running product where
// nobody has enrolled yet must not lock everyone out.
func TestTwoFactorPolicy_TheDefaultDecidesWhoIsChallenged(t *testing.T) {
	for _, tc := range []struct {
		policy             string
		unenrolled, enroll bool
	}{
		{"", true, true}, // unset = required, the behaviour before the knob
		{policyRequired, true, true},
		{policyOptional, false, true},
		{policyDisabled, false, false},
	} {
		t.Run("policy="+tc.policy, func(t *testing.T) {
			m, h := policyFixture()
			m.orgs = nil
			h.TwoFactorPolicy = tc.policy
			if got := challenged(t, h, signInFor("", "")); got != tc.unenrolled {
				t.Errorf("an account without an authenticator: challenged=%v, want %v", got, tc.unenrolled)
			}
			m.enrol()
			if got := challenged(t, h, signInFor("", "")); got != tc.enroll {
				t.Errorf("an account with a confirmed authenticator: challenged=%v, want %v", got, tc.enroll)
			}
		})
	}
}

// optional with the built-in authenticator off: nothing can be enrolled, so
// nobody is challenged — not everyone by message, which is required's case.
func TestTwoFactorPolicy_OptionalWithoutTheAuthenticatorChallengesNobody(t *testing.T) {
	m, h := policyFixture()
	h.TwoFactorPolicy, h.TwoFactorTOTP = policyOptional, false
	m.enrol()
	if challenged(t, h, signInFor("acme", "")) {
		t.Error("optional challenged an account although no authenticator is verified here")
	}
}

// The organization a sign-in arrives for decides, for the kind of the
// person's membership there, over the organization's own and the default.
func TestTwoFactorPolicy_TheOrganizationOverridesPerKind(t *testing.T) {
	m, h := policyFixture()
	h.TwoFactorPolicy = policyRequired
	m.policies["org-acme"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyDisabled}, {Kind: "staff", Policy: policyOptional}}
	m.policies["org-globex"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyDisabled}}

	if challenged(t, h, signInFor("acme", "")) {
		t.Error("acme's staff policy is optional and u1 has no authenticator: challenged")
	}
	if challenged(t, h, signInFor("globex", "")) {
		t.Error("globex's own policy is disabled (no row for clients): challenged")
	}
	m.enrol()
	if !challenged(t, h, signInFor("acme", "")) {
		t.Error("acme's staff policy is optional and u1 enrolled: not challenged")
	}
	if challenged(t, h, signInFor("globex", "")) {
		t.Error("globex is disabled, an authenticator there asks nothing: challenged")
	}
	// The host bound to acme decides as its selector does.
	if !challenged(t, h, signInFor("", "acme.example.com")) {
		t.Error("a sign-in on acme's host did not read acme's policy")
	}
}

// Arriving for an organization the person is not a member of — or for none,
// with several memberships — is the activation's default, never another
// organization's laxer policy.
func TestTwoFactorPolicy_NoMembershipThereIsTheDefault(t *testing.T) {
	m, h := policyFixture()
	h.TwoFactorPolicy = policyRequired
	m.policies["org-acme"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyDisabled}}
	m.policies["org-globex"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyDisabled}}
	if !challenged(t, h, signInFor("initech", "")) {
		t.Error("an organization u1 is not in: not challenged under a required default")
	}
	if !challenged(t, h, signInFor("", "")) {
		t.Error("no organization named and two memberships: not challenged under a required default")
	}
	// One membership is the organization, as Authenticate infers it.
	m.orgs = m.orgs[:1]
	if challenged(t, h, signInFor("", "")) {
		t.Error("u1's only organization disables it: challenged")
	}
}

// A selector naming another organization than the host's refuses the
// sign-in, as Authenticate refuses the request: a policy is never read for an
// organization the request does not belong to.
func TestTwoFactorPolicy_AConflictingSelectorRefuses(t *testing.T) {
	_, h := policyFixture()
	ctx := signInFor("globex", "acme.example.com")
	if _, _, err := mfaSignInGate(ctx, h, gateUser(), testJKT, false, false); err == nil {
		t.Fatal("a selector naming globex on acme's host was signed in")
	}
}

// disabled refuses an enrolment in the organization the caller acts in, and
// only there.
func TestTwoFactorPolicy_DisabledRefusesEnrolment(t *testing.T) {
	m, h := policyFixture()
	m.policies["org-globex"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "client", Policy: policyDisabled}}
	if err := h.enrolmentAllowed(whoAmICtx("u1", "org-globex"), "u1"); refusalCodeOf(err) != CodeTwoFactorDisabled {
		t.Errorf("enrolling in globex, where clients have it disabled: %v", err)
	}
	if err := h.enrolmentAllowed(whoAmICtx("u1", "org-acme"), "u1"); err != nil {
		t.Errorf("enrolling in acme (the default, required): %v", err)
	}
	h.TwoFactorPolicy = policyDisabled
	if err := h.enrolmentAllowed(whoAmICtx("u1", ""), "u1"); refusalCodeOf(err) != CodeTwoFactorDisabled {
		t.Errorf("enrolling with no organization under a disabled default: %v", err)
	}
}

func TestTwoFactorPolicy_TheBootRefusesAnUnknownValue(t *testing.T) {
	for _, p := range []string{"", policyRequired, policyOptional, policyDisabled} {
		if err := checkTwoFactorPolicy(&AuthServiceHandler{TwoFactorPolicy: p}); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"off", "Required", "enrolled_only"} {
		if err := checkTwoFactorPolicy(&AuthServiceHandler{TwoFactorPolicy: p}); err == nil {
			t.Errorf("%q was accepted — a typo would quietly mean something", p)
		}
	}
}

func policyLock(methods ...string) *acllock.Lock {
	perms := map[string]int{}
	for i, m := range methods {
		perms["AUTH_AUTH_SERVICE_"+upperSnake(m)] = i + 1
	}
	return &acllock.Lock{Permissions: perms}
}

func upperSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}

// The backoffice's: realm-wide, values held, each set ending the live row.
func TestSetOrgTwoFactorPolicy(t *testing.T) {
	m, h := policyFixture()
	h.Lock = policyLock("SetOrgTwoFactorPolicy", "ClearOrgTwoFactorPolicy", "ListOrgTwoFactorPolicies")
	if _, err := h.SetOrgTwoFactorPolicy(whoAmICtx("admin", "org-acme"), &pb.SetOrgTwoFactorPolicyReq{OrgId: "org-acme", Policy: policyOptional}); refusalCodeOf(err) != CodeTwoFactorPoliciesRealmOnly {
		t.Errorf("from inside an organization: %v", err)
	}
	realm := whoAmICtx("ops", "")
	if _, err := h.SetOrgTwoFactorPolicy(realm, &pb.SetOrgTwoFactorPolicyReq{OrgId: "org-acme", Policy: "sometimes"}); refusalCodeOf(err) != CodeTwoFactorPolicyInvalid {
		t.Errorf("an unknown value: %v", err)
	}
	if len(m.set) != 0 {
		t.Fatalf("a refused policy was written: %v", m.set)
	}
	for _, req := range []*pb.SetOrgTwoFactorPolicyReq{
		{OrgId: "org-acme", Policy: policyOptional},
		{OrgId: "org-acme", Kind: "staff", Policy: policyRequired},
	} {
		if _, err := h.SetOrgTwoFactorPolicy(realm, req); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(m.set, []string{"org-acme//optional/ops", "org-acme/staff/required/ops"}) ||
		!slices.Equal(m.ended, []string{"org-acme/", "org-acme/staff"}) {
		t.Errorf("set %v, ended %v — each set ends the live row first", m.set, m.ended)
	}
	if _, err := h.ClearOrgTwoFactorPolicy(realm, &pb.ClearOrgTwoFactorPolicyReq{OrgId: "org-acme", Kind: "staff"}); err != nil {
		t.Errorf("clearing: %v", err)
	}
	m.policies["org-acme"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyOptional}}
	resp, err := h.ListOrgTwoFactorPolicies(realm, &pb.ListOrgTwoFactorPoliciesReq{OrgId: "org-acme"})
	if err != nil || len(resp.GetPolicies()) != 1 || resp.GetDefaultPolicy() != policyRequired {
		t.Errorf("list: %v, %v — the rows and the default beside them", resp, err)
	}
}

// The organization's own, from inside it — and only with the endpoint ACL
// gating the method: otherwise every member could switch the factor off.
func TestSetMyOrgTwoFactorPolicy(t *testing.T) {
	m, h := policyFixture()
	inAcme := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, "admin", "x-w17-scope-org_id", "org-acme", "x-w17-scope-org_slug", "acme"))
	req := &pb.SetMyOrgTwoFactorPolicyReq{Org: "acme", Policy: policyDisabled}

	if _, err := h.SetMyOrgTwoFactorPolicy(inAcme, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a method the lock does not gate: %v", err)
	}
	h.Lock = policyLock("SetMyOrgTwoFactorPolicy", "ListMyOrgTwoFactorPolicies")
	if _, err := h.SetMyOrgTwoFactorPolicy(inAcme, &pb.SetMyOrgTwoFactorPolicyReq{Org: "globex", Policy: policyDisabled}); refusalCodeOf(err) != CodeOrgMismatch {
		t.Errorf("naming another organization: %v", err)
	}
	if _, err := h.SetMyOrgTwoFactorPolicy(whoAmICtx("admin", ""), req); err == nil {
		t.Error("with no active organization: accepted")
	}
	if len(m.set) != 0 {
		t.Fatalf("a refused policy was written: %v", m.set)
	}
	if _, err := h.SetMyOrgTwoFactorPolicy(inAcme, req); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.set, []string{"org-acme//disabled/admin"}) {
		t.Errorf("set %v — the active organization's, never the request's", m.set)
	}
	if _, err := h.ListMyOrgTwoFactorPolicies(inAcme, &pb.ListMyOrgTwoFactorPoliciesReq{}); err != nil {
		t.Errorf("list: %v", err)
	}
	if _, err := h.ClearMyOrgTwoFactorPolicy(inAcme, &pb.ClearMyOrgTwoFactorPolicyReq{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("clear, which the lock does not gate: %v", err)
	}
}
