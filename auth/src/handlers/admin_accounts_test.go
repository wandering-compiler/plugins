package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// adminAccountsMock is realmInviteMock (an organization by its slug, the
// caller's realm-wide grants, the role catalogue and its ceiling) plus the
// account writes and the setup links.
type adminAccountsMock struct {
	realmInviteMock
	created     []string // addresses CreateAdminUser wrote
	memberships []string // org/user/role
	grants      []string // user@org:role
	setups      map[string]string
	superseded  []string
	users       map[string]*pb.User
	passwords   map[string]string
}

func newAdminAccounts(realmWide bool) (*AuthServiceHandler, *adminAccountsMock) {
	m := &adminAccountsMock{realmInviteMock: realmInviteMock{realmWide: realmWide},
		setups: map[string]string{}, users: map[string]*pb.User{}, passwords: map[string]string{}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings(),
		AccountSetupURL: "https://app.example/account-setup?token={token}",
		Lock: &acllock.Lock{Permissions: map[string]int{
			"AUTH_AUTH_SERVICE_CREATE_ACCOUNT": 1, "AUTH_AUTH_SERVICE_ISSUE_ACCOUNT_SETUP_LINK": 2,
			"AUTH_AUTH_SERVICE_CREATE_SERVICE_ACCOUNT": 3, "AUTH_AUTH_SERVICE_ISSUE_SERVICE_ACCOUNT_TOKEN": 4,
		}}}
	return h, m
}

func (m *adminAccountsMock) CreateAdminUser(_ context.Context, in *pb.CreateAdminUserReq, _ ...grpc.CallOption) (*pb.CreateAdminUserResp, error) {
	m.created = append(m.created, in.GetEmail())
	id := "user-" + in.GetEmail()
	m.users[id] = &pb.User{Id: id, Email: in.GetEmail(), PasswordHash: "!"}
	return &pb.CreateAdminUserResp{User: m.users[id]}, nil
}

func (m *adminAccountsMock) AddOrgMembership(_ context.Context, in *pb.AddOrgMembershipReq, _ ...grpc.CallOption) (*pb.AddOrgMembershipResp, error) {
	m.memberships = append(m.memberships, in.GetOrgId()+"/"+in.GetUserId()+"/"+in.GetRole())
	return &pb.AddOrgMembershipResp{}, nil
}

func (m *adminAccountsMock) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.grants = append(m.grants, in.GetUserId()+"@"+in.GetOrgId()+":"+in.GetRoleId())
	return &pb.AssignRoleToUserResp{}, nil
}

func (m *adminAccountsMock) CreateAccountSetup(_ context.Context, in *pb.CreateAccountSetupReq, _ ...grpc.CallOption) (*pb.CreateAccountSetupResp, error) {
	m.setups[in.GetTokenHash()] = in.GetUserId()
	return &pb.CreateAccountSetupResp{Id: "setup-1"}, nil
}

func (m *adminAccountsMock) SupersedeAccountSetups(_ context.Context, in *pb.SupersedeAccountSetupsReq, _ ...grpc.CallOption) (*pb.SupersedeAccountSetupsResp, error) {
	m.superseded = append(m.superseded, in.GetUserId())
	for h, u := range m.setups {
		if u == in.GetUserId() {
			delete(m.setups, h)
		}
	}
	return nil, status.Error(codes.NotFound, "none live")
}

func (m *adminAccountsMock) ConsumeAccountSetup(_ context.Context, in *pb.ConsumeAccountSetupReq, _ ...grpc.CallOption) (*pb.ConsumeAccountSetupResp, error) {
	u, ok := m.setups[in.GetTokenHash()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no live link")
	}
	delete(m.setups, in.GetTokenHash())
	return &pb.ConsumeAccountSetupResp{UserId: u}, nil
}

func (m *adminAccountsMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	u, ok := m.users[in.GetUserId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no user")
	}
	return &pb.GetUserByIdResp{User: u}, nil
}

func (m *adminAccountsMock) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

func (m *adminAccountsMock) SetUpAccountPassword(_ context.Context, in *pb.SetUpAccountPasswordReq, _ ...grpc.CallOption) (*pb.SetUpAccountPasswordResp, error) {
	u := m.users[in.GetUserId()]
	if u == nil || u.GetPasswordHash() != "!" {
		return nil, status.Error(codes.NotFound, "has a password")
	}
	u.PasswordHash = in.GetPasswordHash()
	m.passwords[in.GetUserId()] = in.GetPasswordHash()
	return &pb.SetUpAccountPasswordResp{UserId: in.GetUserId()}, nil
}

// The admin creates a person's account in the organization it names — its
// operator a member of none — with the membership and the role THERE, no
// usable password, and a setup link shown once whose hash is all the row keeps.
func TestCreateAccount_InTheNamedOrganizationWithASetupLink(t *testing.T) {
	h, m := newAdminAccounts(false)
	resp, err := h.CreateAccount(ctxWithCaller("ops"), &pb.CreateAccountReq{Org: "acme", Email: "New@Acme.Example", Role: "member"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Join(m.created, ",") != "new@acme.example" {
		t.Errorf("created %v, want the address normalized", m.created)
	}
	user := "user-new@acme.example"
	if strings.Join(m.memberships, ",") != "org-acme/"+user+"/member" || strings.Join(m.grants, ",") != user+"@org-acme:role-1" {
		t.Errorf("membership %v, grants %v — want both in org-acme", m.memberships, m.grants)
	}
	if resp.GetSetupToken() == "" || m.setups[sha256Hex(resp.GetSetupToken())] != user {
		t.Errorf("the setup row is not the hash of the token handed out: %v", m.setups)
	}
	if resp.GetSetupLink() != "https://app.example/account-setup?token="+resp.GetSetupToken() {
		t.Errorf("setup link %q, want account_setup_url with the token", resp.GetSetupLink())
	}
	if resp.GetExpiresAt() == nil {
		t.Error("no expiry")
	}
}

// Realm-wide and only under the endpoint ACL, a signed-in person's, never from
// inside an organization without the realm-wide grant — and a refusal writes
// nothing.
func TestCreateAccount_Refusals(t *testing.T) {
	req := &pb.CreateAccountReq{Org: "acme", Email: "x@acme.example", Role: "member"}
	for _, c := range []struct {
		name string
		ctx  context.Context
		req  *pb.CreateAccountReq
		lock bool
		want codes.Code
	}{
		{"from inside an organization", ctxWithCallerInOrg("u1", "org-1"), req, true, codes.PermissionDenied},
		{"an API token", sessionCallerCtx("ops", ""), req, true, codes.PermissionDenied},
		{"not in the lock", ctxWithCaller("ops"), req, false, codes.PermissionDenied},
		{"no organization named", ctxWithCaller("ops"), &pb.CreateAccountReq{Email: "x@acme.example", Role: "member"}, true, codes.InvalidArgument},
		{"an unknown organization", ctxWithCaller("ops"), &pb.CreateAccountReq{Org: "nope", Email: "x@acme.example", Role: "member"}, true, codes.NotFound},
		{"no role", ctxWithCaller("ops"), &pb.CreateAccountReq{Org: "acme", Email: "x@acme.example"}, true, codes.InvalidArgument},
	} {
		h, m := newAdminAccounts(false)
		if !c.lock {
			h.Lock = &acllock.Lock{Permissions: map[string]int{"AUTH_AUTH_SERVICE_SIGN_IN": 1}}
		}
		_, err := h.CreateAccount(c.ctx, c.req)
		if status.Code(err) != c.want || len(m.created) != 0 || len(m.setups) != 0 {
			t.Errorf("%s: err = %v, created %v — want %v and nothing written", c.name, err, m.created, c.want)
		}
	}
	// A caller holding the method realm-wide may call it from inside one.
	h, m := newAdminAccounts(true)
	if _, err := h.CreateAccount(ctxWithCallerInOrg("ops", "org-1"), req); err != nil || len(m.created) != 1 {
		t.Errorf("realm-wide caller inside an organization: %v", err)
	}
}

// The link sets the first password once: the sign-up's rules first (a refused
// password leaves the link usable), then the link is spent, and a second use
// — or any other token — is the one ACCOUNT_SETUP_INVALID.
func TestSetUpAccount_SetsTheFirstPasswordOnce(t *testing.T) {
	h, m := newAdminAccounts(false)
	created, err := h.CreateAccount(ctxWithCaller("ops"), &pb.CreateAccountReq{Org: "acme", Email: "p@acme.example", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	token := created.GetSetupToken()
	resp, err := h.SetUpAccount(context.Background(), &pb.SetUpAccountReq{Token: token, Password: "a long enough passphrase 42"})
	if err != nil || resp.GetEmail() != "p@acme.example" {
		t.Fatalf("setup: %v %v", resp, err)
	}
	if h := m.passwords["user-p@acme.example"]; h == "" || h == "!" {
		t.Errorf("no password stored: %q", h)
	}
	for _, tok := range []string{token, "not-a-link"} {
		_, err := h.SetUpAccount(context.Background(), &pb.SetUpAccountReq{Token: tok, Password: "a long enough passphrase 42"})
		if refusalCodeOf(err) != CodeAccountSetupInvalid {
			t.Errorf("token %q: err = %v, want %s", tok, err, CodeAccountSetupInvalid)
		}
	}
}

// A new link ends the earlier ones, for an account with no password yet only.
func TestIssueAccountSetupLink(t *testing.T) {
	h, m := newAdminAccounts(false)
	first, err := h.CreateAccount(ctxWithCaller("ops"), &pb.CreateAccountReq{Org: "acme", Email: "q@acme.example", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	id := first.GetUserId()
	next, err := h.IssueAccountSetupLink(ctxWithCaller("ops"), &pb.IssueAccountSetupLinkReq{Ids: []string{id}})
	if err != nil || next.GetSetupToken() == "" || next.GetSetupToken() == first.GetSetupToken() {
		t.Fatalf("issue: %v %v", next, err)
	}
	if _, ok := m.setups[sha256Hex(first.GetSetupToken())]; ok || m.setups[sha256Hex(next.GetSetupToken())] != id {
		t.Errorf("the earlier link still works, or the new one is not stored: %v", m.setups)
	}
	if _, err := h.IssueAccountSetupLink(ctxWithCaller("ops"), &pb.IssueAccountSetupLinkReq{Ids: []string{id, id}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("two ids: %v, want InvalidArgument", err)
	}
	m.users[id].PasswordHash = "$argon2id$set"
	if _, err := h.IssueAccountSetupLink(ctxWithCaller("ops"), &pb.IssueAccountSetupLinkReq{Ids: []string{id}}); refusalCodeOf(err) != CodeAccountAlreadySetUp {
		t.Errorf("an account with a password: %v, want %s", err, CodeAccountAlreadySetUp)
	}
	if _, err := h.IssueAccountSetupLink(ctxWithCallerInOrg("u1", "org-1"), &pb.IssueAccountSetupLinkReq{Ids: []string{id}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("from inside an organization: %v, want PermissionDenied", err)
	}
}

// A realm without organizations: the account and its role are the realm's,
// and naming an organization is refused.
func TestCreateAccount_ARealmWithoutOrganizations(t *testing.T) {
	saved, savedStaged := adminAccountOrgs, orgMembershipStaged
	adminAccountOrgs, orgMembershipStaged = nil, false
	t.Cleanup(func() { adminAccountOrgs, orgMembershipStaged = saved, savedStaged })

	h, m := newAdminAccounts(false)
	if _, err := h.CreateAccount(ctxWithCaller("ops"), &pb.CreateAccountReq{Email: "r@example.com", Role: "member"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(m.memberships) != 0 || strings.Join(m.grants, ",") != "user-r@example.com@:role-1" {
		t.Errorf("memberships %v, grants %v — want one realm-wide grant", m.memberships, m.grants)
	}
	if _, err := h.CreateAccount(ctxWithCaller("ops"), &pb.CreateAccountReq{Org: "acme", Email: "s@example.com", Role: "member"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an organization named in a realm without them: %v, want InvalidArgument", err)
	}
}

// The admin's machine-account calls act in the organization named, not the
// caller's active one: the context carries it into CreateBot / IssueBotToken.
func TestBotOrgIn_TheNamedOrganizationWins(t *testing.T) {
	orgs := &botOrgScope{active: func(context.Context) (string, error) { return "active-org", nil }}
	if got, _ := botOrgIn(context.Background(), orgs); got != "active-org" {
		t.Errorf("no named organization: %q, want the active one", got)
	}
	if got, _ := botOrgIn(withBotOrg(context.Background(), "org-acme"), orgs); got != "org-acme" {
		t.Errorf("named: %q, want org-acme", got)
	}
}

// IssueServiceAccountToken names exactly one machine account, and one that
// belongs to no organization reads like "not a machine account".
func TestIssueServiceAccountToken_Refusals(t *testing.T) {
	h, _ := newAdminAccounts(false)
	if _, err := h.IssueServiceAccountToken(ctxWithCaller("ops"), &pb.IssueServiceAccountTokenReq{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no id: %v, want InvalidArgument", err)
	}
	if _, err := h.IssueServiceAccountToken(ctxWithCallerInOrg("u1", "org-1"), &pb.IssueServiceAccountTokenReq{Ids: []string{"b"}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("from inside an organization: %v, want PermissionDenied", err)
	}
}

func (m *adminAccountsMock) ListUserOrgs(context.Context, *pb.ListUserOrgsReq, ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	return &pb.ListUserOrgsResp{}, nil
}

func TestIssueServiceAccountToken_AnAccountOfNoOrganization(t *testing.T) {
	h, _ := newAdminAccounts(false)
	if _, err := h.IssueServiceAccountToken(ctxWithCaller("ops"), &pb.IssueServiceAccountTokenReq{Ids: []string{"b"}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no organization: %v, want PermissionDenied", err)
	}
}

// adminAccountsCeilingMock is adminAccountsMock with a catalogue the ceiling
// can refuse: "member" carries nothing, "owner" is the organization's wildcard,
// and every account holds "owner".
type adminAccountsCeilingMock struct {
	*adminAccountsMock
}

func (m adminAccountsCeilingMock) ListOrgScopedRoles(context.Context, *pb.ListOrgScopedRolesReq, ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	return &pb.ListOrgScopedRolesResp{Roles: []*pb.OrgScopedRole{{Id: "role-1", Name: "member"}, {Id: "role-owner", Name: "owner"}}}, nil
}

func (m adminAccountsCeilingMock) ListOrgRoleRows(ctx context.Context, _ *pb.ListOrgRoleRowsReq, _ ...grpc.CallOption) (*pb.ListOrgRoleRowsResp, error) {
	return rowsFromScoped(m.ListOrgScopedRoles(ctx, &pb.ListOrgScopedRolesReq{}))
}

func (m adminAccountsCeilingMock) ListRoleGrants(context.Context, *pb.ListRoleGrantsReq, ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	return &pb.ListRoleGrantsResp{Grants: []*pb.RoleGrant{{RoleId: "role-1"}, {RoleId: "role-owner", AllPermissions: true}}}, nil
}

func (m adminAccountsCeilingMock) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{Grants: []*pb.RoleGrant{{RoleId: "role-owner", AllPermissions: true}}}, nil
}

// The admin cannot create an account above itself, nor hand out the setup
// link of one: whoever holds the link acts as the account. A refusal writes
// nothing.
func TestAdminAccounts_HeldToTheRoleCeiling(t *testing.T) {
	h, inner := newAdminAccounts(false)
	m := adminAccountsCeilingMock{inner}
	h.Query, h.Mutation = m, m
	// ctxWithCaller holds permission 5 only; the lock allocates 1–4, so the
	// wildcard carries what ops does not hold.
	ops := ctxWithCaller("ops")

	if _, err := h.CreateAccount(ops, &pb.CreateAccountReq{Org: "acme", Email: "boss@acme.example", Role: "owner"}); refusalCodeOf(err) != CodeRoleAboveCaller || len(inner.created) != 0 || len(inner.setups) != 0 {
		t.Errorf("creating an owner: err = %v, created %v — want %s and nothing written", err, inner.created, CodeRoleAboveCaller)
	}
	created, err := h.CreateAccount(ops, &pb.CreateAccountReq{Org: "acme", Email: "x@acme.example", Role: "member"})
	if err != nil || len(inner.created) != 1 {
		t.Fatalf("a role within the ceiling: %v, created %v", err, inner.created)
	}
	before := len(inner.setups)
	if _, err := h.IssueAccountSetupLink(ops, &pb.IssueAccountSetupLinkReq{Ids: []string{created.GetUserId()}}); refusalCodeOf(err) != CodeRoleAboveCaller || len(inner.setups) != before {
		t.Errorf("a setup link of an account holding owner: err = %v — want %s and no new link", err, CodeRoleAboveCaller)
	}
}
