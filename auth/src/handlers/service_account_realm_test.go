package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Machine accounts in a realm WITHOUT organizations — one organization, the
// owner of the software (a platform's own backoffice). The tests compile every
// feature together, so service_account_org.go has installed the org scope;
// withoutOrgs takes it away for one test, which is what an activation without
// org_membership stages.
func withoutOrgs(t *testing.T) {
	t.Helper()
	prev, prevMark := botOrgs, orgMembershipStaged
	botOrgs, orgMembershipStaged = nil, false
	t.Cleanup(func() { botOrgs, orgMembershipStaged = prev, prevMark })
}

// realmCaller is an operator of a realm without organizations: signed in, no
// org in scope, the permissions Authenticate resolved on the envelope. The
// tenant rides along only because the tests compile tenant_scope's filler too.
func realmCaller(uid string, held ...int32) context.Context {
	return withHeldPermissions(metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(scopeUserIDKey, uid, "x-w17-scope-tenant_id", "tenant-1")), uid, held...)
}

// CreateBot needs no organization, writes no membership, and grants the role
// realm-wide — where every role of such a realm applies.
func TestCreateBot_WithoutOrgs_GrantsTheRoleRealmWide(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{apiRoles: []*pb.ApiRealmRole{{Id: "role-api"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	resp, err := h.CreateBot(realmCaller("operator-1"), &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-api"})
	if err != nil {
		t.Fatalf("a realm without organizations refused a machine account: %v", err)
	}
	if resp.GetUserId() == "" || !m.created {
		t.Fatal("no account was created")
	}
	if m.assigned != "role-api" || m.grantOrg != "" {
		t.Errorf("grant = role %q in org %q, want role-api realm-wide (no org)", m.assigned, m.grantOrg)
	}
	if m.memberOf != "" {
		t.Errorf("a membership was written in a realm without organizations (org %q)", m.memberOf)
	}
}

// The ceiling holds without organizations too: a role above the operator is
// refused before anything is written.
func TestCreateBot_WithoutOrgs_TheRoleCeilingHolds(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{
		apiRoles:  []*pb.ApiRealmRole{{Id: "role-api"}},
		rolePerms: map[string][]int32{"role-api": {999}}, // a permission the caller does not hold
	}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.CreateBot(realmCaller("operator-1", 7), &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-api"})
	if status.Code(err) != codes.PermissionDenied || strings.Contains(err.Error(), "no resolved permissions") {
		t.Fatalf("a role above the operator: code = %v (err %v), want the CEILING's PermissionDenied", status.Code(err), err)
	}
	if m.created {
		t.Error("the account was created before the ceiling refused its role")
	}
}

// ListBots lists the realm's machine accounts — and only the machines, even if
// the source handed back a person.
func TestListBots_WithoutOrgs_ListsTheRealmsMachines(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{realmBots: []*pb.User{
		{Id: "bot-1", Email: "ci@example.com", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"},
		{Id: "human-1", Email: "person@example.com", Kind: pb.AccountKind_HUMAN, TenantId: "tenant-1"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListBots(realmCaller("operator-1"), &pb.ListBotsReq{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !m.realmListed || m.listedOrg != "" {
		t.Errorf("realm list asked = %v, org list asked for %q — want the realm's", m.realmListed, m.listedOrg)
	}
	if len(resp.GetBots()) != 1 || resp.GetBots()[0].GetId() != "bot-1" {
		t.Errorf("bots = %v, want bot-1 only", resp.GetBots())
	}
}

// With organizations, the member list holds people and machines alike since the
// kind filter left the query (it is gated org_membership now, and User.kind is
// service_account's) — the handler keeps the machines.
func TestListBots_InAnOrg_KeepsOnlyTheMachines(t *testing.T) {
	m := &botAdminMock{members: []*pb.User{
		{Id: "bot-1", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"},
		{Id: "human-1", Kind: pb.AccountKind_HUMAN, TenantId: "tenant-1"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListBots(ctxWithCallerInOrg("admin-1", "org-1"), &pb.ListBotsReq{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetBots()) != 1 || resp.GetBots()[0].GetId() != "bot-1" {
		t.Errorf("bots = %v — a member who is a PERSON was listed as a machine account", resp.GetBots())
	}
	if m.realmListed {
		t.Error("an org realm read the realm-wide list")
	}
}

// IssueBotToken needs no organization: the target must be a machine account of
// the realm, which is every machine account.
func TestIssueBotToken_WithoutOrgs_MintsForABot(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.IssueBotToken(realmCaller("operator-1"), &pb.IssueBotTokenReq{UserId: "bot-1"})
	if err != nil || resp.GetToken() == "" || !m.issued {
		t.Fatalf("mint for a realm bot: err=%v token=%q issued=%v", err, resp.GetToken(), m.issued)
	}
	if m.probedOrg != "" {
		t.Errorf("an organization was probed (%q) in a realm without any", m.probedOrg)
	}
}

// …and still refuses a person, and an id that names nothing — with ONE answer,
// so the refusal is no directory of accounts.
func TestIssueBotToken_WithoutOrgs_RefusesAPersonAndAMissingAccountAlike(t *testing.T) {
	withoutOrgs(t)
	rec := &mintRecorder{}
	h := &AuthServiceHandler{Query: botTokenQuery{kind: pb.AccountKind_HUMAN}, Mutation: rec}
	_, errPerson := h.IssueBotToken(realmCaller("operator-1"), &pb.IssueBotTokenReq{UserId: "u1"})
	if status.Code(errPerson) != codes.PermissionDenied || rec.issued {
		t.Fatalf("a person: err=%v issued=%v", errPerson, rec.issued)
	}

	m := &botAdminMock{missing: true}
	h2 := &AuthServiceHandler{Query: m, Mutation: m}
	_, errMissing := h2.IssueBotToken(realmCaller("operator-1"), &pb.IssueBotTokenReq{UserId: "nobody"})
	if status.Code(errMissing) != codes.PermissionDenied || m.issued {
		t.Fatalf("a missing account: err=%v issued=%v", errMissing, m.issued)
	}
	if errPerson.Error() != errMissing.Error() {
		t.Errorf("a person and a missing account are told apart: %q vs %q", errPerson, errMissing)
	}
}

// ListBotRoles offers the api-realm roles under the ceiling, organizations or not.
func TestListBotRoles_WithoutOrgs(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{apiRoles: []*pb.ApiRealmRole{{Id: "role-api", Name: "ci-push"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListBotRoles(realmCaller("operator-1"), &pb.ListBotRolesReq{})
	if err != nil || len(resp.GetRoles()) != 1 || resp.GetRoles()[0].GetId() != "role-api" {
		t.Fatalf("roles = %v, err %v", resp.GetRoles(), err)
	}
}

// A build that has organizations but not their machine-account scoping must
// refuse, not fall back to the realm-wide behaviour — that would list and mint
// across organizations and compile cleanly doing it.
func TestMachineAccounts_OrgsWithoutTheirScopingRefuse(t *testing.T) {
	prev, prevMark := botOrgs, orgMembershipStaged
	botOrgs, orgMembershipStaged = nil, true
	t.Cleanup(func() { botOrgs, orgMembershipStaged = prev, prevMark })

	m := &botAdminMock{apiRoles: []*pb.ApiRealmRole{{Id: "role-api"}}, realmBots: []*pb.User{{Id: "bot-1", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	ctx := ctxWithCallerInOrg("admin-1", "org-1")
	_, errList := h.ListBots(ctx, &pb.ListBotsReq{})
	_, errMint := h.IssueBotToken(ctx, &pb.IssueBotTokenReq{UserId: "bot-1"})
	_, errCreate := h.CreateBot(ctx, &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-api"})
	for name, err := range map[string]error{"list": errList, "mint": errMint, "create": errCreate} {
		if status.Code(err) != codes.Internal {
			t.Errorf("%s: code = %v (err %v), want Internal — the build is missing its org scoping", name, status.Code(err), err)
		}
	}
	if m.realmListed || m.issued || m.created {
		t.Errorf("something ran anyway: listed=%v issued=%v created=%v", m.realmListed, m.issued, m.created)
	}
}

// Under tenant_scope an operator sees, and mints for, only their own tenant's
// machine accounts — without organizations the realm-wide list was every
// tenant's.
func TestMachineAccounts_WithoutOrgs_StayInTheOperatorsTenant(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{realmBots: []*pb.User{
		{Id: "bot-mine", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"},
		{Id: "bot-other", Kind: pb.AccountKind_BOT, TenantId: "tenant-2"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListBots(realmCaller("operator-1"), &pb.ListBotsReq{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetBots()) != 1 || resp.GetBots()[0].GetId() != "bot-mine" {
		t.Errorf("bots = %v — another tenant's machine account was listed", resp.GetBots())
	}

	m2 := &botAdminMock{botTenant2: "tenant-2"}
	h2 := &AuthServiceHandler{Query: m2, Mutation: m2}
	_, err = h2.IssueBotToken(realmCaller("operator-1"), &pb.IssueBotTokenReq{UserId: "bot-other"})
	if status.Code(err) != codes.PermissionDenied || m2.issued {
		t.Fatalf("minting for another tenant's bot: err=%v issued=%v", err, m2.issued)
	}
	if !strings.Contains(err.Error(), errNotABotAccount.Error()) {
		t.Errorf("another tenant's bot is told apart from a non-bot: %v", err)
	}
}

// A caller with no tenant in scope sees no machine account (fail closed).
func TestMachineAccounts_NoTenantInScopeSeesNone(t *testing.T) {
	withoutOrgs(t)
	m := &botAdminMock{realmBots: []*pb.User{{Id: "bot-1", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListBots(withHeldPermissions(ctxWithCaller("operator-1"), "operator-1"), &pb.ListBotsReq{})
	if err != nil || len(resp.GetBots()) != 0 {
		t.Fatalf("a caller with no tenant: bots=%v err=%v", resp.GetBots(), err)
	}
}

// Minting is held to the operator's ceiling: a bot that holds a role the
// operator could not grant gets no token from them — with organizations and
// without.
func TestIssueBotToken_RefusesABotAboveTheOperator(t *testing.T) {
	for name, orgs := range map[string]bool{"with orgs": true, "without orgs": false} {
		t.Run(name, func(t *testing.T) {
			if !orgs {
				withoutOrgs(t)
			}
			m := &botAdminMock{
				botsOrg:   "org-1",
				apiRoles:  []*pb.ApiRealmRole{{Id: "role-admin"}},
				rolePerms: map[string][]int32{"role-admin": {7, 99}},
				botRoles:  []string{"role-admin"},
			}
			h := &AuthServiceHandler{Query: m, Mutation: m}
			md := func() context.Context {
				return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
					scopeUserIDKey, "op-1", "x-w17-scope-org_id", "org-1", "x-w17-scope-tenant_id", "tenant-1"))
			}
			_, err := h.IssueBotToken(withHeldPermissions(md(), "op-1", 7), &pb.IssueBotTokenReq{UserId: "bot-1"})
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "machine account holds a role") {
				t.Fatalf("err = %v, want the mint ceiling's PermissionDenied", err)
			}
			if m.issued {
				t.Error("a token was minted for a bot above the operator")
			}
			// The control: the same operator holding everything the role carries.
			if _, err := h.IssueBotToken(withHeldPermissions(md(), "op-1", 7, 99), &pb.IssueBotTokenReq{UserId: "bot-1"}); err != nil || !m.issued {
				t.Fatalf("an operator holding the bot's role was refused: %v", err)
			}
		})
	}
}
