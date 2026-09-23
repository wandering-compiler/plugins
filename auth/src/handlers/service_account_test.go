package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"github.com/wandering-compiler/platform/plugins/auth/lib/passwordhash"
)

// service_account.go's init() installs the real signInBotGate, so with this
// file compiled the gate is live — the same arrangement user_admin_test.go
// relies on.
//
// ⚠️ This is the test that turns `User.kind` from a label into a control.
// A bot's password_hash is empty and `passwordhash.Verify` already refuses an
// empty stored hash, so a bot is unreachable by password TODAY — by accident.
// The first `password_change` against a bot would hand it a working password
// and open that door. The gate is what keeps it shut on purpose, and this
// asserts the gate rather than the accident.
func TestSignInBotGate(t *testing.T) {
	// The control: a person must still be able to sign in. Without this the
	// test passes just as well if the gate refuses everyone, which would be a
	// far worse bug than the one it guards.
	if err := signInBotGate(&pb.User{Kind: pb.AccountKind_HUMAN}); err != nil {
		t.Errorf("a HUMAN account was refused by the bot gate: %v", err)
	}
	// And an account from before the feature existed — kind unset, which is
	// HUMAN's zero. The migration adds the column with that default, so every
	// existing user takes this path on the first sign-in after the upgrade.
	if err := signInBotGate(&pb.User{}); err != nil {
		t.Errorf("an account predating the feature was refused: %v", err)
	}

	if err := signInBotGate(&pb.User{Kind: pb.AccountKind_BOT}); err == nil {
		t.Error("a BOT signed in with a password — the account type is a label, not a control")
	}
}

// The refusal must not reach the caller as itself: SignIn wraps every arm in
// the same opaque Unauthenticated, so an address cannot be probed to learn it
// belongs to a machine.
func TestSignInBotGate_ReasonStaysInternal(t *testing.T) {
	err := signInBotGate(&pb.User{Kind: pb.AccountKind_BOT})
	if err == nil {
		t.Fatal("no refusal to inspect")
	}
	if err != errAuthnBotNoPassword {
		t.Errorf("unexpected refusal %v — SignIn's opaque wrapping assumes this sentinel", err)
	}
}

// botTokenQuery answers GetUserById with one account of a chosen kind.
type botTokenQuery struct {
	pb.AuthQueryClient
	kind pb.AccountKind
}

func (q botTokenQuery) GetUserById(context.Context, *pb.GetUserByIdReq, ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: "u1", Kind: q.kind}}, nil
}

// The membership probe answers YES here so these cases keep testing what they
// were written for — the KIND check. Their cross-organization sibling covers
// the other half.
func (q botTokenQuery) GetBotInOrg(_ context.Context, in *pb.GetBotInOrgReq, _ ...grpc.CallOption) (*pb.GetBotInOrgResp, error) {
	return &pb.GetBotInOrgResp{UserId: in.GetUserId()}, nil
}

// mintRecorder records whether a token was actually issued.
type mintRecorder struct {
	pb.AuthMutationClient
	issued bool
}

func (m *mintRecorder) IssueApiToken(context.Context, *pb.IssueApiTokenReq, ...grpc.CallOption) (*pb.IssueApiTokenResp, error) {
	m.issued = true
	return &pb.IssueApiTokenResp{Token: &pb.UserToken{Id: "t1", Token: "secret"}}, nil
}

// TestIssueBotToken_RefusesAPerson — the check that IS the feature.
//
// This endpoint is the only one in the plugin that mints a credential for
// SOMEBODY ELSE. Restricted to machine accounts it is a deploy credential;
// unrestricted it is "act as any user", and no UI filtering takes that back.
func TestIssueBotToken_RefusesAPerson(t *testing.T) {
	rec := &mintRecorder{}
	h := &AuthServiceHandler{Query: botTokenQuery{kind: pb.AccountKind_HUMAN}, Mutation: rec}

	_, err := h.IssueBotToken(ctxWithCallerInOrg("admin-1", "org-1"), &pb.IssueBotTokenReq{UserId: "u1"})
	if err == nil {
		t.Fatal("minted a token for a HUMAN account — this endpoint is an impersonation primitive")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("refusal code = %s, want PermissionDenied (the caller named a real account "+
			"and may not mint for it — that is authorisation, not a malformed request)", status.Code(err))
	}
	// ⚠️ And nothing was issued. A check that runs AFTER the mint would leave a
	// live credential behind on the refusal path, which is the failure this
	// assertion exists for — the error alone would not show it.
	if rec.issued {
		t.Error("a token was issued before the target was checked — the refusal leaves a live credential")
	}
}

// The control: a bot must still get one, or the endpoint is refusing everyone
// and the test above passes for the wrong reason.
func TestIssueBotToken_MintsForABot(t *testing.T) {
	rec := &mintRecorder{}
	h := &AuthServiceHandler{Query: botTokenQuery{kind: pb.AccountKind_BOT}, Mutation: rec}

	resp, err := h.IssueBotToken(ctxWithCallerInOrg("admin-1", "org-1"), &pb.IssueBotTokenReq{UserId: "u1"})
	if err != nil {
		t.Fatalf("a BOT was refused a token: %v", err)
	}
	if resp.GetToken() == "" {
		t.Error("no token returned — it is handed back ONCE and never retrievable again")
	}
	if !rec.issued {
		t.Error("no token was actually issued")
	}
}

// --- CreateBot ---------------------------------------------------------

type botAdminMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	apiRoles   []*pb.OrgScopedRole
	created    bool
	assigned   string
	grantOrg   string
	memberOf   string
	listedOrg  string
	probedOrg  string
	probedUser string
	botsOrg    string
	issued     bool
	assignErr  error
}

func (m *botAdminMock) ListApiRealmRoles(ctx context.Context, _ *pb.ListApiRealmRolesReq, _ ...grpc.CallOption) (*pb.ListApiRealmRolesResp, error) {
	return &pb.ListApiRealmRolesResp{Roles: m.apiRoles}, nil
}

func (m *botAdminMock) CreateBotUser(ctx context.Context, in *pb.CreateBotUserReq, _ ...grpc.CallOption) (*pb.CreateBotUserResp, error) {
	m.created = true
	return &pb.CreateBotUserResp{User: &pb.User{Id: "bot-1", Email: in.GetEmail()}}, nil
}

func (m *botAdminMock) AssignRoleToUser(ctx context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.assigned = in.GetRoleId()
	m.grantOrg = in.GetOrgId()
	return &pb.AssignRoleToUserResp{}, m.assignErr
}

func (m *botAdminMock) AddOrgMembership(ctx context.Context, in *pb.AddOrgMembershipReq, _ ...grpc.CallOption) (*pb.AddOrgMembershipResp, error) {
	m.memberOf = in.GetOrgId()
	return &pb.AddOrgMembershipResp{}, nil
}

// A session-realm role granted to a bot is unreachable — permissions resolve
// within the presented token's realm — so accepting one would mint an account
// whose grant silently does nothing. The check is server-side because the
// role id arrives on the wire, not from the list this server rendered.
func TestCreateBot_RefusesARoleFromTheSessionRealm(t *testing.T) {
	m := &botAdminMock{apiRoles: []*pb.OrgScopedRole{{Id: "role-api"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	_, err := h.CreateBot(ctxWithCallerInOrg("admin-1", "org-1"), &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-session"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
	if m.created {
		t.Error("the account was created before the role was checked — a refusal left a bot behind")
	}
}

// Control: without it, a handler that refused every role would pass the test
// above while making the feature unusable.
func TestCreateBot_AcceptsAnApiRealmRoleAndGrantsIt(t *testing.T) {
	m := &botAdminMock{apiRoles: []*pb.OrgScopedRole{{Id: "role-api"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	resp, err := h.CreateBot(ctxWithCallerInOrg("admin-1", "org-1"), &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-api"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.GetUserId() != "bot-1" {
		t.Errorf("user_id = %q, want bot-1", resp.GetUserId())
	}
	// The grant is the point of doing both in one call.
	if m.assigned != "role-api" {
		t.Errorf("role assigned = %q, want role-api — a bot with no role holds a token that does nothing", m.assigned)
	}
}

func TestCreateBot_RoleIsRequired(t *testing.T) {
	m := &botAdminMock{apiRoles: []*pb.OrgScopedRole{{Id: "role-api"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.CreateBot(ctxWithCallerInOrg("admin-1", "org-1"), &pb.CreateBotReq{Email: "ci@example.com"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a bot was created with no role: %v", err)
	}
}

// The bot's stored password must be UNUSABLE, and unusable by construction.
//
// Two constraints meet here and only one value satisfies both: the column
// carries a blank CHECK, so the natural "no password" — the empty string — is
// refused by the database (found live 2026-09-20, after handler tests with a
// mocked mutation had passed: the mock made the storage layer invisible). And
// whatever is stored must never verify.
func TestBotPasswordSentinel_IsNonEmptyAndCannotVerify(t *testing.T) {
	const sentinel = "!"

	if sentinel == "" {
		t.Fatal("empty violates the password_hash blank CHECK — the row cannot be inserted")
	}
	// Any input at all, including the sentinel itself.
	for _, attempt := range []string{"!", "password", "", "$argon2id$v=19$m=65536,t=3,p=4$x$y"} {
		if ok, _ := passwordhash.Verify(sentinel, attempt, passwordhash.Argon2id, passwordhash.Params{}); ok {
			t.Errorf("a password verified against the bot sentinel: %q", attempt)
		}
	}
}

// A machine account must land INSIDE an organization, and its grant with it.
//
// The role is declared org-scoped, so a grant written with no organization
// lands as NULL — which the org axis counts only for realm-wide roles. The
// grant then applies nowhere and the bot authenticates with an EMPTY
// permission set. And with no membership there is no organization to infer,
// so an unattended caller sending no W17-Org header has no scope either.
//
// Both were live: a token minted through the console UI pushed nothing and
// reported "no permissions resolved for this principal" (2026-09-20). Neither
// the handler tests nor the live token mint caught it — the account looked
// correct in every listing.
func TestCreateBot_JoinsTheOrgAndScopesTheGrantToIt(t *testing.T) {
	m := &botAdminMock{apiRoles: []*pb.OrgScopedRole{{Id: "role-api"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.CreateBot(ctxWithCallerInOrg("admin-1", "org-1"), &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-api"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.memberOf != "org-1" {
		t.Errorf("the bot joined %q, want org-1 — without a membership there is no org to infer", m.memberOf)
	}
	if m.grantOrg != "org-1" {
		t.Errorf("the grant was written for org %q, want org-1 — an org-scoped role granted with none applies nowhere", m.grantOrg)
	}
}

// With no active organization there is nothing to grant INTO, so the account
// must not be created at all — an inert bot is a support ticket, not a safe
// default.
func TestCreateBot_RefusesWithNoActiveOrg(t *testing.T) {
	m := &botAdminMock{apiRoles: []*pb.OrgScopedRole{{Id: "role-api"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.CreateBot(ctxWithCaller("admin-1"), &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-api"}); err == nil {
		t.Fatal("a machine account was created with no organization to act in")
	}
	if m.created {
		t.Error("the account was created before the organization was checked")
	}
}

// ctxWithCallerInOrg is ctxWithCaller plus an ACTIVE organization — the scope the
// gateway stamps once the caller has selected one.
func ctxWithCallerInOrg(uid, orgID string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(scopeUserIDKey, uid, "x-w17-scope-org_id", orgID))
}

// --- cross-tenant: the leak that shipped ------------------------------

func (m *botAdminMock) ListBotUsers(ctx context.Context, in *pb.ListBotUsersReq, _ ...grpc.CallOption) (*pb.ListBotUsersResp, error) {
	m.listedOrg = in.GetOrgId()
	return &pb.ListBotUsersResp{}, nil
}

func (m *botAdminMock) IssueApiToken(ctx context.Context, in *pb.IssueApiTokenReq, _ ...grpc.CallOption) (*pb.IssueApiTokenResp, error) {
	m.issued = true
	return &pb.IssueApiTokenResp{Token: &pb.UserToken{Id: "t1", Token: "secret"}}, nil
}

func (m *botAdminMock) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), Kind: pb.AccountKind_BOT}}, nil
}

func (m *botAdminMock) GetBotInOrg(ctx context.Context, in *pb.GetBotInOrgReq, _ ...grpc.CallOption) (*pb.GetBotInOrgResp, error) {
	m.probedOrg, m.probedUser = in.GetOrgId(), in.GetUserId()
	if in.GetOrgId() == m.botsOrg {
		return &pb.GetBotInOrgResp{UserId: in.GetUserId()}, nil
	}
	return &pb.GetBotInOrgResp{}, nil // not in this organization
}

// `User` is not an org-scoped model — a person belongs to several — so the
// request scope does not narrow this list on its own. Without the filter the
// answer is every machine account on the console, and one company's operator
// saw another's on production (2026-09-21).
func TestListBots_AsksOnlyForTheActiveOrganization(t *testing.T) {
	m := &botAdminMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.ListBots(ctxWithCallerInOrg("admin-1", "org-1"), &pb.ListBotsReq{}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if m.listedOrg != "org-1" {
		t.Errorf("the query was asked for org %q — an unfiltered list returns every tenant's bots", m.listedOrg)
	}
}

// With no organization there is nothing to scope to, so the answer must be a
// refusal rather than the unscoped set.
func TestListBots_RefusesWithNoActiveOrg(t *testing.T) {
	m := &botAdminMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.ListBots(ctxWithCaller("admin-1"), &pb.ListBotsReq{}); err == nil {
		t.Fatal("an unscoped caller received a bot list")
	}
	if m.listedOrg != "" {
		t.Error("the query ran anyway")
	}
}

// The id arrives on the WIRE. Listing leaked other tenants' bot ids, and
// nothing between the two steps checked that the target belonged to the
// caller's company — so an operator in one could mint a working credential
// for a machine account in another.
func TestIssueBotToken_RefusesABotFromAnotherOrganization(t *testing.T) {
	m := &botAdminMock{botsOrg: "org-other"}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	_, err := h.IssueBotToken(ctxWithCallerInOrg("admin-1", "org-mine"), &pb.IssueBotTokenReq{UserId: "bot-elsewhere"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if m.issued {
		t.Error("a token was minted for another organization's machine account")
	}
	if m.probedOrg != "org-mine" {
		t.Errorf("the membership probe used org %q, want the CALLER's", m.probedOrg)
	}
}

// --- deinvo 2026-09-23: the claim, driven through SignIn -------------------
//
// TestSignInBotGate above calls the gate DIRECTLY, with a `pb.User` it builds
// itself carrying `Kind: BOT`. That proves the function refuses a bot. It
// proves nothing about the thing we told a consumer on 2026-09-20 — "a
// `kind = BOT` account cannot sign in with a password at all; that path is
// closed for it" — because the User SignIn actually holds comes from
// GetUserByEmail, and for a month that projection did not select `kind`. The
// gate read an unset AccountKind, HUMAN is zero, and the door was open. The
// test agreed with the mock, and the mock agreed with the wrong reading.
//
// So this one goes through SignIn. It is one half of a pair, and neither half
// is worth much alone:
//
//   - TestEveryUserProjectionFillsTheFieldsItsGatesRead reads the DQL and
//     asserts GetUserByEmail actually SELECTs kind;
//   - this asserts that SignIn consults it on the user that lookup returned.
//
// Reported by deinvo, who noticed the fix riding silently in a plugin diff and
// pointed out that the claim it corrected had never been tested.

// signInBotQuery answers GetUserByEmail the way the fixed projection does —
// every field the SELECT names, kind included.
type signInBotQuery struct {
	pb.AuthQueryClient
	kind pb.AccountKind
	hash string
}

func (q signInBotQuery) GetUserByEmail(_ context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{User: &pb.User{
		Id: "u1", Email: in.GetEmail(), PasswordHash: q.hash, Kind: q.kind,
	}}, nil
}

func TestSignIn_RefusesAMachineAccountThatHasAPassword(t *testing.T) {
	// A REAL, verifiable hash: the whole point is that the refusal does not
	// depend on a bot's password being unusable. A bot that went through
	// `password_change` has a working one, and that is the case the claim we
	// made to a consumer is about.
	s := passwordhash.DefaultSettings()
	hash, err := s.Hash("correct-horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Record what the gate is HANDED, not just what it returns. That is the
	// half the isolated test could not reach: the defect was never in the
	// gate, it was in the user arriving with kind unset.
	var seen []pb.AccountKind
	orig := signInBotGate
	signInBotGate = func(u *pb.User) error {
		seen = append(seen, u.GetKind())
		return orig(u)
	}
	t.Cleanup(func() { signInBotGate = orig })

	h := &AuthServiceHandler{Query: signInBotQuery{kind: pb.AccountKind_BOT, hash: hash}, PasswordHash: s}
	_, err = h.SignIn(context.Background(), &pb.SignInReq{Email: "ci@example.com", Password: "correct-horse"})
	if err == nil {
		t.Error("a machine account signed in with its correct password — the path we told a consumer was closed")
	} else if status.Code(err) != codes.Unauthenticated {
		t.Errorf("refusal reached the caller as %v, not the opaque Unauthenticated every SignIn arm uses", status.Code(err))
	}
	if len(seen) != 1 || seen[0] != pb.AccountKind_BOT {
		t.Errorf("SignIn handed the gate %v — the lookup's `kind` did not reach it, which is the defect itself", seen)
	}

	// The decoy. Without it the refusal above proves nothing: SignIn refusing
	// everybody would pass just as well, and that is a far worse bug. Same
	// password, same hash, same handler — only `kind` differs.
	//
	// Asserted at the GATE rather than on a completed sign-in: a human's
	// SignIn continues into device handling, which needs more of the handler
	// wired than this file has. What must be true here is that the gate saw a
	// HUMAN and let it through, so the refusal above is attributable to the
	// field and to nothing else.
	seen = nil
	h = &AuthServiceHandler{Query: signInBotQuery{kind: pb.AccountKind_HUMAN, hash: hash}, PasswordHash: s}
	func() {
		defer func() { _ = recover() }() // a later stage may need plumbing we do not provide
		_, _ = h.SignIn(context.Background(), &pb.SignInReq{Email: "person@example.com", Password: "correct-horse"})
	}()
	if len(seen) != 1 || seen[0] != pb.AccountKind_HUMAN {
		t.Errorf("the gate saw %v for a person — the decoy is not exercising the same path", seen)
	}
	if orig(&pb.User{Kind: pb.AccountKind_HUMAN}) != nil {
		t.Error("the gate refuses a person too — the refusal above says nothing about kind")
	}
}
