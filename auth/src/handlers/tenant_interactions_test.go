package handlers

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- rbac × tenant_scope -----------------------------------------------------

// tenantSignupStore is a deployment with several tenants: users keep the
// tenant they were created in, CountUsers counts the whole table as its
// statement does, and the bootstrap claim is the one constant-key row.
type tenantSignupStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	bySlug  map[string]string   // slug -> tenant id
	tenant  map[string]string   // user id -> tenant id
	roles   map[string][]string // user id -> role ids assigned
	claimed map[string]string   // bootstrap claim key -> holder
}

func (s *tenantSignupStore) GetTenantBySlug(_ context.Context, in *pb.GetTenantBySlugReq, _ ...grpc.CallOption) (*pb.GetTenantBySlugResp, error) {
	if id, ok := s.bySlug[in.GetSlug()]; ok {
		return &pb.GetTenantBySlugResp{TenantId: id}, nil
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (s *tenantSignupStore) CountUsers(context.Context, *pb.CountUsersReq, ...grpc.CallOption) (*pb.CountUsersResp, error) {
	return &pb.CountUsersResp{Count: int64(len(s.tenant))}, nil
}

func (s *tenantSignupStore) GetFirstUserRoles(context.Context, *pb.GetFirstUserRolesReq, ...grpc.CallOption) (*pb.GetFirstUserRolesResp, error) {
	return &pb.GetFirstUserRolesResp{RoleIds: []string{"r-superadmin"}}, nil
}

func (s *tenantSignupStore) GetDefaultRoles(context.Context, *pb.GetDefaultRolesReq, ...grpc.CallOption) (*pb.GetDefaultRolesResp, error) {
	return &pb.GetDefaultRolesResp{RoleIds: []string{"r-member"}}, nil
}

func (s *tenantSignupStore) CreateUser(_ context.Context, in *pb.CreateUserReq, _ ...grpc.CallOption) (*pb.CreateUserResp, error) {
	id := "u-" + string(rune('1'+len(s.tenant)))
	s.tenant[id] = in.GetTenantId()
	return &pb.CreateUserResp{User: &pb.User{Id: id, Email: in.GetEmail()}}, nil
}

func (s *tenantSignupStore) ClaimBootstrapAdmin(_ context.Context, in *pb.ClaimBootstrapAdminReq, _ ...grpc.CallOption) (*pb.ClaimBootstrapAdminResp, error) {
	// Keyed as the table is, so a claim on a per-tenant (or per-account) key
	// would succeed here as it would there.
	if s.claimed[in.GetSlot()] != "" {
		return &pb.ClaimBootstrapAdminResp{Written: proto.Int32(0)}, nil
	}
	s.claimed[in.GetSlot()] = in.GetUserId()
	return &pb.ClaimBootstrapAdminResp{Written: proto.Int32(1)}, nil
}

func (s *tenantSignupStore) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	s.roles[in.GetUserId()] = append(s.roles[in.GetUserId()], in.GetRoleId())
	return &pb.AssignRoleToUserResp{}, nil
}

func (s *tenantSignupStore) IssueToken(context.Context, *pb.IssueTokenReq, ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "t-1"}}, nil
}

// The bootstrap roles go to the first account of the DEPLOYMENT, not of each
// tenant: the count is realm-wide and the claim has one constant key. The first
// account of a second tenant gets the default roles, so opening a tenant does
// not mint it a superadministrator.
func TestSignUp_OnlyTheDeploymentsFirstAccountIsBootstrapped(t *testing.T) {
	prevCreate, prevConfirm := signupCreateUser, signUpConfirmation
	t.Cleanup(func() { signupCreateUser, signUpConfirmation = prevCreate, prevConfirm })
	signupCreateUser, signUpConfirmation = createUserWithResolvedTenant, nil

	s := &tenantSignupStore{
		bySlug:  map[string]string{"acme": "tenant-acme", "globex": "tenant-globex"},
		tenant:  map[string]string{},
		roles:   map[string][]string{},
		claimed: map[string]string{},
	}
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}

	first, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: "a@acme.example", Password: "pw-first-account", TenantSlug: "acme"})
	if err != nil {
		t.Fatalf("first SignUp: %v", err)
	}
	other, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: "a@globex.example", Password: "pw-other-tenant", TenantSlug: "globex"})
	if err != nil {
		t.Fatalf("second tenant's first SignUp: %v", err)
	}
	if s.tenant[other.GetUserId()] != "tenant-globex" {
		t.Fatalf("the second account landed in %q, want tenant-globex", s.tenant[other.GetUserId()])
	}
	if got := s.roles[first.GetUserId()]; len(got) != 1 || got[0] != "r-superadmin" {
		t.Errorf("the deployment's first account got %v, want the bootstrap roles", got)
	}
	if got := s.roles[other.GetUserId()]; len(got) != 1 || got[0] != "r-member" {
		t.Errorf("the first account of a second tenant got %v, want the default roles only", got)
	}

	// The race: the first sign-ups of two tenants both read an empty table.
	// The claim's key is one constant, not per tenant, so only one of them
	// becomes the administrator.
	s = &tenantSignupStore{bySlug: s.bySlug, tenant: map[string]string{}, roles: map[string][]string{}, claimed: map[string]string{}}
	h.Query, h.Mutation = s, s
	ctx := context.Background()
	acmeRoles, err := resolveSignupRoleIDs(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	globexRoles, err := resolveSignupRoleIDs(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	acme, _ := createUserWithResolvedTenant(ctx, h, &pb.SignUpReq{TenantSlug: "acme"}, "b@acme.example", "x")
	globex, _ := createUserWithResolvedTenant(ctx, h, &pb.SignUpReq{TenantSlug: "globex"}, "b@globex.example", "x")
	if err := assignSignupRoleIDs(ctx, h, acme, acmeRoles); err != nil {
		t.Fatal(err)
	}
	if err := assignSignupRoleIDs(ctx, h, globex, globexRoles); err != nil {
		t.Fatal(err)
	}
	admins := 0
	for _, id := range []string{acme, globex} {
		if got := s.roles[id]; len(got) == 1 && got[0] == "r-superadmin" {
			admins++
		}
	}
	if admins != 1 {
		t.Errorf("two tenants' concurrent first sign-ups made %d administrators, want 1 (roles %v)", admins, s.roles)
	}
}

// The two statements the decision rests on carry no tenant: CountUsers counts
// the whole table, and its request has nothing a tenant could ride on.
func TestCountUsers_IsRealmWide(t *testing.T) {
	if n := (&pb.CountUsersReq{}).ProtoReflect().Descriptor().Fields().Len(); n != 0 {
		t.Errorf("CountUsersReq has %d field(s); a per-tenant count would need one", n)
	}
	dql := methodDQL(t, readProto(t, filepath.Join("..", "..", "proto", "queries", "auth_query.proto")), "rpc CountUsers(")
	if !strings.Contains(dql, `"SELECT COUNT(*) AS count FROM @module.User u"`) || strings.Contains(dql, "WHERE") {
		t.Errorf("CountUsers is not a count of the whole table:\n%s", dql)
	}
}

// --- tenant_scope × org_membership -------------------------------------------

// twoScopeStore serves a session token, the caller's tenant and the caller's
// membership of one organization.
type twoScopeStore struct {
	*orgMock
}

func (s twoScopeStore) GetUserByTokenWithPermissions(context.Context, *pb.GetUserByTokenWithPermissionsReq, ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	return &pb.GetUserByTokenWithPermissionsResp{User: &pb.User{Id: "u1"}, TokenId: "t1", StoredTokenHash: "h"}, nil
}

func (s twoScopeStore) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

func (s twoScopeStore) GetUserTenant(context.Context, *pb.GetUserTenantReq, ...grpc.CallOption) (*pb.GetUserTenantResp, error) {
	return &pb.GetUserTenantResp{TenantId: "tenant-acme"}, nil
}

// Both features stamp their scope on one principal, and neither depends on the
// other: in either order the two decorators produce the same scopes and
// labels, each with its own key.
func TestAuthenticate_TenantAndOrgScopesAreStampedIndependently(t *testing.T) {
	pinResolver(t, resolvePrincipalSession)
	prevDec, prevNarrow := scopeDecorators, grantNarrowers
	t.Cleanup(func() { scopeDecorators, grantNarrowers = prevDec, prevNarrow })
	grantNarrowers = nil

	s := twoScopeStore{&orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{"u1|acme": {OrgId: "org-acme"}}}}
	h := &AuthServiceHandler{Query: s, Mutation: &touchRecorder{}, HeaderName: "Authorization", Scheme: "Bearer"}
	req := &pb.AuthReq{Headers: map[string]string{"authorization": "Bearer plain"}}

	var answers []*pb.AuthResp
	for _, order := range [][]scopeDecorator{
		{resolveTenantScope, resolveOrgScope},
		{resolveOrgScope, resolveTenantScope},
	} {
		scopeDecorators = order
		resp, err := h.Authenticate(ctxWithOrg("acme"), req)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if resp.GetScopes()["tenant_id"] != "tenant-acme" || resp.GetScopes()["org_id"] != "org-acme" {
			t.Errorf("scopes = %v, want both tenant_id and org_id", resp.GetScopes())
		}
		answers = append(answers, resp)
	}
	if !reflect.DeepEqual(answers[0].GetScopes(), answers[1].GetScopes()) || !reflect.DeepEqual(answers[0].GetLabels(), answers[1].GetLabels()) {
		t.Errorf("the decorators' order changed the answer: %v / %v", answers[0], answers[1])
	}
}

// --- service_account × authenticate -----------------------------------------

// kindQuery answers GetUser with an account of one kind, or an error.
type kindQuery struct {
	pb.AuthQueryClient
	kind pb.AccountKind
	err  error
}

func (q kindQuery) GetUser(context.Context, *pb.GetUserReq, ...grpc.CallOption) (*pb.User, error) {
	if q.err != nil {
		return nil, q.err
	}
	return &pb.User{Id: "u1", Kind: q.kind}, nil
}

// A machine principal carries labels[account_kind]=bot; a person carries no
// such label, and neither does a principal whose kind could not be read — so a
// rule written as "refuse unless bot" fails closed. The decorator is staged by
// service_account's init, which is what makes Authenticate run it.
func TestLabelMachineAccount_OnlyABotIsLabelled(t *testing.T) {
	for _, c := range []struct {
		name string
		q    kindQuery
		want string
	}{
		{"bot", kindQuery{kind: pb.AccountKind_BOT}, AccountKindBot},
		{"person", kindQuery{kind: pb.AccountKind_HUMAN}, ""},
		{"unreadable", kindQuery{err: status.Error(codes.Unavailable, "db down")}, ""},
	} {
		labels := map[string]string{}
		if err := labelMachineAccount(context.Background(), &AuthServiceHandler{Query: c.q}, "u1", nil, map[string]string{}, labels); err != nil {
			t.Errorf("%s: the label must never fail authentication: %v", c.name, err)
		}
		if got, ok := labels[AccountKindLabel]; got != c.want || (c.want == "" && ok) {
			t.Errorf("%s: labels = %v, want account_kind=%q", c.name, labels, c.want)
		}
	}

	staged := false
	for _, d := range scopeDecorators {
		if reflect.ValueOf(d).Pointer() == reflect.ValueOf(scopeDecorator(labelMachineAccount)).Pointer() {
			staged = true
		}
	}
	if !staged {
		t.Error("labelMachineAccount is not among the staged scope decorators")
	}
}
