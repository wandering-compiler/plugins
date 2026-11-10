package handlers

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- rbac × org_signup -------------------------------------------------------

// bootstrapStore is a deployment with organizations taking registrations on
// their hosts (signupFixture: acme takes clients openly as "member"): users
// counted over the whole table as CountUsers' statement does, and the
// bootstrap claim the one constant-key row.
type bootstrapStore struct {
	*hostMock
	users   []string
	claimed map[string]string // bootstrap claim key -> holder
}

func (s *bootstrapStore) CountUsers(context.Context, *pb.CountUsersReq, ...grpc.CallOption) (*pb.CountUsersResp, error) {
	return &pb.CountUsersResp{Count: int64(len(s.users))}, nil
}

func (s *bootstrapStore) GetFirstUserRoles(context.Context, *pb.GetFirstUserRolesReq, ...grpc.CallOption) (*pb.GetFirstUserRolesResp, error) {
	return &pb.GetFirstUserRolesResp{RoleIds: []string{"r-superadmin"}}, nil
}

func (s *bootstrapStore) GetDefaultRoles(context.Context, *pb.GetDefaultRolesReq, ...grpc.CallOption) (*pb.GetDefaultRolesResp, error) {
	return &pb.GetDefaultRolesResp{RoleIds: []string{"r-default"}}, nil
}

func (s *bootstrapStore) CreateUser(_ context.Context, in *pb.CreateUserReq, _ ...grpc.CallOption) (*pb.CreateUserResp, error) {
	id := fmt.Sprintf("u-%d", len(s.users)+1)
	s.users = append(s.users, id)
	return &pb.CreateUserResp{User: &pb.User{Id: id, Email: in.GetEmail()}}, nil
}

func (s *bootstrapStore) ClaimBootstrapAdmin(_ context.Context, in *pb.ClaimBootstrapAdminReq, _ ...grpc.CallOption) (*pb.ClaimBootstrapAdminResp, error) {
	// Keyed as the table is, so a claim on a per-organization key would
	// succeed here as it would there.
	if s.claimed[in.GetSlot()] != "" {
		return &pb.ClaimBootstrapAdminResp{Written: proto.Int32(0)}, nil
	}
	s.claimed[in.GetSlot()] = in.GetUserId()
	return &pb.ClaimBootstrapAdminResp{Written: proto.Int32(1)}, nil
}

func (s *bootstrapStore) RegisterDevice(_ context.Context, in *pb.RegisterDeviceReq, _ ...grpc.CallOption) (*pb.RegisterDeviceResp, error) {
	return fakeRegisterDevice(in)
}

func (s *bootstrapStore) IssueToken(context.Context, *pb.IssueTokenReq, ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "t-1"}}, nil
}

// rolesOf is what AssignRoleToUser granted userID: "<org>/<role id>", the org
// empty for a realm-wide grant.
func (s *bootstrapStore) rolesOf(userID string) []string {
	var out []string
	for _, g := range s.granted {
		if u, rest, _ := strings.Cut(g, "/"); u == userID {
			out = append(out, rest)
		}
	}
	return out
}

// The bootstrap roles go to the first account of the DEPLOYMENT, not of each
// organization: the count is realm-wide and the claim has one constant key.
// The first account an organization takes on its host gets the default roles
// and the policy's organization role, so opening registration for an
// organization does not mint it a superadministrator — through SignUp itself,
// not only through the role seam.
func TestSignUp_OnlyTheDeploymentsFirstAccountIsBootstrapped(t *testing.T) {
	prevConfirm := signUpConfirmation
	t.Cleanup(func() { signUpConfirmation = prevConfirm })
	signUpConfirmation = nil

	s := &bootstrapStore{hostMock: signupFixture(), claimed: map[string]string{}}
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}

	first, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "owner@example.com", Password: "pw-first-account"})
	if err != nil {
		t.Fatalf("the deployment's first SignUp: %v", err)
	}
	client, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "client@acme.example", Password: "pw-acme-client", SignupHost: "acme.example.com"})
	if err != nil {
		t.Fatalf("acme's first registration on its host: %v", err)
	}
	if got := s.rolesOf(first.GetUserId()); !slices.Equal(got, []string{"/r-superadmin"}) {
		t.Errorf("the deployment's first account got %v, want the bootstrap roles realm-wide", got)
	}
	if got := s.rolesOf(client.GetUserId()); !slices.Equal(got, []string{"/r-default", "org-acme/role-member"}) {
		t.Errorf("acme's first account got %v, want the default roles and acme's member role only", got)
	}
	if !slices.Equal(s.joined, []string{client.GetUserId() + "/org-acme/client/member"}) {
		t.Errorf("joined %v", s.joined)
	}

	// The race: the first registrations of the deployment and of acme both
	// read an empty table. The claim's key is one constant, not per
	// organization, so only one of them becomes the administrator.
	s = &bootstrapStore{hostMock: signupFixture(), claimed: map[string]string{}}
	h.Query, h.Mutation = s, s
	ctx := context.Background()
	realmRoles, err := resolveSignupRoleIDs(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	acmeRoles, err := resolveSignupRoleIDs(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := assignSignupRoleIDs(ctx, h, "u-realm", realmRoles); err != nil {
		t.Fatal(err)
	}
	if err := assignSignupRoleIDs(ctx, h, "u-acme", acmeRoles); err != nil {
		t.Fatal(err)
	}
	admins := 0
	for _, id := range []string{"u-realm", "u-acme"} {
		if slices.Contains(s.rolesOf(id), "/r-superadmin") {
			admins++
		}
	}
	if admins != 1 {
		t.Errorf("two concurrent first registrations made %d administrators, want 1 (granted %v)", admins, s.granted)
	}
}

// The statement the decision rests on carries no organization: CountUsers
// counts the whole table, and its request has nothing an organization could
// ride on.
func TestCountUsers_IsRealmWide(t *testing.T) {
	if n := (&pb.CountUsersReq{}).ProtoReflect().Descriptor().Fields().Len(); n != 0 {
		t.Errorf("CountUsersReq has %d field(s); a per-organization count would need one", n)
	}
	dql := methodDQL(t, readProto(t, filepath.Join("..", "..", "proto", "queries", "auth_query.proto")), "rpc CountUsers(")
	if !strings.Contains(dql, `"SELECT COUNT(*) AS count FROM @module.User u"`) || strings.Contains(dql, "WHERE") {
		t.Errorf("CountUsers is not a count of the whole table:\n%s", dql)
	}
}
