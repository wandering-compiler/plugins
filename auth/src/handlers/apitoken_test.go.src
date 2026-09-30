package handlers

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// apiTokenQueryMock embeds the generated client interface (nil) so it
// satisfies pb.AuthQueryClient, and overrides only the four methods
// the realm-aware resolver calls. Any other call would nil-panic — the
// tests never make one.
type apiTokenQueryMock struct {
	pb.AuthQueryClient

	tok        *pb.GetTokenWithTypeResp
	realmPerms []int32
	subset     []int32
	wildcard   bool // the realm role is a wildcard role

	subsetCalled bool
}

func (m *apiTokenQueryMock) GetTokenWithType(ctx context.Context, in *pb.GetTokenWithTypeReq, opts ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	return m.tok, nil
}

func (m *apiTokenQueryMock) GetUserRolePermissionsByRealm(ctx context.Context, in *pb.GetUserRolePermissionsByRealmReq, opts ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	// Echo the realm so a test can assert the right realm was queried.
	if in.GetTokenType() != m.tok.GetTokenType() {
		return &pb.GetUserRolePermissionsByRealmResp{}, nil
	}
	// One role, carrying the realm's permissions. Role-attributed now: the
	// org axis intersects on role ids, so a grant with no role id would be
	// dropped by a narrower rather than kept.
	return &pb.GetUserRolePermissionsByRealmResp{Grants: []*pb.RoleGrant{{
		RoleId:         "role-realm",
		PermissionIds:  m.realmPerms,
		AllPermissions: m.wildcard,
	}}}, nil
}

func (m *apiTokenQueryMock) GetTokenPermissionSubset(ctx context.Context, in *pb.GetTokenPermissionSubsetReq, opts ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	m.subsetCalled = true
	return &pb.GetTokenPermissionSubsetResp{PermissionIds: m.subset}, nil
}

func TestResolvePrincipalRealmAware_Session_NoSubsetLookup(t *testing.T) {
	mock := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_SESSION},
		realmPerms: []int32{1, 2, 3},
		subset:     []int32{1}, // present, but a SESSION token must NOT consult it
	}
	h := &AuthServiceHandler{Query: mock}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, perms := prin.userID, prin.effectivePermissions(h.Lock)
	_, _ = uid, perms
	if uid != "u1" {
		t.Errorf("userID = %q, want u1", uid)
	}
	if !reflect.DeepEqual(perms, []int32{1, 2, 3}) {
		t.Errorf("perms = %v, want [1 2 3] (full realm perms)", perms)
	}
	if mock.subsetCalled {
		t.Error("SESSION token must not query the per-token subset")
	}
}

// wildcardLock is a small ACL lock the wildcard tests expand against.
func wildcardLock() *acllock.Lock {
	return &acllock.Lock{Version: acllock.CurrentVersion, Permissions: map[string]int{
		"tasks.Task#view": 1, "tasks.Task#add": 2, "tasks.Task#change": 3,
	}}
}

func sortedInt32(in []int32) []int32 {
	out := append([]int32(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// A SESSION wildcard role expands to the full catalogue (GrantAll),
// ignoring any RolePermission-derived realm perms.
func TestResolvePrincipalRealmAware_Wildcard_GrantsAll(t *testing.T) {
	mock := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_SESSION},
		realmPerms: []int32{1}, // must be ignored — wildcard grants the whole lock
		wildcard:   true,
	}
	h := &AuthServiceHandler{Query: mock, Lock: wildcardLock()}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, perms := prin.userID, prin.effectivePermissions(h.Lock)
	_, _ = uid, perms
	if got := sortedInt32(perms); !reflect.DeepEqual(got, []int32{1, 2, 3}) {
		t.Errorf("perms = %v, want [1 2 3] (GrantAll over the lock)", got)
	}
}

// An API wildcard token still narrows by its per-token subset: the
// grant is GrantAll(lock) ∩ subset, never an escalation past the subset.
func TestResolvePrincipalRealmAware_API_Wildcard_NarrowedBySubset(t *testing.T) {
	mock := &apiTokenQueryMock{
		tok:      &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_API},
		wildcard: true,
		subset:   []int32{2, 3, 99}, // 99 not in the catalogue → dropped
	}
	h := &AuthServiceHandler{Query: mock, Lock: wildcardLock()}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, perms := prin.userID, prin.effectivePermissions(h.Lock)
	_, _ = uid, perms
	if got := sortedInt32(perms); !reflect.DeepEqual(got, []int32{2, 3}) {
		t.Errorf("perms = %v, want [2 3] (GrantAll ∩ subset)", got)
	}
}

func TestResolvePrincipalRealmAware_API_EmptySubset_NoNarrowing(t *testing.T) {
	mock := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_API},
		realmPerms: []int32{10, 20},
		subset:     nil, // empty subset = no narrowing
	}
	h := &AuthServiceHandler{Query: mock}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, perms := prin.userID, prin.effectivePermissions(h.Lock)
	_, _ = uid, perms
	if !reflect.DeepEqual(perms, []int32{10, 20}) {
		t.Errorf("perms = %v, want [10 20] (no narrowing)", perms)
	}
}

func TestResolvePrincipalRealmAware_API_Subset_Intersects(t *testing.T) {
	mock := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_API},
		realmPerms: []int32{10, 20, 30},
		subset:     []int32{20, 30, 99}, // 99 not in realm perms -> dropped (no escalation)
	}
	h := &AuthServiceHandler{Query: mock}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, perms := prin.userID, prin.effectivePermissions(h.Lock)
	_, _ = uid, perms
	if !reflect.DeepEqual(perms, []int32{20, 30}) {
		t.Errorf("perms = %v, want [20 30] (realm ∩ subset, no escalation)", perms)
	}
}

func TestIntersectInt32(t *testing.T) {
	cases := []struct {
		a, b, want []int32
	}{
		{[]int32{1, 2, 3}, []int32{2, 3, 4}, []int32{2, 3}},
		{[]int32{1, 2, 3}, nil, []int32{}},
		{[]int32{1, 1, 2}, []int32{1, 2}, []int32{1, 2}}, // dedup
		{[]int32{5}, []int32{9}, []int32{}},
	}
	for i, c := range cases {
		got := intersectInt32(c.a, c.b)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: intersectInt32(%v,%v) = %v, want %v", i, c.a, c.b, got, c.want)
		}
	}
}
