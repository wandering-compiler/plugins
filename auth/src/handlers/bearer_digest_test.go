package handlers

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- a stored digest is not a credential -----------------------------------
//
// Only sha256(token) is stored, so a database read yields digests. That is
// worth something only if presenting a digest gets nobody in: the lookup must
// hash what it is handed, and the legacy plaintext column — the one place a
// value is compared as presented — must be NULL on every row a mint writes.

// digestStore holds one row the way IssueToken writes it: token_hash set, the
// legacy column NULL. A lookup matches with the statement's own predicate,
// `t.token_hash = :token_hash OR t.token = :legacy_token`, NULL matching
// nothing. Both resolvers' queries are served from it.
type digestStore struct {
	pb.AuthQueryClient
	tokenHash string
	legacy    string // "" stands for NULL
	kind      pb.TokenType
}

func (s *digestStore) match(hash, legacy string) bool {
	return hash == s.tokenHash || (s.legacy != "" && legacy == s.legacy)
}

func (s *digestStore) GetUserByTokenWithPermissions(_ context.Context, in *pb.GetUserByTokenWithPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	if !s.match(in.GetTokenHash(), in.GetLegacyToken()) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetUserByTokenWithPermissionsResp{User: &pb.User{Id: "u1"}, TokenId: "t1", StoredTokenHash: s.tokenHash}, nil
}

func (s *digestStore) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	if !s.match(in.GetTokenHash(), in.GetLegacyToken()) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: s.kind, User: &pb.User{Id: "u1"}, StoredTokenHash: s.tokenHash}, nil
}

// The miss path's expiry probe: the row is live, so no expired row matches.
func (s *digestStore) GetExpiredToken(context.Context, *pb.GetExpiredTokenReq, ...grpc.CallOption) (*pb.GetExpiredTokenResp, error) {
	return nil, status.Error(codes.NotFound, "no rows")
}

func (s *digestStore) GetExpiredTokenWithType(context.Context, *pb.GetExpiredTokenWithTypeReq, ...grpc.CallOption) (*pb.GetExpiredTokenWithTypeResp, error) {
	return nil, status.Error(codes.NotFound, "no rows")
}

func (s *digestStore) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

func (s *digestStore) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

func (s *digestStore) GetTokenPermissionSubset(context.Context, *pb.GetTokenPermissionSubsetReq, ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	return &pb.GetTokenPermissionSubsetResp{}, nil
}

// pinResolver installs one resolver for the length of a test.
func pinResolver(t *testing.T, r func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error)) {
	t.Helper()
	prev := resolvePrincipal
	resolvePrincipal = r
	t.Cleanup(func() { resolvePrincipal = prev })
}

// Somebody who read the token table holds the digest. Presented as a bearer it
// must be refused, by both resolvers and for every token kind, while the token
// it is the digest of still works — the control that keeps the refusal from
// passing for a store that refuses everything.
func TestAuthenticate_AStoredDigestIsNotACredential(t *testing.T) {
	plain, digest, err := newBearerToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, rc := range []struct {
		name    string
		resolve func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error)
		kind    pb.TokenType
	}{
		{"session resolver", resolvePrincipalSession, pb.TokenType_TOKEN_TYPE_SESSION},
		{"realm-aware resolver, session", resolvePrincipalRealmAware, pb.TokenType_TOKEN_TYPE_SESSION},
		{"realm-aware resolver, API token", resolvePrincipalRealmAware, pb.TokenType_TOKEN_TYPE_API},
	} {
		t.Run(rc.name, func(t *testing.T) {
			pinResolver(t, rc.resolve)
			h := &AuthServiceHandler{Query: &digestStore{tokenHash: digest, kind: rc.kind}, Mutation: &touchRecorder{}}
			if _, err := bareAuthenticate(t, h, plain); err != nil {
				t.Fatalf("the token itself was refused: %v", err)
			}
			_, err := bareAuthenticate(t, h, digest)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("the stored digest authenticated (err %v)", err)
			}
		})
	}
}

// The other half: the legacy column, compared as presented, is never written
// by a mint. A row a mint creates therefore has it NULL, and the digest cannot
// match it there either. Checked on every INSERT into UserToken, so a new mint
// path is held to it without being named here.
func TestNoMintWritesTheLegacyTokenColumn(t *testing.T) {
	src := readProto(t, filepath.Join("..", "..", "proto", "mutations", "auth_mutation.proto"))
	const insert = "INSERT INTO @module.UserToken SET "
	var mints []string
	for _, m := range regexp.MustCompile(`(?m)^  rpc (\w+)\(`).FindAllStringSubmatch(src, -1) {
		for _, stmt := range dqlStatements(mutationRPCBody(t, m[1])) {
			if !strings.HasPrefix(stmt, insert) {
				continue
			}
			mints = append(mints, m[1])
			set := strings.TrimPrefix(stmt, insert)
			if i := strings.Index(set, " RETURNING "); i >= 0 {
				set = set[:i]
			}
			cols := map[string]bool{}
			for _, a := range strings.Split(set, ",") {
				a = strings.TrimSpace(a)
				if strings.HasPrefix(a, "?feature(") {
					a = strings.TrimSpace(a[strings.Index(a, ")")+1:])
				}
				col, _, ok := strings.Cut(a, "=")
				if !ok {
					t.Fatalf("%s: unparsable assignment %q in %q", m[1], a, stmt)
				}
				cols[strings.TrimSpace(col)] = true
			}
			if !cols["token_hash"] {
				t.Errorf("%s does not write token_hash: %q", m[1], stmt)
			}
			if cols["token"] {
				t.Errorf("%s writes the legacy plaintext column: %q", m[1], stmt)
			}
		}
	}
	if len(mints) < 2 {
		// IssueToken and IssueApiToken (which the bot mint uses too): fewer
		// means the scan broke, not that the mints went away.
		t.Fatalf("found INSERTs into UserToken in %v only — the scan is broken", mints)
	}
}

// dqlStatements returns each `dql:` of an rpc declaration as the one string
// its adjacent literals concatenate to.
func dqlStatements(body string) []string {
	var out []string
	lit := regexp.MustCompile(`^\s*"((?:[^"\\]|\\.)*)"`)
	for _, part := range strings.Split(body, "dql:")[1:] {
		var b strings.Builder
		for {
			m := lit.FindStringSubmatchIndex(part)
			if m == nil {
				break
			}
			b.WriteString(part[m[2]:m[3]])
			part = part[m[1]:]
		}
		out = append(out, b.String())
	}
	return out
}

// --- what one authentication costs -----------------------------------------

// countingStore answers every query a token resolution makes and counts them.
// The token's owner holds `roles` roles, so a cost that grew with the role
// count — a query per role, a query per permission — shows as a different
// total for a larger set.
type countingStore struct {
	pb.AuthQueryClient
	kind  pb.TokenType
	roles int
	calls []string
}

func (s *countingStore) grants() []*pb.RoleGrant {
	out := make([]*pb.RoleGrant, 0, s.roles)
	for i := 0; i < s.roles; i++ {
		out = append(out, &pb.RoleGrant{RoleId: "r" + string(rune('a'+i%26)) + string(rune('a'+i/26)), PermissionIds: []int32{int32(i + 1), int32(i + 2)}})
	}
	return out
}

func (s *countingStore) GetUserByTokenWithPermissions(context.Context, *pb.GetUserByTokenWithPermissionsReq, ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	s.calls = append(s.calls, "GetUserByTokenWithPermissions")
	return &pb.GetUserByTokenWithPermissionsResp{User: &pb.User{Id: "u1"}, TokenId: "t1", StoredTokenHash: "h"}, nil
}

func (s *countingStore) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	s.calls = append(s.calls, "GetUserRoleGrants")
	return &pb.GetUserRoleGrantsResp{Grants: s.grants()}, nil
}

func (s *countingStore) GetTokenWithType(context.Context, *pb.GetTokenWithTypeReq, ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	s.calls = append(s.calls, "GetTokenWithType")
	return &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: s.kind, User: &pb.User{Id: "u1"}, StoredTokenHash: "h"}, nil
}

func (s *countingStore) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	s.calls = append(s.calls, "GetUserRolePermissionsByRealm")
	return &pb.GetUserRolePermissionsByRealmResp{Grants: s.grants()}, nil
}

func (s *countingStore) GetTokenPermissionSubset(context.Context, *pb.GetTokenPermissionSubsetReq, ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	s.calls = append(s.calls, "GetTokenPermissionSubset")
	return &pb.GetTokenPermissionSubsetResp{PermissionIds: []int32{1, 2, 3}}, nil
}

func (s *countingStore) GetUserTenant(context.Context, *pb.GetUserTenantReq, ...grpc.CallOption) (*pb.GetUserTenantResp, error) {
	s.calls = append(s.calls, "GetUserTenant")
	return &pb.GetUserTenantResp{TenantId: "tenant-acme"}, nil
}

func (s *countingStore) GetUser(context.Context, *pb.GetUserReq, ...grpc.CallOption) (*pb.User, error) {
	s.calls = append(s.calls, "GetUser")
	return &pb.User{Id: "u1"}, nil
}

// One token lookup and one role-grant query, whatever the number of roles; an
// API token adds its subset; each staged scope decorator adds one. The cost is
// a property of the configuration, never of how many roles or permissions the
// caller holds.
func TestAuthenticate_QueryCountIsFixedWhateverTheRoleCount(t *testing.T) {
	for _, rc := range []struct {
		name    string
		resolve func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error)
		kind    pb.TokenType
		want    int
	}{
		{"session resolver", resolvePrincipalSession, pb.TokenType_TOKEN_TYPE_SESSION, 2},
		{"realm-aware resolver, session", resolvePrincipalRealmAware, pb.TokenType_TOKEN_TYPE_SESSION, 2},
		{"realm-aware resolver, API token", resolvePrincipalRealmAware, pb.TokenType_TOKEN_TYPE_API, 3},
	} {
		for _, roles := range []int{1, 40} {
			s := &countingStore{kind: rc.kind, roles: roles}
			pinResolver(t, rc.resolve)
			h := &AuthServiceHandler{Query: s, Mutation: &touchRecorder{}}
			if _, err := bareAuthenticate(t, h, "plain"); err != nil {
				t.Fatalf("%s, %d roles: %v", rc.name, roles, err)
			}
			if len(s.calls) != rc.want {
				t.Errorf("%s, %d roles: %d queries %v, want %d", rc.name, roles, len(s.calls), s.calls, rc.want)
			}
		}
	}

	// Two decorators staged (tenant scope, machine label): one query each.
	pinResolver(t, resolvePrincipalSession)
	prevDec, prevNarrow := scopeDecorators, grantNarrowers
	t.Cleanup(func() { scopeDecorators, grantNarrowers = prevDec, prevNarrow })
	s := &countingStore{kind: pb.TokenType_TOKEN_TYPE_SESSION, roles: 40}
	h := &AuthServiceHandler{Query: s, Mutation: &touchRecorder{}, HeaderName: "Authorization", Scheme: "Bearer"}
	scopeDecorators, grantNarrowers = []scopeDecorator{resolveTenantScope, labelMachineAccount}, nil
	if _, err := h.Authenticate(context.Background(), &pb.AuthReq{Headers: map[string]string{"authorization": "Bearer plain"}}); err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 4 {
		t.Errorf("with two decorators: %d queries %v, want 4", len(s.calls), s.calls)
	}
}
