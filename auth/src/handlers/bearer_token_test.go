package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// upgradeRecorder records UpgradeTokenHash calls; the embedded interface
// leaves every other method nil (a call to one would panic, which is the
// point: the upgrade must not touch anything else).
type upgradeRecorder struct {
	pb.AuthMutationClient
	calls []*pb.UpgradeTokenHashReq
}

func (u *upgradeRecorder) UpgradeTokenHash(_ context.Context, in *pb.UpgradeTokenHashReq, _ ...grpc.CallOption) (*pb.UpgradeTokenHashResp, error) {
	u.calls = append(u.calls, in)
	return &pb.UpgradeTokenHashResp{}, nil
}

// A minted token is handed out once and stored only as its sha256.
func TestNewBearerToken(t *testing.T) {
	tok, hash, err := newBearerToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != bearerTokenLen {
		t.Errorf("token length %d, want %d", len(tok), bearerTokenLen)
	}
	if hash != sha256Hex(tok) || hash == tok {
		t.Errorf("hash %q is not sha256(token)", hash)
	}
	if again, _, _ := newBearerToken(); again == tok {
		t.Error("two mints gave the same token")
	}
}

// A lookup that resolved a legacy row (no stored hash) moves it to the hash;
// a row already hashed is left alone.
func TestUpgradeLegacyToken(t *testing.T) {
	rec := &upgradeRecorder{}
	h := &AuthServiceHandler{Mutation: rec}
	h.upgradeLegacyToken(context.Background(), "legacy-plaintext", sha256Hex("legacy-plaintext"), "")
	if len(rec.calls) != 1 || rec.calls[0].GetLegacyToken() != "legacy-plaintext" || rec.calls[0].GetTokenHash() != sha256Hex("legacy-plaintext") {
		t.Fatalf("legacy row: calls = %v, want one upgrade to sha256 of the token", rec.calls)
	}
	h.upgradeLegacyToken(context.Background(), "new-token", sha256Hex("new-token"), sha256Hex("new-token"))
	if len(rec.calls) != 1 {
		t.Errorf("a hashed row was upgraded again: %v", rec.calls)
	}
}

// Authenticate looks the bearer up by hash (with the token for a legacy row)
// and moves a legacy row it resolved to.
func TestResolvePrincipalRealmAware_LegacyRowIsMovedToTheHash(t *testing.T) {
	q := &legacyLookupQuery{}
	rec := &upgradeRecorder{}
	h := &AuthServiceHandler{Query: q, Mutation: rec}
	if _, err := resolvePrincipalRealmAware(context.Background(), h, "plain-legacy"); err != nil {
		t.Fatal(err)
	}
	if q.req.GetTokenHash() != sha256Hex("plain-legacy") || q.req.GetLegacyToken() != "plain-legacy" {
		t.Errorf("lookup req = %v, want the hash and the token (legacy fallback)", q.req)
	}
	if len(rec.calls) != 1 {
		t.Errorf("legacy row not moved: %v", rec.calls)
	}
}

type legacyLookupQuery struct {
	pb.AuthQueryClient
	req      *pb.GetTokenWithTypeReq
	disabled bool
}

func (q *legacyLookupQuery) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	q.req = in
	// No stored hash: the row predates hashing.
	resp := &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_SESSION, User: &pb.User{Id: "u1"}}
	if q.disabled {
		resp.User.DisabledAt = timestamppb.Now()
	}
	return resp, nil
}

func (q *legacyLookupQuery) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

// The default (api_token off) resolver looks the bearer up by hash too and
// moves a legacy row it resolved to; a hashed row is left alone.
func TestResolvePrincipalSession_LegacyRowIsMovedToTheHash(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored string
		want   int
	}{
		{"legacy", "", 1},
		{"hashed", sha256Hex("plain"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &sessionLookupQuery{stored: tc.stored}
			rec := &upgradeRecorder{}
			h := &AuthServiceHandler{Query: q, Mutation: rec}
			if _, err := resolvePrincipalSession(context.Background(), h, "plain"); err != nil {
				t.Fatal(err)
			}
			if q.req.GetTokenHash() != sha256Hex("plain") || q.req.GetLegacyToken() != "plain" {
				t.Errorf("lookup req = %v, want the hash and the token (legacy fallback)", q.req)
			}
			if len(rec.calls) != tc.want {
				t.Fatalf("upgrades = %v, want %d", rec.calls, tc.want)
			}
			if tc.want == 1 && rec.calls[0].GetTokenHash() != sha256Hex("plain") {
				t.Errorf("upgrade hash = %q, want sha256 of the token", rec.calls[0].GetTokenHash())
			}
		})
	}
}

type sessionLookupQuery struct {
	pb.AuthQueryClient
	stored   string
	req      *pb.GetUserByTokenWithPermissionsReq
	disabled bool
}

func (q *sessionLookupQuery) GetUserByTokenWithPermissions(_ context.Context, in *pb.GetUserByTokenWithPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	q.req = in
	u := &pb.User{Id: "u1"}
	if q.disabled {
		u.DisabledAt = timestamppb.Now()
	}
	return &pb.GetUserByTokenWithPermissionsResp{User: u, TokenId: "t1", StoredTokenHash: q.stored}, nil
}

func (q *sessionLookupQuery) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

// A disabled account authenticates with no token, on either resolver.
// DisableUsers deletes the tokens; this covers one minted after it, such as a
// sign-in that raced the disable.
func TestResolvePrincipal_ADisabledAccountIsRefused(t *testing.T) {
	h := &AuthServiceHandler{Query: &sessionLookupQuery{stored: "x", disabled: true}, Mutation: &upgradeRecorder{}}
	if _, err := resolvePrincipalSession(context.Background(), h, "plain"); !errors.Is(err, errAuthnUserDisabled) {
		t.Errorf("session resolver: err = %v, want the disabled-account refusal", err)
	}
	h = &AuthServiceHandler{Query: &legacyLookupQuery{disabled: true}, Mutation: &upgradeRecorder{}}
	if _, err := resolvePrincipalRealmAware(context.Background(), h, "plain"); !errors.Is(err, errAuthnUserDisabled) {
		t.Errorf("realm-aware resolver: err = %v, want the disabled-account refusal", err)
	}
}
