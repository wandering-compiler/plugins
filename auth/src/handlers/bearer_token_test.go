package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"

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
	h.upgradeLegacyToken(context.Background(), "legacy-plaintext", "")
	if len(rec.calls) != 1 || rec.calls[0].GetToken() != "legacy-plaintext" || rec.calls[0].GetTokenHash() != sha256Hex("legacy-plaintext") {
		t.Fatalf("legacy row: calls = %v, want one upgrade to sha256 of the token", rec.calls)
	}
	h.upgradeLegacyToken(context.Background(), "new-token", sha256Hex("new-token"))
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
	if q.req.GetTokenHash() != sha256Hex("plain-legacy") || q.req.GetToken() != "plain-legacy" {
		t.Errorf("lookup req = %v, want the hash and the token (legacy fallback)", q.req)
	}
	if len(rec.calls) != 1 {
		t.Errorf("legacy row not moved: %v", rec.calls)
	}
}

type legacyLookupQuery struct {
	pb.AuthQueryClient
	req *pb.GetTokenWithTypeReq
}

func (q *legacyLookupQuery) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	q.req = in
	// No stored hash: the row predates hashing.
	return &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "t1", TokenType: pb.TokenType_TOKEN_TYPE_SESSION}, nil
}

func (q *legacyLookupQuery) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}
