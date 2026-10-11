package handlers

import (
	"context"

	"github.com/wandering-compiler/sdk/go/lib/randstr"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// bearerTokenLen is the length of a minted bearer token, the same shape the
// tokens have always had.
const bearerTokenLen = 64

// newBearerToken mints a bearer token: the token the caller is handed once,
// and the sha256 the store keeps. Nothing stores the token itself, so whoever
// reads the UserToken table or a backup of it has nothing to present.
func newBearerToken() (token, hash string, err error) {
	token, err = randstr.Token(bearerTokenLen)
	if err != nil {
		return "", "", err
	}
	return token, sha256Hex(token), nil
}

// upgradeLegacyToken moves the row a bearer resolved to onto the hash when it
// is a legacy row — minted before tokens were hashed, so found by its token
// in the clear and reported with an empty storedHash. Best effort: a failed
// move leaves the row as it was, still valid, and the next request using the
// token tries again; it does not fail the request it rides on. hash is
// sha256Hex(token), already computed for the lookup.
func (h *AuthServiceHandler) upgradeLegacyToken(ctx context.Context, token, hash, storedHash string) {
	if storedHash != "" || token == "" {
		return
	}
	_, _ = h.Mutation.UpgradeTokenHash(ctx, &pb.UpgradeTokenHashReq{LegacyToken: token, TokenHash: hash})
}
