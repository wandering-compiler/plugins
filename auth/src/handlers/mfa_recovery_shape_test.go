package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// consumeCounter counts the recovery-code lookups; every other mutation is nil
// and panics if called.
type consumeCounter struct {
	pb.AuthMutationClient
	calls int
}

func (c *consumeCounter) ConsumeRecoveryCode(context.Context, *pb.ConsumeRecoveryCodeReq, ...grpc.CallOption) (*pb.ConsumeRecoveryCodeResp, error) {
	c.calls++
	return &pb.ConsumeRecoveryCodeResp{}, nil
}

// A code that cannot be a recovery code — a six-digit TOTP code, an empty
// string, one character too few or too many — is refused without a storage
// round trip. Every wrong TOTP code reaches this check, so a lookup per guess
// would put a write statement (the consume) behind every one of them.
func TestAcceptRecoveryCode_AWrongShapeIsRefusedWithoutALookup(t *testing.T) {
	c := &consumeCounter{}
	h := &AuthServiceHandler{Mutation: c}
	for _, code := range []string{"", "123456", "abcd-efghj", "abcde-fghjkm", "abcdefghjkmn"} {
		if h.acceptRecoveryCode(context.Background(), "u1", code) {
			t.Errorf("%q was accepted", code)
		}
	}
	if c.calls != 0 {
		t.Fatalf("%d lookups for codes that are not shaped like a recovery code", c.calls)
	}

	// The control: a recovery-shaped code, typed any way a person types it,
	// is looked up — once each.
	for _, code := range []string{"abcde-fghjk", "ABCDE FGHJK", "abcdefghjk"} {
		h.acceptRecoveryCode(context.Background(), "u1", code)
	}
	if c.calls != 3 {
		t.Errorf("%d lookups for three recovery-shaped codes, want 3", c.calls)
	}
}
