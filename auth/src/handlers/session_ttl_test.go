package handlers

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// ttlMutationMock captures the expires_at the service-tier handler
// stamps on a freshly minted session token. It implements BOTH mint
// paths (both now go through IssueToken; the devices feature only adds
// device_id to the same call)
// because the standalone plugin build stages every feature file, so
// devices.go's init() swaps issueSession to the device variant.
type ttlMutationMock struct {
	pb.AuthMutationClient
	gotExpiresAt *timestamppb.Timestamp
	called       bool
}

func (m *ttlMutationMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	m.gotExpiresAt, m.called = in.GetExpiresAt(), true
	return &pb.IssueTokenResp{Token: &pb.UserToken{Token: "tok"}}, nil
}

// sessionTokenExpiry returns NOW + the configured TTL.
func TestSessionTokenExpiry_ConfiguredTTL(t *testing.T) {
	h := &AuthServiceHandler{SessionTokenTTLSeconds: 3600}
	before := time.Now()
	got := h.sessionTokenExpiry()
	after := time.Now()
	if got == nil {
		t.Fatal("sessionTokenExpiry must not be nil for a configured TTL")
	}
	exp := got.AsTime()
	if exp.Before(before.Add(3600*time.Second).Add(-2*time.Second)) ||
		exp.After(after.Add(3600*time.Second).Add(2*time.Second)) {
		t.Errorf("expiry %v not ~NOW+3600s", exp)
	}
}

// An unset (0 / negative) TTL falls back to the 30-day default —
// never a NULL / unbounded session token.
func TestSessionTokenExpiry_DefaultWhenUnset(t *testing.T) {
	for _, ttl := range []int{0, -5} {
		h := &AuthServiceHandler{SessionTokenTTLSeconds: ttl}
		got := h.sessionTokenExpiry()
		if got == nil {
			t.Fatalf("ttl=%d: default must still produce an expiry", ttl)
		}
		d := time.Until(got.AsTime())
		if d < 29*24*time.Hour || d > 31*24*time.Hour {
			t.Errorf("ttl=%d: default expiry ~30d expected, got %v", ttl, d)
		}
	}
}

// The mint path (whichever variant is active) stamps the expiry into
// the issued token — wiring proof for issueSession / the devices
// override.
func TestIssueSession_StampsExpiry(t *testing.T) {
	m := &ttlMutationMock{}
	h := &AuthServiceHandler{Mutation: m, SessionTokenTTLSeconds: 3600}
	if _, _, err := issueSession(context.Background(), h, "user-1", ""); err != nil {
		t.Fatalf("issueSession: %v", err)
	}
	if !m.called {
		t.Fatal("issueSession must call a mint RPC")
	}
	if m.gotExpiresAt == nil {
		t.Fatal("minted session token must carry expires_at (TTL not wired)")
	}
}
