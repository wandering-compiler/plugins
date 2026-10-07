package handlers

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// An API token minted without an expiry takes the deployment's default, so the
// credential nobody remembers to rotate still stops working. The mutation is
// handed the expiry and the caller is told it.
func TestCreateApiToken_DefaultExpiryReachesTheTokenAndTheCaller(t *testing.T) {
	m := &apiTokenMgmtMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m, APITokenDefaultTTLHours: 24}
	before := time.Now()

	resp, err := h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{Name: "ci"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got := m.issueReq.GetExpiresAt()
	if got == nil {
		t.Fatal("the token was minted with no expiry — the default never applied")
	}
	if d := got.AsTime().Sub(before); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("expiry %v is not ~24h out", d)
	}
	if !resp.GetExpiresAt().AsTime().Equal(got.AsTime()) {
		t.Errorf("caller was told %v, token carries %v", resp.GetExpiresAt(), got)
	}
}

// The caller's own expiry wins over the default; 0 as the deployment default
// keeps the old never-expiring behaviour; an expiry in the past is refused
// before anything is minted, on the field it is about.
func TestAPITokenExpiry(t *testing.T) {
	future := timestamppb.New(time.Now().Add(72 * time.Hour))

	h := &AuthServiceHandler{APITokenDefaultTTLHours: 24}
	got, err := h.apiTokenExpiry(ctxWithCaller("u1"), future)
	if err != nil || !got.AsTime().Equal(future.AsTime()) {
		t.Errorf("an explicit expiry: got %v, %v", got, err)
	}

	h = &AuthServiceHandler{APITokenDefaultTTLHours: 0}
	if got, err := h.apiTokenExpiry(ctxWithCaller("u1"), nil); err != nil || got != nil {
		t.Errorf("default 0 must mean never: got %v, %v", got, err)
	}

	m := &apiTokenMgmtMock{}
	h = &AuthServiceHandler{Query: m, Mutation: m, APITokenDefaultTTLHours: 24}
	_, err = h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute))})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an expiry in the past: code %v (%v)", status.Code(err), err)
	}
	var detail *w17pb.ErrorDetail
	for _, d := range status.Convert(err).Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			detail = ed
		}
	}
	if detail.GetField() != "expires_at" || detail.GetCode() != "TOKEN_EXPIRY_IN_PAST" {
		t.Errorf("detail = %v, want TOKEN_EXPIRY_IN_PAST on expires_at", detail)
	}
	if m.issueReq != nil {
		t.Fatalf("a token was minted anyway: %v", m.issueReq)
	}
}

// A timestamp outside what every reader can carry is refused on its field; a
// default lifetime past where time.Duration overflows is refused at boot.
func TestAPITokenExpiry_OutOfRange(t *testing.T) {
	h := &AuthServiceHandler{APITokenDefaultTTLHours: 24}
	_, err := h.apiTokenExpiry(ctxWithCaller("u1"), &timestamppb.Timestamp{Seconds: 1e12})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("year ~33658: code %v (%v)", status.Code(err), err)
	}
	if err := ValidateConfig(&AuthServiceHandler{APITokenDefaultTTLHours: 3_000_000}); err == nil {
		t.Error("a default lifetime that overflows time.Duration was accepted at boot")
	}
	if err := ValidateConfig(&AuthServiceHandler{APITokenDefaultTTLHours: 2160}); err != nil {
		t.Errorf("the default was refused: %v", err)
	}
}
