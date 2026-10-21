package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// adminMfaMock lists one live and one ended enrolment over mfaMock.
type adminMfaMock struct {
	*mfaMock
	rows map[string]*pb.AuthenticatorAdminRow
}

func (m *adminMfaMock) GetAuthenticator(_ context.Context, in *pb.GetAuthenticatorReq, _ ...grpc.CallOption) (*pb.AuthenticatorAdminRow, error) {
	r, ok := m.rows[in.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return r, nil
}

// Reset ends the person's live authenticator AND the recovery codes that
// stand in for it, so the next sign-in falls back to the mailed code. An
// ended enrolment, or an id naming nothing, is left alone.
func TestResetAuthenticators(t *testing.T) {
	inner := &mfaMock{totpSeed: testTotpSeed, totpConfirmed: true, recovery: map[string]bool{"h1": false}}
	m := &adminMfaMock{mfaMock: inner, rows: map[string]*pb.AuthenticatorAdminRow{
		"live":  {Id: "live", User: "u1"},
		"ended": {Id: "ended", User: "u2", RevokedAt: timestamppb.Now()},
	}}
	h := newMfaHandler(inner)
	h.Query, h.Mutation = m, m

	if _, err := h.ResetAuthenticators(ctxWithCaller("op"), &pb.ResetAuthenticatorsReq{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty selection: %v", err)
	}
	if _, err := h.ResetAuthenticators(ctxWithCaller("op"), &pb.ResetAuthenticatorsReq{Ids: []string{"ended", "nothing"}}); err != nil {
		t.Fatal(err)
	}
	if inner.revokedTotp {
		t.Fatal("an ended enrolment was ended again")
	}
	if _, err := h.ResetAuthenticators(ctxWithCaller("op"), &pb.ResetAuthenticatorsReq{Ids: []string{"live"}}); err != nil {
		t.Fatal(err)
	}
	if !inner.revokedTotp || len(inner.recovery) != 0 {
		t.Fatalf("revoked totp %v, live recovery codes %v", inner.revokedTotp, inner.recovery)
	}
}
