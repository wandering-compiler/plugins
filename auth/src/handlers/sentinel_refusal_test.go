package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// A sentinel refusal keeps the sentinel's identity and operator message, and
// carries the person's sentence as the ErrorDetail the gateway renders.
func TestRefuseAs(t *testing.T) {
	err := inviteInvalid(context.Background())
	if !errors.Is(err, errInviteInvalid) || err.Error() != errInviteInvalid.Error() {
		t.Fatalf("identity lost: %v", err)
	}
	st := status.Convert(err)
	if st.Code() != codes.NotFound || st.Message() != status.Convert(errInviteInvalid).Message() {
		t.Errorf("status = %v %q", st.Code(), st.Message())
	}
	var got *w17pb.ErrorDetail
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			got = ed
		}
	}
	if got == nil || got.GetCode() != CodeInviteInvalid || got.GetMessage() != MsgInviteInvalid {
		t.Errorf("detail = %+v", got)
	}
}

// The organization-required refusal of activeOrgID speaks to the person and
// is still errNoActiveOrg to the code that checks for it.
func TestActiveOrgIDRefusal(t *testing.T) {
	_, err := activeOrgID(context.Background())
	if !errors.Is(err, errNoActiveOrg) {
		t.Fatalf("err = %v", err)
	}
	for _, d := range status.Convert(err).Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok && ed.GetCode() == CodeOrganizationRequired && ed.GetMessage() == MsgOrganizationRequired {
			return
		}
	}
	t.Errorf("no ORGANIZATION_REQUIRED detail on %v", err)
}
