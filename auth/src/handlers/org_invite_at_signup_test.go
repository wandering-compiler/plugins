package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// A registration through an invitation's link accepts it when the address
// reaches the floor without a proof of its own, and otherwise leaves it for
// AcceptOrgInvite without failing the registration.
func TestAcceptInviteAtSignup(t *testing.T) {
	withRealSeams(t)
	for _, c := range []struct {
		name     string
		floor    string
		invited  string // "" = open
		proven   bool
		accepted bool
	}{
		{"an open link, no floor", emailProofNone, "", false, true},
		{"an open link under derived: the registrant chose the address", emailProofDerived, "", false, false},
		{"a bound link under derived: accepting derives it", emailProofDerived, "new@corp.example", false, true},
		{"a bound link under full, unconfirmed", emailProofFull, "new@corp.example", false, false},
		{"a bound link under full, the registration confirmed it", emailProofFull, "new@corp.example", true, true},
		{"a link bound to another address", emailProofNone, "else@corp.example", false, false},
	} {
		m := &inviteTokenMock{pendingEmail: c.invited}
		h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: c.floor}
		err := acceptInviteAtSignup(context.Background(), h, "u-new", "new@corp.example", "secret", c.proven)
		if err != nil {
			t.Errorf("%s: %v — a registration must not fail on an invitation it only declines to accept", c.name, err)
		}
		if m.addedMembership != c.accepted {
			t.Errorf("%s: member %v, want %v", c.name, m.addedMembership, c.accepted)
		}
		if !c.accepted && m.consumedHash != "" {
			t.Errorf("%s: the invitation was spent without a membership", c.name)
		}
	}

	m := &inviteTokenMock{pendingErr: status.Error(codes.NotFound, "none")}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if err := acceptInviteAtSignup(context.Background(), h, "u-new", "new@corp.example", "stale", false); err != nil || m.addedMembership {
		t.Errorf("a link that names nothing: err %v, member %v — the gate already admitted the address", err, m.addedMembership)
	}
	_ = pb.EmailProof_UNPROVEN
}
