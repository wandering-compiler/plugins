package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Plain SignUp of an address that has an account answers "sign in instead",
// not the generic AlreadyExists sentence ("Another change reached this first.
// Please try again."), which sent a person who already has an account round
// the registration form. Found live by scripts/console-auth-proof.sh.
func TestSignUp_ATakenAddressSaysSignInInstead(t *testing.T) {
	pinConsoleActivation(t)
	s := newConfirmStore()
	s.users["a@example.com"] = &pb.User{Id: "u-x", Email: "a@example.com"}
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}

	_, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists (err=%v)", status.Code(err), err)
	}
	if d := detailOf(t, err); d.GetCode() != CodeEmailTaken || d.GetMessage() != MsgEmailTaken {
		t.Fatalf("detail = %v, want %s / %q — without it the caller reads \"try again\"", d, CodeEmailTaken, MsgEmailTaken)
	}
}

// The same answer from ConfirmSignUp, where sign_up_confirmation says it.
func TestConfirmSignUp_ATakenAddressSaysSignInInstead(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	s.users["a@example.com"] = &pb.User{Id: "u-x", Email: "a@example.com"}
	resp, err := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: s.codes[resp.GetPendingId()]})
	if d := detailOf(t, err); d.GetCode() != CodeEmailTaken {
		t.Fatalf("detail = %v, want %s", d, CodeEmailTaken)
	}
}

// A role above the inviter is refused WITH the rule. Without the detail the
// gateway renders PermissionDenied as "You do not have access to this." — about
// an endpoint the caller does have access to. Found live by
// scripts/console-auth-proof.sh (an org admin inviting a worker).
func TestInviteToOrg_ARoleAboveTheInviterNamesTheRule(t *testing.T) {
	m := newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}}
	h := &AuthServiceHandler{Query: m}

	ctx := withHeldPermissions(whoAmICtx("u1", "org-1"), "u1", 1, 2)
	_, err := h.InviteToOrg(ctx, &pb.InviteToOrgReq{Email: "x@example.com", Role: "org-admin"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if d := detailOf(t, err); d.GetCode() != CodeRoleAboveCaller || d.GetField() != "role" || d.GetMessage() != MsgRoleAboveCaller {
		t.Fatalf("detail = %v, want %s on field role", d, CodeRoleAboveCaller)
	}
}
