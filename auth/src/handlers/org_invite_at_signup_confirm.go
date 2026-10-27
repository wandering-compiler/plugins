package handlers

import pb "github.com/wandering-compiler/plugins/auth/gen/pb"

// Staged with invite_accept_at_signup and sign_up_confirmation: the
// confirmation carries the link again.
func init() {
	confirmInviteToken = func(req *pb.ConfirmSignUpReq) string { return req.GetInviteToken() }
}
