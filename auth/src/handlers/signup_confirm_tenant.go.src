package handlers

import (
	"context"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// The tenant half of `sign_up_confirmation`, staged only when `tenant_scope`
// is on too (plugin.yaml go_files_combined): the fields it reads and writes
// exist only with both features.
//
// The tenant is resolved when the registration is REQUESTED — from the slug or
// the forwarded Host of the SignUp — and carried on the pending row, so the
// account lands where the person registered and not wherever the confirmation
// request happens to arrive.

func init() {
	pendingSignUpTenant = stampPendingSignUpTenant
	confirmCreateUser = createConfirmedUserInTenant
}

func stampPendingSignUpTenant(ctx context.Context, h *AuthServiceHandler, req *pb.SignUpReq, create *pb.CreatePendingSignUpReq) error {
	tenantID, err := resolveSignupTenant(ctx, h, req)
	if err != nil {
		return err
	}
	create.TenantId = tenantID
	return nil
}

func createConfirmedUserInTenant(ctx context.Context, h *AuthServiceHandler, claimed *pb.ClaimPendingSignUpResp) (string, error) {
	resp, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{
		Email:        claimed.GetEmail(),
		PasswordHash: claimed.GetPasswordHash(),
		TenantId:     claimed.GetTenantId(),
	})
	if err != nil {
		return "", err
	}
	return resp.GetUser().GetId(), nil
}
