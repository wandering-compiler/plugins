package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `admin_mfa` feature: the admin Authenticators page
// and its Reset action. Staged only when the activation enables `admin_mfa`
// (plugin.yaml go_files), which needs user_admin (the admin pages) and
// two_factor (the enrolments it lists).
//
// Reset is the way back for a person who lost both the phone and the recovery
// codes. With every sign-in challenged, such a person cannot sign in at all:
// the authenticator is the only proof their account accepts. Ending the
// enrolment returns them to the mailed code, and they set up a new
// authenticator from there. It is the operator's act, so it ends exactly what
// DisableTotp ends — the authenticator and the unused recovery codes — and
// TotpDisabled carries the operator's device, not the person's.

// ResetAuthenticators ends each selected live authenticator and its account's
// unused recovery codes. An enrolment already ended — disabled, replaced, or
// reset — is left as it is; an id that names nothing is skipped, as
// RevokeDevices skips one.
func (h *AuthServiceHandler) ResetAuthenticators(ctx context.Context, req *pb.ResetAuthenticatorsReq) (*pb.ResetAuthenticatorsResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if len(req.GetIds()) == 0 {
		return nil, errEmptySelection
	}
	for _, id := range req.GetIds() {
		row, err := h.Query.GetAuthenticator(ctx, &pb.GetAuthenticatorReq{Id: id})
		if err != nil {
			if notFoundOK(err) == nil {
				continue
			}
			return nil, err
		}
		if row.GetId() != id || row.GetRevokedAt() != nil {
			continue
		}
		userID := row.GetUser()
		if err := h.inTx(ctx, func(txCtx context.Context) error {
			// By user: the live enrolment is the one the row is, and a
			// concurrent re-enrolment since the read is ended too — the
			// operator meant "this person's authenticator".
			if _, err := h.Mutation.RevokeTotpSecret(txCtx, &pb.RevokeTotpSecretReq{UserId: userID, Thumbprint: requestThumbprint(ctx)}); notFoundOK(err) != nil {
				return err
			}
			_, err := h.Mutation.RevokeRecoveryCodes(txCtx, &pb.RevokeRecoveryCodesReq{UserId: userID})
			return notFoundOK(err)
		}); err != nil {
			return nil, err
		}
	}
	return &pb.ResetAuthenticatorsResp{}, nil
}
