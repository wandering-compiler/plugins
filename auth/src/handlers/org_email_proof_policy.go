package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_email_proof_policy` feature: an
// organization's own address-proof floor over the activation's
// email_proof_required (OrgEmailProofPolicy).
//
// A floor is none (nothing asked), derived (an address a bound invitation
// named, or one its owner proved) or full (only an address its owner proved by
// a round trip: the email_verification link, a sign_up_confirmation code, an
// OAuth provider's email_verified).
//
// It holds on every way into the organization, because an open way in and a
// proven address are two different things: accepting an invitation
// (AcceptOrgInvite, AcceptMyOrgInvite, an invitation taken at registration)
// and registering on the organization's host (org_signup). There no invitation
// derived anything, so any floor above none takes only a registration that
// proves the address itself (signupJoinFloorGate).
//
// Who sets it: the backoffice realm-wide (…OrgEmailProof, the organization
// named by id; refused from inside an organization), and the organization
// from inside itself (…MyOrgEmailProof). Both need the project's endpoint ACL
// to gate the method: who may lower an organization's floor is the project's
// decision, and a method nobody gates would leave it to every member.

func init() {
	emailProofFloorOf = orgEmailProofFloorOf
}

// orgEmailProofFloorOf is emailProofFloorOf with organizations: the
// organization's own floor, or the activation's while it has none.
func orgEmailProofFloorOf(ctx context.Context, h *AuthServiceHandler, orgID string) (string, error) {
	if orgID == "" {
		return normalizedFloor(h), nil
	}
	rows, err := h.Query.ListOrgEmailProofPolicyRows(ctx, &pb.ListOrgEmailProofPolicyRowsReq{OrgId: orgID})
	if notFoundOK(err) != nil {
		return "", err
	}
	for _, r := range rows.GetPolicies() {
		if f := r.GetFloor(); f != "" {
			return f, nil
		}
	}
	return normalizedFloor(h), nil
}

// validEmailProofFloor reports whether a floor is one of the three.
func validEmailProofFloor(floor string) bool {
	switch floor {
	case emailProofNone, emailProofDerived, emailProofFull:
		return true
	}
	return false
}

// refuseEmailProofPoliciesInsideOrg holds the backoffice's floor methods to
// the realm, and every floor method to the endpoint ACL.
func (h *AuthServiceHandler) refuseEmailProofPoliciesInsideOrg(ctx context.Context, method string) error {
	if orgID := scopeOrg(ctx); orgID != "" && !h.heldRealmWide(ctx, method) {
		return refusal(ctx, codes.PermissionDenied, "org_email_proof_policy: the backoffice's floor methods act realm-wide, not from inside an organization",
			CodeEmailProofPoliciesRealmOnly, "", MsgEmailProofPoliciesRealmOnly, nil)
	}
	return h.requireEmailProofPolicyGate(ctx, method)
}

// requireEmailProofPolicyGate refuses a floor method the endpoint ACL does not
// gate: without it, any account that can sign in could lower the floor.
func (h *AuthServiceHandler) requireEmailProofPolicyGate(ctx context.Context, method string) error {
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "org_email_proof_policy: the floor methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// checkOrgEmailProofFloor refuses a floor that is none of the three.
func checkOrgEmailProofFloor(ctx context.Context, floor string) error {
	if !validEmailProofFloor(floor) {
		return refusal(ctx, codes.InvalidArgument, "org_email_proof_policy: floor is none of none, derived, full",
			CodeEmailProofPolicyInvalid, "floor", MsgEmailProofPolicyValue, nil)
	}
	return nil
}

// setEmailProofFloor replaces an organization's live floor.
func (h *AuthServiceHandler) setEmailProofFloor(ctx context.Context, caller, orgID, floor string) error {
	return h.inTx(ctx, func(txCtx context.Context) error {
		if _, err := h.Mutation.EndOrgEmailProofPolicyRow(txCtx, &pb.EndOrgEmailProofPolicyRowReq{
			OrgId: orgID, EndedBy: caller,
		}); notFoundOK(err) != nil {
			return err
		}
		_, err := h.Mutation.SetOrgEmailProofPolicyRow(txCtx, &pb.SetOrgEmailProofPolicyRowReq{
			OrgId: orgID, Floor: floor, SetBy: caller,
		})
		return err
	})
}

// clearEmailProofFloor ends an organization's live floor; clearing one that is
// not set changes nothing.
func (h *AuthServiceHandler) clearEmailProofFloor(ctx context.Context, caller, orgID string) error {
	_, err := h.Mutation.EndOrgEmailProofPolicyRow(ctx, &pb.EndOrgEmailProofPolicyRowReq{OrgId: orgID, EndedBy: caller})
	return notFoundOK(err)
}

// getEmailProofFloor answers an organization's own floor and the activation's
// default beside it.
func (h *AuthServiceHandler) getEmailProofFloor(ctx context.Context, orgID string) (*pb.GetOrgEmailProofResp, error) {
	rows, err := h.Query.ListOrgEmailProofPolicyRows(ctx, &pb.ListOrgEmailProofPolicyRowsReq{OrgId: orgID})
	if notFoundOK(err) != nil {
		return nil, err
	}
	def := normalizedFloor(h)
	if def == "" {
		def = emailProofNone
	}
	out := &pb.GetOrgEmailProofResp{DefaultFloor: def}
	for _, r := range rows.GetPolicies() {
		out.Floor, out.SetAt = r.GetFloor(), r.GetSetAt()
	}
	return out, nil
}

// SetOrgEmailProof — the backoffice's, realm-wide.
func (h *AuthServiceHandler) SetOrgEmailProof(ctx context.Context, req *pb.SetOrgEmailProofReq) (*pb.SetOrgEmailProofResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseEmailProofPoliciesInsideOrg(ctx, "SetOrgEmailProof"); err != nil {
		return nil, err
	}
	if err := checkOrgEmailProofFloor(ctx, req.GetFloor()); err != nil {
		return nil, err
	}
	if err := h.setEmailProofFloor(ctx, caller, req.GetOrgId(), req.GetFloor()); err != nil {
		return nil, err
	}
	return &pb.SetOrgEmailProofResp{}, nil
}

// ClearOrgEmailProof — the backoffice's, realm-wide.
func (h *AuthServiceHandler) ClearOrgEmailProof(ctx context.Context, req *pb.ClearOrgEmailProofReq) (*pb.ClearOrgEmailProofResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseEmailProofPoliciesInsideOrg(ctx, "ClearOrgEmailProof"); err != nil {
		return nil, err
	}
	if err := h.clearEmailProofFloor(ctx, caller, req.GetOrgId()); err != nil {
		return nil, err
	}
	return &pb.ClearOrgEmailProofResp{}, nil
}

// GetOrgEmailProof — the backoffice's, realm-wide.
func (h *AuthServiceHandler) GetOrgEmailProof(ctx context.Context, req *pb.GetOrgEmailProofReq) (*pb.GetOrgEmailProofResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseEmailProofPoliciesInsideOrg(ctx, "GetOrgEmailProof"); err != nil {
		return nil, err
	}
	return h.getEmailProofFloor(ctx, req.GetOrgId())
}

// myOrgForEmailProof is the organization a …MyOrg… call acts in.
func (h *AuthServiceHandler) myOrgForEmailProof(ctx context.Context, org, method string) (caller, orgID string, err error) {
	if caller, err = callerUserID(ctx); err != nil {
		return "", "", Unauthenticated(err)
	}
	if err = refuseOtherOrg(ctx, org); err != nil {
		return "", "", err
	}
	if orgID, err = activeOrgID(ctx); err != nil {
		return "", "", err
	}
	if err = h.requireEmailProofPolicyGate(ctx, method); err != nil {
		return "", "", err
	}
	return caller, orgID, nil
}

// SetMyOrgEmailProof — the organization's own, from inside it.
func (h *AuthServiceHandler) SetMyOrgEmailProof(ctx context.Context, req *pb.SetMyOrgEmailProofReq) (*pb.SetOrgEmailProofResp, error) {
	caller, orgID, err := h.myOrgForEmailProof(ctx, req.GetOrg(), "SetMyOrgEmailProof")
	if err != nil {
		return nil, err
	}
	if err := checkOrgEmailProofFloor(ctx, req.GetFloor()); err != nil {
		return nil, err
	}
	if err := h.setEmailProofFloor(ctx, caller, orgID, req.GetFloor()); err != nil {
		return nil, err
	}
	return &pb.SetOrgEmailProofResp{}, nil
}

// ClearMyOrgEmailProof — the organization's own, from inside it.
func (h *AuthServiceHandler) ClearMyOrgEmailProof(ctx context.Context, req *pb.ClearMyOrgEmailProofReq) (*pb.ClearOrgEmailProofResp, error) {
	caller, orgID, err := h.myOrgForEmailProof(ctx, req.GetOrg(), "ClearMyOrgEmailProof")
	if err != nil {
		return nil, err
	}
	if err := h.clearEmailProofFloor(ctx, caller, orgID); err != nil {
		return nil, err
	}
	return &pb.ClearOrgEmailProofResp{}, nil
}

// GetMyOrgEmailProof — the organization's own, from inside it.
func (h *AuthServiceHandler) GetMyOrgEmailProof(ctx context.Context, req *pb.GetMyOrgEmailProofReq) (*pb.GetOrgEmailProofResp, error) {
	_, orgID, err := h.myOrgForEmailProof(ctx, req.GetOrg(), "GetMyOrgEmailProof")
	if err != nil {
		return nil, err
	}
	return h.getEmailProofFloor(ctx, orgID)
}
