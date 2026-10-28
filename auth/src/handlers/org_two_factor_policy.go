package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_two_factor_policy` feature: an organization's
// own second-factor policy, per kind of membership, over the activation's
// two_factor_policy (OrgTwoFactorPolicy).
//
// A policy is required (every account is challenged), optional (an account
// that confirmed an authenticator is) or disabled (nobody is, and nobody can
// enrol). Kind '' is the organization's own and covers every kind without a
// row of its own, and every member when memberships have no kinds.
//
// Which organization a request is for:
//
//   - a password sign-in: the one it arrives for, decided as Authenticate
//     decides the active organization (chooseOrg) — the host bound to it
//     through an audience that takes the tenant from the host, the W17-Org
//     selector, or the person's only organization. The person's membership
//     there gives the kind. Not a member of it, or no organization at all:
//     the activation's default;
//   - an enrolment (EnrollTotp, ConfirmTotp): the organization the caller acts
//     in; none selected, the activation's default.
//
// Who sets it: the backoffice realm-wide (…OrgTwoFactorPolicy, the
// organization named by id; refused from inside an organization), and the
// organization from inside itself (…MyOrgTwoFactorPolicy). Both need the
// project's endpoint ACL to gate the method: who may switch an organization's
// second factor off is the project's decision, and a method nobody gates
// would leave it to every member.

func init() {
	twoFactorPolicyOf = orgTwoFactorPolicyOf
}

// orgTwoFactorPolicyOf is twoFactorPolicyOf with organizations — see the file
// comment.
func orgTwoFactorPolicyOf(ctx context.Context, h *AuthServiceHandler, userID string, enrol bool) (string, error) {
	orgs, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if notFoundOK(err) != nil {
		return "", err
	}
	var org *pb.UserOrg
	if enrol {
		org = userOrgByID(orgs.GetOrgs(), scopeOrg(ctx))
	} else if org, err = signInOrg(ctx, h, orgs.GetOrgs()); err != nil {
		return "", err
	}
	if org == nil {
		return h.defaultTwoFactorPolicy(), nil
	}
	return h.policyOfOrg(ctx, org.GetOrgId(), membershipKindOf(org))
}

// signInOrg is the person's membership in the organization a sign-in arrives
// for, nil when it arrives for none or for one they do not belong to.
func signInOrg(ctx context.Context, h *AuthServiceHandler, orgs []*pb.UserOrg) (*pb.UserOrg, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	headers := map[string]string{}
	for _, k := range []string{tenantFromHeader, hostHeader} {
		// Gateway-owned keys: only a gateway writes `x-w17-*`.
		if v := md.Get(k); len(v) > 0 && v[0] != "" {
			headers[k] = v[0]
		}
	}
	pick, err := chooseOrg(ctx, h, headers, func() *pb.UserOrg {
		if len(orgs) == 1 {
			return orgs[0]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if pick.sole != nil {
		return pick.sole, nil
	}
	for _, o := range orgs {
		if pick.slug != "" && o.GetSlug() == pick.slug {
			return o, nil
		}
	}
	return nil, nil
}

func userOrgByID(orgs []*pb.UserOrg, orgID string) *pb.UserOrg {
	if orgID == "" {
		return nil
	}
	for _, o := range orgs {
		if o.GetOrgId() == orgID {
			return o
		}
	}
	return nil
}

// policyOfOrg is the organization's policy for a kind: the kind's own row,
// then the organization's own (kind ""), then the activation's default.
func (h *AuthServiceHandler) policyOfOrg(ctx context.Context, orgID, kind string) (string, error) {
	rows, err := h.Query.ListOrgTwoFactorPolicyRows(ctx, &pb.ListOrgTwoFactorPolicyRowsReq{OrgId: orgID})
	if notFoundOK(err) != nil {
		return "", err
	}
	own := ""
	for _, r := range rows.GetPolicies() {
		switch r.GetKind() {
		case kind:
			if kind != "" {
				return r.GetPolicy(), nil
			}
			own = r.GetPolicy()
		case "":
			own = r.GetPolicy()
		}
	}
	if own != "" {
		return own, nil
	}
	return h.defaultTwoFactorPolicy(), nil
}

// refuseTwoFactorPoliciesInsideOrg holds the backoffice's policy methods to
// the realm, and every policy method to the endpoint ACL.
func (h *AuthServiceHandler) refuseTwoFactorPoliciesInsideOrg(ctx context.Context, method string) error {
	if orgID := scopeOrg(ctx); orgID != "" && !h.heldRealmWide(ctx, method) {
		return refusal(ctx, codes.PermissionDenied, "org_two_factor_policy: the backoffice's policy methods act realm-wide, not from inside an organization",
			CodeTwoFactorPoliciesRealmOnly, "", MsgTwoFactorPoliciesRealmOnly, nil)
	}
	return h.requireTwoFactorPolicyGate(ctx, method)
}

// requireTwoFactorPolicyGate refuses a policy method the endpoint ACL does not
// gate: without it, any account that can sign in could switch the second
// factor off.
func (h *AuthServiceHandler) requireTwoFactorPolicyGate(ctx context.Context, method string) error {
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "org_two_factor_policy: the policy methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// checkTwoFactorPolicyRequest holds a policy's value and kind.
func checkTwoFactorPolicyRequest(ctx context.Context, kind, policy string) error {
	if !validTwoFactorPolicy(policy) {
		return refusal(ctx, codes.InvalidArgument, "org_two_factor_policy: policy is none of required, optional, disabled",
			CodeTwoFactorPolicyInvalid, "policy", MsgTwoFactorPolicyValue, nil)
	}
	return checkTwoFactorPolicyKind(ctx, kind)
}

// checkTwoFactorPolicyKind refuses a kind where memberships have none. With
// kinds, "" is still meaningful: the organization's own policy.
func checkTwoFactorPolicyKind(ctx context.Context, kind string) error {
	if kindOfJoin == nil && kind != "" {
		return refusal(ctx, codes.InvalidArgument, "org_two_factor_policy: memberships have no kinds here (membership_kinds is off)",
			CodeTwoFactorPolicyInvalid, "kind", MsgSignUpPolicyNoKind, nil)
	}
	return nil
}

// setTwoFactorPolicy replaces the live policy of (organization, kind).
func (h *AuthServiceHandler) setTwoFactorPolicy(ctx context.Context, caller, orgID, kind, policy string) error {
	return h.inTx(ctx, func(txCtx context.Context) error {
		if _, err := h.Mutation.EndOrgTwoFactorPolicyRow(txCtx, &pb.EndOrgTwoFactorPolicyRowReq{
			OrgId: orgID, Kind: kind, EndedBy: caller,
		}); notFoundOK(err) != nil {
			return err
		}
		_, err := h.Mutation.SetOrgTwoFactorPolicyRow(txCtx, &pb.SetOrgTwoFactorPolicyRowReq{
			OrgId: orgID, Kind: kind, Policy: policy, SetBy: caller,
		})
		return err
	})
}

// clearTwoFactorPolicy ends the live policy of (organization, kind); clearing
// one that is not set changes nothing.
func (h *AuthServiceHandler) clearTwoFactorPolicy(ctx context.Context, caller, orgID, kind string) error {
	_, err := h.Mutation.EndOrgTwoFactorPolicyRow(ctx, &pb.EndOrgTwoFactorPolicyRowReq{OrgId: orgID, Kind: kind, EndedBy: caller})
	return notFoundOK(err)
}

// listTwoFactorPolicies answers an organization's live policies and the
// activation's default beside them.
func (h *AuthServiceHandler) listTwoFactorPolicies(ctx context.Context, orgID string) (*pb.ListOrgTwoFactorPoliciesResp, error) {
	rows, err := h.Query.ListOrgTwoFactorPolicyRows(ctx, &pb.ListOrgTwoFactorPolicyRowsReq{OrgId: orgID})
	if notFoundOK(err) != nil {
		return nil, err
	}
	out := &pb.ListOrgTwoFactorPoliciesResp{DefaultPolicy: h.defaultTwoFactorPolicy()}
	for _, r := range rows.GetPolicies() {
		out.Policies = append(out.Policies, &pb.OrgTwoFactorPolicyInfo{Kind: r.GetKind(), Policy: r.GetPolicy(), SetAt: r.GetSetAt()})
	}
	return out, nil
}

// SetOrgTwoFactorPolicy — the backoffice's, realm-wide.
func (h *AuthServiceHandler) SetOrgTwoFactorPolicy(ctx context.Context, req *pb.SetOrgTwoFactorPolicyReq) (*pb.SetOrgTwoFactorPolicyResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseTwoFactorPoliciesInsideOrg(ctx, "SetOrgTwoFactorPolicy"); err != nil {
		return nil, err
	}
	if err := checkTwoFactorPolicyRequest(ctx, req.GetKind(), req.GetPolicy()); err != nil {
		return nil, err
	}
	if err := h.setTwoFactorPolicy(ctx, caller, req.GetOrgId(), req.GetKind(), req.GetPolicy()); err != nil {
		return nil, err
	}
	return &pb.SetOrgTwoFactorPolicyResp{}, nil
}

// ClearOrgTwoFactorPolicy — the backoffice's, realm-wide.
func (h *AuthServiceHandler) ClearOrgTwoFactorPolicy(ctx context.Context, req *pb.ClearOrgTwoFactorPolicyReq) (*pb.ClearOrgTwoFactorPolicyResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseTwoFactorPoliciesInsideOrg(ctx, "ClearOrgTwoFactorPolicy"); err != nil {
		return nil, err
	}
	if err := checkTwoFactorPolicyKind(ctx, req.GetKind()); err != nil {
		return nil, err
	}
	if err := h.clearTwoFactorPolicy(ctx, caller, req.GetOrgId(), req.GetKind()); err != nil {
		return nil, err
	}
	return &pb.ClearOrgTwoFactorPolicyResp{}, nil
}

// ListOrgTwoFactorPolicies — the backoffice's, realm-wide.
func (h *AuthServiceHandler) ListOrgTwoFactorPolicies(ctx context.Context, req *pb.ListOrgTwoFactorPoliciesReq) (*pb.ListOrgTwoFactorPoliciesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseTwoFactorPoliciesInsideOrg(ctx, "ListOrgTwoFactorPolicies"); err != nil {
		return nil, err
	}
	return h.listTwoFactorPolicies(ctx, req.GetOrgId())
}

// myOrgForTwoFactorPolicy is the organization a …MyOrg… call acts in.
func (h *AuthServiceHandler) myOrgForTwoFactorPolicy(ctx context.Context, org, method string) (caller, orgID string, err error) {
	if caller, err = callerUserID(ctx); err != nil {
		return "", "", Unauthenticated(err)
	}
	if err = refuseOtherOrg(ctx, org); err != nil {
		return "", "", err
	}
	if orgID, err = activeOrgID(ctx); err != nil {
		return "", "", err
	}
	if err = h.requireTwoFactorPolicyGate(ctx, method); err != nil {
		return "", "", err
	}
	return caller, orgID, nil
}

// SetMyOrgTwoFactorPolicy — the organization's own, from inside it.
func (h *AuthServiceHandler) SetMyOrgTwoFactorPolicy(ctx context.Context, req *pb.SetMyOrgTwoFactorPolicyReq) (*pb.SetOrgTwoFactorPolicyResp, error) {
	caller, orgID, err := h.myOrgForTwoFactorPolicy(ctx, req.GetOrg(), "SetMyOrgTwoFactorPolicy")
	if err != nil {
		return nil, err
	}
	if err := checkTwoFactorPolicyRequest(ctx, req.GetKind(), req.GetPolicy()); err != nil {
		return nil, err
	}
	if err := h.setTwoFactorPolicy(ctx, caller, orgID, req.GetKind(), req.GetPolicy()); err != nil {
		return nil, err
	}
	return &pb.SetOrgTwoFactorPolicyResp{}, nil
}

// ClearMyOrgTwoFactorPolicy — the organization's own, from inside it.
func (h *AuthServiceHandler) ClearMyOrgTwoFactorPolicy(ctx context.Context, req *pb.ClearMyOrgTwoFactorPolicyReq) (*pb.ClearOrgTwoFactorPolicyResp, error) {
	caller, orgID, err := h.myOrgForTwoFactorPolicy(ctx, req.GetOrg(), "ClearMyOrgTwoFactorPolicy")
	if err != nil {
		return nil, err
	}
	if err := checkTwoFactorPolicyKind(ctx, req.GetKind()); err != nil {
		return nil, err
	}
	if err := h.clearTwoFactorPolicy(ctx, caller, orgID, req.GetKind()); err != nil {
		return nil, err
	}
	return &pb.ClearOrgTwoFactorPolicyResp{}, nil
}

// ListMyOrgTwoFactorPolicies — the organization's own, from inside it.
func (h *AuthServiceHandler) ListMyOrgTwoFactorPolicies(ctx context.Context, req *pb.ListMyOrgTwoFactorPoliciesReq) (*pb.ListOrgTwoFactorPoliciesResp, error) {
	_, orgID, err := h.myOrgForTwoFactorPolicy(ctx, req.GetOrg(), "ListMyOrgTwoFactorPolicies")
	if err != nil {
		return nil, err
	}
	return h.listTwoFactorPolicies(ctx, orgID)
}
