package handlers

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_signup` feature: registration on an
// organization's own host. Per organization and kind of membership the
// backoffice sets whether people may register there without an invitation,
// and with which role (OrgSignUpPolicy).
//
// A registration without an invitation that arrives through an audience
// gateway taking the tenant from the host (its context reaches every call as
// metadata: restgw.AudienceContextMiddleware), on a host bound to an
// organization (org_hosts):
//
//   - an open policy for a kind the audience admits: the account becomes a
//     member of that kind with that role, in the account's own transaction,
//     whatever invite_only says;
//   - a closed one: refused (SIGNUP_NOT_INVITED), whatever invite_only says;
//   - none for those kinds: invite_only decides as without the feature, and
//     the account joins nothing.
//
// Two open kinds for one audience are a configuration error
// (SIGNUP_KIND_AMBIGUOUS), never a guess. An invitation still decides its own
// organization: a registration carrying one never reaches this.

func init() {
	signupOrgDecide = decideSignUpJoin
	signupOrgJoin = writeSignUpJoin
	hostOrgAnswer = answerOpenKinds
}

// gatewayValue is a gateway-owned key of the incoming metadata. Only a
// gateway writes `x-w17-*` (the edge strips a client's copy).
func gatewayValue(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

func splitGatewayList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// decideSignUpJoin — see the file comment.
func decideSignUpJoin(ctx context.Context, h *AuthServiceHandler) (*orgJoin, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || !slices.Contains(splitGatewayList(gatewayValue(md, tenantFromHeader)), tenantFromHost) {
		return nil, nil
	}
	host := gatewayValue(md, hostHeader)
	if host == "" {
		return nil, nil
	}
	org, err := h.Query.GetOrgOfHost(ctx, &pb.GetOrgOfHostReq{Host: host})
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	policies, err := h.Query.ListOrgSignUpPolicyRows(ctx, &pb.ListOrgSignUpPolicyRowsReq{OrgId: org.GetOrgId()})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	kinds := splitGatewayList(gatewayValue(md, membershipKindsHeader))
	var open []*pb.OrgSignUpPolicyRow
	spoken := false
	for _, p := range policies.GetPolicies() {
		if len(kinds) > 0 && !slices.Contains(kinds, p.GetKind()) {
			continue
		}
		spoken = true
		if p.GetOpen() {
			open = append(open, p)
		}
	}
	switch {
	case len(open) == 1:
		return &orgJoin{orgID: org.GetOrgId(), kind: open[0].GetKind(), role: open[0].GetRole()}, nil
	case len(open) > 1:
		return nil, refusal(ctx, codes.FailedPrecondition,
			"org_signup: more than one kind this audience admits is open for registration in the host's organization",
			CodeSignUpKindAmbiguous, "", MsgSignUpKindAmbiguous, nil)
	case spoken:
		return nil, refusal(ctx, codes.PermissionDenied,
			"org_signup: the host's organization takes this kind by invitation only",
			CodeSignUpNotInvited, "", MsgSignUpNotInvited, nil)
	}
	return nil, nil
}

// writeSignUpJoin makes the new account a member of the organization, of the
// policy's kind, holding its role — as accepting an invitation does, in the
// registration's own transaction. The role is resolved now, against the
// organization's catalogue: one retired since the policy was set refuses the
// registration rather than writing a membership without its grant.
func writeSignUpJoin(txCtx context.Context, h *AuthServiceHandler, userID string, j *orgJoin) error {
	roleID, err := h.roleIDByName(txCtx, j.orgID, j.role)
	if err != nil {
		return err
	}
	add := &pb.AddOrgMembershipReq{UserId: userID, OrgId: j.orgID, Role: j.role}
	if kindOfJoin != nil {
		kindOfJoin(j.kind, add)
	}
	if _, err := h.Mutation.AddOrgMembership(txCtx, add); err != nil {
		return err
	}
	// org_id on the grant scopes it to the organization; empty would be
	// realm-wide, which a registration must never produce.
	if _, err = h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{UserId: userID, RoleId: roleID, OrgId: j.orgID}); err != nil {
		return err
	}
	if signupPolicyProductRoles != nil {
		return signupPolicyProductRoles.grant(txCtx, h, userID, j)
	}
	return nil
}

// signupPolicyProductRoles carries the products' roles an open registration
// is given (product_roles_signup.go); nil without product_roles.
var signupPolicyProductRoles *signupPolicyProductRoleHooks

type signupPolicyProductRoleHooks struct {
	// check holds a policy's roles to the catalogue and the organization's
	// plan, and returns what writes them onto the row.
	check func(ctx context.Context, h *AuthServiceHandler, req *pb.SetOrgSignUpPolicyReq) (func(*pb.SetOrgSignUpPolicyRowReq), error)
	info  func(row *pb.OrgSignUpPolicyRow, out *pb.OrgSignUpPolicyInfo)
	// grant gives the joining account the live policy's roles.
	grant func(txCtx context.Context, h *AuthServiceHandler, userID string, j *orgJoin) error
}

// answerOpenKinds adds the kinds open for registration to GetHostOrg, so a
// sign-up page on the host knows whether to show its form.
func answerOpenKinds(ctx context.Context, h *AuthServiceHandler, resp *pb.HostOrgResp) error {
	policies, err := h.Query.ListOrgSignUpPolicyRows(ctx, &pb.ListOrgSignUpPolicyRowsReq{OrgId: resp.GetOrgId()})
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	for _, p := range policies.GetPolicies() {
		if p.GetOpen() {
			resp.OpenKinds = append(resp.OpenKinds, p.GetKind())
		}
	}
	return nil
}

// refuseSignUpPoliciesInsideOrg holds the policy methods to the realm, as the
// backoffice's other organization methods are.
func (h *AuthServiceHandler) refuseSignUpPoliciesInsideOrg(ctx context.Context, method string) error {
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" {
		return refusal(ctx, codes.PermissionDenied, "org_signup: registration policies are set realm-wide, not from inside an organization",
			CodeSignUpPoliciesRealmOnly, "", MsgSignUpPoliciesRealmOnly, nil)
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "org_signup: the backoffice's policy methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// checkPolicyKind holds a policy's kind to whether memberships have kinds.
func checkPolicyKind(ctx context.Context, kind string) error {
	switch {
	case kindOfJoin != nil && kind == "":
		return refusal(ctx, codes.InvalidArgument, "org_signup: name the membership kind the policy is for",
			CodeSignUpPolicyInvalid, "kind", MsgSignUpPolicyKind, nil)
	case kindOfJoin == nil && kind != "":
		return refusal(ctx, codes.InvalidArgument, "org_signup: memberships have no kinds here (membership_kinds is off)",
			CodeSignUpPolicyInvalid, "kind", MsgSignUpPolicyNoKind, nil)
	}
	return nil
}

// SetOrgSignUpPolicy sets whether a kind may register into the organization
// on its host without an invitation, and with which role. The role must be
// one the organization can hand out (its org-scoped catalogue, never a
// machine account's); a closed policy needs none. Replacing a policy ends
// the previous row.
func (h *AuthServiceHandler) SetOrgSignUpPolicy(ctx context.Context, req *pb.SetOrgSignUpPolicyReq) (*pb.SetOrgSignUpPolicyResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseSignUpPoliciesInsideOrg(ctx, "SetOrgSignUpPolicy"); err != nil {
		return nil, err
	}
	if err := checkPolicyKind(ctx, req.GetKind()); err != nil {
		return nil, err
	}
	role := strings.TrimSpace(req.GetRole())
	if req.GetOpen() {
		if role == "" {
			return nil, refusal(ctx, codes.InvalidArgument, "org_signup: an open policy needs the role a registration gets",
				CodeSignUpPolicyInvalid, "role", MsgSignUpPolicyRole, nil)
		}
		if _, err := h.roleIDByName(ctx, req.GetOrgId(), role); err != nil {
			return nil, err
		}
	} else {
		role = ""
	}
	var writeProductRoles func(*pb.SetOrgSignUpPolicyRowReq)
	if signupPolicyProductRoles != nil && req.GetOpen() {
		if writeProductRoles, err = signupPolicyProductRoles.check(ctx, h, req); err != nil {
			return nil, err
		}
	}
	if err := h.inTx(ctx, func(txCtx context.Context) error {
		if _, err := h.Mutation.EndOrgSignUpPolicyRow(txCtx, &pb.EndOrgSignUpPolicyRowReq{
			OrgId: req.GetOrgId(), Kind: req.GetKind(), EndedBy: caller,
		}); notFoundOK(err) != nil {
			return err
		}
		row := &pb.SetOrgSignUpPolicyRowReq{
			OrgId: req.GetOrgId(), Kind: req.GetKind(), Open: req.GetOpen(), Role: role, SetBy: caller,
		}
		if writeProductRoles != nil {
			writeProductRoles(row)
		}
		_, err := h.Mutation.SetOrgSignUpPolicyRow(txCtx, row)
		return err
	}); err != nil {
		return nil, err
	}
	return &pb.SetOrgSignUpPolicyResp{}, nil
}

// ClearOrgSignUpPolicy ends a kind's policy: invite_only decides for it again.
// Clearing one there is not changes nothing.
func (h *AuthServiceHandler) ClearOrgSignUpPolicy(ctx context.Context, req *pb.ClearOrgSignUpPolicyReq) (*pb.ClearOrgSignUpPolicyResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseSignUpPoliciesInsideOrg(ctx, "ClearOrgSignUpPolicy"); err != nil {
		return nil, err
	}
	if _, err := h.Mutation.EndOrgSignUpPolicyRow(ctx, &pb.EndOrgSignUpPolicyRowReq{
		OrgId: req.GetOrgId(), Kind: req.GetKind(), EndedBy: caller,
	}); notFoundOK(err) != nil {
		return nil, err
	}
	return &pb.ClearOrgSignUpPolicyResp{}, nil
}

// ListOrgSignUpPolicies is an organization's live policies, by kind.
func (h *AuthServiceHandler) ListOrgSignUpPolicies(ctx context.Context, req *pb.ListOrgSignUpPoliciesReq) (*pb.ListOrgSignUpPoliciesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseSignUpPoliciesInsideOrg(ctx, "ListOrgSignUpPolicies"); err != nil {
		return nil, err
	}
	rows, err := h.Query.ListOrgSignUpPolicyRows(ctx, &pb.ListOrgSignUpPolicyRowsReq{OrgId: req.GetOrgId()})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	out := &pb.ListOrgSignUpPoliciesResp{}
	for _, p := range rows.GetPolicies() {
		info := &pb.OrgSignUpPolicyInfo{Kind: p.GetKind(), Open: p.GetOpen(), Role: p.GetRole(), SetAt: p.GetSetAt()}
		if signupPolicyProductRoles != nil {
			signupPolicyProductRoles.info(p, info)
		}
		out.Policies = append(out.Policies, info)
	}
	return out, nil
}
