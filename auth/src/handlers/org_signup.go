package handlers

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_signup` feature: registration on an
// organization's own host. Per organization and kind of membership the
// backoffice sets whether people may register there without an invitation,
// and with which role (OrgSignUpPolicy).
//
// A registration without an invitation that arrives through an audience
// gateway taking the organization from the host (its context reaches every call as
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
//
// A registration page on the identity's own host — one host serving several
// organizations' sign-ups, bound to none of them — names the host the person
// comes from in the request (`signup_host`). With no gateway host it decides
// as the host would: the organization bound to it and that organization's
// policies, with the kinds filter of the audience when one names kinds and
// none otherwise. Nothing is verified beyond the binding, and nothing needs to
// be: an open policy admits anyone who reaches that host, so naming it gains
// nothing more, and a closed or absent one admits nothing either way. The
// page shows the organization the same way (GetHostOrg for the host, then
// the organization's approved envelope). A gateway host bound to an
// organization is the request's own and wins; a body host naming another one is
// refused (SIGNUP_HOST_CONFLICT). A gateway host bound to none (the identity's
// own, behind an audience reading the host) leaves the body host to decide.

func init() {
	signupOrgDecide = decideSignUpJoin
	signupOrgJoin = writeSignUpJoin
	signupHostOf = requestSignupHost
	hostOrgAnswer = answerOpenKinds
}

// requestSignupHost is signupHostOf: the host a SignUp or an OAuth exchange
// names. Asked of the field, not of the type: OAuthExchangeReq exists only
// with oauth, and this file stages without it.
func requestSignupHost(req proto.Message) string {
	if r, ok := req.(interface{ GetSignupHost() string }); ok {
		return r.GetSignupHost()
	}
	return ""
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
func decideSignUpJoin(ctx context.Context, h *AuthServiceHandler, bodyHost string) (*orgJoin, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	host := ""
	if slices.Contains(splitGatewayList(gatewayValue(md, orgFromHeader)), orgFromHost) {
		host = gatewayValue(md, hostHeader)
	}
	if bodyHost != "" {
		// Normalised as the gateway reports a host, and refused on the field
		// the caller sent.
		named, err := normalHostOf(ctx, bodyHost, "signup_host")
		if err != nil {
			return nil, err
		}
		switch {
		case host == "":
			host = named
		case named != host:
			// A gateway host decides only when it is bound to an organization:
			// the identity's own host behind an audience that reads the host
			// is bound to none, and its page is the one that names the host.
			bound, err := hostIsBound(ctx, h, host)
			if err != nil {
				return nil, err
			}
			if bound {
				return nil, refusal(ctx, codes.InvalidArgument,
					"org_signup: signup_host names "+named+", but the registration arrived on "+host+", which is bound to an organization",
					CodeSignUpHostConflict, "signup_host", MsgSignUpHostConflict, nil)
			}
			host = named
		}
	}
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

// hostIsBound reports whether host is bound to a live organization.
func hostIsBound(ctx context.Context, h *AuthServiceHandler, host string) (bool, error) {
	_, err := h.Query.GetOrgOfHost(ctx, &pb.GetOrgOfHostReq{Host: host})
	if status.Code(err) == codes.NotFound {
		return false, nil
	}
	return err == nil, err
}

// writeSignUpJoin makes the new account a member of the organization, of the
// policy's kind, holding its role — as accepting an invitation does, in the
// registration's own transaction. The role is resolved now, against the
// organization's catalogue: one retired since the policy was set refuses the
// registration rather than writing a membership without its grant — and never
// falls back to another role, which nobody chose for this policy and nobody's
// ceiling was checked against.
//
// The role is granted as it reads NOW, so it is held to the snapshot the live
// policy stored when its operator was checked against the role ceiling, as an
// invitation's acceptance is (checkRoleWithinSnapshot): a role widened since,
// or another role now answering to the name, refuses the registration
// (SIGNUP_POLICY_STALE) and nothing is written. So does a registration whose
// kind is no longer open (a confirmation parked while the policy was closed
// or replaced with another role): the policy that would grant the role is
// the live one, and it must be the one checked.
//
// An open policy with no snapshot — seeded by fixtures, or set before the
// snapshot was stored — was never held to an operator's ceiling (fixtures
// are the project's own, and a policy from before kept the meaning it had).
// Its first registration pins the role as it reads then
// (PinOrgSignUpPolicySnapshotRow, under the same lock), so a role widened
// after that refuses the registrations that follow, as for any other policy.
func writeSignUpJoin(txCtx context.Context, h *AuthServiceHandler, userID string, j *orgJoin) error {
	// Under the organization's lock, as every grant there is: the role is
	// resolved and granted with no edit or retirement of it in between.
	if err := h.lockOrgRow(txCtx, j.orgID); err != nil {
		return err
	}
	roleID, err := h.roleIDByName(txCtx, j.orgID, j.role)
	if err != nil {
		return err
	}
	if err := checkSignUpPolicyRole(txCtx, h, j, roleID); err != nil {
		return err
	}
	// No one joins an organization the operators suspended.
	if err := checkOrgEntry(txCtx, h, j.orgID); err != nil {
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

// checkSignUpPolicyRole holds the role a registration is about to be granted
// to the snapshot of the live open policy of its kind (see writeSignUpJoin).
func checkSignUpPolicyRole(txCtx context.Context, h *AuthServiceHandler, j *orgJoin, roleID string) error {
	policies, err := h.Query.ListOrgSignUpPolicyRows(txCtx, &pb.ListOrgSignUpPolicyRowsReq{OrgId: j.orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	snapshot, live := "", false
	for _, p := range policies.GetPolicies() {
		if p.GetKind() == j.kind && p.GetOpen() {
			snapshot, live = p.GetRoleSnapshot(), true
		}
	}
	if live && snapshot == "" {
		if snapshot, err = h.roleSnapshotNow(txCtx, roleID); err != nil {
			return err
		}
		if _, err := h.Mutation.PinOrgSignUpPolicySnapshotRow(txCtx, &pb.PinOrgSignUpPolicySnapshotRowReq{
			OrgId: j.orgID, Kind: j.kind, RoleSnapshot: snapshot,
		}); err != nil && status.Code(err) != codes.NotFound {
			return err
		}
	}
	within, err := h.roleWithinSnapshot(txCtx, roleID, snapshot)
	if err != nil {
		return err
	}
	if !within {
		return refusal(txCtx, codes.FailedPrecondition,
			"org_signup: the open policy's role is not the one it was pinned to (widened, or another role under the name), or the kind is no longer open — set the policy again",
			CodeSignUpPolicyStale, "", MsgSignUpPolicyStale, nil)
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
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" && !h.heldRealmWide(ctx, method) {
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
// machine account's) and one the caller may grant (the role ceiling,
// role_ceiling.go — what they hold covers everything it carries), and the
// role as it was then is stored with the policy for the registration to be
// held to; a closed policy needs none. Replacing a policy ends the previous
// row.
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
	snapshot := ""
	if req.GetOpen() {
		if role == "" {
			return nil, refusal(ctx, codes.InvalidArgument, "org_signup: an open policy needs the role a registration gets",
				CodeSignUpPolicyInvalid, "role", MsgSignUpPolicyRole, nil)
		}
		roleID, err := h.roleIDByName(ctx, req.GetOrgId(), role)
		if err != nil {
			return nil, err
		}
		// The registration grants this role later with no ceiling of its own
		// (the registrant holds nothing), so the policy is where the grant is
		// authorised: held to the setter's ceiling, as an invitation is.
		// The snapshot — the role as the setter was allowed to hand it out —
		// is stored, and the registration holds the role to it.
		if snapshot, err = h.checkMayGrantRole(ctx, roleID); err != nil {
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
			RoleSnapshot: snapshot,
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
func (h *AuthServiceHandler) ListOrgSignUpPolicies(ctx context.Context, req *pb.ListOrgSignUpPoliciesReq) (_ *pb.ListOrgSignUpPoliciesResp, err error) {
	defer markReplaySafe(&err)
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
