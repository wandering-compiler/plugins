package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// InviteToOrgAdmin is the backoffice's invitation: into the organization the
// request names by its slug (`org`), which its operator is usually no member
// of. Realm-wide and gated by the endpoint ACL, as the backoffice's
// product-role and plan methods are — a method of its own, not a mode of
// InviteToOrg, because InviteToOrg is every member's and a project's default
// role commonly grants it to every account: a realm path through it would let
// anyone invite themselves into any organization. The role ceiling applies
// against what the caller holds where it acts.
func (h *AuthServiceHandler) InviteToOrgAdmin(ctx context.Context, req *pb.InviteToOrgReq) (*pb.InviteToOrgResp, error) {
	if resp, done, err := underOrgLock(ctx, h, h.backofficeInviteLockOrg(ctx, req.GetOrg()), req, h.InviteToOrgAdmin); done {
		return resp, err
	}
	inviter, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseBackofficeInvitesInsideOrg(ctx, "InviteToOrgAdmin"); err != nil {
		return nil, err
	}
	orgID, err := h.backofficeOrgBySlug(ctx, "InviteToOrgAdmin", req.GetOrg())
	if err != nil {
		return nil, err
	}
	return h.inviteInto(ctx, orgID, inviter, req)
}

// RevokeOrgInvites is the backoffice withdrawing the invitations it picked
// from the realm-wide OrgInvites list, in whatever organizations they are —
// realm-wide and gated by the endpoint ACL, as InviteToOrgAdmin. Every one is held to the role ceiling first, as RevokeOrgInvite
// holds a member — one above the caller refuses the whole call before any is
// closed. An id no longer pending (accepted, closed, unknown) is skipped.
func (h *AuthServiceHandler) RevokeOrgInvites(ctx context.Context, req *pb.RevokeOrgInvitesReq) (*pb.RevokeOrgInvitesResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseBackofficeInvitesInsideOrg(ctx, "RevokeOrgInvites"); err != nil {
		return nil, err
	}
	var pending []*pb.PendingOrgInviteRef
	for _, id := range req.GetIds() {
		ref, err := h.Query.GetPendingOrgInvite(ctx, &pb.GetPendingOrgInviteReq{Id: id})
		if status.Code(err) == codes.NotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		if ok, err := h.inviteRoleCeiling(ref.GetOrgId())(ctx, ref.GetRole()); err != nil {
			return nil, err
		} else if !ok {
			return nil, refusal(ctx, codes.PermissionDenied, "revoke org invites: invitation "+id+" offers a role above the caller's",
				CodeInviteAboveCaller, "ids", MsgInviteAboveCaller, nil)
		}
		pending = append(pending, ref)
	}
	revoked := int32(0)
	for _, ref := range pending {
		// Closed in its own organization (org_id in the statement's WHERE),
		// not deleted: the row stays, with who withdrew it.
		_, err := h.Mutation.CloseOrgInvite(ctx, &pb.CloseOrgInviteReq{
			InviteId: ref.GetId(),
			OrgId:    ref.GetOrgId(),
			ClosedBy: callerID,
		})
		if status.Code(err) == codes.NotFound {
			continue // accepted or closed since it was read
		}
		if err != nil {
			return nil, err
		}
		revoked++
	}
	return &pb.RevokeOrgInvitesResp{Revoked: revoked}, nil
}

// refuseBackofficeInvitesInsideOrg is the backoffice invitation methods'
// gate, the one their product-role and plan siblings have: from inside an
// organization only for a caller holding the method realm-wide, and only for
// a method the lock gates (an endpoint the ACL guards) — unbound, nothing
// says who may call it, so nobody does.
func (h *AuthServiceHandler) refuseBackofficeInvitesInsideOrg(ctx context.Context, method string) error {
	if orgID := scopeOrg(ctx); orgID != "" && !h.heldRealmWide(ctx, method) {
		return status.Error(codes.PermissionDenied,
			"backoffice_invites: "+method+" is the backoffice's and acts realm-wide, not from inside an organization — invite into your own with InviteToOrg")
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "backoffice_invites: the backoffice's invitation methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// backofficeOrgBySlug is the live organization named by slug.
func (h *AuthServiceHandler) backofficeOrgBySlug(ctx context.Context, method, slug string) (string, error) {
	if slug == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s: name the organization (org, its slug)", method)
	}
	o, err := h.Query.GetOrganizationBySlug(ctx, &pb.GetOrganizationBySlugReq{Slug: slug})
	if status.Code(err) == codes.NotFound {
		return "", status.Errorf(codes.NotFound, "%s: no organization %q", method, slug)
	}
	if err != nil {
		return "", err
	}
	return o.GetId(), nil
}

// backofficeInviteLockOrg is the organization InviteToOrgAdmin locks: the one
// it already holds, else the one the request names; "" when it cannot be read
// — the method's own run then refuses.
func (h *AuthServiceHandler) backofficeInviteLockOrg(ctx context.Context, slug string) string {
	if held, _ := ctx.Value(orgLockKey{}).(string); held != "" {
		return held
	}
	id, err := h.backofficeOrgBySlug(ctx, "InviteToOrgAdmin", slug)
	if err != nil {
		return ""
	}
	return id
}
