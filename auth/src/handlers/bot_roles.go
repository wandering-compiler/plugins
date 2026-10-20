package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `bot_roles` feature: a machine account holds any
// combination of the API-realm roles, set after creation with SetBotRoles,
// and the bot directory says which. Staged only when the activation enables
// `bot_roles` (plugin.yaml go_files), which requires organizations: a bot's
// grants are made inside the operator's one.
//
// A pipeline that pushes and deploys holds both roles that do that, rather
// than a combined role somebody has to declare for every pairing. CreateBot
// still grants one role in the same call; the rest follow here.

func init() {
	botSummaryFill = fillBotRoles
}

// fillBotRoles lists the roles a bot holds in the caller's organization on its
// directory entry.
func fillBotRoles(ctx context.Context, h *AuthServiceHandler, bot *pb.BotSummary) error {
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil
	}
	held, err := h.Query.ListUserOrgGrants(ctx, &pb.ListUserOrgGrantsReq{UserId: bot.GetId(), OrgId: orgID})
	if err != nil {
		return err
	}
	bot.RoleIds = append(bot.RoleIds, held.GetRoleIds()...)
	return nil
}

// SetBotRoles replaces the roles a machine account holds.
//
// The operator rules of IssueBotToken apply first (operableBot): the bot is in
// the caller's organization, visible to them, and holds nothing above their
// ceiling — the roles it gives up are roles the caller must have been able to
// grant. Then every new role is an API-realm one the caller could grant, as at
// CreateBot. The change is one transaction: a bot is never left holding half
// of the old set and half of the new.
func (h *AuthServiceHandler) SetBotRoles(ctx context.Context, req *pb.SetBotRolesReq) (*pb.SetBotRolesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	wanted := map[string]bool{}
	var ordered []string
	for _, id := range req.GetRoleIds() {
		if id != "" && !wanted[id] {
			wanted[id] = true
			ordered = append(ordered, id)
		}
	}
	if len(ordered) == 0 {
		return nil, status.Error(codes.InvalidArgument, "role_ids is empty — a bot with no role holds a token that does nothing")
	}
	if _, err := h.operableBot(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	allowed, err := h.Query.ListApiRealmRoles(ctx, &pb.ListApiRealmRolesReq{})
	if err != nil {
		return nil, err
	}
	for _, id := range ordered {
		if !containsRole(allowed.GetRoles(), id) {
			return nil, status.Error(codes.InvalidArgument, errRoleNotForBots.Error())
		}
		if _, err := h.checkMayGrantRole(ctx, id); err != nil {
			return nil, err
		}
	}

	// The bot's grants are in the caller's organization — operableBot proved
	// the bot is a member of it.
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	// The grants IN this organization — the ones this call replaces. A
	// realm-wide grant is not the organization's to change.
	held, err := h.Query.ListUserOrgGrants(ctx, &pb.ListUserOrgGrantsReq{UserId: req.GetUserId(), OrgId: orgID})
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, id := range held.GetRoleIds() {
		has[id] = true
	}
	err = h.inOrgTx(ctx, func(txCtx context.Context) error {
		for _, id := range held.GetRoleIds() {
			if wanted[id] {
				continue
			}
			if _, err := h.Mutation.RevokeRoleFromUser(txCtx, &pb.RevokeRoleFromUserReq{
				UserId: req.GetUserId(), RoleId: id, OrgId: orgID,
			}); err != nil {
				return err
			}
		}
		for _, id := range ordered {
			if has[id] {
				continue
			}
			if _, err := h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{
				UserId: req.GetUserId(), RoleId: id, OrgId: orgID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.SetBotRolesResp{RoleIds: ordered}, nil
}
