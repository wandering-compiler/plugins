package handlers

import (
	"context"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file is part of the `user_admin` feature: the admin's Disable / Enable
// actions, and the rule they and the erasure share — an operator cannot end
// their own account, nor the realm's last account able to administer it.

// The sentences a person reads for these refusals. Mirrored into plugin.yaml
// by `make plugin-msgids-sync` (see errors.go).
//
//w17:msgid
const (
	MsgOwnAccount = "You cannot disable or erase your own account. Ask another administrator."
	MsgLastAdmin  = "This would leave no active account able to administer the realm. Give someone else an administrator role first."
)

// The codes a client branches on for the same refusals.
const (
	CodeOwnAccount = "OWN_ACCOUNT"
	CodeLastAdmin  = "LAST_ADMIN"
)

// realmAdmins, set when `rbac` is on as well (admin_lockout_rbac.go), is every
// account that can administer the realm: active, holding a live wildcard role
// of the session realm. It reads them under a lock on their rows, so a check
// made inside a transaction holds until it commits. ok is false without rbac:
// there are no roles, and so no account the rule could protect.
var realmAdmins = func(ctx context.Context, h *AuthServiceHandler) (ids []string, ok bool, err error) {
	return nil, false, nil
}

// refuseOwnAccount refuses an operator acting on their own account: disabling
// it would sign them out mid-action and erasing it cannot be undone, and the
// person who should decide that is another administrator.
func refuseOwnAccount(ctx context.Context, operator string, ids []string) error {
	for _, id := range ids {
		if id == operator {
			return refusal(ctx, codes.FailedPrecondition,
				"the operator's own account "+id+" is in the selection",
				CodeOwnAccount, "", MsgOwnAccount, nil)
		}
	}
	return nil
}

// refuseLeavingNoAdmin refuses ending the accounts in ids (a disable or an
// erasure) when no other account able to administer the realm would remain
// (LAST_ADMIN, FailedPrecondition). A realm with none already — no wildcard
// role granted to anyone, or no rbac — refuses nothing: there is nothing left
// to protect, and a project whose administrators are not wildcard-role holders
// is not one this rule can speak for.
func refuseLeavingNoAdmin(ctx context.Context, h *AuthServiceHandler, ids []string) error {
	admins, ok, err := realmAdmins(ctx, h)
	if err != nil {
		return err
	}
	if !ok || len(admins) == 0 {
		return nil
	}
	ending := make(map[string]bool, len(ids))
	for _, id := range ids {
		ending[id] = true
	}
	for _, a := range admins {
		if !ending[a] {
			return nil
		}
	}
	return refusal(ctx, codes.FailedPrecondition,
		"the selection holds every account able to administer the realm",
		CodeLastAdmin, "", MsgLastAdmin, nil)
}

// DisableAccounts disables each selected account and emits UserDisabled for
// each one it disabled — the admin Users and ServiceAccounts pages' Disable
// action. The operator's own account and the realm's last administrators are
// refused before anything is written; the check and the writes are one
// transaction that first locks the administrators' rows, so two operators
// disabling each other at once cannot both pass. An account already disabled
// is done, not an error.
func (h *AuthServiceHandler) DisableAccounts(ctx context.Context, req *pb.DisableAccountsReq) (*pb.DisableAccountsResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	ids := req.GetIds()
	if len(ids) == 0 {
		return nil, errEmptySelection
	}
	if err := refuseOwnAccount(ctx, operator, ids); err != nil {
		return nil, err
	}
	thumbprint := requestThumbprint(ctx)
	if err := h.inTx(ctx, func(txCtx context.Context) error {
		if err := refuseLeavingNoAdmin(txCtx, h, ids); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := h.Mutation.DisableUser(txCtx, &pb.DisableUserReq{UserId: id, By: operator, Thumbprint: thumbprint}); notFoundOK(err) != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &pb.DisableAccountsResp{}, nil
}

// EnableAccounts re-enables each selected account and emits UserEnabled for
// each one it enabled — the pages' Enable action. An erased account stays
// disabled and one already enabled is done; neither is an error.
func (h *AuthServiceHandler) EnableAccounts(ctx context.Context, req *pb.EnableAccountsReq) (*pb.EnableAccountsResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	ids := req.GetIds()
	if len(ids) == 0 {
		return nil, errEmptySelection
	}
	thumbprint := requestThumbprint(ctx)
	for _, id := range ids {
		if _, err := h.Mutation.EnableUser(ctx, &pb.EnableUserReq{UserId: id, By: operator, Thumbprint: thumbprint}); notFoundOK(err) != nil {
			return nil, err
		}
	}
	return &pb.EnableAccountsResp{}, nil
}
