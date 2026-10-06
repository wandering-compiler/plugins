package handlers

import (
	"context"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements turnkey declarative role assignment — the `rbac`
// feature slice of SignUp. It is staged into a bundle ONLY when the
// activation enables `rbac` (plugin.yaml go_files), so its references to
// the RBAC-gated Role queries + AssignRoleToUser mutation never dangle
// when rbac is off — then the base no-op signupAssignRoles (auth_service.go)
// stays in effect and no role tables are touched. Standalone (the plugin
// author's own go test) always compiles it.

// init swaps in the real role resolve + assign paths on package load.
func init() {
	signupResolveRoleIDs = resolveSignupRoleIDs
	signupAssignRoleIDs = assignSignupRoleIDs
}

// resolveSignupRoleIDs picks the declarative role set for a new signup: the
// first_user (bootstrap-admin) roles when there is no user yet — this signup
// will be the first — else the default roles. Membership is seeded from
// `(w17.acl_roles)` into the assign_first_user / assign_default Role columns;
// this reads them realm-agnostically (a UserRole link carries no realm — the
// realm only gates which roles count at auth time). A wildcard (all_permissions)
// first_user role thus makes the very first account a superadmin with zero
// manual steps.
//
// Called by SignUp BEFORE it opens the write transaction: query servers do not
// join the distx tx (they read the pool), so the count must reflect COMMITTED
// state — `CountUsers == 0` correctly means "the user in flight is the first"
// (it isn't committed yet). Running this inside the tx would read 0 and
// misclassify every signup after the first.
func resolveSignupRoleIDs(ctx context.Context, h *AuthServiceHandler) ([]string, error) {
	cnt, err := h.Query.CountUsers(ctx, &pb.CountUsersReq{})
	if err != nil {
		return nil, err
	}
	if cnt.GetCount() == 0 {
		resp, err := h.Query.GetFirstUserRoles(ctx, &pb.GetFirstUserRolesReq{})
		if err != nil {
			return nil, err
		}
		return resp.GetRoleIds(), nil
	}
	resp, err := h.Query.GetDefaultRoles(ctx, &pb.GetDefaultRolesReq{})
	if err != nil {
		return nil, err
	}
	return resp.GetRoleIds(), nil
}

// assignSignupRoleIDs links the resolved roles to the freshly created user.
// Called INSIDE SignUp's transaction (ctx carries the distx w17-tx-id), so the
// UserRole rows commit atomically with the user row — a failure here rolls the
// whole signup back rather than leaving an orphan user without a role.
func assignSignupRoleIDs(ctx context.Context, h *AuthServiceHandler, userID string, roleIDs []string) error {
	for _, rid := range roleIDs {
		if _, err := h.Mutation.AssignRoleToUser(ctx, &pb.AssignRoleToUserReq{UserId: userID, RoleId: rid}); err != nil {
			return err
		}
	}
	return nil
}
