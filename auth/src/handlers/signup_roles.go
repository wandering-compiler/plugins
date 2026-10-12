package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
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
// first_user (bootstrap-admin) roles when there is no user yet, else the
// default roles. Membership is seeded from `(w17.acl_roles)` into the
// assign_first_user / assign_default Role columns; this reads them
// realm-agnostically (a UserRole link carries no realm — the realm only
// gates which roles count at auth time). A wildcard (all_permissions)
// first_user role thus makes the very first account a superadmin with zero
// manual steps.
//
// Called BEFORE the write transaction: query servers do not join the distx
// tx (they read the pool), so the count reflects COMMITTED state. "Zero" is
// only a candidate, though — two sign-ups can both read it. The first_user
// set comes back marked `bootstrap`, with the default roles as `fallback`,
// and assignSignupRoleIDs settles it inside the transaction.
func resolveSignupRoleIDs(ctx context.Context, h *AuthServiceHandler) (signupRoles, error) {
	cnt, err := h.Query.CountUsers(ctx, &pb.CountUsersReq{})
	if err != nil {
		return signupRoles{}, err
	}
	def, err := h.Query.GetDefaultRoles(ctx, &pb.GetDefaultRolesReq{})
	if err != nil {
		return signupRoles{}, err
	}
	if cnt.GetCount() != 0 {
		return signupRoles{ids: def.GetRoleIds()}, nil
	}
	first, err := h.Query.GetFirstUserRoles(ctx, &pb.GetFirstUserRolesReq{})
	if err != nil {
		return signupRoles{}, err
	}
	return signupRoles{ids: first.GetRoleIds(), bootstrap: true, fallback: def.GetRoleIds()}, nil
}

// bootstrapSlot is the constant key of the one BootstrapClaim row. The column
// is a SLUG (lowercase letters, digits and hyphens), and storage validates it
// before the write.
const bootstrapSlot = "first-user"

// assignSignupRoleIDs links the resolved roles to the freshly created user.
// Called INSIDE the sign-up transaction (ctx carries the distx w17-tx-id), so
// the UserRole rows — and the bootstrap claim — commit atomically with the
// user row: a failure rolls the whole sign-up back, and a rolled-back sign-up
// leaves the claim free for the next one.
//
// A `bootstrap` set is assigned only to the sign-up that writes the claim. A
// concurrent one blocks on the claim's key until the first commits, then
// conflicts, writes nothing, and gets the default roles.
// That holds under READ COMMITTED (the transaction opens at the driver default,
// PostgreSQL's) and on MySQL; a stricter PostgreSQL default answers the
// blocked sign-up with a serialization failure instead. Without DistTx the
// claim commits on its own, ahead of the role links. A `written` that is not
// 1, absent included, counts as a lost claim: fail closed, default roles.
func assignSignupRoleIDs(ctx context.Context, h *AuthServiceHandler, userID string, roles signupRoles) error {
	ids := roles.ids
	if roles.bootstrap {
		claim, err := h.Mutation.ClaimBootstrapAdmin(ctx, &pb.ClaimBootstrapAdminReq{Slot: bootstrapSlot, UserId: userID})
		if err != nil {
			return err
		}
		if claim.GetWritten() != 1 {
			ids = roles.fallback
		}
	}
	for _, rid := range ids {
		if _, err := h.Mutation.AssignRoleToUser(ctx, &pb.AssignRoleToUserReq{UserId: userID, RoleId: rid}); err != nil {
			return err
		}
	}
	return nil
}
