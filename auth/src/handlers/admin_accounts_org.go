package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file exists only when BOTH `admin_accounts` and `org_membership` are on
// (plugin.yaml, `go_files_combined`): what organizations add to the admin's
// account methods — the organization named by its slug, its role catalogue,
// its lock and the membership a new account is written into. admin_accounts.go
// alone serves a realm without organizations and cannot name these calls.
func init() {
	adminAccountOrgs = &adminAccountOrgScope{
		refuseInsideOrg: refuseAdminAccountsInsideOrg,
		bySlug:          adminAccountOrgBySlug,
		roleID: func(ctx context.Context, h *AuthServiceHandler, orgID, name string) (string, error) {
			return h.roleIDByName(ctx, orgID, name)
		},
		lock:   lockAdminAccountOrg,
		enroll: enrollAdminAccount,
		orgOf:  adminAccountOrgOf,
	}
}

// refuseAdminAccountsInsideOrg: realm-wide methods, so from inside an
// organization only for a caller holding the method realm-wide — an
// organization's member creating accounts in other organizations is exactly
// what they must not do.
func refuseAdminAccountsInsideOrg(ctx context.Context, h *AuthServiceHandler, method string) error {
	if orgID := scopeOrg(ctx); orgID != "" && !h.heldRealmWide(ctx, method) {
		return status.Error(codes.PermissionDenied,
			"admin_accounts: "+method+" is the admin's and acts realm-wide, not from inside an organization")
	}
	return nil
}

// adminAccountOrgBySlug is the live organization named by slug.
func adminAccountOrgBySlug(ctx context.Context, h *AuthServiceHandler, method, slug string) (string, error) {
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

// lockAdminAccountOrg takes orgID's row lock in the transaction and marks
// txCtx as under it, as withOrgLock does: the ceiling re-checked there reads
// the operator's grants as they are now.
func lockAdminAccountOrg(h *AuthServiceHandler, txCtx context.Context, orgID string) (context.Context, error) {
	if err := h.lockOrgRow(txCtx, orgID); err != nil {
		return nil, err
	}
	return context.WithValue(txCtx, orgLockKey{}, orgID), nil
}

// enrollAdminAccount makes the new account a member of orgID and grants its
// role THERE, as accepting an invitation does: membership first, and org_id on
// the grant, or the role would count in no organization (or in every one).
func enrollAdminAccount(txCtx context.Context, h *AuthServiceHandler, userID, orgID, roleName, roleID string) error {
	if _, err := h.Mutation.AddOrgMembership(txCtx, &pb.AddOrgMembershipReq{
		UserId: userID, OrgId: orgID, Role: roleName,
	}); err != nil {
		return err
	}
	_, err := h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{
		UserId: userID, RoleId: roleID, OrgId: orgID,
	})
	return err
}

// adminAccountOrgOf is the organization an account belongs to: a machine
// account belongs to exactly one. "" when it belongs to none.
func adminAccountOrgOf(ctx context.Context, h *AuthServiceHandler, userID string) (string, error) {
	resp, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return "", err
	}
	if len(resp.GetOrgs()) == 0 {
		return "", nil
	}
	return resp.GetOrgs()[0].GetOrgId(), nil
}
