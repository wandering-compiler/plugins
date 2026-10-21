package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// This file implements the `org_roles` feature: an organization composes
// roles of its own from the deployed lock's permissions (Role.org_id), and
// only that organization sees, grants and edits them. Staged only when the
// activation enables `org_roles` (plugin.yaml go_files).
//
// A custom role is an ordinary org-scoped Role with RolePermission rows, so
// nothing on the permission side changes: Authenticate resolves it like any
// seeded role, and the gateway's per-method check reads the result. What this
// adds is who may write one, and where it is offered:
//
//   - the catalogue every org-role grant reads (invitation, acceptance, role
//     change, the picker) becomes the organization's own: the shared org
//     roles plus its custom ones, never another organization's;
//   - the role ceiling applies to composing as it does to granting: a role
//     may carry only permissions its author holds, and an existing role may be
//     changed or deleted only by someone who covers what it carries now.
//
// A preset (the seed's) role is never edited here: the seed owns it and would
// rewrite it on the next apply.

// The sentences a person reads for these refusals. Mirrored into plugin.yaml
// by `make plugin-msgids-sync` (see errors.go).
//
//w17:msgid
const (
	MsgOrgRoleNotOwn            = "That role is not one of this organization's own roles, so it cannot be changed here."
	MsgOrgRoleNoPermissions     = "Choose at least one permission for the role."
	MsgOrgRoleUnknownPermission = "Permission {permission} is not part of this deployment."
	MsgOrgRoleInUse             = "Someone still holds this role, directly or through a team. Give them another role first."
	MsgOrgRoleNoName            = "Give the role a name."
)

// The codes a client branches on for the same refusals.
const (
	CodeOrgRoleNotOwn            = "ORG_ROLE_NOT_OWN"
	CodeOrgRoleNoPermissions     = "ORG_ROLE_NO_PERMISSIONS"
	CodeOrgRoleUnknownPermission = "ORG_ROLE_UNKNOWN_PERMISSION"
	CodeOrgRoleInUse             = "ORG_ROLE_IN_USE"
	CodeOrgRoleNoName            = "ORG_ROLE_NO_NAME"
)

func init() {
	orgRoleCatalogue = orgRoleRows
}

// noOrg is the organization id that owns no role.
const noOrg = "00000000-0000-0000-0000-000000000000"

// orgRoleRows is the organization's catalogue for every org-role grant: the
// shared org roles and its own, of either realm (assignableRoles drops the
// API-realm ones).
func orgRoleRows(ctx context.Context, h *AuthServiceHandler, orgID string) ([]*pb.OrgScopedRole, error) {
	if orgID == "" {
		// No organization: the shared roles only. The nil UUID owns no role.
		orgID = noOrg
	}
	resp, err := h.Query.ListOrgRoleRows(ctx, &pb.ListOrgRoleRowsReq{OrgId: orgID})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.OrgScopedRole, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		row := &pb.OrgScopedRole{
			Id:          r.GetId(),
			Name:        r.GetName(),
			Description: r.GetDescription(),
			DisplayName: r.GetDisplayName(),
		}
		copyTokenType(r, row)
		out = append(out, row)
	}
	return out, nil
}

// copyTokenType carries the realm from one catalogue row to another. By
// reflection, like isAPIRealmRow: the field exists only with api_token.
func copyTokenType(from, to proto.Message) {
	src := from.ProtoReflect().Descriptor().Fields().ByName("token_type")
	dst := to.ProtoReflect().Descriptor().Fields().ByName("token_type")
	if src == nil || dst == nil {
		return
	}
	to.ProtoReflect().Set(dst, from.ProtoReflect().Get(src))
}

// ListOrgRoles returns the roles of the caller's organization with what each
// carries, for the role editor and the pickers. Bots' roles are left out: they
// are listed with the bots (ListBotRoles).
func (h *AuthServiceHandler) ListOrgRoles(ctx context.Context, req *pb.ListOrgRolesReq) (*pb.ListOrgRolesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := h.Query.ListOrgRoleRows(ctx, &pb.ListOrgRoleRowsReq{OrgId: orgID})
	if err != nil {
		return nil, err
	}
	catalogue, err := h.roleCatalogue(ctx)
	if err != nil {
		return nil, err
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListOrgRolesResp{}
	for _, r := range rows.GetRoles() {
		if isAPIRealmRow(r) {
			continue
		}
		role := &pb.OrgRole{
			Id:             r.GetId(),
			Name:           r.GetName(),
			DisplayName:    r.GetDisplayName(),
			Description:    r.GetDescription(),
			Custom:         r.GetCustom(),
			AllPermissions: r.GetAllPermissions(),
			Grantable:      grantable[r.GetId()],
		}
		if !r.GetAllPermissions() {
			role.PermissionIds = sortedIDs(catalogue[r.GetId()])
		}
		out.Roles = append(out.Roles, role)
	}
	return out, nil
}

// CreateOrgRole composes a new role of the caller's organization.
func (h *AuthServiceHandler) CreateOrgRole(ctx context.Context, req *pb.CreateOrgRoleReq) (*pb.CreateOrgRoleResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(req.GetDisplayName())
	if label == "" {
		return nil, refusal(ctx, codes.InvalidArgument, "display_name is required", CodeOrgRoleNoName, "display_name", MsgOrgRoleNoName, nil)
	}
	perms, err := h.checkRolePermissions(ctx, req.GetPermissionIds())
	if err != nil {
		return nil, err
	}
	name, err := orgRoleName(label)
	if err != nil {
		return nil, err
	}
	var roleID string
	err = h.inOrgTx(ctx, func(txCtx context.Context) error {
		created, err := h.Mutation.CreateRole(txCtx, &pb.CreateRoleReq{Name: name, Description: req.GetDescription()})
		if err != nil {
			return err
		}
		roleID = created.GetRole().GetId()
		if _, err := h.Mutation.ClaimRoleForOrg(txCtx, &pb.ClaimRoleForOrgReq{RoleId: roleID, OrgId: orgID, DisplayName: label}); err != nil {
			return err
		}
		for _, id := range perms {
			if _, err := h.Mutation.AddPermissionToRole(txCtx, &pb.AddPermissionToRoleReq{RoleId: roleID, PermissionId: id, AddedBy: callerID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.CreateOrgRoleResp{RoleId: roleID, Name: name}, nil
}

// UpdateOrgRole renames one of the organization's roles and sets what it
// carries. The caller covers the role as it is (the ceiling on changing what
// someone else holds) and as it will be (the ceiling on composing).
func (h *AuthServiceHandler) UpdateOrgRole(ctx context.Context, req *pb.UpdateOrgRoleReq) (*pb.UpdateOrgRoleResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := h.ownOrgRole(ctx, req.GetOrg(), req.GetRoleId())
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(req.GetDisplayName())
	if label == "" {
		return nil, refusal(ctx, codes.InvalidArgument, "display_name is required", CodeOrgRoleNoName, "display_name", MsgOrgRoleNoName, nil)
	}
	perms, err := h.checkRolePermissions(ctx, req.GetPermissionIds())
	if err != nil {
		return nil, err
	}
	catalogue, err := h.roleCatalogue(ctx)
	if err != nil {
		return nil, err
	}
	current := map[int32]bool{}
	for _, id := range catalogue[req.GetRoleId()] {
		current[id] = true
	}
	wanted := map[int32]bool{}
	for _, id := range perms {
		wanted[id] = true
	}
	err = h.inOrgTx(ctx, func(txCtx context.Context) error {
		if _, err := h.Mutation.UpdateOrgRoleLabel(txCtx, &pb.UpdateOrgRoleLabelReq{
			RoleId: req.GetRoleId(), OrgId: orgID, DisplayName: label, Description: req.GetDescription(),
		}); err != nil {
			return err
		}
		for _, id := range perms {
			if current[id] {
				continue
			}
			if _, err := h.Mutation.AddPermissionToRole(txCtx, &pb.AddPermissionToRoleReq{RoleId: req.GetRoleId(), PermissionId: id, AddedBy: callerID}); err != nil {
				return err
			}
		}
		for _, id := range sortedIDs(catalogue[req.GetRoleId()]) {
			if wanted[id] {
				continue
			}
			if _, err := h.Mutation.RemovePermissionFromRole(txCtx, &pb.RemovePermissionFromRoleReq{RoleId: req.GetRoleId(), PermissionId: id, RemovedBy: callerID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.UpdateOrgRoleResp{RoleId: req.GetRoleId()}, nil
}

// DeleteOrgRole retires one of the organization's roles that nobody holds.
func (h *AuthServiceHandler) DeleteOrgRole(ctx context.Context, req *pb.DeleteOrgRoleReq) (*pb.DeleteOrgRoleResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if _, err := h.ownOrgRole(ctx, req.GetOrg(), req.GetRoleId()); err != nil {
		return nil, err
	}
	held, err := h.Query.CountRoleGrants(ctx, &pb.CountRoleGrantsReq{RoleId: req.GetRoleId()})
	if err != nil {
		return nil, err
	}
	count := held.GetCount()
	for _, counter := range roleHolderCounters {
		more, err := counter(ctx, h, req.GetRoleId())
		if err != nil {
			return nil, err
		}
		count += more
	}
	if count > 0 {
		return nil, refusal(ctx, codes.FailedPrecondition,
			"role "+req.GetRoleId()+" still has "+strconv.FormatInt(count, 10)+" live grant(s)",
			CodeOrgRoleInUse, "role_id", MsgOrgRoleInUse, nil)
	}
	if _, err := h.Mutation.DeleteRole(ctx, &pb.DeleteRoleReq{RoleId: req.GetRoleId()}); err != nil {
		return nil, err
	}
	return &pb.DeleteOrgRoleResp{RoleId: req.GetRoleId()}, nil
}

// ownOrgRole is what changing a role requires: it is the caller's
// organization's own (not a shared one, not another organization's — both
// the same refusal, so the answer names no other company's role), and the
// caller covers what it carries now. It returns the organization.
func (h *AuthServiceHandler) ownOrgRole(ctx context.Context, org, roleID string) (string, error) {
	if err := refuseOtherOrg(ctx, org); err != nil {
		return "", err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return "", err
	}
	rows, err := h.Query.ListOrgRoleRows(ctx, &pb.ListOrgRoleRowsReq{OrgId: orgID})
	if err != nil {
		return "", err
	}
	own := false
	for _, r := range rows.GetRoles() {
		if r.GetId() == roleID && r.GetCustom() {
			own = true
		}
	}
	if !own {
		return "", refusal(ctx, codes.NotFound,
			"role "+roleID+" is not a custom role of organization "+orgID,
			CodeOrgRoleNotOwn, "role_id", MsgOrgRoleNotOwn, nil)
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return "", err
	}
	if !grantable[roleID] {
		return "", refusal(ctx, codes.PermissionDenied, errRoleAboveCaller.Error(),
			CodeRoleAboveCaller, "role_id", MsgRoleAboveCaller, nil)
	}
	return orgID, nil
}

// checkRolePermissions validates what a role is to carry: at least one
// permission, each allocated by the deployed lock, each held by the caller.
// It returns them deduplicated and sorted.
func (h *AuthServiceHandler) checkRolePermissions(ctx context.Context, ids []int32) ([]int32, error) {
	perms := sortedIDs(ids)
	if len(perms) == 0 {
		return nil, refusal(ctx, codes.InvalidArgument, "permission_ids is empty",
			CodeOrgRoleNoPermissions, "permission_ids", MsgOrgRoleNoPermissions, nil)
	}
	known := map[int32]bool{}
	if h.Lock != nil {
		for _, id := range acllock.GrantAll(h.Lock) {
			known[id] = true
		}
	}
	for _, id := range perms {
		if !known[id] {
			n := strconv.FormatInt(int64(id), 10)
			return nil, refusal(ctx, codes.InvalidArgument, "permission "+n+" is not allocated by the deployed lock",
				CodeOrgRoleUnknownPermission, "permission_ids", MsgOrgRoleUnknownPermission, map[string]string{"permission": n})
		}
	}
	held, err := callerHeldPermissions(ctx)
	if err != nil {
		return nil, err
	}
	if !allHeld(perms, held) {
		return nil, refusal(ctx, codes.PermissionDenied, errRoleAboveCaller.Error(),
			CodeRoleAboveCaller, "permission_ids", MsgRoleAboveCaller, nil)
	}
	return perms, nil
}

// sortedIDs returns ids deduplicated and in ascending order.
func sortedIDs(ids []int32) []int32 {
	seen := map[int32]bool{}
	out := make([]int32, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// orgRoleName derives the role's technical name — what an invitation
// carries — from its label: a slug of it and a random suffix, because
// Role.name is unique across the deployment and two organizations may well
// both have a "Developer".
func orgRoleName(label string) (string, error) {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 80 {
			break
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "role"
	}
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return slug + "-" + hex.EncodeToString(suffix), nil
}
