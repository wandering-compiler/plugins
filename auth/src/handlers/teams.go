package handlers

import (
	"context"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `teams` feature: an organization groups its
// members into teams, and a team holds org-scoped roles that every member
// holds while they are in it. Staged only when the activation enables `teams`
// (plugin.yaml go_files).
//
// A team is a group of PEOPLE, not a kind of role. Roles stay flat: the
// product defines what one means (the seed, org_roles), the organization
// decides who holds it — directly, or through a team. That is why a team is
// its own table rather than a role made of roles: the catalogue belongs to the
// product and teams to the tenant, and the resolver stays a union instead of a
// walk over a role graph.
//
// Where the roles count. Authenticate adds a member's team roles for a SESSION
// acting in the team's organization (orgGrantSources, in the organization
// narrower), and nowhere else: not realm-wide, not in another organization,
// not for an API token — a token's ceiling stays its holder's api-realm roles.
//
// The role ceiling holds wherever someone gains or loses a role through a
// team: giving the team a role or taking one away (the caller covers that
// role), adding a member or removing one, and deleting the team (the caller
// covers every role the team holds). Removing someone from the organization
// asks the caller to cover their team roles too (memberHeldRoleSources) and
// ends their team memberships in the same transaction
// (membershipRemovalCascades); deleting the organization ends its teams
// (orgRemovalCascades); a role a team holds is in use (roleHolderCounters);
// and a wildcard role held through a team makes its member a superadmin of
// the organization for the last-superadmin rule (superadminSources), which
// removing a member from a team, changing a team's roles and deleting a team
// are held to as well (refuseLeavingNoSuperadmin).

// The sentences a person reads for these refusals. Mirrored into plugin.yaml
// by `make plugin-msgids-sync` (see errors.go).
//
//w17:msgid
const (
	MsgTeamNotFound         = "There is no such team in this organization."
	MsgTeamNoName           = "Give the team a name."
	MsgTeamNameTaken        = "This organization already has a team named {name}."
	MsgTeamAboveCaller      = "This team holds a role with permissions you do not have, so you cannot change its members or delete it."
	MsgTeamMemberNotInOrg   = "Only a member of this organization can join one of its teams."
	MsgTeamMemberIsBot      = "A machine account is not a team member. Give it its roles directly."
	MsgTeamMemberAlready    = "This person is already in the team."
	MsgTeamRoleNotAvailable = "Role {role} is not one this organization's teams can hold."
)

// The codes a client branches on for the same refusals.
const (
	CodeTeamNotFound         = "TEAM_NOT_FOUND"
	CodeTeamNoName           = "TEAM_NO_NAME"
	CodeTeamNameTaken        = "TEAM_NAME_TAKEN"
	CodeTeamAboveCaller      = "TEAM_ABOVE_CALLER"
	CodeTeamMemberNotInOrg   = "TEAM_MEMBER_NOT_IN_ORG"
	CodeTeamMemberIsBot      = "TEAM_MEMBER_IS_BOT"
	CodeTeamMemberAlready    = "TEAM_MEMBER_ALREADY"
	CodeTeamRoleNotAvailable = "TEAM_ROLE_NOT_AVAILABLE"
)

func init() {
	orgGrantSources = append(orgGrantSources, teamRoleGrants)
	memberHeldRoleSources = append(memberHeldRoleSources, teamRoleIDsOfMember)
	membershipRemovalCascades = append(membershipRemovalCascades, endTeamMemberships)
	orgRemovalCascades = append(orgRemovalCascades, endTeamsOfOrg)
	roleHolderCounters = append(roleHolderCounters, countTeamRoleHolders)
	superadminSources = append(superadminSources, teamSuperadmins)
}

// teamRoleGrants is teams' orgGrantSource: the roles the user holds through
// their teams in the organization. No row is no grant, not an error.
func teamRoleGrants(ctx context.Context, h *AuthServiceHandler, userID, orgID string) ([]*pb.RoleGrant, error) {
	resp, err := h.Query.GetUserTeamRoleGrants(ctx, &pb.GetUserTeamRoleGrantsReq{UserId: userID, OrgId: orgID})
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return resp.GetGrants(), nil
}

// teamRoleIDsOfMember is teams' memberHeldRoleSource: the ids of the roles
// teamRoleGrants answers.
func teamRoleIDsOfMember(ctx context.Context, h *AuthServiceHandler, userID, orgID string) ([]string, error) {
	grants, err := teamRoleGrants(ctx, h, userID, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.GetRoleId())
	}
	return out, nil
}

// endTeamMemberships is teams' membershipRemovalCascade.
func endTeamMemberships(ctx context.Context, h *AuthServiceHandler, userID, orgID, by string) error {
	_, err := h.Mutation.EndUserTeamMemberships(ctx, &pb.EndUserTeamMembershipsReq{UserId: userID, OrgId: orgID, RemovedBy: by})
	return err
}

// endTeamsOfOrg is teams' orgRemovalCascade.
func endTeamsOfOrg(ctx context.Context, h *AuthServiceHandler, orgID, by string) error {
	_, err := h.Mutation.EndTeamsOfOrg(ctx, &pb.EndTeamsOfOrgReq{OrgId: orgID, DeletedBy: by})
	return err
}

// teamSuperadmins is teams' superadminSource: the wildcard roles members of
// the organization hold through a team, one row per member, team and role.
func teamSuperadmins(ctx context.Context, h *AuthServiceHandler, orgID string) ([]*pb.OrgSuperadminRow, error) {
	resp, err := h.Query.ListOrgTeamSuperadmins(ctx, &pb.ListOrgTeamSuperadminsReq{OrgId: orgID})
	if notFoundOK(err) != nil {
		return nil, err
	}
	return resp.GetGrants(), nil
}

// countTeamRoleHolders is teams' roleHolderCounter.
func countTeamRoleHolders(ctx context.Context, h *AuthServiceHandler, roleID string) (int64, error) {
	resp, err := h.Query.CountTeamRoleGrants(ctx, &pb.CountTeamRoleGrantsReq{RoleId: roleID})
	if err != nil {
		return 0, err
	}
	return resp.GetCount(), nil
}

// ListOrgTeams returns the organization's teams with their members and roles,
// and whether the caller may manage each.
func (h *AuthServiceHandler) ListOrgTeams(ctx context.Context, req *pb.ListOrgTeamsReq) (*pb.ListOrgTeamsResp, error) {
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
	teams, err := h.Query.ListTeamsByOrg(ctx, &pb.ListTeamsByOrgReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	members, err := h.Query.ListTeamMembersByOrg(ctx, &pb.ListTeamMembersByOrgReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	roles, err := h.Query.ListTeamRolesByOrg(ctx, &pb.ListTeamRolesByOrgReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]*pb.OrgTeam{}
	out := &pb.ListOrgTeamsResp{}
	for _, t := range teams.GetTeams() {
		team := &pb.OrgTeam{
			Id:          t.GetId(),
			Name:        t.GetName(),
			Description: t.GetDescription(),
			CreatedAt:   t.GetCreatedAt(),
			Manageable:  true,
		}
		byID[t.GetId()] = team
		out.Teams = append(out.Teams, team)
	}
	for _, m := range members.GetMembers() {
		if team := byID[m.GetTeamId()]; team != nil {
			team.Members = append(team.Members, &pb.OrgTeamMember{UserId: m.GetUserId(), Email: m.GetEmail(), AddedAt: m.GetAddedAt()})
		}
	}
	for _, r := range roles.GetRoles() {
		if team := byID[r.GetTeamId()]; team != nil {
			team.RoleIds = append(team.RoleIds, r.GetRoleId())
			team.Manageable = team.GetManageable() && grantable[r.GetRoleId()]
		}
	}
	return out, nil
}

// CreateOrgTeam creates a team in the caller's organization. A new team holds
// no role and has no member, so nothing is granted and no ceiling applies.
func (h *AuthServiceHandler) CreateOrgTeam(ctx context.Context, req *pb.CreateOrgTeamReq) (*pb.CreateOrgTeamResp, error) {
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
	name, err := teamName(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	resp, err := h.Mutation.CreateTeam(ctx, &pb.CreateTeamReq{OrgId: orgID, Name: name, Description: strings.TrimSpace(req.GetDescription()), CreatedBy: callerID})
	if err != nil {
		return nil, teamNameRefusal(ctx, err, name)
	}
	return &pb.CreateOrgTeamResp{TeamId: resp.GetTeamId()}, nil
}

// UpdateOrgTeam renames a team or changes its description. Nobody gains or
// loses a role, so no ceiling applies.
func (h *AuthServiceHandler) UpdateOrgTeam(ctx context.Context, req *pb.UpdateOrgTeamReq) (*pb.UpdateOrgTeamResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := h.ownTeam(ctx, req.GetOrg(), req.GetTeamId())
	if err != nil {
		return nil, err
	}
	name, err := teamName(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	resp, err := h.Mutation.UpdateTeam(ctx, &pb.UpdateTeamReq{Id: req.GetTeamId(), OrgId: orgID, Name: name, Description: strings.TrimSpace(req.GetDescription())})
	if err != nil {
		return nil, teamNameRefusal(ctx, err, name)
	}
	return &pb.UpdateOrgTeamResp{TeamId: resp.GetTeamId()}, nil
}

// DeleteOrgTeam ends a team, its memberships and its roles. Every member loses
// the team's roles, so the caller covers them.
func (h *AuthServiceHandler) DeleteOrgTeam(ctx context.Context, req *pb.DeleteOrgTeamReq) (*pb.DeleteOrgTeamResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := h.ownTeam(ctx, req.GetOrg(), req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if _, err := h.coverTeamRoles(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	var teamID string
	err = h.guardSuperadmins(ctx, orgID, func(txCtx context.Context) error {
		// Deleting the team ends every wildcard its members hold through it.
		return h.refuseLeavingNoSuperadmin(txCtx, orgID, func(g *pb.OrgSuperadminRow) bool {
			return g.GetTeamId() == req.GetTeamId()
		})
	}, func(txCtx context.Context) error {
		resp, err := h.Mutation.DeleteTeam(txCtx, &pb.DeleteTeamReq{Id: req.GetTeamId(), OrgId: orgID, DeletedBy: callerID})
		if err != nil {
			return err
		}
		teamID = resp.GetTeamId()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.DeleteOrgTeamResp{TeamId: teamID}, nil
}

// AddOrgTeamMember adds a person of the organization to a team. They gain the
// team's roles, so the caller covers them.
func (h *AuthServiceHandler) AddOrgTeamMember(ctx context.Context, req *pb.AddOrgTeamMemberReq) (*pb.AddOrgTeamMemberResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := h.ownTeam(ctx, req.GetOrg(), req.GetTeamId())
	if err != nil {
		return nil, err
	}
	account, err := h.Query.GetOrgMemberAccount(ctx, &pb.GetOrgMemberAccountReq{UserId: req.GetUserId(), OrgId: orgID})
	if status.Code(err) == codes.NotFound {
		return nil, refusal(ctx, codes.FailedPrecondition,
			"user "+req.GetUserId()+" is not a member of organization "+orgID,
			CodeTeamMemberNotInOrg, "user_id", MsgTeamMemberNotInOrg, nil)
	}
	if err != nil {
		return nil, err
	}
	if isBotAccount(account.GetUser()) {
		return nil, refusal(ctx, codes.InvalidArgument,
			"user "+req.GetUserId()+" is a machine account",
			CodeTeamMemberIsBot, "user_id", MsgTeamMemberIsBot, nil)
	}
	if _, err := h.coverTeamRoles(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	resp, err := h.Mutation.AddTeamMember(ctx, &pb.AddTeamMemberReq{TeamId: req.GetTeamId(), UserId: req.GetUserId(), OrgId: orgID, AddedBy: callerID})
	if isUniqueConflict(err) {
		return nil, refusal(ctx, codes.AlreadyExists,
			"user "+req.GetUserId()+" is already a member of team "+req.GetTeamId(),
			CodeTeamMemberAlready, "user_id", MsgTeamMemberAlready, nil)
	}
	if err != nil {
		return nil, err
	}
	return &pb.AddOrgTeamMemberResp{MemberId: resp.GetMemberId()}, nil
}

// RemoveOrgTeamMember takes a person out of a team. They lose the team's
// roles, so the caller covers them.
func (h *AuthServiceHandler) RemoveOrgTeamMember(ctx context.Context, req *pb.RemoveOrgTeamMemberReq) (*pb.RemoveOrgTeamMemberResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := h.ownTeam(ctx, req.GetOrg(), req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if _, err := h.coverTeamRoles(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	var memberID string
	err = h.guardSuperadmins(ctx, orgID, func(txCtx context.Context) error {
		// The member loses every wildcard they hold through this team.
		return h.refuseLeavingNoSuperadmin(txCtx, orgID, func(g *pb.OrgSuperadminRow) bool {
			return g.GetTeamId() == req.GetTeamId() && g.GetUserId() == req.GetUserId()
		})
	}, func(txCtx context.Context) error {
		resp, err := h.Mutation.RemoveTeamMember(txCtx, &pb.RemoveTeamMemberReq{TeamId: req.GetTeamId(), UserId: req.GetUserId(), RemovedBy: callerID})
		if err != nil {
			return err
		}
		memberID = resp.GetMemberId()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.RemoveOrgTeamMemberResp{MemberId: memberID}, nil
}

// SetOrgTeamRoles replaces the roles a team holds, in one transaction. Each
// role is an org-scoped session-realm role of the organization's catalogue,
// and the caller covers every role the change gives or takes away. A role the
// team keeps is not asked about: nobody gains or loses it.
func (h *AuthServiceHandler) SetOrgTeamRoles(ctx context.Context, req *pb.SetOrgTeamRolesReq) (*pb.SetOrgTeamRolesResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := h.ownTeam(ctx, req.GetOrg(), req.GetTeamId())
	if err != nil {
		return nil, err
	}
	wanted := sortedStrings(req.GetRoleIds())
	available, err := h.assignableRoles(ctx, orgID)
	if err != nil {
		return nil, err
	}
	offered := map[string]bool{}
	for _, r := range available {
		offered[r.GetId()] = true
	}
	for _, id := range wanted {
		if !offered[id] {
			return nil, refusal(ctx, codes.InvalidArgument,
				"role "+id+" is not an org-scoped session role of organization "+orgID,
				CodeTeamRoleNotAvailable, "role_ids", MsgTeamRoleNotAvailable, map[string]string{"role": id})
		}
	}
	current, err := h.teamRoleIDs(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, id := range wanted {
		keep[id] = true
	}
	held := map[string]bool{}
	for _, id := range current {
		held[id] = true
	}
	var added, removed []string
	for _, id := range wanted {
		if !held[id] {
			added = append(added, id)
		}
	}
	for _, id := range current {
		if !keep[id] {
			removed = append(removed, id)
		}
	}
	if len(added)+len(removed) > 0 {
		grantable, err := h.grantableRoleIDs(ctx)
		if err != nil {
			return nil, err
		}
		for _, id := range append(append([]string(nil), added...), removed...) {
			if !grantable[id] {
				return nil, refusal(ctx, codes.PermissionDenied, errRoleAboveCaller.Error(),
					CodeRoleAboveCaller, "role_ids", MsgRoleAboveCaller, nil)
			}
		}
	}
	// A team left with no wildcard role ends every wildcard its members hold
	// through it; one that keeps or gains a wildcard keeps them superadmins.
	endsWildcards := false
	if len(removed) > 0 {
		wildcard, err := h.wildcardRoleIDs(ctx)
		if err != nil {
			return nil, err
		}
		endsWildcards = true
		for _, id := range wanted {
			if wildcard[id] {
				endsWildcards = false
				break
			}
		}
	}
	err = h.guardSuperadmins(ctx, orgID, func(txCtx context.Context) error {
		if !endsWildcards {
			return nil
		}
		return h.refuseLeavingNoSuperadmin(txCtx, orgID, func(g *pb.OrgSuperadminRow) bool {
			return g.GetTeamId() == req.GetTeamId()
		})
	}, func(txCtx context.Context) error {
		for _, id := range removed {
			if _, err := h.Mutation.RevokeTeamRole(txCtx, &pb.RevokeTeamRoleReq{TeamId: req.GetTeamId(), RoleId: id, RevokedBy: callerID}); err != nil {
				return err
			}
		}
		for _, id := range added {
			if _, err := h.Mutation.GrantTeamRole(txCtx, &pb.GrantTeamRoleReq{TeamId: req.GetTeamId(), RoleId: id, OrgId: orgID, GrantedBy: callerID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.SetOrgTeamRolesResp{RoleIds: wanted}, nil
}

// ownTeam is what acting on a team requires: it is a live team of the
// organization the caller acts in. Another organization's team gets the same
// answer as no team, so the refusal names nobody else's. It returns the
// organization.
func (h *AuthServiceHandler) ownTeam(ctx context.Context, org, teamID string) (string, error) {
	if err := refuseOtherOrg(ctx, org); err != nil {
		return "", err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return "", err
	}
	team, err := h.Query.GetTeam(ctx, &pb.GetTeamReq{Id: teamID})
	if err != nil && status.Code(err) != codes.NotFound {
		return "", err
	}
	if err != nil || team.GetOrgId() != orgID {
		return "", refusal(ctx, codes.NotFound,
			"team "+teamID+" is not a live team of organization "+orgID,
			CodeTeamNotFound, "team_id", MsgTeamNotFound, nil)
	}
	return orgID, nil
}

// teamRoleIDs is the live roles a team holds.
func (h *AuthServiceHandler) teamRoleIDs(ctx context.Context, teamID string) ([]string, error) {
	resp, err := h.Query.ListTeamRoleIds(ctx, &pb.ListTeamRoleIdsReq{TeamId: teamID})
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sortedStrings(resp.GetRoleIds()), nil
}

// coverTeamRoles refuses a caller who does not cover every role the team
// holds — what anyone joining, leaving or losing the team gains or loses. It
// returns the roles.
func (h *AuthServiceHandler) coverTeamRoles(ctx context.Context, teamID string) ([]string, error) {
	roles, err := h.teamRoleIDs(ctx, teamID)
	if err != nil || len(roles) == 0 {
		return roles, err
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range roles {
		if !grantable[id] {
			return nil, refusal(ctx, codes.PermissionDenied,
				"team "+teamID+" holds role "+id+", which the caller does not cover",
				CodeTeamAboveCaller, "team_id", MsgTeamAboveCaller, nil)
		}
	}
	return roles, nil
}

// teamName trims a team's name and refuses an empty one.
func teamName(ctx context.Context, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", refusal(ctx, codes.InvalidArgument, "name is required", CodeTeamNoName, "name", MsgTeamNoName, nil)
	}
	return name, nil
}

// teamNameRefusal reads a write's unique conflict as the name being taken —
// the one unique index a team's create and rename can hit.
func teamNameRefusal(ctx context.Context, err error, name string) error {
	if isUniqueConflict(err) {
		return refusal(ctx, codes.AlreadyExists, "a live team of the organization is named "+name,
			CodeTeamNameTaken, "name", MsgTeamNameTaken, map[string]string{"name": name})
	}
	return err
}

// sortedStrings returns ids deduplicated, without empties, in ascending order.
func sortedStrings(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
