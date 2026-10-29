package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file is staged when `user_admin` and `rbac` are both on (plugin.yaml
// go_files_combined): the last-admin rule needs the roles to know who
// administers the realm.

func init() {
	realmAdmins = listRealmAdmins
}

// listRealmAdmins is the realm's administrators who can act: the accounts of
// AuthQuery.ListRealmSuperadmins (a live grant of a live wildcard role), minus
// a disabled or erased account and an API-realm grant — a machine account's
// wildcard administers nothing through a session. The query locks the rows it
// reads.
func listRealmAdmins(ctx context.Context, h *AuthServiceHandler) ([]string, bool, error) {
	resp, err := h.Query.ListRealmSuperadmins(ctx, &pb.ListRealmSuperadminsReq{})
	if err != nil {
		return nil, true, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, g := range resp.GetGrants() {
		if g.GetDisabledAt() != nil || g.GetErasedAt() != nil || isAPIRealmRow(g) || seen[g.GetUserId()] {
			continue
		}
		seen[g.GetUserId()] = true
		ids = append(ids, g.GetUserId())
	}
	return ids, true, nil
}
