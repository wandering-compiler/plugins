package handlers

import (
	"context"
	"os"
	"slices"
	"strings"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What membership_kinds adds to oauth_server, staged only when both are on:
// an MCP client's grant is for one resource — one audience's MCP surface — and
// the consent page offers only the organizations where the user holds a
// membership of a kind that audience admits. With exactly one, it is the only
// choice; with none, the page refuses at once (MEMBERSHIP_NOT_ADMITTED)
// instead of minting a token every call of which would be refused.
//
// The audience of a resource comes from the domain's audience table
// (w17_audiences), which codegen generates from the protos: each audience's
// admitted kinds and the variable carrying its MCP surface's public URL — the
// gateway's own, which the deploy fills here too. A resource the table does
// not name (no audiences, an MCP surface of another domain) is not filtered:
// the gateway's admission still applies on every call.

func init() {
	oauthOrgsForResource = orgsForResource
	oauthCheckOrgResource = checkOrgForResource
}

// resourceKinds are the membership kinds the audience serving resource
// admits; nil when the table names no such audience, or names it ambiguously.
func (h *AuthServiceHandler) resourceKinds(resource string) []string {
	want := strings.TrimRight(resource, "/")
	var found []string
	matches := 0
	for _, entry := range strings.Split(h.Audiences, ";") {
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		url := strings.TrimRight(os.Getenv(parts[2]), "/")
		if url == "" || url != want {
			continue
		}
		matches++
		for _, k := range strings.Split(parts[1], "|") {
			if k != "" && !slices.Contains(found, k) {
				found = append(found, k)
			}
		}
	}
	if matches != 1 {
		// None, or two audiences publishing one URL (a dev box where every
		// MCP surface defaults to the same address): no filter here.
		return nil
	}
	return found
}

// admittedOrgIDs are the organizations where userID holds a membership of one
// of kinds.
func admittedOrgIDs(ctx context.Context, h *AuthServiceHandler, userID string, kinds []string) (map[string]bool, error) {
	admitted, _, err := admittedOrgs(ctx, h, userID, kinds)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, o := range admitted {
		out[o.GetOrgId()] = true
	}
	return out, nil
}

// orgsForResource narrows the consent page's organizations to the ones the
// resource's audience admits, each once (a person staff and client of one
// organization is listed once).
func orgsForResource(ctx context.Context, h *AuthServiceHandler, userID, resource string, orgs []*pb.OAuthConsentOrg) ([]*pb.OAuthConsentOrg, error) {
	kinds := h.resourceKinds(resource)
	var ok map[string]bool
	if len(kinds) > 0 {
		var err error
		if ok, err = admittedOrgIDs(ctx, h, userID, kinds); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	out := make([]*pb.OAuthConsentOrg, 0, len(orgs))
	for _, o := range orgs {
		if seen[o.GetId()] || (ok != nil && !ok[o.GetId()]) {
			continue
		}
		seen[o.GetId()] = true
		out = append(out, o)
	}
	if len(kinds) > 0 && len(out) == 0 {
		return nil, membershipNotAdmitted(ctx)
	}
	return out, nil
}

// checkOrgForResource refuses an approval naming an organization the
// resource's audience does not admit the user in.
func checkOrgForResource(ctx context.Context, h *AuthServiceHandler, userID, orgID, resource string) error {
	kinds := h.resourceKinds(resource)
	if len(kinds) == 0 {
		return nil
	}
	ok, err := admittedOrgIDs(ctx, h, userID, kinds)
	if err != nil {
		return err
	}
	if !ok[orgID] {
		return membershipNotAdmitted(ctx)
	}
	return nil
}
