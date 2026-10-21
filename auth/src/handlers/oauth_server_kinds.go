package handlers

import (
	"context"
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
// (w17_audiences, parsed at boot), which codegen generates from the protos:
// each audience's admitted kinds and the variable carrying its MCP surface's
// public URL — the gateway's own, which the deploy fills here too. A resource
// the table does not name (an MCP surface of another domain) is not filtered:
// the gateway's admission still applies on every call.

func init() {
	oauthOrgsForResource = orgsForResource
	oauthCheckOrgResource = checkOrgForResource
	audienceURLsNeeded = true
}

// resourceKinds are the membership kinds the audience whose MCP surface is
// resource admits; nil when no audience of this domain publishes it (an MCP
// surface of another domain), where the gateway's own admission is the check.
// The table was parsed at boot, which refuses an unset URL and two audiences
// sharing one.
func (h *AuthServiceHandler) resourceKinds(resource string) ([]string, error) {
	table, err := h.audienceTable()
	if err != nil {
		return nil, err
	}
	want := strings.TrimRight(resource, "/")
	for _, a := range table {
		if a.url != "" && a.url == want {
			return a.kinds, nil
		}
	}
	return nil, nil
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
// resource's audience admits.
func orgsForResource(ctx context.Context, h *AuthServiceHandler, userID, resource string, orgs []*pb.OAuthConsentOrg) ([]*pb.OAuthConsentOrg, error) {
	kinds, err := h.resourceKinds(resource)
	if err != nil {
		return nil, err
	}
	var ok map[string]bool
	if len(kinds) > 0 {
		if ok, err = admittedOrgIDs(ctx, h, userID, kinds); err != nil {
			return nil, err
		}
	}
	out := make([]*pb.OAuthConsentOrg, 0, len(orgs))
	for _, o := range orgs {
		if ok == nil || ok[o.GetId()] {
			out = append(out, o)
		}
	}
	if len(kinds) > 0 && len(out) == 0 {
		return nil, membershipNotAdmitted(ctx)
	}
	return out, nil
}

// checkOrgForResource refuses an approval naming an organization the
// resource's audience does not admit the user in.
func checkOrgForResource(ctx context.Context, h *AuthServiceHandler, userID, orgID, resource string) error {
	kinds, err := h.resourceKinds(resource)
	if err != nil {
		return err
	}
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
