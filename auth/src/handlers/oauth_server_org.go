package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What organizations add to the oauth_server feature, staged only when both
// it and org_membership are on: an MCP client sends no W17-Org, so the user
// chooses on the consent page which of their organizations the grant
// belongs to, and every token of the grant acts in that one.

func init() {
	oauthConsentOrgs = consentOrgs
	oauthCheckOrg = checkConsentOrg
	oauthOrgScope = resolveOAuthOrgScope
}

// consentOrgs are the organizations the consent page offers.
func consentOrgs(ctx context.Context, h *AuthServiceHandler, userID string) ([]*pb.OAuthConsentOrg, error) {
	got, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.OAuthConsentOrg, 0, len(got.GetOrgs()))
	for _, o := range got.GetOrgs() {
		out = append(out, &pb.OAuthConsentOrg{Id: o.GetOrgId(), Slug: o.GetSlug(), Name: o.GetName()})
	}
	return out, nil
}

var errOAuthOrgNotMember = errors.New("oauth: the organization is not one of the user's")

// orgOfUser is the slug of orgID when the user is a member of it, "" when
// not.
func orgOfUser(ctx context.Context, h *AuthServiceHandler, userID, orgID string) (string, error) {
	if orgID == "" {
		return "", nil
	}
	got, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return "", err
	}
	for _, o := range got.GetOrgs() {
		if o.GetOrgId() == orgID {
			return o.GetSlug(), nil
		}
	}
	return "", nil
}

// checkConsentOrg: the organization named for a grant is one the user
// belongs to.
func checkConsentOrg(ctx context.Context, h *AuthServiceHandler, userID, orgID string) error {
	if orgID == "" {
		// A user of no organization grants with their realm-wide roles; one
		// who has organizations names the one the app acts in.
		got, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
		if err != nil {
			return err
		}
		if len(got.GetOrgs()) == 0 {
			return nil
		}
		return refusal(ctx, codes.InvalidArgument, errOAuthOrgNotMember.Error(), CodeOAuthOrgRequired, "org_id", MsgOAuthOrgRequired, nil)
	}
	slug, err := orgOfUser(ctx, h, userID, orgID)
	if err != nil {
		return err
	}
	if slug == "" {
		return refusal(ctx, codes.InvalidArgument, errOAuthOrgNotMember.Error(), CodeOAuthOrgRequired, "org_id", MsgOAuthOrgRequired, nil)
	}
	return nil
}

// resolveOAuthOrgScope stamps the organization an OAuth token carries, while
// the user still belongs to it. A W17-Org naming another is refused, as two
// organizations in one request are anywhere else.
func resolveOAuthOrgScope(ctx context.Context, h *AuthServiceHandler, userID, orgID string, headers, scopes, labels map[string]string) error {
	slug, err := orgOfUser(ctx, h, userID, orgID)
	if err != nil {
		return err
	}
	if slug == "" {
		return DeniedOrgNotMember(errOrgNotMember)
	}
	if named := orgSlugFromHeaders(headers); named != "" && named != slug {
		return DeniedOrgNotMember(errOrgNotMember)
	}
	stampOrg(scopes, labels, orgID, slug)
	return nil
}
