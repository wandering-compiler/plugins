package handlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `membership_kinds` feature: memberships of several
// KINDS (`staff`, `client`, …) — the auth half of audience surfaces
// (`w17/audience.proto` in the SDK). A domain publishing several audiences
// serves each from its own gateway, and that gateway names the kinds it admits
// in every Authenticate (x-w17-membership-kinds, which only a gateway writes).
// Staged only with the feature; it requires org_membership.
//
// A membership has ONE kind: a person is an organization's staff or its
// client, and may be staff of one organization and client of another. Every
// read that takes one membership per (user, organization) stays true.
//
// What it changes, all of it subtractive:
//
//   - the organization a request acts in is resolved among the memberships
//     of an admitted kind only, and a caller holding none is refused 403
//     before any handler — a client calling the staff surface reaches no
//     endpoint of it;
//   - an invitation's kind is held to what the inviter's audiences may
//     invite (membership_kinds_invite.go).
//
// A gateway that names no kinds — every gateway of a domain without
// audiences — admits every membership, and nothing about it changes.

var errMembershipNotAdmitted = errors.New("membership_kinds: none of the caller's memberships is of a kind this audience admits")

func init() {
	orgScopeByKind = resolveOrgScopeByKind
	configChecks = append(configChecks, parseAudienceTable)
	authRespEnrichers = append(authRespEnrichers, answerMembershipKind)
	kindOfJoin = func(kind string, add *pb.AddOrgMembershipReq) { add.Kind = kind }
	membershipKindOf = (*pb.UserOrg).GetMembershipKind
}

// answerMembershipKind answers the kind of the caller's membership in the
// organization the request acts in (AuthResp.membership_kind) — what a
// project calls the account type, and like the organization it is the
// request's: the same person may be staff of one organization and a client
// of another, in two tabs at once. Read once the organization is resolved,
// whichever way it was (the selector, the sole membership, an OAuth token's
// organization, an audience's kinds). Empty when the request acts in no
// organization.
func answerMembershipKind(ctx context.Context, h *AuthServiceHandler, prin *authPrincipal, resp *pb.AuthResp) error {
	orgID := resp.GetScopes()["org_id"]
	if orgID == "" {
		return nil
	}
	all, err := userOrgs(ctx, h, prin.userID)
	if err != nil {
		return err
	}
	if o := orgByID(all, orgID); o != nil {
		resp.MembershipKind = o.GetMembershipKind()
	}
	return nil
}

// userOrgs is the caller's memberships, read once per Authenticate (the
// request's memo): an audience gateway's resolution and the kind answered
// read the same list.
func userOrgs(ctx context.Context, h *AuthServiceHandler, userID string) ([]*pb.UserOrg, error) {
	key := "membership_kinds.user_orgs." + userID
	memo := requestMemoOf(ctx)
	if v, ok := memo[key].([]*pb.UserOrg); ok {
		return v, nil
	}
	resp, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	if memo != nil {
		memo[key] = resp.GetOrgs()
	}
	return resp.GetOrgs(), nil
}

// membershipNotAdmitted is the 403 for a caller the audience does not admit.
func membershipNotAdmitted(ctx context.Context) error {
	return &notAdmittedError{err: refusal(ctx, codes.PermissionDenied, errMembershipNotAdmitted.Error(),
		CodeMembershipNotAdmitted, "", MsgMembershipNotAdmitted, nil)}
}

// admittedOrgs is the caller's memberships of an admitted kind (every one when
// kinds is empty), and all of them.
func admittedOrgs(ctx context.Context, h *AuthServiceHandler, userID string, kinds []string) (admitted, all []*pb.UserOrg, err error) {
	all, err = userOrgs(ctx, h, userID)
	if err != nil {
		return nil, nil, err
	}
	for _, o := range all {
		if len(kinds) == 0 || slices.Contains(kinds, o.GetMembershipKind()) {
			admitted = append(admitted, o)
		}
	}
	return admitted, all, nil
}

func orgByID(list []*pb.UserOrg, id string) *pb.UserOrg {
	for _, o := range list {
		if o.GetOrgId() == id {
			return o
		}
	}
	return nil
}

func orgBySlug(list []*pb.UserOrg, slug string) *pb.UserOrg {
	for _, o := range list {
		if o.GetSlug() == slug {
			return o
		}
	}
	return nil
}

// resolveOrgScopeByKind is resolveOrgScope through a gateway that admits only
// some kinds (resolveOrgScope calls it only then). The same order — an OAuth
// token's organization, then what the request names by the audience's tenant
// sources (chooseOrg), then the caller's sole organization — over the
// memberships the audience admits. A membership of
// another kind in the named organization is 403, not "not a member".
func resolveOrgScopeByKind(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error {
	admitted, all, err := admittedOrgs(ctx, h, userID, kindsFromHeaders(headers))
	if err != nil {
		return err
	}
	// An OAuth access token acts in the organization chosen on the consent
	// page: held to an admitted kind here, then resolved as on any gateway
	// (oauthOrgScope), so its checks are the one copy.
	if orgID := oauthTokenOrg(ctx); orgID != "" {
		if oauthOrgScope == nil {
			return DeniedOrgNotMember(errOrgNotMember)
		}
		if orgByID(admitted, orgID) == nil {
			if orgByID(all, orgID) != nil {
				return membershipNotAdmitted(ctx)
			}
			return DeniedOrgNotMember(errOrgNotMember)
		}
		return oauthOrgScope(ctx, h, userID, orgID, headers, scopes, labels)
	}

	// The organization the request names — by the audience's tenant
	// sources, or the selector — or the sole admitted one (chooseOrg).
	pick, err := chooseOrg(ctx, h, headers, func() *pb.UserOrg {
		if len(admitted) == 1 {
			return admitted[0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if o := pick.sole; o != nil {
		stampOrg(scopes, labels, o.GetOrgId(), o.GetSlug())
		return nil
	}
	if slug := pick.slug; slug != "" {
		if o := orgBySlug(admitted, slug); o != nil {
			stampOrg(scopes, labels, o.GetOrgId(), o.GetSlug())
			return nil
		}
		if orgBySlug(all, slug) != nil {
			return membershipNotAdmitted(ctx)
		}
		return DeniedOrgNotMember(errOrgNotMember)
	}
	if len(admitted) == 0 {
		// The audience is for members of an admitted kind, and this caller
		// is a member of nothing it admits.
		return membershipNotAdmitted(ctx)
	}
	// Several admitted organizations and none named: ambiguous, as in
	// resolveOrgScope — no scope, which a scoped model refuses, and the mark
	// that lets the gateway answer "name one" (markOrgUnnamed).
	markOrgUnnamed(ctx, headers)
	return nil
}

// audienceURLsNeeded is set by the oauth_server combination
// (oauth_server_kinds.go): only the consent page reads the audiences' MCP
// URLs, so only then is an unset one a boot error.
var audienceURLsNeeded bool

// parseAudienceTable reads w17_audiences once, at boot. A table that does not
// parse, or — with the consent page — names an MCP URL variable the deploy
// did not set, refuses to boot: either would quietly turn the consent page's
// filter off.
func parseAudienceTable(h *AuthServiceHandler) error {
	table, err := readAudienceTable(h.Audiences)
	if err != nil {
		return err
	}
	h.audiences, h.audiencesRead = table, true
	return nil
}

// audienceTable is the parsed table: the one ValidateConfig read at boot, or
// — for a handler that did not go through it — read now, so the consent
// filter and the invite check never fall open for want of a boot step.
func (h *AuthServiceHandler) audienceTable() ([]audienceEntry, error) {
	if h.audiencesRead {
		return h.audiences, nil
	}
	return readAudienceTable(h.Audiences)
}

func readAudienceTable(raw string) ([]audienceEntry, error) {
	var out []audienceEntry
	urls, names := map[string]string{}, map[string]bool{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) != 4 || parts[0] == "" {
			return nil, fmt.Errorf("auth plugin: w17_audiences entry %q is not <audience>:<kinds>:<URL variable>:<invites> — the table is generated; regenerate instead of editing it", entry)
		}
		if names[parts[0]] {
			return nil, fmt.Errorf("auth plugin: w17_audiences names audience %s twice", parts[0])
		}
		names[parts[0]] = true
		e := audienceEntry{name: parts[0], kinds: splitKinds(parts[1]), invites: splitKinds(parts[3])}
		if v := parts[2]; v != "" {
			e.url = strings.TrimRight(strings.TrimSpace(os.Getenv(v)), "/")
			if e.url == "" && audienceURLsNeeded {
				return nil, fmt.Errorf("auth plugin: %s is unset — the public URL of the %s audience's MCP surface, the same value its gateway reads; without it the consent page cannot tell which organizations that audience admits", v, e.name)
			}
			if prev, dup := urls[e.url]; dup && e.url != "" {
				return nil, fmt.Errorf("auth plugin: audiences %s and %s publish MCP at one URL (%s) — each audience's MCP surface needs its own", prev, e.name, e.url)
			}
			if e.url != "" {
				urls[e.url] = e.name
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// invitable is the kinds a caller this audience admits may invite: its
// `invites`, or its own kinds when it names none.
func (a audienceEntry) invitable() []string {
	if len(a.invites) > 0 {
		return a.invites
	}
	return a.kinds
}

func splitKinds(s string) []string {
	var out []string
	for _, k := range strings.Split(s, "|") {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// checkKindWithinCaller refuses a kind of membership the caller may not hand
// out in orgID: one no audience admits, or one the audiences admitting the
// caller's own kind there may not invite. A caller from outside the
// organization (the backoffice) may hand out any known kind when outsiders
// is set; ” (no kind) is always allowed.
func checkKindWithinCaller(ctx context.Context, h *AuthServiceHandler, callerID, orgID, kind string, outsiders bool) error {
	table, err := h.audienceTable()
	if err != nil {
		return err
	}
	// No audience names a kind: nothing is gated on the kind, so nothing
	// limits which one is handed out — the same as no audience at all.
	gated := false
	for _, a := range table {
		gated = gated || len(a.kinds) > 0
	}
	if !gated || kind == "" {
		return nil
	}
	refuse := func() error {
		return refusal(ctx, codes.PermissionDenied, "membership_kinds: the caller's kind of membership may not hand out this kind",
			CodeInviteKindNotAllowed, "kind", MsgInviteKindNotAllowed, nil)
	}
	known := false
	for _, a := range table {
		known = known || slices.Contains(a.kinds, kind)
	}
	if !known {
		return refuse()
	}
	_, all, err := admittedOrgs(ctx, h, callerID, nil)
	if err != nil {
		return err
	}
	m := orgByID(all, orgID)
	if m == nil {
		if outsiders {
			return nil
		}
		return refuse()
	}
	for _, a := range table {
		if slices.Contains(a.kinds, m.GetMembershipKind()) && slices.Contains(a.invitable(), kind) {
			return nil
		}
	}
	return refuse()
}

// UpdateOrgMembershipKind changes a member's kind of membership — staff to
// client, say — without removing and re-inviting them. Under the same rules
// as both halves: the caller must be allowed to manage the member (the role
// ceiling), and to hand out the new kind (as an invitation of it).
func (h *AuthServiceHandler) UpdateOrgMembershipKind(ctx context.Context, req *pb.UpdateOrgMembershipKindReq) (*pb.UpdateOrgMembershipKindResp, error) {
	if resp, done, err := underOrgLock(ctx, h, h.membershipOrg(ctx, req.GetId()), req, h.UpdateOrgMembershipKind); done {
		return resp, err
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	m, err := h.checkMayManageMembership(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if err := checkKindWithinCaller(ctx, h, callerID, m.GetOrgId(), req.GetKind(), true); err != nil {
		return nil, err
	}
	resp, err := h.Mutation.SetOrgMembershipKind(ctx, &pb.SetOrgMembershipKindReq{Id: req.GetId(), Kind: req.GetKind()})
	if err != nil {
		return nil, err
	}
	return &pb.UpdateOrgMembershipKindResp{MembershipId: resp.GetMembershipId()}, nil
}
