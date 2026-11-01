package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"slices"
	"strconv"

	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// This file implements the `org_membership` feature — GitHub-style
// multi-org membership (one identity belongs to MANY Organizations via
// OrgMembership), the generalization of single-tenant tenant_scope.
// Staged into a bundle only when the activation enables `org_membership`
// (plugin.yaml maps the feature to this file via go_files). With the
// feature off it is not staged, so the decorator below never registers and
// Authenticate stamps no org scope. Standalone (`go test`) always compiles
// it.

// orgScopeMetadataKey is the gRPC metadata key the gateway threads the
// request's ACTIVE-org selector under (the W17-Org header → w17-org). It is
// deliberately NOT in the reserved x-w17-* namespace: that namespace carries
// only VERIFIED auth/scope metadata the gateway sets from its auth response,
// and forwarding a client-controlled header into it would let a caller forge
// their org scope. The CLIENT chooses which org context to act in (a slug),
// but the plugin VALIDATES membership before stamping the trusted
// scopes[org_id] — see resolveOrgScope.
// The literal lives in the SDK: the REST gateway has to advertise this same
// header in its CORS preflight, and a second copy of the string is a second
// thing to forget. See principal.OrgScopeHeader.
const orgScopeMetadataKey = principal.OrgScopeHeader

// errOrgNotMember fails Authenticate closed when the request asks to act in
// an org the principal is not a member of (so a client can never scope into
// another org's data by setting the header).
var errOrgNotMember = errors.New("active org: caller is not a member of the requested organization")

// init wires the org-scope decorator on package load. The bundle imports
// this package (alias-imported under the activation name), so the init runs
// once during server bring-up.
func init() {
	orgMembershipStaged = true // see feature_marks.go

	// WhoAmI answers "who am I and where am I", not just "who".
	//
	// Before this, every screen rebuilt the org half from further calls and
	// none of them could say which organization an answer belonged to: the
	// active org travels in a HEADER, so a response carries no trace of it.
	// The UI therefore answered "which org is this" from its own memory — the
	// module-level state that, once stale, can show one organization's data
	// under another's name and fail every screen with a 401.
	//
	// Installed here rather than written into the base handler because both
	// the fields and the queries behind them exist only under org_membership.
	whoAmIEnrich = func(ctx context.Context, h *AuthServiceHandler, userID string, resp *pb.WhoAmIResp) {
		// Best-effort, deliberately. WhoAmI's job is to answer WHO the caller
		// is; the org half is enrichment, and failing the whole call because a
		// second query was unavailable would take down sign-in checks and
		// session probes with it. A caller that gets identity and no orgs is
		// in a worse state than usual, not a broken one.
		if list, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID}); err == nil {
			resp.Orgs = list.GetOrgs()
		}
		// The org the REQUEST resolved to, read from the same verified scope
		// the handlers act under — not re-derived from the header, which is
		// client-supplied and may name an org the caller does not belong to.
		// So this field says what the server DID, which is the only version
		// worth reporting.
		if orgID, err := activeOrgID(ctx); err == nil {
			resp.ActiveOrgId = orgID
		}
	}

	scopeDecorators = append(scopeDecorators, resolveOrgScope)
	grantNarrowers = append(grantNarrowers, narrowGrantsToActiveOrg)
}

// orgGrantSources are what other features grant a session INSIDE one
// organization, read by narrowGrantsToActiveOrg for the active one: teams
// appends its members' team roles. APPENDED from a feature file's init(), like
// grantNarrowers. A source answers role-attributed grants of org-scoped roles
// for that organization only — what it returns is added, never intersected.
var orgGrantSources []func(ctx context.Context, h *AuthServiceHandler, userID, orgID string) ([]*pb.RoleGrant, error)

// narrowGrantsToActiveOrg restricts the principal to what applies IN THE
// ACTIVE ORGANIZATION, and lets a team's roles add to it.
//
// Without the narrowing the two halves of this plugin disagree: scopes[org_id]
// isolates the caller's ROWS to one company while the grants stay the union of
// every role they hold in every company. An accountant in company A who is an
// admin of company B would carry B's permissions into A — the data would be
// A's, the rights B's.
//
// The intersection is over ROLE IDS, not permission ids, and that is what lets
// this run alongside api_token at all. Intersecting sets of permissions is only
// sound when one answer is a subset of the other, and neither query can see the
// other's axis: a permission reachable through a session-realm role scoped to
// org X *and* through an api-realm realm-wide role passed both filters for a
// session token acting in org Y, where neither role applies. Intersecting on
// roles removes the possibility — a permission survives only when ONE role
// grants it and that role passed every axis.
//
// Two cases for the narrowing, both subtractive:
//
//   - an active org — realm-wide roles plus those assigned inside that org.
//   - no active org (member of none, or of several with no `W17-Org` header)
//     — realm-wide roles alone. Falling back to the unfiltered set here would
//     reopen the leak on precisely the request that failed to name a company.
//
// Then the active organization's own session grants (orgGrantSources: a
// team's roles) — a session only, this organization only.
//
// Organization ownership adds nothing. It used to: a principal named by
// Organization.owner_id got a synthetic wildcard grant here, which expanded
// over the WHOLE deployed permission lock — realm-wide power through any app
// endpoint not row-scoped by org_id — and nothing in the plugin ever wrote the
// column. Whoever administers an organization holds a role in it, like
// everyone else (the column is gone; see Organization in models.proto).
// realmPermissionsScope is the scope Authenticate sets on a request acting
// inside an organization whose credential holds roles realm-wide: `*` for a
// realm-wide wildcard, otherwise the permission ids those roles grant,
// sorted and comma-separated. The backoffice may be a member somewhere: a
// plugin's backoffice method that refuses inside an organization reads it to
// act realm-wide for a caller holding the method realm-wide (the grant
// plugin's envelope decisions; this plugin's own ask heldRealmWide). Per
// credential and organization, never per method, so the gateway's auth cache
// keeps it right. Gateway-written (x-w17-scope-*, cleared from client input
// at the edge).
const realmPermissionsScope = "realm_permissions"

// orgPermissionsScope / orgProductRolesScope are what a request that names no
// organization was narrowed away from: the permissions (this domain's ids, or
// `*`) and the products' permission codes the caller holds only through roles
// inside organizations. The SDK spells them acllock.OrgPermissionsScope /
// acllock.OrgProductRolesScope; the plugin keeps its own copy, as it does for
// the gateway headers, so it builds against an SDK from before them.
//
// A gateway's gate reads them when a permission is missing, and answers
// ORGANIZATION_REQUIRED ("name the organization", W17-Org) instead of
// MISSING_PERMISSION ("no access") — the two were indistinguishable, so a
// product could not ask a member of several organizations which one to act
// in. They say only what the CALLER holds, never which organizations, and are
// written only when the request could have named one and did not
// (markOrgUnnamed). Gateway-written (x-w17-scope-*, cleared from client input
// at the edge), like realm_permissions.
const (
	orgPermissionsScope  = "org_permissions"
	orgProductRolesScope = "org_product_roles"
)

// orgUnnamedMemo is the request memo's mark that the request named no
// organization where it could have (the W17-Org selector is accepted there)
// and none was inferred — set by the org-scope resolution, read by the
// narrower and product_roles' answer. Its value is an orgUnnamedMark.
const orgUnnamedMemo = "org_membership.unnamed"

// orgUnnamedMark says which organizations the request could have named: every
// one the caller belongs to (anyOrg), or — on an audience that admits only
// some membership kinds — those it admits. A role held in an organization the
// audience would refuse is not "name it and you have it", so the hint leaves
// it out.
type orgUnnamedMark struct {
	anyOrg bool
	orgs   map[string]bool
}

// reaches reports whether naming orgID could reach a role held there.
func (m orgUnnamedMark) reaches(orgID string) bool { return m.anyOrg || m.orgs[orgID] }

// markOrgUnnamed records, for this Authenticate, that the request could have
// named an organization and did not: any of the caller's (admitted nil), or
// one of admitted. An audience whose tenant sources omit DEFAULT takes no
// selector, so naming one would be refused there: nothing to tell the caller
// to do, and nothing is marked.
func markOrgUnnamed(ctx context.Context, headers map[string]string, admitted []*pb.UserOrg) {
	if sources := tenantFromHeaders(headers); len(sources) > 0 && !slices.Contains(sources, tenantFromDefault) {
		return
	}
	memo := requestMemoOf(ctx)
	if memo == nil {
		return
	}
	mark := orgUnnamedMark{anyOrg: admitted == nil, orgs: map[string]bool{}}
	for _, o := range admitted {
		mark.orgs[o.GetOrgId()] = true
	}
	memo[orgUnnamedMemo] = mark
}

// orgUnnamed returns the mark markOrgUnnamed set, and whether it did.
func orgUnnamed(ctx context.Context) (orgUnnamedMark, bool) {
	v, ok := requestMemoOf(ctx)[orgUnnamedMemo].(orgUnnamedMark)
	return v, ok
}

// callerOnlyMethods act on the caller alone and never inside an organization,
// so naming one is no condition of calling them: ListMyOrgs is how a client
// learns which organization it could name. A request naming none keeps them
// from a role held inside an organization — never more than that role grants
// — instead of being refused, or told to name the organization it is asking
// for (ORGANIZATION_REQUIRED). w17ctl calls ListMyOrgs naming none.
var callerOnlyMethods = []string{"ListMyOrgs"}

// keepCallerOnly grants the request, of what aside (the roles a request
// naming no organization set aside) carries, the callerOnlyMethods.
func keepCallerOnly(ctx context.Context, h *AuthServiceHandler, p *authPrincipal, aside []*pb.RoleGrant) {
	var keep []int32
	for _, m := range callerOnlyMethods {
		// The auth service's own method, whatever service is being served:
		// a principal is also resolved for another service's call
		// (ResolveUser), where grpc.Method names that one.
		id, ok := lockIDOfServiceMethod(h.Lock, pb.AuthService_ServiceDesc.ServiceName, m)
		if !ok {
			continue
		}
		for _, g := range aside {
			if g.GetAllPermissions() || slices.Contains(g.GetPermissionIds(), int32(id)) {
				keep = append(keep, int32(id))
				break
			}
		}
	}
	if len(keep) > 0 {
		p.grants = append(p.grants, &pb.RoleGrant{PermissionIds: keep})
	}
}

// setAsideOrgPermissions stamps orgPermissionsScope: what `aside` — the grants
// of roles held inside organizations, which a request naming none does not
// count — would grant. A wildcard role makes it `*`.
//
// The hint can over-reach: an organization's packages or plan may still take
// a permission away once one is named, and then the caller reads
// MISSING_PERMISSION on the next request. It does not include a team's roles
// (orgGrantSources): those are read per organization, and a request naming
// none has no organization to read them for — a permission held only through
// a team stays MISSING_PERMISSION without the header.
func setAsideOrgPermissions(aside []*pb.RoleGrant, scopes map[string]string) {
	var ids []int32
	for _, g := range aside {
		if g.GetAllPermissions() {
			scopes[orgPermissionsScope] = "*"
			return
		}
		ids = append(ids, g.GetPermissionIds()...)
	}
	if len(ids) == 0 {
		return
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(int(id))
	}
	scopes[orgPermissionsScope] = strings.Join(parts, ",")
}

func narrowGrantsToActiveOrg(ctx context.Context, h *AuthServiceHandler, p *authPrincipal, scopes map[string]string) error {
	orgID := scopes["org_id"]

	var eligible []*pb.RoleGrant
	if orgID != "" {
		resp, err := h.Query.GetUserOrgPermissions(ctx, &pb.GetUserOrgPermissionsReq{
			UserId: p.userID,
			OrgId:  orgID,
		})
		if err != nil {
			return err
		}
		eligible = resp.GetGrants()
	} else {
		resp, err := h.Query.GetUserRealmWidePermissions(ctx, &pb.GetUserRealmWidePermissionsReq{UserId: p.userID})
		if err != nil {
			return err
		}
		eligible = resp.GetGrants()
	}

	keep := make(map[string]struct{}, len(eligible))
	for _, g := range eligible {
		keep[g.GetRoleId()] = struct{}{}
	}
	survivors := make([]*pb.RoleGrant, 0, len(p.grants))
	var aside []*pb.RoleGrant
	for _, g := range p.grants {
		if _, ok := keep[g.GetRoleId()]; ok {
			survivors = append(survivors, g)
		} else {
			aside = append(aside, g)
		}
	}
	p.grants = survivors
	if orgID == "" {
		keepCallerOnly(ctx, h, p, aside)
	}
	// A request that could have named an organization and did not keeps its
	// realm-wide roles only — and says what it set aside, so the gateway can
	// answer "name one" for a permission among them rather than "no access".
	if mark, ok := orgUnnamed(ctx); orgID == "" && ok {
		if !mark.anyOrg {
			// Only the roles held in an organization the audience admits:
			// naming another would be refused, so it is no fix to suggest.
			admittedRoles := map[string]bool{}
			for oid := range mark.orgs {
				resp, err := h.Query.GetUserOrgPermissions(ctx, &pb.GetUserOrgPermissionsReq{UserId: p.userID, OrgId: oid})
				if err != nil {
					return err
				}
				for _, g := range resp.GetGrants() {
					admittedRoles[g.GetRoleId()] = true
				}
			}
			aside = slices.DeleteFunc(aside, func(g *pb.RoleGrant) bool { return !admittedRoles[g.GetRoleId()] })
		}
		setAsideOrgPermissions(aside, scopes)
	}

	// A request acting inside an organization tells the backend what its
	// credential holds realm-wide there (realmPermissionsScope): another
	// plugin's backoffice method (the grant plugin's envelope decisions)
	// acts realm-wide on it, as this plugin's do on heldRealmWide; it cannot
	// read who holds what itself.
	if orgID != "" {
		realm, err := h.Query.GetUserRealmWidePermissions(ctx, &pb.GetUserRealmWidePermissionsReq{UserId: p.userID})
		if err != nil {
			return err
		}
		p.realmWide = make(map[string]bool, len(realm.GetGrants()))
		for _, g := range realm.GetGrants() {
			p.realmWide[g.GetRoleId()] = true
		}
		var ids []int32
		wildcard := false
		for _, g := range p.grants {
			if !p.realmWide[g.GetRoleId()] {
				continue
			}
			if g.GetAllPermissions() {
				wildcard = true
				break
			}
			ids = append(ids, g.GetPermissionIds()...)
		}
		switch {
		case wildcard:
			scopes[realmPermissionsScope] = "*"
		case len(ids) > 0:
			slices.Sort(ids)
			ids = slices.Compact(ids)
			parts := make([]string, len(ids))
			for i, id := range ids {
				parts[i] = strconv.Itoa(int(id))
			}
			scopes[realmPermissionsScope] = strings.Join(parts, ",")
		}
	}

	// Grants that exist only INSIDE the active organization and only for a
	// session — a team's roles (teams). They are added after the intersection
	// rather than run through it: they are org-scoped by construction (a team
	// belongs to one organization, and the source answers for this one), so
	// the eligible set has nothing to say about them, and an API token's
	// ceiling stays its holder's api-realm roles.
	if orgID != "" && p.realm == pb.TokenType_TOKEN_TYPE_SESSION {
		for _, source := range orgGrantSources {
			grants, err := source(ctx, h, p.userID, orgID)
			if err != nil {
				return err
			}
			p.grants = append(p.grants, grants...)
		}
	}

	return nil
}

// oauthOrgScope resolves the organization of an OAuth access token; set by
// the oauth_server + org_membership file (oauth_server_org.go), nil without
// it — and then no token carries an organization.
var oauthOrgScope func(ctx context.Context, h *AuthServiceHandler, userID, orgID string, headers, scopes, labels map[string]string) error

// membershipKindOf is the kind of a membership: "" here, its kind with
// membership_kinds (UserOrg.membership_kind is field-gated, so only that
// feature's file may name it).
var membershipKindOf = func(*pb.UserOrg) string { return "" }

// orgScopeByKind replaces resolveOrgScope's resolution when membership
// kinds are staged (membership_kinds.go); nil without them.
var orgScopeByKind func(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error

// The keys an audience gateway writes for the tenant's sources and the host
// (principal.TenantFromKey / principal.HostKey and the TenantFrom* values of
// the SDK that ships tenant_from), spelled here so the plugin builds against
// an SDK from before them.
const (
	tenantFromHeader  = "x-w17-tenant-from"
	hostHeader        = "x-w17-host"
	tenantFromHost    = "host"
	tenantFromDefault = "default"
)

// kindOfJoin stamps a membership's kind on a membership a registration
// creates without an invitation (org_signup); set by membership_kinds, nil
// without it — then a membership has no kind.
var kindOfJoin func(kind string, add *pb.AddOrgMembershipReq)

// orgSlugOfHost is the slug of the organization a host is bound to, "" for
// none; set by org_hosts (org_hosts.go), nil without it.
var orgSlugOfHost func(ctx context.Context, h *AuthServiceHandler, host string) (string, error)

// pickOrg is the organization a request acts in, before the membership check:
// a slug the request named (selector, path, host), or the caller's sole
// membership, or neither.
type pickOrg struct {
	slug string
	sole *pb.UserOrg
}

// chooseOrg decides which organization a request names, by the places its
// audience takes the tenant from (x-w17-tenant-from, in order; the
// gateway writes it, never a client). sole is the caller's only membership
// the request could act in, nil when there is not exactly one; it is asked
// only where inferring is allowed.
//
// Without sources (a gateway with no audience, or one that names none): the
// W17-Org selector, else the sole membership. With them, the first that
// names an organization decides:
//
//   - host: the organization the request's host is bound to (org_hosts);
//     an unbound host names nothing. A selector naming another organization
//     is refused — the host decided, and a request does not get to override
//     it — never followed.
//   - default: the selector, else the sole membership.
//   - invitation: names nothing on a request (it is read where an invitation
//     is accepted).
//
// A selector the audience does not take (its sources omit default, and no
// host decided) is refused rather than ignored: a client sending one expects
// it to count. Nothing named leaves the request in no organization.
//
// The refusals are notAdmittedError: Authenticate passes them to the caller
// as the 403 (or, for a deployment error, the FailedPrecondition) they carry
// instead of folding them into "You are not signed in." — the credential is
// fine, and signing in again would change nothing.
func chooseOrg(ctx context.Context, h *AuthServiceHandler, headers map[string]string, sole func() *pb.UserOrg) (pickOrg, error) {
	selector := orgSlugFromHeaders(headers)
	if selector == "" {
		selector = orgSlugFromContext(ctx)
	}
	inferred := func() (pickOrg, bool) {
		if h.NoOrgFromSoleMembership {
			return pickOrg{}, false
		}
		if o := sole(); o != nil {
			return pickOrg{sole: o}, true
		}
		return pickOrg{}, false
	}
	sources := tenantFromHeaders(headers)
	if len(sources) == 0 {
		if selector != "" {
			return pickOrg{slug: selector}, nil
		}
		p, _ := inferred()
		return p, nil
	}
	takesSelector := false
	for _, src := range sources {
		switch src {
		case tenantFromHost:
			if orgSlugOfHost == nil {
				return pickOrg{}, &notAdmittedError{err: status.Error(codes.FailedPrecondition,
					"org_membership: the audience takes the tenant from the host, and org_hosts is not activated")}
			}
			host := headerValue(headers, hostHeader)
			if host == "" {
				continue
			}
			slug, err := orgSlugOfHost(ctx, h, host)
			if err != nil {
				return pickOrg{}, err
			}
			if slug == "" {
				continue
			}
			if selector != "" && selector != slug {
				return pickOrg{}, &notAdmittedError{err: refusal(ctx, codes.PermissionDenied,
					"org_membership: the selector names another organization than the host is bound to",
					CodeOrgHostConflict, "", MsgOrgHostConflict, nil)}
			}
			return pickOrg{slug: slug}, nil
		case tenantFromDefault:
			takesSelector = true
			if selector != "" {
				return pickOrg{slug: selector}, nil
			}
			if p, ok := inferred(); ok {
				return p, nil
			}
		}
	}
	if selector != "" && !takesSelector {
		return pickOrg{}, &notAdmittedError{err: refusal(ctx, codes.PermissionDenied,
			"org_membership: the audience does not take the organization from a selector",
			CodeOrgSelectorNotAccepted, "", MsgOrgSelectorNotAccepted, nil)}
	}
	return pickOrg{}, nil
}

// tenantFromHeaders is the audience's tenant sources, in order; nil when its
// gateway names none.
func tenantFromHeaders(headers map[string]string) []string {
	v := headerValue(headers, tenantFromHeader)
	if v == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// headerValue reads a gateway-written key out of the AuthReq header map,
// whatever case a hand-built caller used.
func headerValue(headers map[string]string, key string) string {
	if v := headers[key]; v != "" {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// resolveOrgScope stamps scopes[org_id] for the request's ACTIVE org. The
// active org is a client-selected slug (w17-org metadata), but it is
// validated against the principal's membership here, so a caller can only
// ever scope into an org they belong to:
//
//   - a slug the caller IS a member of → scopes[org_id] = that org's id.
//   - a slug the caller is NOT a member of → fail closed (Authenticate
//     returns the same opaque Unauthenticated as every other failure).
//   - no header, and the caller belongs to exactly ONE org → that org,
//     unless org_from_sole_membership is off (NoOrgFromSoleMembership).
//     Unambiguous: there is no second org the request could have meant, and
//     the value is still read from OrgMembership, never from the request.
//   - through an audience that names where it takes the tenant from
//     (tenant_from), that order decides instead — see chooseOrg.
//   - no header, and the caller belongs to none or to several → no org
//     scope. Zero orgs has nothing to stamp; several is genuinely ambiguous
//     and guessing would pick which org a write lands in. Both leave the
//     scope unset, so a scoped model answers PermissionDenied ("missing
//     required scope: org_id") rather than quietly serving the wrong rows —
//     the caller resends with the header (`w17ctl` sends it from the org
//     chosen at `init`).
//
// The single-org inference exists because the alternative is worse than
// verbose: without it every request that omits the header fails on a scoped
// model, which on a one-org install is every request but `init`. It cannot
// widen access — one membership row means one reachable org either way.
//
// org_id is the data-scope key: a project scoping its rows by
// name: "org_id" then gets per-org isolation (auto-WHERE / owner-stamp)
// with no hand-written facade, exactly like tenant_scope's tenant_id.
func resolveOrgScope(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error {
	// The admin plane is realm-wide: no organization is selected, so only
	// realm-wide roles survive the narrowing (see AuthenticateAdmin).
	if onAdminPlane(ctx) {
		return nil
	}
	// Through an audience gateway that admits only some kinds of membership,
	// the resolution is membership_kinds.go's: it runs over the admitted
	// memberships alone. Any other gateway admits every membership, and the
	// resolution below is the same with or without kinds.
	if orgScopeByKind != nil && len(kindsFromHeaders(headers)) > 0 {
		return orgScopeByKind(ctx, h, userID, headers, scopes, labels)
	}
	// An OAuth access token belongs to the organization the user chose on
	// the consent page (oauth_server); its client names none.
	if orgID := oauthTokenOrg(ctx); orgID != "" {
		if oauthOrgScope == nil {
			return DeniedOrgNotMember(errOrgNotMember)
		}
		return oauthOrgScope(ctx, h, userID, orgID, headers, scopes, labels)
	}
	pick, err := chooseOrg(ctx, h, headers, func() *pb.UserOrg { return soleOrg(ctx, h, userID) })
	if err != nil {
		return err
	}
	if pick.sole != nil {
		stampOrg(scopes, labels, pick.sole.GetOrgId(), pick.sole.GetSlug())
		return nil
	}
	slug := pick.slug
	if slug == "" {
		markOrgUnnamed(ctx, headers, nil)
		return nil
	}
	// NotFound is "not a member", not a failure: a generated single-row read
	// reports no row as NotFound. Returned as an error it skipped the
	// ORG_NOT_MEMBER answer, so a caller who named the wrong org read "You are
	// not signed in.".
	//
	// Live membership is the only claim on an organization. Ownership
	// (Organization.owner_id) once was a second one, read when the membership
	// lookup found nothing; it is gone with the column, so a principal without
	// a live membership cannot select the organization, whoever created it.
	resp, err := h.Query.GetUserOrgBySlug(ctx, &pb.GetUserOrgBySlugReq{UserId: userID, Slug: slug})
	if notFoundOK(err) != nil {
		return err
	}
	orgID := resp.GetOrgId()
	if orgID == "" {
		return DeniedOrgNotMember(errOrgNotMember)
	}
	stampOrg(scopes, labels, orgID, slug)
	return nil
}

// stampOrg writes the resolved org to BOTH keys it owns.
//
// scopes[org_id] filters the caller's ROWS. labels[org_id] decides which
// connected clients an event reaches — and until it was written here, the
// console's data was per-org while its event stream was not: unlabelled
// events go to every authenticated client, so one org's activity was
// announced to all of them. The isolation was real in the database and
// absent one surface over.
//
// org_id is a legitimate audience key in a way most scopes are not: it
// partitions WHO may see a thing, not merely which rows belong to whom.
// scopes[user_id] deliberately gets no label — an event stream keyed by the
// acting user would deliver each public event to exactly one person.
func stampOrg(scopes, labels map[string]string, orgID, slug string) {
	scopes["org_id"] = orgID
	labels["org_id"] = orgID
	// The slug rides along as a scope so a consumer can RENDER the
	// organization without a second lookup. It is verified by construction:
	// the org was resolved BY this slug (or read off the membership row), so
	// the pair cannot disagree.
	//
	// A scope and not a label. Labels decide which connected clients an event
	// reaches, and an audience keyed by a display name is the same audience
	// keyed by its id — a second key for one thing, which is how two ways to
	// name the same audience drift apart.
	//
	// Its consumer today is the console stamping org_slug into a project's
	// lock: org_id is a UUID, and a UUID in a diff tells a reviewer nothing
	// about which organization a project just moved to.
	if slug != "" {
		scopes["org_slug"] = slug
	}
}

// soleOrg is the caller's organization when they have exactly one, nil
// otherwise. A lookup failure is NOT fatal: the caller simply gets no org
// scope, which a scoped model then refuses — the same outcome as having
// several orgs, and it keeps an unrelated query error from turning every
// unscoped request (login, `org list`) into an auth failure.
func soleOrg(ctx context.Context, h *AuthServiceHandler, userID string) *pb.UserOrg {
	resp, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		// Not fatal, and not silent: a scoped model then refuses with "missing
		// required scope", and this line is what says why.
		slog.WarnContext(ctx, "auth: sole-organization inference skipped: listing the caller's organizations failed", "user_id", userID, "error", err)
		return nil
	}
	if orgs := resp.GetOrgs(); len(orgs) == 1 && orgs[0].GetOrgId() != "" {
		return orgs[0]
	}
	return nil
}

// orgSlugFromHeaders reads the active-org selector out of the AuthReq
// header map — the SAME channel the bearer token arrives on, and the one
// every transport fills.
//
// This is the primary source, and the context read below is the fallback,
// because the context does NOT carry it on a public gRPC surface: the rpc
// gateway sanitizes the incoming metadata, passes it as AuthReq.Headers,
// and then calls Authenticate with the raw incoming context — which has no
// OUTGOING metadata, and the internal dialer installs no forwarding
// interceptor. REST worked only because its MetadataPropagation middleware
// stamps outgoing metadata before the handler runs.
//
// Nobody noticed because the one deployment with organizations has users
// who belong to exactly ONE of them, so the sole-org inference quietly supplied
// the right answer and the selector never had to work.
//
// Both gateways lowercase what they collect (REST from HTTP headers, rpc
// from metadata keys, which are lowercase by protocol), so one lookup
// covers both; the defensive scan handles a hand-built caller.
func orgSlugFromHeaders(headers map[string]string) string {
	if v := headers[orgScopeMetadataKey]; v != "" {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, orgScopeMetadataKey) {
			return v
		}
	}
	return ""
}

// orgSlugFromContext reads the gateway-forwarded active-org slug from the
// incoming gRPC metadata. Empty when absent.
func orgSlugFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get(orgScopeMetadataKey); len(v) > 0 {
		return v[0]
	}
	return ""
}

// ListMyOrgs returns the organizations the bearer-authenticated caller is a
// member of — for the CLI's `org list`, the login-time membership cache,
// and the init org picker. The caller is the gateway-resolved principal
// (callerUserID — same source as WhoAmI), never a client-sent user_id.
func (h *AuthServiceHandler) ListMyOrgs(ctx context.Context, _ *pb.ListMyOrgsReq) (*pb.ListMyOrgsResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	return &pb.ListMyOrgsResp{Orgs: resp.GetOrgs()}, nil
}

// errNoActiveOrg fires when an org-scoped RPC is called without a resolved
// active org. Authenticate stamps scopes[org_id] only after VALIDATING
// membership, so its absence means the caller named no org (no W17-Org
// header, and no sole org to infer) or is not a member of the one they
// named.
var errNoActiveOrg = status.Error(codes.FailedPrecondition,
	"no active organization for this request (send the W17-Org header naming an org you belong to)")

// activeOrgID returns the organization this request acts in — the one
// Authenticate resolved from the W17-Org header (or inferred, when the
// caller belongs to exactly one) and VALIDATED against membership.
//
// Read from the trusted scope, never from the request body. Every
// org-scoped RPC could have taken an org_id parameter and every one of them
// would then have had to remember to distrust it; the value that is already
// proven is right here, and a handler cannot forget to use the only org it
// is given.
func activeOrgID(ctx context.Context) (string, error) {
	orgID, ok := principal.Scope(ctx, "org_id")
	if !ok || orgID == "" {
		return "", errNoActiveOrg
	}
	return orgID, nil
}

// ListOrgMembers returns everyone in the caller's active organization.
//
// It lives HERE and not with the invitations, even though the two screens
// that use it are the same screen: the rpc is gated `org_membership`, and a
// handler staged under a different feature would leave an activation that
// enables membership WITHOUT invites holding an interface method nothing
// implements. That is not hypothetical — e2e-project's admin_auth
// activation is exactly that combination, and it is what caught this.
func (h *AuthServiceHandler) ListOrgMembers(ctx context.Context, req *pb.ListOrgMembersReq) (*pb.ListOrgMembersResp, error) {
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	size := int(req.GetPageSize())
	switch {
	case size <= 0:
		size = orgMembersPageDefault
	case size > orgMembersPageMax:
		size = orgMembersPageMax
	}
	after, err := orgMembersPageAfter(req.GetPageToken())
	if err != nil {
		return nil, err
	}
	// One row more than the page tells whether another page follows.
	resp, err := h.Query.ListOrgMembersByOrg(ctx, &pb.ListOrgMembersByOrgReq{OrgId: orgID, AfterEmail: after, Limit: int32(size + 1)})
	if err != nil {
		return nil, err
	}
	rows := resp.GetMembers()
	next := ""
	if len(rows) > size {
		rows = rows[:size]
		next = base64.RawURLEncoding.EncodeToString([]byte(rows[size-1].GetEmail()))
	}
	out := make([]*pb.OrgMember, 0, len(rows))
	for _, m := range rows {
		out = append(out, &pb.OrgMember{
			UserId:   m.GetUserId(),
			Email:    m.GetEmail(),
			Role:     m.GetRole(),
			JoinedAt: m.GetJoinedAt(),

			MembershipId: m.GetMembershipId(),
		})
	}
	return &pb.ListOrgMembersResp{Members: out, NextPageToken: next}, nil
}

// An organization's members are listed a page at a time
// (org_membership/members-paged): a large organization is never read whole
// into one answer.
const (
	orgMembersPageDefault = 100
	orgMembersPageMax     = 500
)

// orgMembersPageAfter decodes a page token — the last address of the previous
// page — into the keyset the query seeks past. An empty token is the first
// page.
func orgMembersPageAfter(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) == 0 || len(b) > 320 || !utf8.Valid(b) {
		return "", status.Error(codes.InvalidArgument, "org_membership: page_token is not one this list issued")
	}
	return string(b), nil
}

// heldRealmWide reports whether the caller holds the call being served —
// the backoffice method named method — through a realm-wide role: its
// permission, or a wildcard (org_membership/realm-call-acts-realm-wide). The
// backoffice's methods refuse a request acting inside an organization, which
// a caller who belongs to one is whenever they name none (the sole
// organization is inferred); held realm-wide, the call is the backoffice's
// wherever the request acts, and is refused only to one who holds it inside
// an organization alone. Asked of the store, not of the request's
// permissions: those are the organization's too.
func (h *AuthServiceHandler) heldRealmWide(ctx context.Context, method string) bool {
	if v, _ := principal.Scope(ctx, realmPermissionsScope); v == "*" {
		return true
	}
	userID, err := callerUserID(ctx)
	if err != nil {
		return false
	}
	id, ok := lockIDOfCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method)
	if !ok {
		return false
	}
	resp, err := h.Query.GetUserRealmWidePermissions(ctx, &pb.GetUserRealmWidePermissionsReq{UserId: userID})
	if err != nil {
		// Unknown: refused, as before.
		return false
	}
	for _, g := range resp.GetGrants() {
		if g.GetAllPermissions() || slices.Contains(g.GetPermissionIds(), int32(id)) {
			return true
		}
	}
	return false
}
