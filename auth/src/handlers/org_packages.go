package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"
	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_packages` feature: what an organization's
// members can hold is bounded by the packages the organization has been
// given (w17/packages.proto in the SDK). A project names its packages — sets
// of its methods and audiences — in the domain's protos; codegen hands them
// to this plugin as the generated w17_packages table; the backoffice gives an
// organization whole packages (AddOrgPackage / RemoveOrgPackage, realm-wide).
//
// On every Authenticate acting in an organization:
//
//   - a GOVERNED permission — one of a project method, which the table lists
//     — survives only when one of the organization's packages grants it,
//     whatever the caller's roles say, the owner's wildcard included. A
//     method no package grants is held by nobody there (default deny);
//     a plugin's methods (sign-in, the account's own settings) are not
//     governed unless a package lists them;
//   - an audience gateway whose audience some package names admits the
//     caller only when one of the organization's packages names it; an
//     audience no package names is open;
//   - a `default` package is every organization's without being given (and
//     cannot be taken).
//
// Handing roles out needs nothing more: the role ceiling is what the caller
// holds in this request, which is already bounded by the packages, so nobody
// grants or composes a role above the organization's packages. Realm-wide
// requests (the backoffice's own, no organization) are not narrowed.

var errPackageAudienceOff = errors.New("org_packages: the organization's packages do not open this audience")

func init() {
	configChecks = append(configChecks, parsePackageTable)
	scopeDecorators = append(scopeDecorators, refuseAudienceOutsidePackages)
	grantNarrowers = append(grantNarrowers, narrowGrantsToPackages)
}

// parsePackageTable reads w17_packages once, at boot; a table that does not
// parse refuses to boot rather than leave an organization unbounded.
func parsePackageTable(h *AuthServiceHandler) error {
	t, err := readPackageTable(h.PackagesTable)
	if err != nil {
		return err
	}
	h.packages, h.packagesRead = t, true
	return nil
}

// packageTable returns the parsed table: the one read at boot, or — for a
// handler that skipped ValidateConfig — read now, so the bound never falls
// open for want of a boot step. nil when the domain declares no packages.
func (h *AuthServiceHandler) packageTable() (*orgPackageTable, error) {
	if h.packagesRead {
		return h.packages, nil
	}
	return readPackageTable(h.PackagesTable)
}

func readPackageTable(raw string) (*orgPackageTable, error) {
	if raw == "" {
		return nil, nil
	}
	var t orgPackageTable
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return nil, fmt.Errorf("auth plugin: w17_packages does not parse (%w) — the table is generated; regenerate instead of editing it", err)
	}
	t.byName, t.gatedAudiences = map[string]orgPackage{}, map[string]bool{}
	for _, p := range t.Packages {
		if p.Name == "" {
			return nil, fmt.Errorf("auth plugin: w17_packages names a package with no name — regenerate")
		}
		t.byName[p.Name] = p
		for _, a := range p.Audiences {
			t.gatedAudiences[a] = true
		}
	}
	return &t, nil
}

// orgPackagesOf is the packages orgID holds: the default ones, and the live
// rows the table still declares (a package dropped from the protos grants
// nothing). Read once per Authenticate: the audience check and the narrowing
// both ask, through the request's memo.
func orgPackagesOf(ctx context.Context, h *AuthServiceHandler, t *orgPackageTable, orgID string) ([]orgPackage, error) {
	if m := requestMemoOf(ctx); m != nil {
		if v, ok := m["org_packages:"+orgID].([]orgPackage); ok {
			return v, nil
		}
	}
	out, err := readOrgPackages(ctx, h, t, orgID)
	if err == nil {
		if m := requestMemoOf(ctx); m != nil {
			m["org_packages:"+orgID] = out
		}
	}
	return out, err
}

func readOrgPackages(ctx context.Context, h *AuthServiceHandler, t *orgPackageTable, orgID string) ([]orgPackage, error) {
	resp, err := h.Query.ListOrgPackages(ctx, &pb.ListOrgPackagesReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	var out []orgPackage
	for _, p := range t.Packages {
		if p.Default {
			out = append(out, p)
		}
	}
	for _, r := range resp.GetPackages() {
		if p, ok := t.byName[r.GetPackage()]; ok && !p.Default {
			out = append(out, p)
		}
	}
	return out, nil
}

// refuseAudienceOutsidePackages is the audience half: a scope decorator, so
// its refusal reaches the caller as the 403 it is rather than a sign-in
// prompt.
func refuseAudienceOutsidePackages(ctx context.Context, h *AuthServiceHandler, _ string, headers, scopes, _ map[string]string) error {
	t, err := h.packageTable()
	if err != nil {
		return err
	}
	aud, orgID := headers[audienceHeader], scopes["org_id"]
	if t == nil || !t.gatedAudiences[aud] || orgID == "" {
		return nil
	}
	pkgs, err := orgPackagesOf(ctx, h, t, orgID)
	if err != nil {
		return err
	}
	for _, p := range pkgs {
		if slices.Contains(p.Audiences, aud) {
			return nil
		}
	}
	return &notAdmittedError{err: refusal(ctx, codes.PermissionDenied, errPackageAudienceOff.Error(),
		CodePackageAudienceOff, "", MsgPackageAudienceOff, nil)}
}

// narrowGrantsToPackages drops, from every grant the caller holds in the
// active organization, the governed permissions none of its packages grants.
func narrowGrantsToPackages(ctx context.Context, h *AuthServiceHandler, p *authPrincipal, scopes map[string]string) error {
	t, err := h.packageTable()
	if err != nil {
		return err
	}
	orgID := scopes["org_id"]
	if t == nil || orgID == "" {
		return nil
	}
	if !lockHasPermissions(h.Lock) {
		// Nothing to look the methods up in (a project without the ACL gets
		// an empty lock): refuse rather than leave the organization unbounded.
		return status.Error(codes.FailedPrecondition, "org_packages: no ACL lock to bound the organization's permissions with — packages need the endpoint ACL")
	}
	pkgs, err := orgPackagesOf(ctx, h, t, orgID)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, pk := range pkgs {
		for _, m := range pk.Methods {
			allowed[m] = true
		}
	}
	denied := map[int32]bool{}
	for _, code := range t.Governed {
		if id, ok := acllock.IDByString(h.Lock, code); ok && !allowed[code] {
			denied[int32(id)] = true
		}
	}
	if len(denied) == 0 {
		return nil
	}
	for _, g := range p.grants {
		ids := g.GetPermissionIds()
		if g.GetAllPermissions() {
			// A wildcard is expanded here, so the expansion is bounded too.
			ids = acllock.GrantAll(h.Lock)
			g.AllPermissions = false
		}
		kept := make([]int32, 0, len(ids))
		for _, id := range ids {
			if !denied[id] {
				kept = append(kept, id)
			}
		}
		g.PermissionIds = kept
	}
	return nil
}

// refuseInsideOrg holds the backoffice's calls to the realm: an organization
// does not give itself packages, whatever roles its admins hold. A request
// acts in an organization when it names one or when its caller belongs to
// exactly one (resolveOrgScope infers it) — so the backoffice acts from
// accounts that belong to no organization.
//
// And who may call it at all is the project's endpoint ACL: the method must
// be in the deployed lock, or nobody may — without an ACL any signed-in
// account outside an organization would pass. method is the RPC's name
// (lockGatesCall finds its key).
func (h *AuthServiceHandler) refuseInsideOrg(ctx context.Context, method string) error {
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" {
		return refusal(ctx, codes.PermissionDenied, "org_packages: packages are given realm-wide, not from inside an organization",
			CodePackagesRealmOnly, "", MsgPackagesRealmOnly, nil)
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "org_packages: the backoffice's package methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

func (h *AuthServiceHandler) checkPackageName(ctx context.Context, name string) error {
	t, err := h.packageTable()
	if err != nil {
		return err
	}
	if t == nil || t.byName[name].Name == "" {
		return refusal(ctx, codes.InvalidArgument, "org_packages: no such package", CodePackageUnknown, "package", MsgPackageUnknown, nil)
	}
	if t.byName[name].Default {
		return refusal(ctx, codes.FailedPrecondition, "org_packages: a default package is every organization's; it is not given or taken",
			CodePackageDefault, "package", MsgPackageDefault, nil)
	}
	return nil
}

// AddOrgPackage gives an organization a package. Giving one it already has
// changes nothing.
func (h *AuthServiceHandler) AddOrgPackage(ctx context.Context, req *pb.AddOrgPackageReq) (*pb.AddOrgPackageResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseInsideOrg(ctx, "AddOrgPackage"); err != nil {
		return nil, err
	}
	if err := h.checkPackageName(ctx, req.GetPackage()); err != nil {
		return nil, err
	}
	live, err := h.Query.ListOrgPackages(ctx, &pb.ListOrgPackagesReq{OrgId: req.GetOrgId()})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	for _, r := range live.GetPackages() {
		if r.GetPackage() == req.GetPackage() {
			return &pb.AddOrgPackageResp{}, nil
		}
	}
	// A concurrent add of the same package lands on the unique index: it is
	// given either way, which is what was asked.
	if _, err := h.Mutation.EnableOrgPackage(ctx, &pb.EnableOrgPackageReq{
		OrgId: req.GetOrgId(), Package: req.GetPackage(), EnabledBy: caller,
	}); err != nil && !isUniqueConflict(err) {
		return nil, err
	}
	return &pb.AddOrgPackageResp{}, nil
}

// RemoveOrgPackage takes a package from an organization; its members lose
// what only it granted on their next request. Taking one it does not have
// changes nothing.
func (h *AuthServiceHandler) RemoveOrgPackage(ctx context.Context, req *pb.RemoveOrgPackageReq) (*pb.RemoveOrgPackageResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseInsideOrg(ctx, "RemoveOrgPackage"); err != nil {
		return nil, err
	}
	// A package dropped from the protos may still be taken (its row ends);
	// a default one is never given, so never taken.
	if t, err := h.packageTable(); err != nil {
		return nil, err
	} else if t != nil && t.byName[req.GetPackage()].Default {
		return nil, refusal(ctx, codes.FailedPrecondition, "org_packages: a default package is every organization's; it is not given or taken",
			CodePackageDefault, "package", MsgPackageDefault, nil)
	}
	if _, err := h.Mutation.EndOrgPackage(ctx, &pb.EndOrgPackageReq{
		OrgId: req.GetOrgId(), Package: req.GetPackage(), EndedBy: caller,
	}); err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return &pb.RemoveOrgPackageResp{}, nil
}

// ListPackagesOfOrg is the backoffice's view of one organization.
func (h *AuthServiceHandler) ListPackagesOfOrg(ctx context.Context, req *pb.ListPackagesOfOrgReq) (*pb.OrgPackagesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseInsideOrg(ctx, "ListPackagesOfOrg"); err != nil {
		return nil, err
	}
	return h.orgPackagesResp(ctx, req.GetOrgId())
}

// ListMyOrgPackages is the active organization's own packages.
func (h *AuthServiceHandler) ListMyOrgPackages(ctx context.Context, req *pb.ListMyOrgPackagesReq) (*pb.OrgPackagesResp, error) {
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
	return h.orgPackagesResp(ctx, orgID)
}

func (h *AuthServiceHandler) orgPackagesResp(ctx context.Context, orgID string) (*pb.OrgPackagesResp, error) {
	live, err := h.Query.ListOrgPackages(ctx, &pb.ListOrgPackagesReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	// What the organization holds, as Authenticate counts it: the default
	// packages, then the given ones.
	out := &pb.OrgPackagesResp{}
	t, err := h.packageTable()
	if err != nil {
		return nil, err
	}
	if t != nil {
		for _, p := range t.Packages {
			if p.Default {
				out.Packages = append(out.Packages, &pb.OrgPackageInfo{Package: p.Name, Default: true})
			}
		}
	}
	for _, r := range live.GetPackages() {
		if t != nil && t.byName[r.GetPackage()].Default {
			continue
		}
		out.Packages = append(out.Packages, &pb.OrgPackageInfo{Package: r.GetPackage(), EnabledAt: r.GetEnabledAt()})
	}
	return out, nil
}
