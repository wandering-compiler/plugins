package handlers

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// pkgMock answers the package reads and writes.
type pkgMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	live    map[string][]string // org → live package names
	enabled []string
	ended   []string
}

// GetUserRealmWidePermissions: nobody here holds a role realm-wide.
func (m *pkgMock) GetUserRealmWidePermissions(context.Context, *pb.GetUserRealmWidePermissionsReq, ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	return &pb.GetUserRealmWidePermissionsResp{}, nil
}

func (m *pkgMock) ListOrgPackages(_ context.Context, in *pb.ListOrgPackagesReq, _ ...grpc.CallOption) (*pb.ListOrgPackagesResp, error) {
	out := &pb.ListOrgPackagesResp{}
	for _, n := range m.live[in.GetOrgId()] {
		out.Packages = append(out.Packages, &pb.OrgPackageRow{Package: n})
	}
	return out, nil
}

func (m *pkgMock) EnableOrgPackage(_ context.Context, in *pb.EnableOrgPackageReq, _ ...grpc.CallOption) (*pb.EnableOrgPackageResp, error) {
	m.enabled = append(m.enabled, in.GetOrgId()+"/"+in.GetPackage())
	return &pb.EnableOrgPackageResp{}, nil
}

func (m *pkgMock) EndOrgPackage(_ context.Context, in *pb.EndOrgPackageReq, _ ...grpc.CallOption) (*pb.EndOrgPackageResp, error) {
	m.ended = append(m.ended, in.GetOrgId()+"/"+in.GetPackage())
	return &pb.EndOrgPackageResp{}, nil
}

const testPackages = `{"packages":[
 {"name":"base","methods":["ex.Notes.List"],"audiences":["staff"]},
 {"name":"pro","methods":["ex.Notes.List","ex.Notes.Ask"],"audiences":["staff","client"]},
 {"name":"floor","methods":["ex.Notes.New"],"default":true}],
 "governed":["ex.Notes.List","ex.Notes.Ask","ex.Notes.New"]}`

func pkgHandler(t *testing.T, live map[string][]string) (*AuthServiceHandler, *pkgMock) {
	t.Helper()
	m := &pkgMock{live: live}
	h := &AuthServiceHandler{Query: m, Mutation: m, PackagesTable: testPackages,
		Lock: &acllock.Lock{Permissions: map[string]int{"ex.Notes.List": 1, "ex.Notes.Ask": 2, "ex.Notes.New": 3, "auth.AuthService.ChangePassword": 9,
			"AUTH_AUTH_SERVICE_ADD_ORG_PACKAGE": 10, "AUTH_AUTH_SERVICE_REMOVE_ORG_PACKAGE": 11, "AUTH_AUTH_SERVICE_LIST_PACKAGES_OF_ORG": 12}}}
	if err := parsePackageTable(h); err != nil {
		t.Fatal(err)
	}
	return h, m
}

// In an organization the project's permissions are what its packages grant
// — whatever the roles say, a wildcard included — and a method no package
// grants (New) is held by nobody. A plugin's permission (9) is untouched.
func TestNarrowGrantsToPackages(t *testing.T) {
	h, _ := pkgHandler(t, map[string][]string{"org-a": {"base"}})
	p := &authPrincipal{grants: []*pb.RoleGrant{
		{RoleId: "r", PermissionIds: []int32{1, 2, 3, 9}},
		{RoleId: "owner", AllPermissions: true},
	}}
	if err := narrowGrantsToPackages(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatal(err)
	}
	got := p.effectivePermissions(h.Lock)
	slices.Sort(got)
	// base grants List (1) and the default floor New (3); Ask (2) is outside
	// both. The plugin's permissions (9, and the package methods 10-12 the
	// wildcard expands to) are not governed — refuseInsideOrg is what keeps an
	// org-admin off the package methods.
	if !slices.Equal(got, []int32{1, 3, 9, 10, 11, 12}) {
		t.Errorf("held = %v, want [1 3 9 10 11 12]", got)
	}
	// Realm-wide (no organization): untouched.
	p = &authPrincipal{grants: []*pb.RoleGrant{{RoleId: "r", PermissionIds: []int32{1, 2, 3}}}}
	if err := narrowGrantsToPackages(context.Background(), h, p, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if len(p.effectivePermissions(h.Lock)) != 3 {
		t.Errorf("a realm-wide request was narrowed")
	}
	// No package given: the default floor only.
	p = &authPrincipal{grants: []*pb.RoleGrant{{RoleId: "r", PermissionIds: []int32{1, 2, 3}}}}
	if err := narrowGrantsToPackages(context.Background(), h, p, map[string]string{"org_id": "org-none"}); err != nil {
		t.Fatal(err)
	}
	if got := p.effectivePermissions(h.Lock); !slices.Equal(got, []int32{3}) {
		t.Errorf("an organization given no package holds %v, want the default floor [3]", got)
	}
	// No lock, or the empty one a project without the ACL embeds: refused,
	// not unbounded.
	for _, l := range []*acllock.Lock{nil, {Version: 1}} {
		h.Lock = l
		if err := narrowGrantsToPackages(context.Background(), h, &authPrincipal{}, map[string]string{"org_id": "org-a"}); err == nil {
			t.Errorf("with lock %+v an organization went unbounded", l)
		}
	}
}

// An audience gateway admits an organization's member only when one of its
// packages opens that audience, and says so with a 403.
func TestRefuseAudienceOutsidePackages(t *testing.T) {
	h, _ := pkgHandler(t, map[string][]string{"org-a": {"base"}, "org-b": {"pro"}})
	call := func(org, aud string) error {
		return refuseAudienceOutsidePackages(context.Background(), h, "u",
			map[string]string{audienceHeader: aud}, map[string]string{"org_id": org}, nil)
	}
	if err := call("org-a", "staff"); err != nil {
		t.Errorf("base opens staff: %v", err)
	}
	if err := call("org-a", "client"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("base does not open client: err = %v, want PermissionDenied", err)
	}
	if err := call("org-b", "client"); err != nil {
		t.Errorf("pro opens client: %v", err)
	}
	if err := call("org-a", "partner"); err != nil {
		t.Errorf("an audience no package names is open: %v", err)
	}
}

// Packages are given realm-wide: a call from inside an organization is
// refused, and so is a package the domain does not declare.
func TestAddOrgPackage(t *testing.T) {
	h, m := pkgHandler(t, map[string][]string{"org-a": {"base"}})
	inOrg := whoAmICtx("admin", "org-a")
	if _, err := h.AddOrgPackage(inOrg, &pb.AddOrgPackageReq{OrgId: "org-a", Package: "pro"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("from inside the organization: err = %v, want PermissionDenied", err)
	}
	realm := whoAmICtx("backoffice", "")
	if _, err := h.AddOrgPackage(realm, &pb.AddOrgPackageReq{OrgId: "org-a", Package: "gold"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an undeclared package: err = %v, want InvalidArgument", err)
	}
	if _, err := h.AddOrgPackage(realm, &pb.AddOrgPackageReq{OrgId: "org-a", Package: "base"}); err != nil || len(m.enabled) != 0 {
		t.Errorf("a package already given: err = %v, wrote %v", err, m.enabled)
	}
	if _, err := h.AddOrgPackage(realm, &pb.AddOrgPackageReq{OrgId: "org-a", Package: "pro"}); err != nil || !slices.Equal(m.enabled, []string{"org-a/pro"}) {
		t.Errorf("giving pro: err = %v, wrote %v", err, m.enabled)
	}
	if _, err := h.RemoveOrgPackage(realm, &pb.RemoveOrgPackageReq{OrgId: "org-a", Package: "base"}); err != nil || !slices.Equal(m.ended, []string{"org-a/base"}) {
		t.Errorf("taking base: err = %v, ended %v", err, m.ended)
	}
}

// A default package is neither given nor taken; listing an organization's
// packages shows it.
func TestDefaultPackageIsNotGivenOrTaken(t *testing.T) {
	h, _ := pkgHandler(t, map[string][]string{"org-a": {"base"}})
	ctx := whoAmICtx("ops", "")
	if _, err := h.AddOrgPackage(ctx, &pb.AddOrgPackageReq{OrgId: "org-a", Package: "floor"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("giving the default: err = %v, want FailedPrecondition", err)
	}
	if _, err := h.RemoveOrgPackage(ctx, &pb.RemoveOrgPackageReq{OrgId: "org-a", Package: "floor"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("taking the default: err = %v, want FailedPrecondition", err)
	}
	resp, err := h.ListPackagesOfOrg(ctx, &pb.ListPackagesOfOrgReq{OrgId: "org-a"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range resp.GetPackages() {
		got = append(got, fmt.Sprintf("%s/%v", p.GetPackage(), p.GetDefault()))
	}
	if !slices.Equal(got, []string{"floor/true", "base/false"}) {
		t.Errorf("listed %v, want the default floor and the given base", got)
	}
}

// Without the endpoint ACL nobody gives packages: the method is not in the
// lock.
func TestAddOrgPackageNeedsTheACL(t *testing.T) {
	h, _ := pkgHandler(t, nil)
	h.Lock = &acllock.Lock{Permissions: map[string]int{"ex.Notes.List": 1}}
	if _, err := h.AddOrgPackage(whoAmICtx("anyone", ""), &pb.AddOrgPackageReq{OrgId: "org-a", Package: "pro"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("err = %v, want PermissionDenied", err)
	}
}

func TestReadPackageTable(t *testing.T) {
	if tb, err := readPackageTable(""); tb != nil || err != nil {
		t.Errorf("empty: %v %v", tb, err)
	}
	if _, err := readPackageTable("{not json"); err == nil {
		t.Error("a table that does not parse booted")
	}
	if _, err := readPackageTable(`{"packages":[{"methods":["a"]}]}`); err == nil {
		t.Error("a nameless package booted")
	}
}

// Served as a project's service (an activation named admin_auth), the call is
// found under that service's key — and a key with only the same tail is not
// it.
func TestLockGatesCall(t *testing.T) {
	l := &acllock.Lock{Permissions: map[string]int{"ADMIN_AUTH_AUTH_SERVICE_ADD_ORG_PACKAGE": 1, "BILLING_AUTH_SERVICE_REMOVE_ORG_PACKAGE": 2}}
	served := func(method string) context.Context {
		return grpc.NewContextWithServerTransportStream(context.Background(), &methodStream{method: method})
	}
	if !lockGatesCall(served("/e2e.app.admin_auth.AuthService/AddOrgPackage"), l, pb.AuthService_ServiceDesc.ServiceName, "AddOrgPackage") {
		t.Error("the project's own key was not found")
	}
	if lockGatesCall(served("/e2e.app.admin_auth.AuthService/RemoveOrgPackage"), l, pb.AuthService_ServiceDesc.ServiceName, "RemoveOrgPackage") {
		t.Error("another service's key with the same tail passed")
	}
}

type methodStream struct {
	grpc.ServerTransportStream
	method string
}

func (s *methodStream) Method() string { return s.method }
