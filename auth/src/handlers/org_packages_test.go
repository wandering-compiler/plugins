package handlers

import (
	"context"
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
 {"name":"pro","methods":["ex.Notes.List","ex.Notes.Ask"],"audiences":["staff","client"]}],
 "governed":["ex.Notes.List","ex.Notes.Ask","ex.Notes.New"]}`

func pkgHandler(t *testing.T, live map[string][]string) (*AuthServiceHandler, *pkgMock) {
	t.Helper()
	m := &pkgMock{live: live}
	h := &AuthServiceHandler{Query: m, Mutation: m, PackagesTable: testPackages,
		Lock: &acllock.Lock{Permissions: map[string]int{"ex.Notes.List": 1, "ex.Notes.Ask": 2, "ex.Notes.New": 3, "auth.AuthService.ChangePassword": 9}}}
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
	if !slices.Equal(got, []int32{1, 9}) {
		t.Errorf("held = %v, want [1 9] (base grants List; Ask and New are outside it)", got)
	}
	// Realm-wide (no organization): untouched.
	p = &authPrincipal{grants: []*pb.RoleGrant{{RoleId: "r", PermissionIds: []int32{1, 2, 3}}}}
	if err := narrowGrantsToPackages(context.Background(), h, p, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if len(p.effectivePermissions(h.Lock)) != 3 {
		t.Errorf("a realm-wide request was narrowed")
	}
	// No packages at all: nothing governed is held.
	p = &authPrincipal{grants: []*pb.RoleGrant{{RoleId: "r", PermissionIds: []int32{1, 2, 3}}}}
	if err := narrowGrantsToPackages(context.Background(), h, p, map[string]string{"org_id": "org-none"}); err != nil {
		t.Fatal(err)
	}
	if got := p.effectivePermissions(h.Lock); len(got) != 0 {
		t.Errorf("an organization with no package holds %v", got)
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
