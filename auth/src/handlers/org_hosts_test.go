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

// hostMock is orgMock with the host bindings (org_hosts) beside it.
type hostMock struct {
	orgMock
	hosts map[string]*pb.OrgHostRow // live bindings by host
	bound []string
	ended []string
}

func (m *hostMock) GetOrgOfHost(_ context.Context, in *pb.GetOrgOfHostReq, _ ...grpc.CallOption) (*pb.OrgHostRow, error) {
	if r := m.hosts[in.GetHost()]; r != nil {
		return r, nil
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (m *hostMock) ListOrgHostRows(context.Context, *pb.ListOrgHostRowsReq, ...grpc.CallOption) (*pb.ListOrgHostRowsResp, error) {
	out := &pb.ListOrgHostRowsResp{}
	for _, r := range m.hosts {
		out.Hosts = append(out.Hosts, r)
	}
	return out, nil
}

func (m *hostMock) BindOrgHostRow(_ context.Context, in *pb.BindOrgHostRowReq, _ ...grpc.CallOption) (*pb.BindOrgHostRowResp, error) {
	m.bound = append(m.bound, in.GetHost()+"→"+in.GetOrgId())
	return &pb.BindOrgHostRowResp{}, nil
}

func (m *hostMock) EndOrgHostRow(_ context.Context, in *pb.EndOrgHostRowReq, _ ...grpc.CallOption) (*pb.EndOrgHostRowResp, error) {
	m.ended = append(m.ended, in.GetHost())
	return &pb.EndOrgHostRowResp{}, nil
}

// bob is a member of acme and globex; acme.example.com serves acme.
func hostFixture() *hostMock {
	return &hostMock{
		orgMock: orgMock{
			orgsByUser: map[string][]*pb.UserOrg{
				"bob": {{OrgId: "org-acme", Slug: "acme", MembershipKind: "client"}, {OrgId: "org-globex", Slug: "globex", MembershipKind: "client"}},
				"sam": {{OrgId: "org-globex", Slug: "globex", MembershipKind: "client"}},
			},
			bySlug: map[string]*pb.GetUserOrgBySlugResp{
				"bob|acme": {OrgId: "org-acme"}, "bob|globex": {OrgId: "org-globex"}, "sam|globex": {OrgId: "org-globex"},
			},
		},
		hosts: map[string]*pb.OrgHostRow{"acme.example.com": {Host: "acme.example.com", OrgId: "org-acme", Slug: "acme"}},
	}
}

// resolveVia runs resolveOrgScope as an audience gateway calls it: its
// tenant sources, the host and the selector in the header map.
func resolveVia(h *AuthServiceHandler, user, from, host, selector, kinds string) (string, error) {
	headers := map[string]string{}
	if from != "" {
		headers[tenantFromHeader] = from
	}
	if host != "" {
		headers[hostHeader] = host
	}
	if selector != "" {
		headers["w17-org"] = selector
	}
	if kinds != "" {
		headers[membershipKindsHeader] = kinds
	}
	scopes := map[string]string{}
	err := resolveOrgScope(context.Background(), h, user, headers, scopes, map[string]string{})
	return scopes["org_id"], err
}

// The audience's tenant sources decide which organization a request names,
// in order, with or without membership kinds; the caller still needs a
// membership there.
func TestResolveOrgScope_TenantFromHost(t *testing.T) {
	for _, kinds := range []string{"", "client"} {
		for _, c := range []struct {
			name, user, from, host, selector string
			noSole                           bool
			want, code                       string
		}{
			{name: "the host decides", user: "bob", from: "host,default", host: "acme.example.com", want: "org-acme"},
			{name: "a selector agreeing with the host", user: "bob", from: "host,default", host: "acme.example.com", selector: "acme", want: "org-acme"},
			{name: "a selector naming another organization than the host", user: "bob", from: "host,default", host: "acme.example.com", selector: "globex", code: CodeOrgHostConflict},
			{name: "an unbound host falls to the selector", user: "bob", from: "host,default", host: "other.example.com", selector: "globex", want: "org-globex"},
			{name: "an unbound host, several organizations, no selector", user: "bob", from: "host,default", host: "other.example.com"},
			{name: "an unbound host falls to the sole membership", user: "sam", from: "host,default", host: "other.example.com", want: "org-globex"},
			{name: "the sole membership switched off", user: "sam", from: "host,default", host: "other.example.com", noSole: true},
			{name: "a host-only audience ignores no selector: it refuses one", user: "bob", from: "host", host: "other.example.com", selector: "globex", code: CodeOrgSelectorNotAccepted},
			{name: "a host-only audience never infers", user: "sam", from: "host", host: "other.example.com"},
			{name: "a host of an organization the caller is no member of", user: "sam", from: "host,default", host: "acme.example.com", code: "not a member"},
			{name: "default before host: the selector decides first", user: "bob", from: "default,host", host: "acme.example.com", selector: "globex", want: "org-globex"},
			{name: "no sources: the selector", user: "bob", selector: "globex", want: "org-globex"},
			{name: "no sources: the sole membership", user: "sam", want: "org-globex"},
			{name: "no sources, the sole membership switched off", user: "sam", noSole: true},
		} {
			t.Run(kinds+"/"+c.name, func(t *testing.T) {
				h := &AuthServiceHandler{Query: hostFixture(), NoOrgFromSoleMembership: c.noSole}
				got, err := resolveVia(h, c.user, c.from, c.host, c.selector, kinds)
				switch {
				case c.code == "not a member":
					if err == nil {
						t.Errorf("acted in %q, want a refusal", got)
					}
				case c.code != "":
					if _, code := detailCode(t, err); code != c.code {
						t.Errorf("err = %v, want %s", err, c.code)
					}
				case err != nil:
					t.Errorf("err = %v", err)
				case got != c.want:
					t.Errorf("acted in %q, want %q", got, c.want)
				}
			})
		}
	}
}

// Switched off, the inference does not even read the memberships: nothing
// it could find would be used.
func TestResolveOrgScope_SoleInferenceOffReadsNothing(t *testing.T) {
	m := hostFixture()
	h := &AuthServiceHandler{Query: m, NoOrgFromSoleMembership: true}
	if got, err := resolveVia(h, "sam", "", "", "", ""); err != nil || got != "" || m.listCalls != 0 {
		t.Errorf("acted in %q, err %v, %d membership reads", got, err, m.listCalls)
	}
}

// An audience naming the host without org_hosts activated is a deployment
// error, said on every request rather than quietly skipped.
func TestResolveOrgScope_HostWithoutOrgHosts(t *testing.T) {
	saved := orgSlugOfHost
	orgSlugOfHost = nil
	defer func() { orgSlugOfHost = saved }()
	h := &AuthServiceHandler{Query: hostFixture()}
	if _, err := resolveVia(h, "bob", "host,default", "acme.example.com", "", ""); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
}

func hostsHandler(m *hostMock) *AuthServiceHandler {
	return &AuthServiceHandler{Query: m, Mutation: m, Lock: &acllock.Lock{Permissions: map[string]int{
		"AUTH_AUTH_SERVICE_BIND_ORG_HOST": 1, "AUTH_AUTH_SERVICE_UNBIND_ORG_HOST": 2, "AUTH_AUTH_SERVICE_LIST_ORG_HOSTS": 3,
	}}}
}

// The backoffice binds hosts realm-wide: never from inside an organization,
// never a host bound to another organization, never a non-host.
func TestBindOrgHost(t *testing.T) {
	m := hostFixture()
	h := hostsHandler(m)
	inOrg := whoAmICtx("admin", "org-acme")
	if _, err := h.BindOrgHost(inOrg, &pb.BindOrgHostReq{Host: "acme.example.org", OrgId: "org-acme"}); refusalCodeOf(err) != CodeHostsRealmOnly {
		t.Errorf("from inside an organization: err = %v, want %s", err, CodeHostsRealmOnly)
	}
	realm := whoAmICtx("ops", "")
	for _, bad := range []string{"acme", "https://acme.example.org", "acme.example.org:443", "acme..example.org", ""} {
		if _, err := h.BindOrgHost(realm, &pb.BindOrgHostReq{Host: bad, OrgId: "org-acme"}); refusalCodeOf(err) != CodeHostInvalid {
			t.Errorf("host %q: err = %v, want %s", bad, err, CodeHostInvalid)
		}
	}
	if _, err := h.BindOrgHost(realm, &pb.BindOrgHostReq{Host: "acme.example.com", OrgId: "org-globex"}); refusalCodeOf(err) != CodeHostTaken {
		t.Errorf("a host bound to another organization: err = %v, want %s", err, CodeHostTaken)
	}
	if _, err := h.BindOrgHost(realm, &pb.BindOrgHostReq{Host: "Acme.Example.com.", OrgId: "org-acme"}); err != nil || len(m.bound) != 0 {
		t.Errorf("binding a host again to its organization: err = %v, wrote %v", err, m.bound)
	}
	if _, err := h.BindOrgHost(realm, &pb.BindOrgHostReq{Host: "Globex.Example.com", OrgId: "org-globex"}); err != nil || !slices.Equal(m.bound, []string{"globex.example.com→org-globex"}) {
		t.Errorf("binding a new host: err = %v, wrote %v", err, m.bound)
	}
	if _, err := h.UnbindOrgHost(realm, &pb.UnbindOrgHostReq{Host: "acme.example.com"}); err != nil || !slices.Equal(m.ended, []string{"acme.example.com"}) {
		t.Errorf("unbinding: err = %v, ended %v", err, m.ended)
	}
	if _, err := h.UnbindOrgHost(inOrg, &pb.UnbindOrgHostReq{Host: "acme.example.com"}); refusalCodeOf(err) != CodeHostsRealmOnly {
		t.Errorf("unbinding from inside an organization: err = %v", err)
	}
	if _, err := h.ListOrgHosts(inOrg, &pb.ListOrgHostsReq{}); refusalCodeOf(err) != CodeHostsRealmOnly {
		t.Errorf("listing from inside an organization: err = %v", err)
	}
}

// Without the endpoint ACL the backoffice's host methods refuse: nothing
// else would stop any signed-in account outside an organization.
func TestBindOrgHostNeedsTheACL(t *testing.T) {
	m := hostFixture()
	h := &AuthServiceHandler{Query: m, Mutation: m, Lock: &acllock.Lock{}}
	if _, err := h.BindOrgHost(whoAmICtx("ops", ""), &pb.BindOrgHostReq{Host: "globex.example.com", OrgId: "org-globex"}); status.Code(err) != codes.PermissionDenied || len(m.bound) != 0 {
		t.Errorf("err = %v, wrote %v", err, m.bound)
	}
}

// Anyone may ask which organization a host serves; a host bound to none, or
// no host at all, is found = false and never an error.
func TestGetHostOrg(t *testing.T) {
	h := hostsHandler(hostFixture())
	ctx := context.Background()
	resp, err := h.GetHostOrg(ctx, &pb.GetHostOrgReq{Host: "ACME.example.com"})
	if err != nil || !resp.GetFound() || resp.GetOrgId() != "org-acme" || resp.GetSlug() != "acme" {
		t.Errorf("a bound host: %v, err %v", resp, err)
	}
	for _, host := range []string{"other.example.com", "not a host"} {
		resp, err = h.GetHostOrg(ctx, &pb.GetHostOrgReq{Host: host})
		if err != nil || resp.GetFound() || resp.GetOrgId() != "" {
			t.Errorf("%q: %v, err %v", host, resp, err)
		}
	}
}

// refusalCodeOf is the ErrorDetail code of err, "" without one.
func refusalCodeOf(err error) string {
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if ed, ok := d.(interface{ GetCode() string }); ok {
			return ed.GetCode()
		}
	}
	return ""
}
