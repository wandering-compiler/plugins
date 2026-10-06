package handlers

import (
	"context"
	"errors"
	"testing"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type tenantScopeMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	tenantByUser map[string]string
	err          error
}

func (m *tenantScopeMock) GetUserTenant(_ context.Context, in *pb.GetUserTenantReq, _ ...grpc.CallOption) (*pb.GetUserTenantResp, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &pb.GetUserTenantResp{TenantId: m.tenantByUser[in.GetUserId()]}, nil
}

// tenant_id is published as BOTH a row filter and a broadcast audience key.
//
// Publishing only the scope is the shape that made a tenant-partitioned
// database announce every change to every tenant: the hub delivers an
// UNLABELLED event to all authenticated clients, so rows were isolated and
// the event stream was not. restgw's TestEventbusEventSource_LabelFiltering
// proves the filter works once a key exists; this proves the key exists.
func TestResolveTenantScope_PublishesBothKeys(t *testing.T) {
	h := &AuthServiceHandler{Query: &tenantScopeMock{
		tenantByUser: map[string]string{"u1": "tenant-acme"},
	}}
	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveTenantScope(context.Background(), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc["tenant_id"] != "tenant-acme" {
		t.Errorf("scopes[tenant_id] = %q, want tenant-acme", sc["tenant_id"])
	}
	if lb["tenant_id"] != "tenant-acme" {
		t.Errorf("labels[tenant_id] = %q, want tenant-acme — without it this tenant's events carry no audience key and reach every tenant", lb["tenant_id"])
	}
}

// The control case, and it is not a formality: a decorator that stamped
// unconditionally would pass the assertion above while handing a label to a
// principal who has no tenant — an audience key nobody can satisfy, or worse
// an empty one that matches everything.
func TestResolveTenantScope_NoTenantStampsNeither(t *testing.T) {
	h := &AuthServiceHandler{Query: &tenantScopeMock{tenantByUser: map[string]string{}}}
	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveTenantScope(context.Background(), h, "nobody", nil, sc, lb); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := sc["tenant_id"]; ok {
		t.Error("a user with no tenant must not get a scope")
	}
	if _, ok := lb["tenant_id"]; ok {
		t.Error("a user with no tenant must not get a broadcast label either")
	}
}

// A lookup failure propagates rather than silently producing a tenant-less
// principal — the scoped model then refuses, instead of a request running
// unfiltered.
func TestResolveTenantScope_LookupErrorPropagates(t *testing.T) {
	boom := errors.New("db down")
	h := &AuthServiceHandler{Query: &tenantScopeMock{err: boom}}
	err := resolveTenantScope(context.Background(), h, "u1", nil, map[string]string{}, map[string]string{})
	if !errors.Is(err, boom) {
		t.Fatalf("want the raw lookup error, got %v", err)
	}
}

func (m *tenantScopeMock) GetTenantByDomain(_ context.Context, in *pb.GetTenantByDomainReq, _ ...grpc.CallOption) (*pb.GetTenantByDomainResp, error) {
	if id, ok := m.tenantByUser["domain:"+in.GetDomain()]; ok {
		return &pb.GetTenantByDomainResp{TenantId: id}, nil
	}
	// What a generated single-row read answers for no row.
	return nil, status.Error(codes.NotFound, "no rows")
}

// The REST gateway forwards the request's Host as x-forwarded-host; a port on
// it does not change the tenant, and an address that names no tenant is a
// clear refusal — it reached a REST caller as 500 "Something went wrong on our
// side" (found live by examples/auth-proof).
func TestResolveSignupTenant_ByForwardedHost(t *testing.T) {
	h := &AuthServiceHandler{Query: &tenantScopeMock{tenantByUser: map[string]string{"domain:alpha.example": "t-alpha"}}}
	at := func(md ...string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(md...))
	}
	for _, md := range [][]string{
		{"x-forwarded-host", "alpha.example"},
		{"x-forwarded-host", "alpha.example:8443"},
		{"host", "alpha.example"},
	} {
		got, err := resolveSignupTenant(at(md...), h, &pb.SignUpReq{})
		if err != nil || got != "t-alpha" {
			t.Errorf("%v: tenant = %q, %v; want t-alpha", md, got, err)
		}
	}
	for _, md := range [][]string{{"x-forwarded-host", "nowhere.example"}, {}} {
		_, err := resolveSignupTenant(at(md...), h, &pb.SignUpReq{})
		if status.Code(err) != codes.InvalidArgument || detailOf(t, err).GetCode() != CodeTenantUnknown {
			t.Errorf("%v: want InvalidArgument/%s, got %v", md, CodeTenantUnknown, err)
		}
	}
}
