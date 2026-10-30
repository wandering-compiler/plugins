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

// An account that resolves to no tenant is REFUSED, not authenticated
// unscoped (tenant_scope gap 3). It used to stamp nothing and succeed, so a
// tenant_scope project got a principal with no tenant filter at all — the one
// case where isolation must not quietly degrade. Nothing is stamped either: an
// empty label would be an audience key that matches everything.
func TestResolveTenantScope_NoTenantRefuses(t *testing.T) {
	h := &AuthServiceHandler{Query: &tenantScopeMock{tenantByUser: map[string]string{}}}
	sc, lb := map[string]string{}, map[string]string{}
	err := resolveTenantScope(context.Background(), h, "nobody", nil, sc, lb)
	if !errors.Is(err, errNoTenant) {
		t.Fatalf("a principal with no tenant: %v, want errNoTenant", err)
	}
	if len(sc) != 0 || len(lb) != 0 {
		t.Errorf("a refused principal was stamped: scopes %v labels %v", sc, lb)
	}
}

// Through the decorator chain the refusal is an authentication refusal —
// Unauthenticated, the opaque answer every other failure gets — and the
// decorators after it do not run.
func TestRunScopeDecorators_NoTenantIsUnauthenticated(t *testing.T) {
	prev := scopeDecorators
	t.Cleanup(func() { scopeDecorators = prev })
	ranAfter := false
	scopeDecorators = []scopeDecorator{
		resolveTenantScope,
		func(context.Context, *AuthServiceHandler, string, map[string]string, map[string]string, map[string]string) error {
			ranAfter = true
			return nil
		},
	}
	h := &AuthServiceHandler{Query: &tenantScopeMock{tenantByUser: map[string]string{}}}
	err := runScopeDecorators(context.Background(), h, "nobody", nil, map[string]string{}, map[string]string{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no tenant through the chain: %v, want Unauthenticated", err)
	}
	if ranAfter {
		t.Error("a decorator after the refusal still ran")
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
// clear refusal, not a 500 "Something went wrong on our side" to a REST
// caller.
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
