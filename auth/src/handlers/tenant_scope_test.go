package handlers

import (
	"context"
	"errors"
	"testing"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"google.golang.org/grpc"
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
