package handlers

import (
	"context"
	"fmt"

	"google.golang.org/grpc/metadata"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements the `tenant_scope` feature. It is staged
// into a bundle ONLY when the activation enables `tenant_scope`
// (plugin.yaml maps the feature to this file via go_files). With
// the feature off it is not staged, so the decorator below never
// registers and Authenticate stamps only the user_id scope — the
// base handler stays a clean no-op pass-through. Standalone (the
// plugin author's own `go test`) always compiles it, since gating
// happens at activation staging, not in the source tree.

// signupHostMetadataKey is the gRPC metadata key the gateway threads
// the forwarded Host header under (MetadataPropagation lowercases
// header names + strips an X- prefix; "Host" → "host"). Host-based
// tenancy reads it at SignUp.
const signupHostMetadataKey = "host"

// init wires the tenant_scope behaviour on package load: the
// Authenticate scope decorator (per-request tenant_id) AND the SignUp
// create path (bind the new user to the request's tenant). The bundle
// imports this package (alias-imported under the activation name), so
// the init runs once during server bring-up.
func init() {
	scopeDecorators = append(scopeDecorators, resolveTenantScope)
	signupCreateUser = createUserWithResolvedTenant
}

// createUserWithResolvedTenant is the tenant_scope SignUp create path
// (overrides the base tenant-less create): resolve the request's tenant
// (URL slug, else the forwarded Host) to a tenant id, then create the
// user stamped with it.
//
// It calls the SAME CreateUser the baseline does. `CreateUserReq.TenantId`
// and the INSERT assignment behind it are `tenant_scope`-gated, and this
// file is staged only with that feature, so the field is always there when
// this runs. The tenant-aware twin it used to call is gone.
func createUserWithResolvedTenant(ctx context.Context, h *AuthServiceHandler, req *pb.SignUpReq, email, passwordHash string) (string, error) {
	tenantID, err := resolveSignupTenant(ctx, h, req)
	if err != nil {
		return "", err
	}
	resp, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{
		Email:        email,
		PasswordHash: passwordHash,
		TenantId:     tenantID,
	})
	if err != nil {
		return "", err
	}
	return resp.GetUser().GetId(), nil
}

// resolveSignupTenant maps the request's tenant identifier to a tenant
// id. URL-based tenancy: the gateway binds `{tenant_slug}` to
// req.tenant_slug → GetTenantBySlug. Host-based tenancy: the forwarded
// Host header → GetTenantByDomain. Slug wins when both are present.
// Errors when neither resolves — tenant_id is required (NOT NULL), so
// SignUp fails closed rather than creating an orphan user.
func resolveSignupTenant(ctx context.Context, h *AuthServiceHandler, req *pb.SignUpReq) (string, error) {
	if slug := req.GetTenantSlug(); slug != "" {
		resp, err := h.Query.GetTenantBySlug(ctx, &pb.GetTenantBySlugReq{Slug: slug})
		if err != nil {
			return "", err
		}
		if tid := resp.GetTenantId(); tid != "" {
			return tid, nil
		}
		return "", fmt.Errorf("signup: no tenant for slug %q", slug)
	}
	if host := hostFromContext(ctx); host != "" {
		resp, err := h.Query.GetTenantByDomain(ctx, &pb.GetTenantByDomainReq{Domain: host})
		if err != nil {
			return "", err
		}
		if tid := resp.GetTenantId(); tid != "" {
			return tid, nil
		}
		return "", fmt.Errorf("signup: no tenant for host %q", host)
	}
	return "", fmt.Errorf("signup: tenant_scope on but request carries no tenant (need a URL {tenant_slug} or a forwarded Host)")
}

// hostFromContext reads the gateway-forwarded Host header from the
// incoming gRPC metadata. Empty when absent (slug-based deploys).
func hostFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get(signupHostMetadataKey); len(v) > 0 {
		return v[0]
	}
	return ""
}

// resolveTenantScope resolves the authenticated principal's tenant
// and stamps it as the `tenant_id` data scope. tenant_id is sourced
// from auth (never client-sent, per the data-scope rule): the
// gateway threads scopes["tenant_id"] into x-w17-scope-tenant_id
// metadata, and a project scoping its rows by name: "tenant_id"
// gets per-tenant isolation with no hand-written facade.
//
// User.tenant_id is NOT NULL, so a resolved principal always yields
// a tenant; a query error fails Authenticate closed (the same
// opaque Unauthenticated path as every other failure).
// tenant_id is published as BOTH keys: it filters the caller's rows and it
// decides who hears about them.
//
// This was held back when org_id landed, on the stated grounds that narrowing
// delivery for every tenant_scope project was uncovered by tests. That reason
// was weaker than it sounded: the hub's cross-tenant filtering IS covered, in
// both directions and with a decoy — restgw's TestEventbusEventSource_
// LabelFiltering asserts an alpha-scoped event reaches the alpha principal and
// NOT the beta one, and its sibling pins that an UNLABELLED event must not
// reach a label-bearing principal at all. What was genuinely missing was this
// line: the wiring that gives a tenant's events a key to be filtered ON.
//
// Without it the two halves disagreed by construction — rows partitioned per
// tenant, events unlabelled and therefore broadcast to every authenticated
// client of every tenant, which the second test above calls a leak by name.
//
// A tenant that resolves to no id stamps neither, so nothing gains an audience
// key it did not already have as a row filter.
func resolveTenantScope(ctx context.Context, h *AuthServiceHandler, userID string, _, scopes, labels map[string]string) error {
	resp, err := h.Query.GetUserTenant(ctx, &pb.GetUserTenantReq{UserId: userID})
	if err != nil {
		return err
	}
	if tid := resp.GetTenantId(); tid != "" {
		scopes["tenant_id"] = tid
		labels["tenant_id"] = tid
	}
	return nil
}
