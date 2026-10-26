package handlers

import (
	"context"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_hosts` feature: a host (white-label or
// co-brand) bound to the organization it serves. The backoffice binds and
// unbinds hosts realm-wide; anyone may ask which organization a host serves.
//
// What reads it: an audience that takes the tenant from the host
// (w17/audience.proto TENANT_SOURCE_HOST). Its gateway hands Authenticate the
// host the request arrived on (x-w17-host), and resolveOrgScope acts
// in the organization the host is bound to — through orgSlugOfHost, which
// this file installs. The caller still needs a membership there: the host
// chooses among the caller's organizations, as the W17-Org selector does,
// and grants nothing.

func init() {
	orgSlugOfHost = lookupOrgSlugOfHost
}

// hostRE is a lower-case DNS name of at least two labels: what the gateway
// reports (lower-case, no port, no trailing dot) and what a binding stores.
var hostRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalHost is a host as the gateway reports it: lower-case, without a
// trailing dot. A port, a scheme or a path is no host.
func normalHost(ctx context.Context, host string) (string, error) {
	return normalHostOf(ctx, host, "host")
}

// normalHostOf is normalHost refusing on the request field that carried the
// host (org_signup's `signup_host`, for one).
func normalHostOf(ctx context.Context, host, field string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if len(h) > 253 || !hostRE.MatchString(h) {
		return "", refusal(ctx, codes.InvalidArgument, "org_hosts: "+field+" is not a host name", CodeHostInvalid, field, MsgHostInvalid, nil)
	}
	return h, nil
}

// lookupOrgSlugOfHost is the slug of the live organization host is bound to,
// "" when it is bound to none (or its organization is deleted).
func lookupOrgSlugOfHost(ctx context.Context, h *AuthServiceHandler, host string) (string, error) {
	row, err := h.Query.GetOrgOfHost(ctx, &pb.GetOrgOfHostReq{Host: host})
	if status.Code(err) == codes.NotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return row.GetSlug(), nil
}

// refuseHostsInsideOrg holds the backoffice's host methods to the realm: a
// call acting inside an organization is refused, and so is one the endpoint
// ACL does not gate.
func (h *AuthServiceHandler) refuseHostsInsideOrg(ctx context.Context, method string) error {
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" && !h.heldRealmWide(ctx, method) {
		return refusal(ctx, codes.PermissionDenied, "org_hosts: hosts are bound realm-wide, not from inside an organization",
			CodeHostsRealmOnly, "", MsgHostsRealmOnly, nil)
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "org_hosts: the backoffice's host methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// BindOrgHost binds a host to the organization it serves. Binding a host
// again to the organization it serves changes nothing; one bound to another
// organization is refused until it is unbound.
func (h *AuthServiceHandler) BindOrgHost(ctx context.Context, req *pb.BindOrgHostReq) (*pb.BindOrgHostResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseHostsInsideOrg(ctx, "BindOrgHost"); err != nil {
		return nil, err
	}
	host, err := normalHost(ctx, req.GetHost())
	if err != nil {
		return nil, err
	}
	cur, err := h.Query.GetOrgOfHost(ctx, &pb.GetOrgOfHostReq{Host: host})
	switch {
	case err == nil && cur.GetOrgId() == req.GetOrgId():
		return &pb.BindOrgHostResp{}, nil
	case err == nil:
		return nil, refusal(ctx, codes.FailedPrecondition, "org_hosts: the host is bound to another organization",
			CodeHostTaken, "host", MsgHostTaken, nil)
	case status.Code(err) != codes.NotFound:
		return nil, err
	}
	// A concurrent binding of the same host lands on the unique index: one
	// of the two wins, and the loser is told the host is taken.
	if _, err := h.Mutation.BindOrgHostRow(ctx, &pb.BindOrgHostRowReq{
		Host: host, OrgId: req.GetOrgId(), BoundBy: caller,
	}); err != nil {
		if isUniqueConflict(err) {
			return nil, refusal(ctx, codes.FailedPrecondition, "org_hosts: the host is bound to another organization",
				CodeHostTaken, "host", MsgHostTaken, nil)
		}
		return nil, err
	}
	return &pb.BindOrgHostResp{}, nil
}

// UnbindOrgHost ends a host's binding; the organization's requests arriving
// on it take the tenant from the audience's next source from then on.
// Unbinding a host bound to nothing changes nothing.
func (h *AuthServiceHandler) UnbindOrgHost(ctx context.Context, req *pb.UnbindOrgHostReq) (*pb.UnbindOrgHostResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseHostsInsideOrg(ctx, "UnbindOrgHost"); err != nil {
		return nil, err
	}
	host, err := normalHost(ctx, req.GetHost())
	if err != nil {
		return nil, err
	}
	if _, err := h.Mutation.EndOrgHostRow(ctx, &pb.EndOrgHostRowReq{Host: host, EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return &pb.UnbindOrgHostResp{}, nil
}

// ListOrgHosts is every live binding, by host.
func (h *AuthServiceHandler) ListOrgHosts(ctx context.Context, _ *pb.ListOrgHostsReq) (*pb.ListOrgHostsResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseHostsInsideOrg(ctx, "ListOrgHosts"); err != nil {
		return nil, err
	}
	rows, err := h.Query.ListOrgHostRows(ctx, &pb.ListOrgHostRowsReq{})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	out := &pb.ListOrgHostsResp{}
	for _, r := range rows.GetHosts() {
		out.Hosts = append(out.Hosts, &pb.OrgHostInfo{Host: r.GetHost(), OrgId: r.GetOrgId(), Slug: r.GetSlug(), BoundAt: r.GetBoundAt()})
	}
	return out, nil
}

// GetHostOrg is the organization a host serves, for anyone: a sign-in page
// on a white-label host renders it before anyone signs in. A host bound to
// none — or no host at all — is found = false, never an error, so the answer
// tells a caller nothing it could not see by visiting the host.
func (h *AuthServiceHandler) GetHostOrg(ctx context.Context, req *pb.GetHostOrgReq) (*pb.HostOrgResp, error) {
	host, err := normalHost(ctx, req.GetHost())
	if err != nil {
		return &pb.HostOrgResp{}, nil
	}
	row, err := h.Query.GetOrgOfHost(ctx, &pb.GetOrgOfHostReq{Host: host})
	if status.Code(err) == codes.NotFound {
		return &pb.HostOrgResp{}, nil
	}
	if err != nil {
		return nil, err
	}
	resp := &pb.HostOrgResp{Found: true, OrgId: row.GetOrgId(), Slug: row.GetSlug()}
	if hostOrgAnswer != nil {
		if err := hostOrgAnswer(ctx, h, resp); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// hostOrgAnswer adds to GetHostOrg's answer what another feature knows
// about the host's organization — org_signup's open kinds. nil without one.
var hostOrgAnswer func(ctx context.Context, h *AuthServiceHandler, resp *pb.HostOrgResp) error
