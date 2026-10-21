// Package handlers holds the grant plugin's business logic: GrantService
// over the GrantQuery / GrantMutation storage primitives.
package handlers

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/grant/gen/pb"
)

// GrantServiceHandler implements pb.GrantServiceServer.
type GrantServiceHandler struct {
	Query    pb.GrantQueryClient
	Mutation pb.GrantMutationClient
	// Lock is the deployed ACL lock: the backoffice's methods must be in it
	// (realmOnly), or nobody may call them.
	Lock *acllock.Lock
}

var (
	accentRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// checkFields refuses an envelope the pages could not render safely: a link
// that is not absolute https (or http on localhost), a colour that is not
// #rrggbb, a host that is not a lower-case DNS name.
func checkFields(f *pb.EnvelopeFields) error {
	if strings.TrimSpace(f.GetDisplayName()) == "" {
		return invalid("display_name", "an envelope names the organization")
	}
	for field, v := range map[string]string{
		"logo_light_url": f.GetLogoLightUrl(), "logo_dark_url": f.GetLogoDarkUrl(),
		"website_url": f.GetWebsiteUrl(), "support_url": f.GetSupportUrl(),
		"privacy_url": f.GetPrivacyUrl(), "terms_url": f.GetTermsUrl(),
	} {
		if v != "" && !safeURL(v) {
			return invalid(field, "a link is an absolute https:// URL (http:// only for localhost)")
		}
	}
	if c := f.GetAccentColor(); c != "" && !accentRE.MatchString(c) {
		return invalid("accent_color", "a colour is #rrggbb")
	}
	if h := f.GetVerifiedHost(); h != "" && !hostRE.MatchString(h) {
		return invalid("verified_host", "a host is a lower-case DNS name")
	}
	return nil
}

func safeURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1"
	}
	return false
}

func invalid(field, why string) error {
	return status.Errorf(codes.InvalidArgument, "grant: %s: %s", field, why)
}

// ProposeEnvelope writes a new proposed version for the organization the
// caller acts in. It is shown nowhere until the backoffice approves it.
func (h *GrantServiceHandler) ProposeEnvelope(ctx context.Context, req *pb.ProposeEnvelopeReq) (*pb.EnvelopeVersion, error) {
	caller, orgID, err := inOrg(ctx)
	if err != nil {
		return nil, err
	}
	f := req.GetFields()
	if f == nil {
		f = &pb.EnvelopeFields{}
	}
	if err := checkFields(f); err != nil {
		return nil, err
	}
	resp, err := h.Mutation.InsertEnvelope(ctx, &pb.InsertEnvelopeReq{
		OrgId: orgID, ProposedBy: caller,
		DisplayName: f.GetDisplayName(), LogoLightUrl: f.GetLogoLightUrl(), LogoDarkUrl: f.GetLogoDarkUrl(),
		VerifiedHost: f.GetVerifiedHost(), WebsiteUrl: f.GetWebsiteUrl(), SupportUrl: f.GetSupportUrl(),
		PrivacyUrl: f.GetPrivacyUrl(), TermsUrl: f.GetTermsUrl(), AccentColor: f.GetAccentColor(),
		DefaultLanguage: f.GetDefaultLanguage(), OperatedBy: f.GetOperatedBy(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.EnvelopeVersion{Id: resp.GetId(), OrgId: orgID, Status: "proposed", Fields: f}, nil
}

// GetMyEnvelopes is every version of the caller's organization, newest
// first: what is shown, what waits, what was refused and why.
func (h *GrantServiceHandler) GetMyEnvelopes(ctx context.Context, _ *pb.GetMyEnvelopesReq) (*pb.EnvelopeVersionsResp, error) {
	_, orgID, err := inOrg(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := h.Query.ListOrgEnvelopes(ctx, &pb.ListOrgEnvelopesReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return versions(rows.GetEnvelopes()), nil
}

// ListEnvelopeProposals is what waits for the backoffice.
func (h *GrantServiceHandler) ListEnvelopeProposals(ctx context.Context, _ *pb.ListEnvelopeProposalsReq) (*pb.EnvelopeVersionsResp, error) {
	if _, err := h.realmOnly(ctx, "GRANT_GRANT_SERVICE_LIST_ENVELOPE_PROPOSALS"); err != nil {
		return nil, err
	}
	rows, err := h.Query.ListPendingEnvelopes(ctx, &pb.ListPendingEnvelopesReq{})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return versions(rows.GetEnvelopes()), nil
}

// ApproveEnvelope makes a proposal the organization's shown envelope,
// superseding the previous one.
func (h *GrantServiceHandler) ApproveEnvelope(ctx context.Context, req *pb.ApproveEnvelopeReq) (*pb.EnvelopeVersion, error) {
	caller, err := h.realmOnly(ctx, "GRANT_GRANT_SERVICE_APPROVE_ENVELOPE")
	if err != nil {
		return nil, err
	}
	resp, err := h.Mutation.ApproveEnvelopeRow(ctx, &pb.ApproveEnvelopeRowReq{Id: req.GetId(), DecidedBy: caller})
	if err != nil {
		return nil, err
	}
	return &pb.EnvelopeVersion{Id: resp.GetId(), OrgId: resp.GetOrgId(), Status: "approved"}, nil
}

// RejectEnvelope refuses a proposal, with a note for the organization.
func (h *GrantServiceHandler) RejectEnvelope(ctx context.Context, req *pb.RejectEnvelopeReq) (*pb.EnvelopeVersion, error) {
	caller, err := h.realmOnly(ctx, "GRANT_GRANT_SERVICE_REJECT_ENVELOPE")
	if err != nil {
		return nil, err
	}
	resp, err := h.Mutation.RejectEnvelopeRow(ctx, &pb.RejectEnvelopeRowReq{Id: req.GetId(), DecidedBy: caller, DecisionNote: req.GetNote()})
	if err != nil {
		return nil, err
	}
	return &pb.EnvelopeVersion{Id: resp.GetId(), Status: "rejected", DecisionNote: req.GetNote()}, nil
}

// BindHost binds a co-brand host to the organization it presents. A host
// bound to another organization is refused: unbind it first.
func (h *GrantServiceHandler) BindHost(ctx context.Context, req *pb.BindHostReq) (*pb.BindHostResp, error) {
	caller, err := h.realmOnly(ctx, "GRANT_GRANT_SERVICE_BIND_HOST")
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(req.GetHost())
	if !hostRE.MatchString(host) {
		return nil, invalid("host", "a host is a lower-case DNS name")
	}
	cur, err := h.Query.GetHostBinding(ctx, &pb.GetHostBindingReq{Host: host})
	switch {
	case err == nil && cur.GetOrgId() == req.GetOrgId():
		return &pb.BindHostResp{}, nil
	case err == nil:
		return nil, status.Error(codes.FailedPrecondition, "grant: the host presents another organization — unbind it first")
	case status.Code(err) != codes.NotFound:
		return nil, err
	}
	if _, err := h.Mutation.InsertHostBinding(ctx, &pb.InsertHostBindingReq{Host: host, OrgId: req.GetOrgId(), CreatedBy: caller}); err != nil {
		return nil, err
	}
	return &pb.BindHostResp{}, nil
}

// UnbindHost ends a host's binding. Unbinding a host that is not bound
// changes nothing.
func (h *GrantServiceHandler) UnbindHost(ctx context.Context, req *pb.UnbindHostReq) (*pb.UnbindHostResp, error) {
	caller, err := h.realmOnly(ctx, "GRANT_GRANT_SERVICE_UNBIND_HOST")
	if err != nil {
		return nil, err
	}
	if _, err := h.Mutation.EndHostBinding(ctx, &pb.EndHostBindingReq{Host: strings.ToLower(req.GetHost()), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return &pb.UnbindHostResp{}, nil
}

// ListHosts is every live co-brand host.
func (h *GrantServiceHandler) ListHosts(ctx context.Context, _ *pb.ListHostsReq) (*pb.ListHostsResp, error) {
	if _, err := h.realmOnly(ctx, "GRANT_GRANT_SERVICE_LIST_HOSTS"); err != nil {
		return nil, err
	}
	rows, err := h.Query.ListHostBindings(ctx, &pb.ListHostBindingsReq{})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	out := &pb.ListHostsResp{}
	for _, b := range rows.GetBindings() {
		out.Hosts = append(out.Hosts, &pb.HostBindingView{Host: b.GetHost(), OrgId: b.GetOrgId(), CreatedAt: b.GetCreatedAt()})
	}
	return out, nil
}

// GetOrgEnvelope is an organization's APPROVED envelope; found = false when
// it has none, and a page then renders neutrally.
func (h *GrantServiceHandler) GetOrgEnvelope(ctx context.Context, req *pb.GetOrgEnvelopeReq) (*pb.PublicEnvelope, error) {
	return h.approved(ctx, req.GetOrgId())
}

// GetHostEnvelope is the approved envelope of the organization a co-brand
// host presents; found = false for a host nobody bound.
func (h *GrantServiceHandler) GetHostEnvelope(ctx context.Context, req *pb.GetHostEnvelopeReq) (*pb.PublicEnvelope, error) {
	b, err := h.Query.GetHostBinding(ctx, &pb.GetHostBindingReq{Host: strings.ToLower(req.GetHost())})
	if status.Code(err) == codes.NotFound {
		return &pb.PublicEnvelope{}, nil
	}
	if err != nil {
		return nil, err
	}
	return h.approved(ctx, b.GetOrgId())
}

func (h *GrantServiceHandler) approved(ctx context.Context, orgID string) (*pb.PublicEnvelope, error) {
	e, err := h.Query.GetApprovedEnvelope(ctx, &pb.GetApprovedEnvelopeReq{OrgId: orgID})
	if status.Code(err) == codes.NotFound {
		return &pb.PublicEnvelope{OrgId: orgID}, nil
	}
	if err != nil {
		return nil, err
	}
	return &pb.PublicEnvelope{Found: true, OrgId: orgID, Fields: fieldsOf(e)}, nil
}

func fieldsOf(e *pb.EnvelopeRow) *pb.EnvelopeFields {
	return &pb.EnvelopeFields{
		DisplayName: e.GetDisplayName(), LogoLightUrl: e.GetLogoLightUrl(), LogoDarkUrl: e.GetLogoDarkUrl(),
		VerifiedHost: e.GetVerifiedHost(), WebsiteUrl: e.GetWebsiteUrl(), SupportUrl: e.GetSupportUrl(),
		PrivacyUrl: e.GetPrivacyUrl(), TermsUrl: e.GetTermsUrl(), AccentColor: e.GetAccentColor(),
		DefaultLanguage: e.GetDefaultLanguage(), OperatedBy: e.GetOperatedBy(),
	}
}

func versions(rows []*pb.EnvelopeRow) *pb.EnvelopeVersionsResp {
	out := &pb.EnvelopeVersionsResp{}
	for _, e := range rows {
		out.Envelopes = append(out.Envelopes, &pb.EnvelopeVersion{
			Id: e.GetId(), OrgId: e.GetOrgId(), Status: e.GetStatus(), Fields: fieldsOf(e),
			ProposedAt: e.GetProposedAt(), DecidedAt: e.GetDecidedAt(), DecisionNote: e.GetDecisionNote(),
		})
	}
	return out
}
