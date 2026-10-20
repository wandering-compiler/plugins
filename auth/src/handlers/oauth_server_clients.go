package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/plugins/auth/lib/safefetch"
)

// The clients of the oauth_server feature — public clients only (no
// secret; PKCE is the binding), known in one of two ways:
//
//   - registered at the registration endpoint (RFC 7591): the client_id is
//     one this server mints;
//   - a Client ID Metadata Document: the client_id is an https URL serving
//     the client's metadata, read here (guarded against private addresses)
//     and kept, then read again once a day old.
//
// What a client says about itself (name, links) is unverified and shown as
// such; what binds it is its redirect URIs, matched exactly.

const (
	// cimdMaxAge is how long a metadata document is trusted before it is
	// read again.
	cimdMaxAge = 24 * time.Hour
	// cimdStaleMax is how long a known client keeps working on its last
	// document while the URL does not answer.
	cimdStaleMax = 7 * 24 * time.Hour
	// maxRedirectURIs bounds one client's redirects.
	maxRedirectURIs = 10
)

// fetchClientMetadata reads a metadata document. A variable so tests can
// serve one without the network.
var fetchClientMetadata = func(ctx context.Context, rawURL string) ([]byte, error) {
	return safefetch.Get(ctx, rawURL, safefetch.Options{})
}

// RegisterOAuthClient is the registration endpoint (RFC 7591) for public
// clients. The gateway caps it per address; this decides what a client may
// register.
func (h *AuthServiceHandler) RegisterOAuthClient(ctx context.Context, req *pb.RegisterOAuthClientReq) (*pb.RegisterOAuthClientResp, error) {
	if !h.OAuthDynamicRegistration {
		return &pb.RegisterOAuthClientResp{OauthError: oauthInvalidClientMetadata, OauthErrorDescription: "registration is closed here; use a client ID metadata document"}, nil
	}
	md := clientMetadata{
		RedirectURIs: req.GetRedirectUris(), ClientName: req.GetClientName(), ClientURI: req.GetClientUri(),
		LogoURI: req.GetLogoUri(), GrantTypes: req.GetGrantTypes(), ResponseTypes: req.GetResponseTypes(),
	}
	if err := h.checkClientMetadata(&md); err != nil {
		oe, _ := asOAuthError(err)
		return &pb.RegisterOAuthClientResp{OauthError: oe.code, OauthErrorDescription: oe.desc}, nil
	}
	clientID, err := newClientID()
	if err != nil {
		return nil, err
	}
	created, err := h.Mutation.CreateOAuthClient(ctx, &pb.CreateOAuthClientReq{
		ClientId:     clientID,
		ClientIdHash: sha256Hex(clientID),
		Kind:         pb.OAuthClientKind_OAUTH_CLIENT_KIND_DCR,
		ClientName:   md.ClientName,
		ClientUri:    md.ClientURI,
		LogoUri:      md.LogoURI,
		RedirectUris: strings.Join(md.RedirectURIs, "\n"),
		SoftwareId:   truncate(req.GetSoftwareId(), 200),
		CreatedIp:    truncate(req.GetClientAddr(), 64),
	})
	if err != nil {
		return nil, err
	}
	issued := created.GetCreatedAt()
	if issued == nil {
		issued = timestamppb.Now()
	}
	return &pb.RegisterOAuthClientResp{ClientId: clientID, IssuedAt: issued}, nil
}

// newClientID mints a registered client's id: random, so one client cannot
// guess another's.
func newClientID() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "w17c_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// clientMetadata is what a registration request or a metadata document
// says, in RFC 7591's names.
type clientMetadata struct {
	ClientID      string   `json:"client_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	ClientName    string   `json:"client_name"`
	ClientURI     string   `json:"client_uri"`
	LogoURI       string   `json:"logo_uri"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	AuthMethod    string   `json:"token_endpoint_auth_method"`
}

// checkClientMetadata decides whether a client may be known as it describes
// itself, and trims what it says to what is stored.
func (h *AuthServiceHandler) checkClientMetadata(md *clientMetadata) error {
	if len(md.RedirectURIs) == 0 {
		return oauthRefuse(oauthInvalidRedirectURI, "at least one redirect_uri is required")
	}
	if len(md.RedirectURIs) > maxRedirectURIs {
		return oauthRefuse(oauthInvalidRedirectURI, "at most 10 redirect_uris")
	}
	hosts, _ := parseOAuthRedirectHosts(h.OAuthRedirectHosts)
	for _, r := range md.RedirectURIs {
		if err := checkClientRedirect(r, hosts); err != nil {
			return oauthRefuse(oauthInvalidRedirectURI, r+": "+err.Error())
		}
	}
	for _, g := range md.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			return oauthRefuse(oauthInvalidClientMetadata, "grant type "+g+" is not supported")
		}
	}
	for _, t := range md.ResponseTypes {
		if t != "code" {
			return oauthRefuse(oauthInvalidClientMetadata, "response type "+t+" is not supported")
		}
	}
	if m := md.AuthMethod; m != "" && m != "none" {
		return oauthRefuse(oauthInvalidClientMetadata, "only public clients (token_endpoint_auth_method none)")
	}
	for _, link := range []*string{&md.ClientURI, &md.LogoURI} {
		if *link == "" {
			continue
		}
		if u, err := url.Parse(*link); err != nil || u.Scheme != "https" || u.Host == "" || len(*link) > 2048 {
			*link = "" // a link the page could not show safely is dropped, not refused
		}
	}
	md.ClientName = truncate(strings.TrimSpace(md.ClientName), 200)
	return nil
}

// checkClientRedirect: an https URL (on an allowed host, when the
// deployment lists them), a loopback one — a program on the user's
// computer — or a private-use scheme of a native app (RFC 8252 §7.1:
// `cursor://…`, `com.example.app:/cb`), which PKCE binds to the app that
// started the flow and the consent page names. Never a fragment (RFC 6749
// §3.1.2), never credentials, never a scheme a browser treats as content or
// navigation of its own.
func checkClientRedirect(raw string, hosts map[string]bool) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || len(raw) > 2048:
		return redirectError("not an absolute URL")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return redirectError("has a fragment")
	case u.User != nil:
		return redirectError("carries credentials")
	case isLoopbackRedirect(raw):
		return nil
	case u.Scheme == "https":
		if u.Host == "" {
			return redirectError("not an absolute URL")
		}
		if len(hosts) > 0 && !hosts[strings.ToLower(u.Hostname())] {
			return redirectError("its host is not one this server sends codes to")
		}
		return nil
	case u.Scheme == "http":
		return redirectError("must be https, or http on a loopback address")
	case refusedRedirectSchemes[u.Scheme] || !privateUseScheme(u.Scheme):
		return redirectError("its scheme is not one a native app can claim")
	}
	return nil
}

// refusedRedirectSchemes are schemes a browser handles itself.
var refusedRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true, "about": true, "blob": true,
	"ws": true, "wss": true, "ftp": true, "chrome": true, "chrome-extension": true, "moz-extension": true,
	"view-source": true, "intent": true,
}

// privateUseScheme: a scheme as RFC 3986 spells one, lower-case.
func privateUseScheme(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

type redirectError string

func (e redirectError) Error() string { return string(e) }

// resolveOAuthClient finds the client a request names: a registered one by
// its id, or a metadata-document client by its URL — read now when it is
// new or its document is a day old.
func (h *AuthServiceHandler) resolveOAuthClient(ctx context.Context, clientID, clientAddr string) (*pb.OAuthClientRow, error) {
	if clientID == "" || len(clientID) > 2048 {
		return nil, oauthRefuse(oauthInvalidClient, "unknown client")
	}
	known, err := h.oauthClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if known != nil && known.GetDisabledAt() != nil {
		return nil, oauthRefuse(oauthInvalidClient, "unknown client")
	}
	if !strings.HasPrefix(clientID, "https://") {
		if known == nil {
			return nil, oauthRefuse(oauthInvalidClient, "unknown client")
		}
		return known, nil
	}
	if known != nil && known.GetMetadataFetchedAt() != nil && time.Since(known.GetMetadataFetchedAt().AsTime()) < cimdMaxAge {
		return known, nil
	}
	md, ferr := h.readClientMetadata(ctx, clientID)
	if ferr != nil {
		// A known client keeps working on its last document for a while: a
		// metadata host that is briefly down must not sign everyone out.
		if known != nil && known.GetMetadataFetchedAt() != nil && time.Since(known.GetMetadataFetchedAt().AsTime()) < cimdStaleMax {
			if _, isOAuth := asOAuthError(ferr); !isOAuth {
				return known, nil
			}
		}
		if _, isOAuth := asOAuthError(ferr); !isOAuth {
			return nil, oauthRefuse(oauthInvalidClient, "the client's metadata document could not be read")
		}
		return nil, ferr
	}
	uris := strings.Join(md.RedirectURIs, "\n")
	if known != nil {
		if _, err := h.Mutation.RefreshOAuthClientMetadata(ctx, &pb.RefreshOAuthClientMetadataReq{
			Id: known.GetId(), ClientName: md.ClientName, ClientUri: md.ClientURI, LogoUri: md.LogoURI, RedirectUris: uris,
		}); err != nil {
			return nil, err
		}
		known.ClientName, known.ClientUri, known.LogoUri, known.RedirectUris = md.ClientName, md.ClientURI, md.LogoURI, uris
		return known, nil
	}
	if _, err := h.Mutation.CreateOAuthClient(ctx, &pb.CreateOAuthClientReq{
		ClientId:          clientID,
		ClientIdHash:      sha256Hex(clientID),
		Kind:              pb.OAuthClientKind_OAUTH_CLIENT_KIND_CIMD,
		ClientName:        md.ClientName,
		ClientUri:         md.ClientURI,
		LogoUri:           md.LogoURI,
		RedirectUris:      uris,
		CreatedIp:         truncate(clientAddr, 64),
		MetadataFetchedAt: timestamppb.Now(),
	}); err != nil && status.Code(err) != codes.AlreadyExists {
		return nil, err
	}
	// Read back: a concurrent first request may have written the row.
	known, err = h.oauthClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if known == nil {
		return nil, status.Error(codes.Unavailable, "oauth: the client written was not read back")
	}
	return known, nil
}

// oauthClientByID reads a client by its id; nil when there is none.
func (h *AuthServiceHandler) oauthClientByID(ctx context.Context, clientID string) (*pb.OAuthClientRow, error) {
	got, err := h.Query.GetOAuthClientByHash(ctx, &pb.GetOAuthClientByHashReq{ClientIdHash: sha256Hex(clientID)})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, nil
		}
		return nil, err
	}
	if got.GetClient().GetClientId() != clientID {
		return nil, nil
	}
	return got.GetClient(), nil
}

// readClientMetadata fetches and checks a metadata document: it must name
// itself (client_id equal to its URL) and describe a public client.
func (h *AuthServiceHandler) readClientMetadata(ctx context.Context, clientID string) (*clientMetadata, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" || u.User != nil {
		return nil, oauthRefuse(oauthInvalidClient, "a client ID URL must be https with a path")
	}
	body, err := fetchClientMetadata(ctx, clientID)
	if err != nil {
		return nil, err
	}
	var md clientMetadata
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, oauthRefuse(oauthInvalidClient, "the client's metadata document is not valid JSON")
	}
	if md.ClientID != clientID {
		return nil, oauthRefuse(oauthInvalidClient, "the client's metadata document names another client_id")
	}
	if err := h.checkClientMetadata(&md); err != nil {
		oe, _ := asOAuthError(err)
		return nil, oauthRefuse(oauthInvalidClient, "the client's metadata document: "+oe.desc)
	}
	return &md, nil
}
