package handlers

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

const testCodePage = testIssuer + "/oauth/code"

func registerW17ctl(t *testing.T, h *AuthServiceHandler, redirects ...string) string {
	t.Helper()
	resp, err := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: redirects, ClientName: "w17ctl", SoftwareId: "w17ctl"})
	if err != nil || resp.GetOauthError() != "" {
		t.Fatalf("register: %v %v", err, resp)
	}
	return resp.GetClientId()
}

// w17ctl on another machine than the browser asks for a session with the
// deployment's code page as its redirect: the consent page says where the
// answer goes, and the code it shows lives 5 minutes, not 1.
func TestOAuthServer_SessionThroughTheCodePage(t *testing.T) {
	h, s := oauthHandler()
	h.OAuthCodeRedirect = testCodePage
	// A redirect-host list that does not name the issuer's host: the code
	// page is this server's own and is allowed regardless.
	h.OAuthRedirectHosts = "claude.ai"
	cid := registerW17ctl(t, h, "http://127.0.0.1/callback", testCodePage)

	b, err := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, testCodePage))
	if err != nil || b.GetOauthError() != "" || b.GetRequestId() == "" {
		t.Fatalf("begin: %v %v", err, b)
	}
	got, err := h.GetOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.GetOAuthAuthorizationReq{RequestId: b.GetRequestId()})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetKind() != pb.OAuthGrantKind_OAUTH_GRANT_KIND_SESSION || !strings.Contains(got.GetRedirectHost(), "type into w17ctl") {
		t.Errorf("consent = kind %v, redirect host %q", got.GetKind(), got.GetRedirectHost())
	}
	a, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.ApproveOAuthAuthorizationReq{RequestId: b.GetRequestId()})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(a.GetRedirectUrl())
	if u.Scheme+"://"+u.Host+u.Path != testCodePage || u.Query().Get("code") == "" || u.Query().Get("state") != "st-1" || u.Query().Get("iss") != testIssuer {
		t.Errorf("approve redirect = %s", a.GetRedirectUrl())
	}
	for _, row := range s.auths {
		if left := time.Until(row.codeExpires); left < 4*time.Minute || left > 5*time.Minute {
			t.Errorf("code page code lives %s, want 5 min", left)
		}
	}

	// The loopback keeps its one minute.
	b2, _ := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, "http://127.0.0.1:49152/callback"))
	a2, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.ApproveOAuthAuthorizationReq{RequestId: b2.GetRequestId()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a2.GetRedirectUrl(), "http://127.0.0.1:49152/callback?") {
		t.Fatalf("loopback redirect = %s", a2.GetRedirectUrl())
	}
	for _, row := range s.auths {
		if row.req.GetRedirectUri() != testCodePage {
			if left := time.Until(row.codeExpires); left > time.Minute {
				t.Errorf("loopback code lives %s, want 1 min", left)
			}
		}
	}
}

// Without oauth_code_redirect the code page is no way to a session: w17ctl is
// told this console does not offer it, any other client that a resource is
// required.
func TestOAuthServer_CodePageRefused(t *testing.T) {
	h, _ := oauthHandler()
	cid := registerW17ctl(t, h, testCodePage)
	b, err := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, testCodePage))
	if err != nil || b.GetOauthError() != oauthInvalidTarget || !strings.Contains(b.GetOauthErrorDescription(), "does not offer sign-in with a code") {
		t.Errorf("w17ctl without a code page: %v %v", err, b)
	}

	h.OAuthCodeRedirect = testCodePage
	other := register(t, h, testCodePage)
	b, err = h.BeginOAuthAuthorization(context.Background(), beginReq(other, testCodePage))
	if err != nil || b.GetOauthError() != oauthInvalidTarget || !strings.Contains(b.GetOauthErrorDescription(), "a resource is required") {
		t.Errorf("a session through the code page for a client that is not w17ctl: %v %v", err, b)
	}
}

// oauth_code_redirect is held at boot to an https URL compared whole.
func TestCheckOAuthCodeRedirect(t *testing.T) {
	for raw, ok := range map[string]bool{
		"":                                       true,
		"https://api.example.com/oauth/code":     true,
		"http://api.example.com/oauth/code":      false,
		"http://localhost:8080/oauth/code":       true,
		"https://api.example.com/oauth/code?x=1": false,
		"https://api.example.com/oauth/code#x":   false,
		"https://u:p@api.example.com/oauth/code": false,
		"/oauth/code":                            false,
	} {
		if err := checkOAuthCodeRedirect(raw); (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok %v", raw, err, ok)
		}
	}
}
