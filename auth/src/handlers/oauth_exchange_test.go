package handlers

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

func exchangeHandler(t *testing.T) (*AuthServiceHandler, *oauthMock, string) {
	t.Helper()
	srv := fakeIdP(t, map[string]any{"sub": "ext-1", "email": "alice@idp.com"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "google", ClientId: "cid", Secret: "csec",
		AuthorizeUrl: "https://idp.example/authorize",
		TokenUrl:     srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	return &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings(), OAuthRedirectBase: "https://app.example"}, m, testState(t, "csec", "google", "")
}

// Without a challenge nothing could bind the login to the browser that
// started it, so the flow does not start.
func TestOAuthAuthorizeURL_RequiresAPKCEChallenge(t *testing.T) {
	h, _, _ := exchangeHandler(t)
	for _, ch := range []string{"", "short", strings.Repeat("a", 42) + "=", strings.Repeat("a", 44)} {
		if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", CodeChallenge: ch}); err == nil {
			t.Errorf("code_challenge %q was accepted", ch)
		}
	}
}

// The callback is a URL anyone can be made to open; it must carry no
// session. What it hands out is a code bound to the browser's challenge,
// stored only as its hash.
func TestOAuthCallback_HandsOutACodeNotASession(t *testing.T) {
	h, m, state := exchangeHandler(t)
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	if m.issuedHash != "" {
		t.Error("the callback issued a session")
	}
	row := m.loginCodes[sha256Hex(resp.GetCode())]
	if resp.GetCode() == "" || row == nil {
		t.Fatalf("no login code stored for the returned code %q", resp.GetCode())
	}
	if row.GetCodeChallenge() != challengeDigest(pkceChallengeOf(validVerifier())) {
		t.Errorf("code bound to challenge %q, want the authorize step's", row.GetCodeChallenge())
	}
	if _, plain := m.loginCodes[resp.GetCode()]; plain {
		t.Error("the login code is stored in the clear")
	}
}

// The login CSRF this flow closes: a callback link minted by one browser,
// opened by another. The other browser has a different verifier, and a
// wrong verifier burns the code, so the right one cannot be tried after.
func TestOAuthExchange_OnlyTheStartingBrowsersVerifierRedeems(t *testing.T) {
	h, m, state := exchangeHandler(t)
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("x", 43)
	if _, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: other}); err == nil {
		t.Fatal("another browser's verifier redeemed the code")
	}
	if m.issuedHash != "" {
		t.Error("a refused exchange issued a session")
	}
	if _, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier()}); err == nil {
		t.Error("a code that met a wrong verifier still redeemed")
	}
}

func TestOAuthExchange_ACodeRedeemsOnce(t *testing.T) {
	h, _, state := exchangeHandler(t)
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	if redeem(t, h, resp).GetToken() == "" {
		t.Fatal("the first exchange issued no session")
	}
	if _, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier()}); err == nil {
		t.Error("a code redeemed twice")
	}
}

func TestOAuthExchange_RefusesAShortVerifierOrNoCode(t *testing.T) {
	h, _, _ := exchangeHandler(t)
	for _, r := range []*pb.OAuthExchangeReq{
		{Code: "c", CodeVerifier: strings.Repeat("x", 42)},
		{Code: "", CodeVerifier: validVerifier()},
	} {
		if _, err := h.OAuthExchange(context.Background(), r); err == nil {
			t.Errorf("exchange %+v was accepted", r)
		}
	}
}

// Towards the provider: the token request carries the PKCE verifier whose
// challenge went out in the authorize URL, so an intercepted provider code
// is useless to anyone else.
func TestOAuthCallback_SendsPKCEToTheProvider(t *testing.T) {
	var gotVerifier string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotVerifier = r.PostForm.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sub":"s","email":"a@b.c"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "google", ClientId: "cid", Secret: "csec", AuthorizeUrl: "https://idp.example/authorize",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings(), OAuthRedirectBase: "https://app.example"}

	az, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", CodeChallenge: pkceChallengeOf(validVerifier())})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(az.GetAuthorizeUrl())
	q := u.Query()
	if _, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: q.Get("state")}); err != nil {
		t.Fatal(err)
	}
	if gotVerifier == "" || pkceChallengeOf(gotVerifier) != q.Get("code_challenge") {
		t.Errorf("token request verifier %q does not match the authorize challenge %q", gotVerifier, q.Get("code_challenge"))
	}
	if q.Get("code_challenge") == pkceChallengeOf(validVerifier()) {
		t.Error("the browser's challenge was forwarded to the provider; the provider leg needs its own")
	}
}

// The state travels in the provider URL and the callback URL, so it must not
// reveal the browser's challenge: with it, someone could start a sign-in of
// their own bound to that challenge and hand the victim the callback link.
func TestOAuthAuthorizeURL_TheStateDoesNotRevealTheBrowsersChallenge(t *testing.T) {
	h, _, _ := exchangeHandler(t)
	ch := pkceChallengeOf(validVerifier())
	az, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", CodeChallenge: ch})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(az.GetAuthorizeUrl())
	state := u.Query().Get("state")
	payload, _, _ := strings.Cut(state, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	if strings.Contains(state, ch) || strings.Contains(string(raw), ch) {
		t.Errorf("the state carries the browser's code_challenge: %s", raw)
	}
}
