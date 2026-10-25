package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// withFormPost turns oauth_form_post on for one test, as an activation that
// enables it.
func withFormPost(t *testing.T, on bool) {
	t.Helper()
	prev := formPostServed
	formPostServed = on
	t.Cleanup(func() { formPostServed = prev })
}

// appleKey is a P-256 key as Apple hands it out: a PKCS#8 PEM (.p8).
func appleKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// verifyES256 checks a compact JWS against pub and returns its header and
// claims — what Apple's token endpoint does with the client secret.
func verifyES256(t *testing.T, pub *ecdsa.PublicKey, jws string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("client secret %q is not a compact JWS", jws)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature is not r‖s (64 bytes): %d bytes, %v", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the client secret does not verify with the key's public half")
	}
	for i, into := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims
}

// appleIdP is a token endpoint that records the form POSTed to it and answers
// with idToken (and, to a GET, as a userinfo endpoint).
func appleIdP(t *testing.T, idToken string, sent *url.Values) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			*sent = r.PostForm
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "id_token": idToken, "token_type": "bearer"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Sign in with Apple, end to end in the plugin: the authorize URL asks for
// form_post, the provider comes back by the form POST, the token exchange
// sends a client secret minted from the .p8 key (verified here the way Apple
// verifies it), and the identity comes off the id_token — whose
// email_verified Apple sends as the string "true".
func TestOAuthCallbackForm_SignInWithApple(t *testing.T) {
	withFormPost(t, true)
	key, p8 := appleKey(t)
	var sent url.Values
	state := testState(t, p8, "apple", "/home")
	claims, _ := json.Marshal(map[string]any{
		"sub": "001234.apple", "email": "x7q@privaterelay.appleid.com", "email_verified": "true", "is_private_email": "true",
		"aud": "com.example.web", "exp": time.Now().Add(time.Hour).Unix(), "nonce": oidcNonce(p8, stateNonce(t, state)),
	})
	srv := appleIdP(t, "h."+base64.RawURLEncoding.EncodeToString(claims)+".sig", &sent)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p-apple", Name: "apple", ClientId: "com.example.web", Secret: p8,
		AuthorizeUrl: "https://appleid.apple.com/auth/authorize", TokenUrl: srv.URL + "/auth/token",
		Scopes: "name email", ResponseMode: "form_post", TeamId: "TEAM123456", KeyId: "KEY7890AB", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings(), OAuthRedirectBase: "https://app.example"}

	au, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "apple", CodeChallenge: pkceChallengeOf(validVerifier())})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !strings.Contains(au.GetAuthorizeUrl(), "response_mode=form_post") {
		t.Errorf("the authorize URL does not ask for form_post: %s", au.GetAuthorizeUrl())
	}

	before := time.Now()
	cb, err := h.OAuthCallbackForm(context.Background(), &pb.OAuthCallbackReq{Provider: "apple", Code: "c-apple", State: state})
	if err != nil {
		t.Fatalf("form callback: %v", err)
	}
	if cb.GetRedirectAfter() != "/home" || redeem(t, h, cb).GetToken() == "" {
		t.Fatalf("the form callback did not complete the sign-in: %+v", cb)
	}
	if m.createdUser.GetEmail() != "x7q@privaterelay.appleid.com" || m.createdIdent.GetExternalId() != "001234.apple" {
		t.Errorf("identity off the id_token: user=%+v ident=%+v", m.createdUser, m.createdIdent)
	}
	if len(m.verified) != 1 {
		t.Errorf("Apple's email_verified \"true\" was not taken as verified: %v", m.verified)
	}

	secret := sent.Get("client_secret")
	if secret == p8 || strings.Contains(secret, "PRIVATE KEY") {
		t.Fatal("the .p8 key itself went to the token endpoint")
	}
	header, c := verifyES256(t, &key.PublicKey, secret)
	if header["alg"] != "ES256" || header["kid"] != "KEY7890AB" {
		t.Errorf("header = %v", header)
	}
	u, _ := url.Parse(srv.URL)
	if c["iss"] != "TEAM123456" || c["sub"] != "com.example.web" || c["aud"] != "http://"+u.Host {
		t.Errorf("claims = %v, want iss team, sub client id, aud the token endpoint's origin", c)
	}
	iat, exp := int64(c["iat"].(float64)), int64(c["exp"].(float64))
	if iat < before.Unix()-1 || exp-iat != int64(clientSecretJWTTTL/time.Second) {
		t.Errorf("iat %d exp %d: want minted now, valid %s", iat, exp, clientSecretJWTTTL)
	}
}

// A provider that comes back by the query string has the GET callback: the
// form route refuses it, before anything is exchanged.
func TestOAuthCallbackForm_RefusesAQueryProvider(t *testing.T) {
	var sent url.Values
	srv := appleIdP(t, "", &sent)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "google", ClientId: "cid", Secret: "csec", TokenUrl: srv.URL, Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.OAuthCallbackForm(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: testState(t, "csec", "google", "")}); err == nil {
		t.Fatal("a query-string provider was accepted on the form callback")
	}
	if sent != nil {
		t.Error("the refused callback still exchanged the code")
	}
}

// A provider with a plain client secret is unchanged: no response_mode on
// the authorize URL, the secret sent as it is.
func TestOAuthProvider_PlainSecretUnchanged(t *testing.T) {
	var sent url.Values
	state := testState(t, "csec", "google", "")
	srv := appleIdP(t, "", &sent)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "google", ClientId: "cid", Secret: "csec",
		AuthorizeUrl: "https://idp.example/authorize", TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/token", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	au, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", CodeChallenge: pkceChallengeOf(validVerifier())})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(au.GetAuthorizeUrl(), "response_mode") {
		t.Errorf("a query-string provider asks for a response_mode: %s", au.GetAuthorizeUrl())
	}
	_, _ = h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if sent.Get("client_secret") != "csec" {
		t.Errorf("client_secret = %q, want the stored secret", sent.Get("client_secret"))
	}
}

// What the plugin cannot sign with, or cannot be sent back to, it refuses
// rather than sending the provider something it will reject.
func TestOAuthProvider_AppleMisconfigurations(t *testing.T) {
	_, p8 := appleKey(t)
	rsa := "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"
	for name, p := range map[string]*pb.OAuthProvider{
		"team without key":   {Secret: p8, TeamId: "T", TokenUrl: "https://appleid.apple.com/auth/token"},
		"key without team":   {Secret: p8, KeyId: "K", TokenUrl: "https://appleid.apple.com/auth/token"},
		"not a PEM":          {Secret: "csec", TeamId: "T", KeyId: "K", TokenUrl: "https://appleid.apple.com/auth/token"},
		"not a key":          {Secret: rsa, TeamId: "T", KeyId: "K", TokenUrl: "https://appleid.apple.com/auth/token"},
		"relative token url": {Secret: p8, TeamId: "T", KeyId: "K", TokenUrl: "/auth/token"},
	} {
		if _, err := clientSecret(p, time.Now()); err == nil {
			t.Errorf("%s: a client secret was minted", name)
		}
	}
	withFormPost(t, true)
	for _, mode := range []string{"fragment", "query ", "FORM_POST"} {
		if checkResponseMode(&pb.OAuthProvider{ResponseMode: mode}) == nil {
			t.Errorf("response_mode %q accepted", mode)
		}
	}
}

// Without oauth_form_post nothing receives the provider's POST, so a
// form_post provider is refused before the user is sent to it — not after,
// at a callback that does not exist.
func TestOAuthAuthorizeURL_FormPostNeedsItsRoute(t *testing.T) {
	withFormPost(t, false)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "apple", ClientId: "cid", Secret: "csec", AuthorizeUrl: "https://appleid.apple.com/auth/authorize",
		ResponseMode: "form_post", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	_, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "apple", CodeChallenge: pkceChallengeOf(validVerifier())})
	if err == nil || !errors.Is(err, errOAuthFormPostOff) {
		t.Fatalf("a form_post provider without its route: %v, want %v", err, errOAuthFormPostOff)
	}
}
