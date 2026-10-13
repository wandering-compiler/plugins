package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- the outbound calls are bounded ----------------------------------------
//
// The token and userinfo endpoints are whatever URL the provider row names.
// A provider that hangs, or answers without end, must cost a sign-in a
// bounded time and a bounded amount of memory.

func TestOAuthHTTPClient_TimesOutAfterFifteenSeconds(t *testing.T) {
	if got := oauthHTTPClient.Timeout; got != 15*time.Second {
		t.Fatalf("outbound OAuth timeout = %v, want 15s (0 waits forever)", got)
	}
}

// padded returns a JSON object with the given fields and a filler string that
// brings the body to n bytes. Truncated anywhere, it is no longer JSON.
func padded(fields string, n int) string {
	head := "{" + fields + `,"pad":"`
	tail := `"}`
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
}

// oversizedIdP answers both endpoints with a body of exactly n bytes.
func oversizedIdP(t *testing.T, n int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(padded(`"access_token":"at-123"`, n)))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(padded(`"sub":"ext-1","email":"alice@idp.example"`, n)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// At most 1 MiB of either answer is read. A larger body is cut there — and a
// cut JSON body is refused, never half-parsed — while one that fits works.
func TestOAuthOutbound_ReadsAtMostOneMiB(t *testing.T) {
	const limit = 1 << 20
	for _, c := range []struct {
		name string
		size int
		ok   bool
	}{
		{"fits", limit, true},
		{"one byte over", limit + 1, false},
		{"far over", 4 * limit, false},
	} {
		srv := oversizedIdP(t, c.size)
		h := &AuthServiceHandler{OAuthRedirectBase: "https://app.example"}
		p := &pb.OAuthProvider{Name: "acme", ClientId: "cid", Secret: "csec", TokenUrl: srv.URL + "/token"}

		_, err := h.exchangeCode(context.Background(), p, "auth-code", "verifier")
		if (err == nil) != c.ok {
			t.Errorf("token endpoint, %s (%d bytes): err = %v, want ok=%v", c.name, c.size, err, c.ok)
		}
		_, err = h.fetchUserinfo(context.Background(), srv.URL+"/userinfo", "at-123")
		if (err == nil) != c.ok {
			t.Errorf("userinfo endpoint, %s (%d bytes): err = %v, want ok=%v", c.name, c.size, err, c.ok)
		}
	}
}

// --- oauth × two_factor ------------------------------------------------------

// An OAuth sign-in is not challenged for the plugin's second factor — the
// identity provider is treated as one (Verified finding 8, Decided). The gate
// here challenges everybody, so a session can only come out of the exchange if
// the gate was never asked.
func TestOAuthExchange_IsNotChallengedForTheSecondFactor(t *testing.T) {
	asked := 0
	saved := signInMfaGate
	signInMfaGate = func(context.Context, *AuthServiceHandler, *pb.User, string, bool) (*pb.SignInResp, bool, error) {
		asked++
		return &pb.SignInResp{}, true, nil
	}
	t.Cleanup(func() { signInMfaGate = saved })

	srv := fakeIdP(t, map[string]any{"sub": "ext-1", "email": "alice@idp.example"}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", Secret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		identity: &pb.OAuthIdentity{Id: "id-existing", UserId: "u-existing"},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	cb, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: testState(t, "csec", "google", "")})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if ex := redeem(t, h, cb); ex.GetToken() == "" {
		t.Fatal("the exchange issued no session")
	}
	if asked != 0 {
		t.Errorf("the second-factor gate was consulted %d time(s) on an OAuth sign-in", asked)
	}
}

// --- user_admin × oauth ------------------------------------------------------

// deletedOwnerMock is oauthMock after DeleteUser: the identity row survived
// (DeleteUser purges tokens and the User row only), the account it names is
// gone.
type deletedOwnerMock struct{ *oauthMock }

func (deletedOwnerMock) GetUserById(context.Context, *pb.GetUserByIdReq, ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return nil, status.Error(codes.NotFound, "no rows")
}

// A provider identity whose account was deleted resolves to nobody. It must
// not sign in, and must not quietly register a fresh account in its place
// either: the callback refuses with the opaque Unauthenticated and writes
// nothing — no login code, no user, no identity — until the row is removed.
func TestOAuthCallback_AnIdentityWhoseAccountWasDeletedCannotSignIn(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-1", "email": "alice@idp.example", "email_verified": true}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", Secret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		identity: &pb.OAuthIdentity{Id: "id-orphan", UserId: "u-deleted"},
	}
	q := deletedOwnerMock{m}
	h := &AuthServiceHandler{Query: q, Mutation: q, PasswordHash: testPasswordSettings()}
	_, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: testState(t, "csec", "google", "")})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("callback for an orphaned identity: %v, want Unauthenticated", err)
	}
	if len(m.loginCodes) != 0 || m.createdUser != nil || m.createdIdent != nil || m.issuedHash != "" {
		t.Errorf("an orphaned identity wrote something: codes=%d user=%+v identity=%+v issued=%q",
			len(m.loginCodes), m.createdUser, m.createdIdent, m.issuedHash)
	}
}

// DeleteUser removes the account's tokens and the User row, and nothing a
// feature owns: the rows of OAuthIdentity, UserRole, OrgMembership, Device and
// UserTotpSecret outlive it, for the UserDeleted consumer to clean up.
func TestDeleteUser_PurgesTokensAndTheUserOnly(t *testing.T) {
	body := mutationRPCBody(t, "DeleteUser")
	tables := moduleTables(body)
	if strings.Join(tables, ",") != "UserToken,User" {
		t.Errorf("DeleteUser touches %v, want UserToken then User:\n%s", tables, body)
	}
	if !strings.Contains(body, `event: "UserDeleted"`) {
		t.Errorf("DeleteUser emits no UserDeleted for downstream cleanup:\n%s", body)
	}
}

// moduleTables lists the @module tables a statement set names, in order.
func moduleTables(body string) []string {
	var out []string
	for _, part := range strings.Split(body, "@module.")[1:] {
		end := strings.IndexAny(part, " \"")
		if end < 0 {
			end = len(part)
		}
		out = append(out, part[:end])
	}
	return out
}
