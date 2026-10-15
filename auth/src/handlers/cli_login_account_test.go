package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// accountCliMock is cliMock with the code's account in a chosen state, as
// GetUserById reads it at exchange time.
type accountCliMock struct {
	*cliMock
	user *pb.User
}

func (m accountCliMock) GetUserById(context.Context, *pb.GetUserByIdReq, ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: m.user}, nil
}

// A code approved while the account could sign in, and exchanged after it was
// disabled — or for a machine account, which never holds a session — mints
// nothing: the exchange re-reads the account, as SignIn would.
func TestCliToken_AnUnsignableAccountGetsNoSession(t *testing.T) {
	for _, c := range []struct {
		name string
		user *pb.User
	}{
		{"disabled", &pb.User{Id: "user-1", DisabledAt: timestamppb.Now()}},
		{"machine account", &pb.User{Id: "user-1", Kind: pb.AccountKind_BOT}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := accountCliMock{cliMock: newCliMock(), user: &pb.User{Id: "user-1"}}
			h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
			verifier := validVerifier()
			authz, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{
				CodeChallenge: pkceChallenge(verifier),
				RedirectUri:   "http://127.0.0.1:54123/cb",
			})
			if err != nil {
				t.Fatalf("CliAuthorize: %v", err)
			}

			m.user = c.user // the account changed between approval and exchange
			h.Query, h.Mutation = m, m
			_, err = h.CliToken(mintCtx(), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("CliToken for a %s account: %v, want Unauthenticated", c.name, err)
			}
			if m.issuedFor != "" {
				t.Errorf("a session was minted for a %s account", c.name)
			}
		})
	}
}

// --- two_factor × cli_login --------------------------------------------------

// The exchange never runs the second factor: the code it redeems was minted by
// CliAuthorize for a caller already signed in with a session (an API token is
// refused there — TestCliAuthorize_AnAPITokenCallerIsRefused), so the factor
// was passed when that session was. The gate here challenges everybody; a
// session out of CliToken means it was not consulted.
func TestCliToken_RunsNoSecondFactor(t *testing.T) {
	asked := 0
	saved := signInMfaGate
	signInMfaGate = func(context.Context, *AuthServiceHandler, *pb.User, string, bool, bool) (*pb.SignInResp, bool, error) {
		asked++
		return &pb.SignInResp{}, true, nil
	}
	t.Cleanup(func() { signInMfaGate = saved })

	m := newCliMock()
	h := newCliHandler(m)
	verifier := validVerifier()
	authz, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(verifier),
		RedirectUri:   "http://127.0.0.1:54123/cb",
	})
	if err != nil {
		t.Fatalf("CliAuthorize: %v", err)
	}
	tok, err := h.CliToken(mintCtx(), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier})
	if err != nil || tok.GetToken() == "" {
		t.Fatalf("CliToken: %v", err)
	}
	if asked != 0 {
		t.Errorf("the second-factor gate was consulted %d time(s) by a CLI exchange", asked)
	}
}
