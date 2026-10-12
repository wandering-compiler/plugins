package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

func detailCode(t *testing.T, err error) (codes.Code, string) {
	t.Helper()
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return st.Code(), ed.GetCode()
		}
	}
	return st.Code(), ""
}

// OAuth refusals a person can act on carry their own code; the rest are
// OAUTH_FAILED; a sign-up gate's coded refusal passes through unchanged.
func TestOAuthRefusal_Codes(t *testing.T) {
	cases := []struct {
		name  string
		cause error
		code  codes.Code
		want  string
	}{
		{"account never verified its address", errOAuthLocalUnverified, codes.Unauthenticated, CodeOAuthAccountUnverified},
		{"provider did not verify", errOAuthEmailUnverified, codes.Unauthenticated, CodeOAuthEmailUnverified},
		{"disabled, behind the opaque wrapper", Unauthenticated(errAuthnUserDisabled), codes.Unauthenticated, CodeAccountDisabled},
		{"state", errOAuthState, codes.Unauthenticated, CodeOAuthFailed},
		{"login code", errOAuthCodeInvalid, codes.Unauthenticated, CodeOAuthFailed},
		{"not invited passes through", errSignUpNotInvited, codes.PermissionDenied, CodeSignUpNotInvited},
		{"bound elsewhere passes through", errInviteOtherAddress, codes.PermissionDenied, CodeInviteOtherAddress},
		{"allowlist passes through", errSignUpClosed, codes.PermissionDenied, CodeSignUpClosed},
		{"an outage stays an outage", status.Error(codes.Unavailable, "db down"), codes.Unavailable, CodeAuthUnavailable},
		// The storage tier attaches an ErrorDetail to these; carrying one
		// must not carry the status past the classification.
		{"a storage timeout with its detail is an outage", storageStatus(codes.DeadlineExceeded, "TIMEOUT"), codes.Unavailable, CodeAuthUnavailable},
		{"a storage not-found with its detail is a refusal", storageStatus(codes.NotFound, "NOT_FOUND"), codes.Unauthenticated, CodeOAuthFailed},
		{"a disabled account's outage is an outage", Unauthenticated(status.Error(codes.Unavailable, "db down")), codes.Unavailable, CodeAuthUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, got := detailCode(t, oauthRefusal(tc.cause))
			if c != tc.code || got != tc.want {
				t.Errorf("= %v/%q, want %v/%q", c, got, tc.code, tc.want)
			}
		})
	}
}

func storageStatus(c codes.Code, code string) error {
	return withUserDetail(status.New(c, "AuthQuery/GetProviderByName: storage words"), code, "storage sentence").Err()
}

// The handlers route the account gates through the same classification: a
// provider sign-in to a disabled account says so, on the callback and on the
// exchange of a code minted before the disable.
func TestOAuth_ADisabledAccountSaysAccountDisabled(t *testing.T) {
	h, m, state := exchangeHandler(t)
	m.identity = &pb.OAuthIdentity{UserId: "user-9", ProviderId: "p1", ExternalId: "ext-1"}
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	m.userDisabled = true
	_, err = h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier()})
	if c, got := detailCode(t, err); c != codes.Unauthenticated || got != CodeAccountDisabled {
		t.Errorf("exchange = %v/%q, want Unauthenticated/%s", c, got, CodeAccountDisabled)
	}
	_, err = h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if c, got := detailCode(t, err); c != codes.Unauthenticated || got != CodeAccountDisabled {
		t.Errorf("callback = %v/%q, want Unauthenticated/%s", c, got, CodeAccountDisabled)
	}
}

// The OAuth handlers answer with these codes, not the opaque bare refusal.
func TestOAuthExchange_ABadCodeSaysOAuthFailed(t *testing.T) {
	h, _, _ := exchangeHandler(t)
	_, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: "nope", CodeVerifier: validVerifier()})
	if _, got := detailCode(t, err); got != CodeOAuthFailed {
		t.Errorf("code = %q, want %s (err %v)", got, CodeOAuthFailed, err)
	}
}

type tokenGateQuery struct {
	gateQuery
	byToken *pb.GetPendingOrgInviteByTokenResp
}

func (q *tokenGateQuery) GetPendingOrgInviteByToken(context.Context, *pb.GetPendingOrgInviteByTokenReq, ...grpc.CallOption) (*pb.GetPendingOrgInviteByTokenResp, error) {
	if q.byToken == nil {
		return nil, status.Error(codes.NotFound, "none")
	}
	return q.byToken, nil
}

// A real invitation bound to another address, with nothing inviting the
// registering one, says so apart from "not invited".
func TestSignupInviteGate_ABoundInvitationForAnotherAddress(t *testing.T) {
	h := &AuthServiceHandler{InviteOnly: true, Query: &tokenGateQuery{byToken: &pb.GetPendingOrgInviteByTokenResp{Email: "invited@example.com"}}}
	err := signupInviteGate(context.Background(), h, "other@example.com", "tok")
	if !errors.Is(err, errInviteOtherAddress) {
		t.Fatalf("err = %v, want the other-address refusal", err)
	}
	h.Query = &tokenGateQuery{}
	if err := signupInviteGate(context.Background(), h, "other@example.com", "stale"); !errors.Is(err, errSignUpNotInvited) {
		t.Errorf("a token that matched nothing: %v, want not-invited", err)
	}
}
