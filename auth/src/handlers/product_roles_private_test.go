package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// privateCallerCtx is a request the identity's private gateway admitted for
// domain: the gateway writes the calling domain into the metadata.
func privateCallerCtx(domain string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(callerDomainKey, domain))
}

// A product is answered only through the identity's private surface, and only
// for itself: no caller domain (a product dialing the tiers) and another
// product's (one asking as another) are refused before anything is read.
func TestAnswerProductRoles_OnlyThroughThePrivateSurfaceAsItself(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no private gateway": context.Background(),
		"another product":    privateCallerCtx("beta"),
	} {
		ctx = context.WithValue(ctx, authHeadersKey{}, map[string]string{productHeader: "alpha"})
		err := answerProductRoles(ctx, &AuthServiceHandler{}, &authPrincipal{userID: "u1"}, nil)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v, want PermissionDenied", name, err)
		}
	}
}
