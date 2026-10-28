package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// errResolveUserID is ResolveUser's refusal of a request that names nobody.
var errResolveUserID = errors.New("ResolveUser needs a user id")

// ResolveUser answers what a person holds — the AuthResp Authenticate would
// answer for a session of theirs carrying these headers — without a
// credential.
//
// It exists for one shape. Another domain, behind its own access policy,
// calls a method on this domain's private surface naming the person it acts
// for; the private surface hands this domain no principal of the caller's,
// because permission ids are per domain and the caller's would read as
// this domain's. The method then needs the person as THIS domain sees them:
// principal.ActAs stamps whatever envelope it is given, and every check here
// that reads the envelope — the role ceiling above all — judges what is in
// it. Stamping a bare user id made that person hold nothing, so they could
// grant no role that carries a permission. ResolveUser is the envelope to
// stamp:
//
//	who, err := auth.ResolveUser(ctx, &authpb.ResolveUserReq{UserId: req.GetUserId(), Headers: map[string]string{"w17-org": req.GetOrgSlug()}})
//	ctx, err = principal.ActAs(ctx, who, who.GetScopes())
//
// The answer comes from principalResp, the half of Authenticate after the
// credential, so it is the same roles, organization, narrowing and wildcard
// expansion, not a second resolver that has to agree with the first. The
// person is read as a session: their session-realm roles count (an API or
// MCP token's realm needs the token). The answer says so (acted_for), since
// it names no session token, which is how a check that re-reads grants under
// an organization's lock tells a session from a token. A disabled account is
// refused like its sign-in.
//
// The organization comes from the request's headers alone. The incoming
// `w17-org` is dropped first: Authenticate falls back to it, and here it
// would be whatever the caller's caller happened to forward.
//
// It trusts its caller with any user, as the domain's own business code is
// trusted with the domain's data. No preset surfaces it; a project must not
// either.
func (h *AuthServiceHandler) ResolveUser(ctx context.Context, req *pb.ResolveUserReq) (*pb.AuthResp, error) {
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, errResolveUserID.Error())
	}
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	user := got.GetUser()
	if err := signInDisabledGate(user); err != nil {
		return nil, err
	}
	grants, err := callerRealmGrants(ctx, h, userID, true)
	if err != nil {
		return nil, err
	}
	if in, ok := metadata.FromIncomingContext(ctx); ok {
		in = in.Copy()
		in.Delete(principal.OrgScopeHeader)
		ctx = metadata.NewIncomingContext(ctx, in)
	}
	resp, err := h.principalResp(ctx, &authPrincipal{
		userID: userID,
		realm:  pb.TokenType_TOKEN_TYPE_SESSION,
		grants: grants,
		user:   user,
	}, req.GetHeaders())
	if err != nil {
		return nil, err
	}
	resp.ActedFor = true
	return resp, nil
}
