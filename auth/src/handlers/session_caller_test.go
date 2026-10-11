package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// sessionCallerCtx is a caller as the gateway hands it to a handler: the
// user_id scope plus the x-w17-user envelope Authenticate stamped. An empty
// sessionTokenID is an API-token caller, which Authenticate leaves without one.
func sessionCallerCtx(uid, sessionTokenID string) context.Context {
	raw, err := proto.Marshal(&pb.AuthResp{UserId: uid, SessionTokenId: sessionTokenID, PermissionIds: []int32{5}})
	if err != nil {
		panic(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, uid,
		userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

// An API token limited to one permission must not mint a token: the new one is
// built from the holder's roles, so it would carry every API-realm permission
// the holder has. Nothing may be written either.
func TestCreateApiToken_AnAPITokenCallerIsRefused(t *testing.T) {
	m := &apiTokenMgmtMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.CreateApiToken(sessionCallerCtx("u1", ""), &pb.CreateApiTokenReq{Name: "wider"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller minted a token: err = %v, want PermissionDenied", err)
	}
	if m.issueReq != nil {
		t.Errorf("a refused mint still wrote a token: %+v", m.issueReq)
	}
}

// The CLI exchange mints a full session, so an API token must not start it.
func TestCliAuthorize_AnAPITokenCallerIsRefused(t *testing.T) {
	m := &cliMock{codes: map[string]*cliCode{}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.CliAuthorize(sessionCallerCtx("u1", ""), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(validVerifier()),
		RedirectUri:   "http://127.0.0.1:1/cb",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller started a CLI login: err = %v, want PermissionDenied", err)
	}
	if len(m.codes) != 0 {
		t.Errorf("a refused authorization still stored a code: %d stored", len(m.codes))
	}
}
