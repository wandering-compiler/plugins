package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

func errorDetailOf(t *testing.T, err error) *w17pb.ErrorDetail {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a status: %v", err)
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return ed
		}
	}
	return nil
}

// A request scoped into an organization the caller is not in used to read
// "You are not signed in." — to a caller whose token had just been accepted,
// and whose mistake (an org ID where W17-Org wants the slug) that sentence
// hides. Same code as every authentication refusal, so no contract moves; the
// detail is what a person reads, and it survives the decorator loop.
func TestOrgNotMember_SaysWhatIsWrong(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{}, owned: map[string]string{}}}

	prev := scopeDecorators
	scopeDecorators = []scopeDecorator{resolveOrgScope}
	t.Cleanup(func() { scopeDecorators = prev })

	err := runScopeDecorators(ctxWithOrg("01a08faa-bba7-7f3c-bc4b-962c69e23b74"), h, "u1", nil,
		map[string]string{}, map[string]string{})
	if !errors.Is(err, errOrgNotMember) {
		t.Fatalf("want errOrgNotMember underneath, got %v", err)
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated (the contract)", status.Code(err))
	}
	d := errorDetailOf(t, err)
	if d == nil || d.GetCode() != CodeOrgNotMember || d.GetMessage() != MsgOrgNotMember {
		t.Fatalf("detail = %v, want %s / %q", d, CodeOrgNotMember, MsgOrgNotMember)
	}
}

// Any other decorator failure keeps the opaque answer: no detail is invented
// from a cause nobody classified.
func TestScopeDecorators_UnclassifiedFailureStaysOpaque(t *testing.T) {
	prev := scopeDecorators
	scopeDecorators = []scopeDecorator{func(context.Context, *AuthServiceHandler, string, map[string]string, map[string]string, map[string]string) error {
		return errors.New("something else")
	}}
	t.Cleanup(func() { scopeDecorators = prev })

	err := runScopeDecorators(context.Background(), &AuthServiceHandler{}, "u1", nil, map[string]string{}, map[string]string{})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", status.Code(err))
	}
	if d := errorDetailOf(t, err); d != nil {
		t.Errorf("an unclassified failure carried a detail: %v", d)
	}
}

// The REST path names the org and the gateway makes it the W17-Org it
// authenticates, so the two agree. A gRPC caller can still name one org in
// the request and another in its metadata; acting in either is a guess.
func TestRefuseOtherOrg(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(principal.ScopeKey("org_slug"), "acme"))
	if err := refuseOtherOrg(ctx, ""); err != nil {
		t.Errorf("an empty org defers to authentication: %v", err)
	}
	if err := refuseOtherOrg(ctx, "acme"); err != nil {
		t.Errorf("the authenticated org was refused: %v", err)
	}
	err := refuseOtherOrg(ctx, "other")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeOrgMismatch || d.GetField() != "org" {
		t.Errorf("detail = %v, want %s on field org", d, CodeOrgMismatch)
	}
}

// A request that names an org in the field but resolved NONE (a gRPC or MCP
// caller sending `org` alone) named one org, not two: no ORG_MISMATCH. The
// handler's activeOrgID then answers it with "send the W17-Org header"
// (review of #212).
func TestRefuseOtherOrgDefersWhenNoOrgWasResolved(t *testing.T) {
	if err := refuseOtherOrg(context.Background(), "acme"); err != nil {
		t.Fatalf("no resolved org, one named: %v — want it left to activeOrgID", err)
	}
	h := &AuthServiceHandler{Query: &orgMock{}}
	_, err := h.ListOrgMembers(orgAuthedCtx("u1"), &pb.ListOrgMembersReq{Org: "acme"})
	if !errors.Is(err, errNoActiveOrg) && !strings.Contains(fmt.Sprint(err), "W17-Org") {
		t.Fatalf("ListOrgMembers{org} with no resolved org = %v, want the no-active-org answer naming W17-Org", err)
	}
}
