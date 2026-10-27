package handlers

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// pagedMembers answers ListOrgMembersByOrg as the query does: ordered by
// address, past after_email, at most limit rows.
type pagedMembers struct {
	pb.AuthQueryClient
	emails []string
	asked  []*pb.ListOrgMembersByOrgReq
}

func (m *pagedMembers) ListOrgMembersByOrg(_ context.Context, in *pb.ListOrgMembersByOrgReq, _ ...grpc.CallOption) (*pb.ListOrgMembersByOrgResp, error) {
	m.asked = append(m.asked, in)
	sorted := append([]string(nil), m.emails...)
	sort.Strings(sorted)
	var rows []*pb.OrgMemberRow
	for _, e := range sorted {
		if in.GetAfterEmail() != "" && e <= in.GetAfterEmail() {
			continue
		}
		if len(rows) == int(in.GetLimit()) {
			break
		}
		rows = append(rows, &pb.OrgMemberRow{UserId: "u-" + e, Email: e})
	}
	return &pb.ListOrgMembersByOrgResp{Members: rows}, nil
}

func memberPageCtx() context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(principal.ScopeKey("user_id"), "u1", principal.ScopeKey("org_id"), "org-1"))
}

// An organization's members come a page at a time, and walking the pages by
// their tokens visits every member exactly once, in address order
// (org_membership/members-paged).
func TestListOrgMembers_PagesVisitEveryMemberOnce(t *testing.T) {
	q := &pagedMembers{}
	for i := range 7 {
		q.emails = append(q.emails, fmt.Sprintf("m%02d@example.com", i))
	}
	h := &AuthServiceHandler{Query: q}
	var seen []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 4 {
			t.Fatal("the pages never ended")
		}
		resp, err := h.ListOrgMembers(memberPageCtx(), &pb.ListOrgMembersReq{PageSize: 3, PageToken: token})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.GetMembers()) > 3 {
			t.Fatalf("a page of %d members, asked for 3", len(resp.GetMembers()))
		}
		for _, m := range resp.GetMembers() {
			seen = append(seen, m.GetEmail())
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if fmt.Sprint(seen) != fmt.Sprint(q.emails) {
		t.Errorf("walked %v, want %v", seen, q.emails)
	}
}

// A page that ends exactly at the last member says no page follows: the
// handler reads one row past the page to know.
func TestListOrgMembers_AFullLastPageHasNoNextToken(t *testing.T) {
	q := &pagedMembers{emails: []string{"a@x", "b@x"}}
	resp, err := (&AuthServiceHandler{Query: q}).ListOrgMembers(memberPageCtx(), &pb.ListOrgMembersReq{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetMembers()) != 2 || resp.GetNextPageToken() != "" {
		t.Errorf("got %d members and token %q, want both and no token", len(resp.GetMembers()), resp.GetNextPageToken())
	}
}

// An unset page size is 100 and a larger one is cut to 500, so no request
// reads a whole organization.
func TestListOrgMembers_PageSizeIsBounded(t *testing.T) {
	for _, c := range []struct {
		asked int32
		reads int32
	}{{0, 101}, {-5, 101}, {10, 11}, {500, 501}, {100000, 501}} {
		q := &pagedMembers{}
		if _, err := (&AuthServiceHandler{Query: q}).ListOrgMembers(memberPageCtx(), &pb.ListOrgMembersReq{PageSize: c.asked}); err != nil {
			t.Fatal(err)
		}
		if got := q.asked[0].GetLimit(); got != c.reads {
			t.Errorf("page_size %d read %d rows, want %d", c.asked, got, c.reads)
		}
	}
}

// A token this list did not issue is refused, never read as an address.
func TestListOrgMembers_AForeignTokenIsRefused(t *testing.T) {
	for _, tok := range []string{"not base64!", "_w"} {
		q := &pagedMembers{emails: []string{"a@x"}}
		_, err := (&AuthServiceHandler{Query: q}).ListOrgMembers(memberPageCtx(), &pb.ListOrgMembersReq{PageToken: tok})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("token %q: %v, want InvalidArgument", tok, err)
		}
		if len(q.asked) != 0 {
			t.Errorf("token %q reached the query", tok)
		}
	}
}
