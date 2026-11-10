package handlers

import (
	"context"
	"reflect"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- service_account × authenticate -----------------------------------------

// kindQuery answers GetUser with an account of one kind, or an error.
type kindQuery struct {
	pb.AuthQueryClient
	kind pb.AccountKind
	err  error
}

func (q kindQuery) GetUser(context.Context, *pb.GetUserReq, ...grpc.CallOption) (*pb.UserAccount, error) {
	if q.err != nil {
		return nil, q.err
	}
	return &pb.UserAccount{Id: "u1", Kind: q.kind}, nil
}

// A machine principal carries labels[account_kind]=bot; a person carries no
// such label, and neither does a principal whose kind could not be read — so a
// rule written as "refuse unless bot" fails closed. The decorator is staged by
// service_account's init, which is what makes Authenticate run it.
func TestLabelMachineAccount_OnlyABotIsLabelled(t *testing.T) {
	for _, c := range []struct {
		name string
		q    kindQuery
		want string
	}{
		{"bot", kindQuery{kind: pb.AccountKind_BOT}, AccountKindBot},
		{"person", kindQuery{kind: pb.AccountKind_HUMAN}, ""},
		{"unreadable", kindQuery{err: status.Error(codes.Unavailable, "db down")}, ""},
	} {
		labels := map[string]string{}
		if err := labelMachineAccount(context.Background(), &AuthServiceHandler{Query: c.q}, "u1", nil, map[string]string{}, labels); err != nil {
			t.Errorf("%s: the label must never fail authentication: %v", c.name, err)
		}
		if got, ok := labels[AccountKindLabel]; got != c.want || (c.want == "" && ok) {
			t.Errorf("%s: labels = %v, want account_kind=%q", c.name, labels, c.want)
		}
	}

	staged := false
	for _, d := range scopeDecorators {
		if reflect.ValueOf(d).Pointer() == reflect.ValueOf(scopeDecorator(labelMachineAccount)).Pointer() {
			staged = true
		}
	}
	if !staged {
		t.Error("labelMachineAccount is not among the staged scope decorators")
	}
}
