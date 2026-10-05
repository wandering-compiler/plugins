package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
)

// signedIn is a context carrying the gateway's verified principal the way the
// auth plugin's AuthResp encodes it: permission_ids (1), user_id (2), scopes
// (3). Built by hand so the test pins the WIRE, not this plugin's own message.
func signedIn(userID string) context.Context {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, protowire.AppendVarint(nil, 7))
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, userID)
	md := metadata.Pairs("x-w17-user", base64.StdEncoding.EncodeToString(b))
	return metadata.NewIncomingContext(context.Background(), md)
}

// The decision is recorded under the signed-in operator, read from the
// verified principal.
func TestDecideWorkers_RecordsTheSignedInCaller(t *testing.T) {
	w := &workerStore{}
	h := &ClusterServiceHandler{Workers: w}
	if _, err := h.BanWorkers(signedIn("op-1"), &pb.DecideWorkersActionReq{Ids: []string{"a", "b"}}); err != nil {
		t.Fatalf("BanWorkers: %v", err)
	}
	if _, err := h.UnbanWorkers(signedIn("op-2"), &pb.DecideWorkersActionReq{Ids: []string{"a"}}); err != nil {
		t.Fatalf("UnbanWorkers: %v", err)
	}
	if len(w.decisions) != 2 {
		t.Fatalf("decisions = %v", w.decisions)
	}
	if d := w.decisions[0]; !d.ban || d.by != "op-1" || len(d.ids) != 2 {
		t.Fatalf("ban recorded as %+v, want ban by op-1 of 2 workers", d)
	}
	if d := w.decisions[1]; d.ban || d.by != "op-2" {
		t.Fatalf("unban recorded as %+v, want unban by op-2", d)
	}
}

// With no verified principal there is nobody to record, so nothing is decided.
func TestDecideWorkers_RefusesWithoutACaller(t *testing.T) {
	w := &workerStore{}
	h := &ClusterServiceHandler{Workers: w}
	_, err := h.BanWorkers(context.Background(), &pb.DecideWorkersActionReq{Ids: []string{"a"}})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if _, err := h.BanWorkers(signedIn("op"), &pb.DecideWorkersActionReq{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty selection: err = %v, want InvalidArgument", err)
	}
	if len(w.decisions) != 0 {
		t.Fatalf("a refused call decided %v", w.decisions)
	}
}
