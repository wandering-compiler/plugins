package handlers

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// The code the operator receives is one the RELAY holds and will redeem —
// minted there, not here — and it comes with the fingerprint the worker pins
// that relay by.
func TestIssueRegistrationCode_TheCodeIsTheRelays(t *testing.T) {
	codeStore, err := regcode.New(time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := relaycore.New(relaycore.Options{TicketTTL: time.Minute})
	reg := workeradmit.New()
	_, dial := serveWithOptions(t, &relayserver.Server{
		Pool: pool, Workers: reg, Codes: codeStore, ProxyAddress: "r:9000", ProxyFingerprint: "relayfp",
	}, relayserver.BanServerOptions(reg)...)
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "eu-1", URL: "m", Fingerprint: "relayfp"}}},
		Dial:    dial,
	}

	resp, err := h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"1"}})
	if err != nil {
		t.Fatalf("IssueRegistrationCode: %v", err)
	}
	if resp.GetRelay() != "eu-1" || resp.GetRelayFingerprint() != "relayfp" {
		t.Errorf("resp = %v, want relay eu-1 with its pinned fingerprint", resp)
	}
	if !resp.GetExpiresAt().AsTime().After(time.Now()) {
		t.Errorf("the code expires at %v, already past", resp.GetExpiresAt().AsTime())
	}
	if err := codeStore.Redeem(resp.GetCode()); err != nil {
		t.Fatalf("the relay does not hold the code the operator was given: %v", err)
	}
}

// A code is one relay's: a selection of several is refused, not answered
// with a code nobody can tell the destination of.
func TestIssueRegistrationCode_ExactlyOneRelay(t *testing.T) {
	h := &ClusterServiceHandler{Workers: &workerStore{}, Relays: &store{}}
	for _, ids := range [][]string{nil, {"1", "2"}} {
		_, err := h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: ids})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("ids %v: %v, want InvalidArgument", ids, err)
		}
	}
}
