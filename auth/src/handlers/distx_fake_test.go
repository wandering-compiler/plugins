package handlers

import (
	"context"

	"google.golang.org/grpc"

	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
)

// recordingDistTx is THE transaction coordinator stand-in for this package.
//
// # Why this exists, and what it replaced
//
// Three handlers hold a pair of writes together in one transaction, each
// because a consumer lost something real when they were apart (a consumer): a
// reset that burned the link without changing the password, and a bot token
// minted LIVE with no narrowing — which the resolver reads as
// `all_permissions`, so a caller who asked for a narrow credential and got an
// error back could be leaving behind a wider one.
//
// Every one of those transactions is conditional on `h.DistTx != nil`, and
// every generated bundle wires it (`pluginwire.go` sets
// `DistTx: distxLocalClient{…}` unconditionally). The unit tests did not: they
// built handlers with the field zero, so the nil branch ran, no transaction
// was ever opened, and the atomicity the comments describe at length was
// exercised by NOTHING. A suite in that state stays green if `distx.Begin`
// is deleted.
//
// What stood in for it was a test that read the handler's own SOURCE for the
// string "distx.Begin(" (`mfa_test.go`). That proves a call site exists. It
// cannot tell a Commit from a Rollback, and it cannot notice a Begin whose
// handle is dropped on the failure path — which is the only thing the fix was
// for.
//
// So the seam under test is the one the generated bundle actually hands the
// handler: a client. Drive it, then assert on what the handler DID with the
// transaction.
type recordingDistTx struct {
	distxpb.W17DistributedTransactionClient

	// beginErr fails the Begin, for the arm where a handler must not proceed
	// to touch anything.
	beginErr error

	begun      []string // ConnectionName per Begin, in order
	committed  []string // TxId per Commit
	rolledBack []string // TxId per Rollback
}

// txID is fixed and non-empty: a handler that threaded an EMPTY id would look
// identical to one that threaded the right one if the fake handed out "".
const fakeTxID = "tx-recorded-1"

func (r *recordingDistTx) Begin(_ context.Context, in *distxpb.BeginRequest, _ ...grpc.CallOption) (*distxpb.BeginResponse, error) {
	if r.beginErr != nil {
		return nil, r.beginErr
	}
	r.begun = append(r.begun, in.GetConnectionName())
	return &distxpb.BeginResponse{TxId: fakeTxID}, nil
}

func (r *recordingDistTx) Commit(_ context.Context, in *distxpb.CommitRequest, _ ...grpc.CallOption) (*distxpb.CommitResponse, error) {
	r.committed = append(r.committed, in.GetTxId())
	return &distxpb.CommitResponse{}, nil
}

func (r *recordingDistTx) Rollback(_ context.Context, in *distxpb.RollbackRequest, _ ...grpc.CallOption) (*distxpb.RollbackResponse, error) {
	r.rolledBack = append(r.rolledBack, in.GetTxId())
	return &distxpb.RollbackResponse{}, nil
}

// settled reports how the single expected transaction ended, as a word a
// failure message can print: "committed", "rolled back", "left open", or
// "never begun".
func (r *recordingDistTx) settled() string {
	switch {
	case len(r.begun) == 0:
		return "never begun"
	case len(r.committed) > 0 && len(r.rolledBack) > 0:
		return "both committed AND rolled back"
	case len(r.committed) > 0:
		return "committed"
	case len(r.rolledBack) > 0:
		return "rolled back"
	}
	return "left open"
}
