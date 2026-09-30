package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// uniqueViolationErr builds the error shape storage returns for a
// duplicate key: InvalidArgument + a w17.ErrorDetail{code:
// UNIQUE_VIOLATION} (the real grpcerr.Wrap contract).
func uniqueViolationErr(t *testing.T) error {
	t.Helper()
	st, err := status.New(codes.InvalidArgument, "already exists").
		WithDetails(&w17pb.ErrorDetail{Code: "UNIQUE_VIOLATION", Message: "already exists"})
	if err != nil {
		t.Fatalf("build detail: %v", err)
	}
	return st.Err()
}

const testWebhookSecret = "whsec_test_secret"

// signStripe builds a valid Stripe-Signature header for a payload. It
// timestamps with the current time so the stripe driver's replay-
// tolerance window (default 5 min) accepts it without the test having to
// reach into the driver's clock.
func signStripe(payload []byte, secret string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(payload)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func ctxWithSig(payload []byte) context.Context {
	md := metadata.Pairs("stripe-signature", signStripe(payload, testWebhookSecret))
	return metadata.NewIncomingContext(context.Background(), md)
}

func webhookHandler(m *fakeMutation) *PaymentServiceHandler {
	return &PaymentServiceHandler{Mutation: m, Query: &fakeQuery{}, Backend: &fakeBackend{}, WebhookSecret: testWebhookSecret}
}

func TestIngestStripe_Succeeded(t *testing.T) {
	m := &fakeMutation{}
	h := webhookHandler(m)
	body := []byte(`{"id":"evt_1","type":"payment_intent.succeeded","data":{"object":{"id":"pi_42"}}}`)

	resp, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body})
	if err != nil {
		t.Fatalf("IngestStripe: %v", err)
	}
	if !resp.GetHandled() {
		t.Error("want handled=true")
	}
	if m.succeededFor != "pi_42" {
		t.Errorf("MarkPaymentSucceeded provider id = %q, want pi_42", m.succeededFor)
	}
}

func TestIngestStripe_Failed(t *testing.T) {
	m := &fakeMutation{}
	h := webhookHandler(m)
	body := []byte(`{"id":"evt_2","type":"payment_intent.payment_failed","data":{"object":{"id":"pi_99"}}}`)

	if _, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body}); err != nil {
		t.Fatalf("IngestStripe: %v", err)
	}
	if m.failedFor != "pi_99" {
		t.Errorf("MarkPaymentFailed provider id = %q, want pi_99", m.failedFor)
	}
}

// noRowsErr is the error shape a TRANSITION-GUARDED mutation returns
// when its WHERE matched nothing: the generated single-row
// `RETURNING` scan gets sql.ErrNoRows, grpcerr.Wrap maps it to
// NotFound, and the rpc facade forwards it verbatim.
func noRowsErr() error {
	return status.Error(codes.NotFound, "PaymentMutation.MarkPaymentSucceeded: sql: no rows in result set")
}

// TestIngestStripe_Redelivery_RunsNoSideEffectAndEmitsNothing — D-F5.
//
// Q43-pay-1 deliberately runs the idempotent side effects BEFORE the
// dedup ledger, and accepts that a redelivered event reaches the
// reconciliation mutation a second time. What that trade missed is the
// EVENT. The generated emit wrapper fires after every SUCCESSFUL inner
// call (`if err != nil { return nil, err }` sits between the call and
// the emit — see any generated `w17/services/*/src/eventbus/wrap.go`),
// and the reconciliation UPDATE used to be unconditional, so it matched
// the already-SUCCEEDED row on every redelivery and PaymentSucceeded
// was emitted again. Any non-idempotent subscriber (ship the order,
// grant the entitlement, send the receipt) then acted twice.
//
// The fix is a transition guard in the DQL (`AND status <> 3`), which
// makes a redelivery match zero rows → NotFound → no emit. This test
// pins the HANDLER half of that contract:
//
//   - NotFound from a reconciliation mutation must not fail the webhook
//     when the dedup ledger confirms the event was already processed;
//   - the cross-feature side effect must NOT run again;
//   - the answer stays handled=false so the provider stops retrying.
//
// It replaces TestIngestStripe_DuplicateIsNoOp, which asserted only
// resp.Handled == false — and therefore stayed green while both the
// side effect and the emission ran a second time.
func TestIngestStripe_Redelivery_RunsNoSideEffectAndEmitsNothing(t *testing.T) {
	m := &fakeMutation{
		succeededErr:     noRowsErr(),           // the guard refused the transition
		markProcessedErr: uniqueViolationErr(t), // …and the ledger says: seen before
	}
	q := &fakeQuery{creditTopup: &pb.CreditTopup{ProviderPaymentId: "pi_42", UserId: "u1", Amount: "20.00"}}
	h := &PaymentServiceHandler{Mutation: m, Query: q, Backend: &fakeBackend{}, WebhookSecret: testWebhookSecret}
	body := []byte(`{"id":"evt_1","type":"payment_intent.succeeded","data":{"object":{"id":"pi_42"}}}`)

	resp, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body})
	if err != nil {
		t.Fatalf("a redelivery of an already-processed event must not fail the webhook: %v", err)
	}
	if resp.GetHandled() {
		t.Error("duplicate must report handled=false")
	}
	// The event half: the mutation refused the transition, so it returned
	// an error, so the emit wrapper could not fire. Nothing to assert on
	// the fake beyond "the handler did not treat it as a state change".
	if m.succeededFor != "" {
		t.Errorf("the guard refused the transition — no state change may be recorded, got %q", m.succeededFor)
	}
	// The side-effect half: the top-up grant is the cross-feature hook
	// that used to re-run on every redelivery.
	if m.lastApply != nil {
		t.Errorf("redelivery granted credit a second time: %+v", m.lastApply)
	}
	if m.markGrantedFor != "" {
		t.Errorf("redelivery re-stamped the top-up as granted (%q)", m.markGrantedFor)
	}
}

// TestIngestStripe_UnknownProviderPayment_MustNotAcknowledge — the other
// half of the NotFound discrimination (D-F5 / D-F6).
//
// A guarded UPDATE that matches nothing is ambiguous: either the row is
// already in the target state (a redelivery — above), or the local
// Payment row does not exist yet. The second is a REAL race:
// TopUpCredit calls the provider before its own CreatePayment INSERT
// (prepaid.go), so a fast `payment_intent.succeeded` can outrun it.
// That case must keep failing, so the provider redelivers and the
// reconciliation eventually lands — swallowing it loses the payment.
//
// The discriminator is the dedup ledger's own INSERT: a UNIQUE
// violation means we fully processed this event id before (redelivery);
// a fresh insert means we did not, so the provider id is unknown here.
func TestIngestStripe_UnknownProviderPayment_MustNotAcknowledge(t *testing.T) {
	m := &fakeMutation{succeededErr: noRowsErr()} // ledger insert succeeds: first sighting
	q := &fakeQuery{creditTopup: &pb.CreditTopup{ProviderPaymentId: "pi_42", UserId: "u1", Amount: "20.00"}}
	h := &PaymentServiceHandler{Mutation: m, Query: q, Backend: &fakeBackend{}, WebhookSecret: testWebhookSecret}
	body := []byte(`{"id":"evt_new","type":"payment_intent.succeeded","data":{"object":{"id":"pi_42"}}}`)

	_, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("an unknown provider id must fail so the provider redelivers, got %v", err)
	}
	if m.lastApply != nil {
		t.Errorf("no credit may be granted for a payment that was never reconciled: %+v", m.lastApply)
	}
}

// TestIngestStripe_SideEffectFailure_DoesNotStrand — Q43-pay-1. A transient
// side-effect failure must surface as an error WITHOUT recording the dedup
// row, so the provider's redelivery re-runs the side effect. Recording
// dedup first (the old order) stranded the event: the dedup row outlived
// the failed handler and the redelivery short-circuited handled=false,
// never re-running the side effect (charge taken, credit never granted).
func TestIngestStripe_SideEffectFailure_DoesNotStrand(t *testing.T) {
	m := &fakeMutation{succeededErr: status.Error(codes.Unavailable, "transient db blip")}
	h := webhookHandler(m)
	body := []byte(`{"id":"evt_1","type":"payment_intent.succeeded","data":{"object":{"id":"pi_42"}}}`)

	if _, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body}); err == nil {
		t.Fatal("a side-effect failure must return an error so the provider re-delivers")
	}
	if m.markedProcessed {
		t.Error("event must NOT be marked processed when a side effect failed (else the redelivery strands it)")
	}
}

func TestIngestStripe_BadSignature(t *testing.T) {
	m := &fakeMutation{}
	h := webhookHandler(m)
	body := []byte(`{"id":"evt_3","type":"payment_intent.succeeded","data":{"object":{"id":"pi_1"}}}`)
	// Sign with the WRONG secret.
	md := metadata.Pairs("stripe-signature", signStripe(body, "whsec_attacker"))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := h.IngestStripe(ctx, &pb.IngestStripeReq{RawPayload: body})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
	if m.succeededFor != "" {
		t.Error("must not process an unverified webhook")
	}
}
