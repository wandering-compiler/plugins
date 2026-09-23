package handlers

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// The hooks are registered by subscriptions.go / prepaid.go init() in
// the test binary (all files present), so IngestStripe dispatches to
// them — exactly as a build with both features staged would.

func TestIngestStripe_SubscriptionEvent_Reconciles(t *testing.T) {
	m := &fakeMutation{}
	h := webhookHandler(m)
	body := []byte(`{"id":"evt_s1","type":"customer.subscription.updated","data":{"object":{"id":"sub_x","status":"past_due","current_period_end":1893456000}}}`)

	if _, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body}); err != nil {
		t.Fatalf("IngestStripe: %v", err)
	}
	if m.lastMarkSub == nil {
		t.Fatal("subscription webhook did not reconcile (MarkSubscriptionStatus not called)")
	}
	if m.lastMarkSub.GetProviderSubscriptionId() != "sub_x" {
		t.Errorf("provider sub id = %q", m.lastMarkSub.GetProviderSubscriptionId())
	}
	if m.lastMarkSub.GetStatus() != int32(pb.Subscription_PAST_DUE) {
		t.Errorf("status = %d, want PAST_DUE", m.lastMarkSub.GetStatus())
	}
	if m.lastMarkSub.GetCurrentPeriodEnd() == nil {
		t.Error("current_period_end not carried from event")
	}
}

func TestTopUpCredit(t *testing.T) {
	be := &fakeBackend{createRes: backend.PaymentResult{ProviderPaymentID: "pi_top", ClientSecret: "pi_top_secret", Status: "requires_confirmation"}}
	m := &fakeMutation{}
	q := &fakeQuery{customer: &pb.Customer{Id: "cust-1", ProviderCustomerId: "cus_1"}}
	h := newHandler(q, m, be)

	resp, err := h.TopUpCredit(context.Background(), &pb.TopUpCreditReq{UserId: "u1", Amount: "20.00", Currency: "usd", IdempotencyKey: "top1"})
	if err != nil {
		t.Fatalf("TopUpCredit: %v", err)
	}
	if resp.GetClientSecret() != "pi_top_secret" {
		t.Errorf("client_secret = %q", resp.GetClientSecret())
	}
	// A pending top-up was recorded against the charge.
	if m.lastCreateTopup == nil || m.lastCreateTopup.GetProviderPaymentId() != "pi_top" {
		t.Errorf("pending top-up not recorded: %+v", m.lastCreateTopup)
	}
	if m.lastCreateTopup.GetAmount() != "20.00" {
		t.Errorf("top-up amount = %q", m.lastCreateTopup.GetAmount())
	}
}

func TestIngestStripe_TopUpSuccess_GrantsCredit(t *testing.T) {
	m := &fakeMutation{}
	q := &fakeQuery{creditTopup: &pb.CreditTopup{ProviderPaymentId: "pi_42", UserId: "u1", Amount: "20.00"}}
	h := &PaymentServiceHandler{Mutation: m, Query: q, Backend: &fakeBackend{}, WebhookSecret: testWebhookSecret}
	body := []byte(`{"id":"evt_p1","type":"payment_intent.succeeded","data":{"object":{"id":"pi_42"}}}`)

	if _, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body}); err != nil {
		t.Fatalf("IngestStripe: %v", err)
	}
	if m.succeededFor != "pi_42" {
		t.Errorf("payment not marked succeeded: %q", m.succeededFor)
	}
	if m.lastApply == nil || m.lastApply.GetUserId() != "u1" || m.lastApply.GetDelta() != "20.00" {
		t.Errorf("credit not granted: %+v", m.lastApply)
	}
	if m.lastApply.GetReason() != "topup" {
		t.Errorf("grant reason = %q, want topup", m.lastApply.GetReason())
	}
	if m.markGrantedFor != "pi_42" {
		t.Errorf("top-up not marked granted: %q", m.markGrantedFor)
	}
}

func TestIngestStripe_TopUpAlreadyGranted_NoOp(t *testing.T) {
	m := &fakeMutation{}
	q := &fakeQuery{creditTopup: &pb.CreditTopup{ProviderPaymentId: "pi_42", UserId: "u1", Amount: "20.00", GrantedAt: timestamppb.Now()}}
	h := &PaymentServiceHandler{Mutation: m, Query: q, Backend: &fakeBackend{}, WebhookSecret: testWebhookSecret}
	body := []byte(`{"id":"evt_p2","type":"payment_intent.succeeded","data":{"object":{"id":"pi_42"}}}`)

	if _, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body}); err != nil {
		t.Fatalf("IngestStripe: %v", err)
	}
	if m.lastApply != nil {
		t.Error("already-granted top-up must not re-grant")
	}
}

func TestIngestStripe_SucceededNotATopUp_NoGrant(t *testing.T) {
	m := &fakeMutation{}
	q := &fakeQuery{creditTopup: nil} // no top-up for this charge
	h := &PaymentServiceHandler{Mutation: m, Query: q, Backend: &fakeBackend{}, WebhookSecret: testWebhookSecret}
	body := []byte(`{"id":"evt_p3","type":"payment_intent.succeeded","data":{"object":{"id":"pi_plain"}}}`)

	if _, err := h.IngestStripe(ctxWithSig(body), &pb.IngestStripeReq{RawPayload: body}); err != nil {
		t.Fatalf("IngestStripe: %v", err)
	}
	if m.succeededFor != "pi_plain" {
		t.Error("plain payment should still be marked succeeded")
	}
	if m.lastApply != nil {
		t.Error("plain payment must not grant credit")
	}
}
