package handlers

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// stripe_webhooks/redelivery-no-second-effect and
// concurrent-delivery-one-effect, for every family of events the webhook
// acts on. The guarantee must come from each family's transition guard, not
// from the processed-events ledger, so every copy here gets past the ledger:
// a redelivery after the first delivery's ledger write failed, and copies
// delivered at once (each reads the ledger before any writes it).

// webhookFamily sets up what one event acts on, renders the event, and names
// what it announces — once.
type webhookFamily struct {
	name  string
	setup func(t *testing.T, r *rig) []byte
	want  map[string]int
}

func subscribed(t *testing.T, r *rig) string {
	t.Helper()
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: 290000, Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	sv, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	return sv.GetSubscription().GetProviderSubscriptionId()
}

func webhookFamilies() []webhookFamily {
	return []webhookFamily{
		{"payment_intent.succeeded", func(t *testing.T, r *rig) []byte {
			return eventJSON("evt_s", "payment_intent.succeeded", r.charge("user-a", 10000, "k").GetProviderPaymentId(), nil)
		}, map[string]int{"PaymentSucceeded": 1}},
		{"payment_intent.payment_failed", func(t *testing.T, r *rig) []byte {
			return eventJSON("evt_f", "payment_intent.payment_failed", r.charge("user-a", 10000, "k").GetProviderPaymentId(), nil)
		}, map[string]int{"PaymentFailed": 1}},
		{"refund.created (made at the provider)", func(t *testing.T, r *rig) []byte {
			p := r.paid("user-a", 100000, "k")
			re := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)
			return refundEvent("evt_r", "refund.created", re, p.GetProviderPaymentId())
		}, map[string]int{"ProviderRefundRecorded": 1}},
		{"refund.updated (pending → succeeded)", func(t *testing.T, r *rig) []byte {
			p := r.paid("user-a", 100000, "k")
			r.stripe.refundStatus = "pending"
			own, err := refund(r, p.GetId(), 30000, "r-1")
			if err != nil {
				t.Fatal(err)
			}
			r.stripe.setRefundStatus(own.GetRefund().GetProviderRefundId(), "succeeded")
			return refundEvent("evt_ru", "refund.updated", own.GetRefund().GetProviderRefundId(), p.GetProviderPaymentId())
		}, map[string]int{"RefundStatusChanged:SUCCEEDED": 1}},
		{"refund.failed", func(t *testing.T, r *rig) []byte {
			p := r.paid("user-a", 100000, "k")
			r.stripe.refundStatus = "pending"
			own, err := refund(r, p.GetId(), 30000, "r-1")
			if err != nil {
				t.Fatal(err)
			}
			r.stripe.setRefundStatus(own.GetRefund().GetProviderRefundId(), "failed")
			return refundEvent("evt_rf", "refund.failed", own.GetRefund().GetProviderRefundId(), p.GetProviderPaymentId())
		}, map[string]int{"RefundStatusChanged:FAILED": 1}},
		{"charge.dispute.created", func(t *testing.T, r *rig) []byte {
			p := r.paid("user-a", 100000, "k")
			return disputeEvent(t, "evt_dc", "charge.dispute.created", "dp_1", p.GetProviderPaymentId(), "needs_response", 1000, time.Now().Unix())
		}, map[string]int{"DisputeOpened:NEEDS_RESPONSE": 1}},
		{"charge.dispute.closed", func(t *testing.T, r *rig) []byte {
			p := r.paid("user-a", 100000, "k")
			now := time.Now().Unix()
			deliverOK(t, r, disputeEvent(t, "evt_d0", "charge.dispute.created", "dp_1", p.GetProviderPaymentId(), "needs_response", 1000, now-10))
			return disputeEvent(t, "evt_dl", "charge.dispute.closed", "dp_1", p.GetProviderPaymentId(), "lost", 1000, now)
		}, map[string]int{"DisputeOpened:NEEDS_RESPONSE": 1, "DisputeClosed:LOST": 1}},
		{"customer.subscription.updated", func(t *testing.T, r *rig) []byte {
			sid := subscribed(t, r)
			return eventJSON("evt_su", "customer.subscription.updated", sid, map[string]any{"status": "active", "current_period_end": 1893456000})
		}, map[string]int{"SubscriptionStatusChanged": 1}},
		{"customer.subscription.updated (same status, new period)", func(t *testing.T, r *rig) []byte {
			sid := subscribed(t, r)
			deliverOK(t, r, withCreated(t, eventJSON("evt_su0", "customer.subscription.updated", sid, map[string]any{"status": "active", "current_period_end": 1893456000}), time.Now().Unix()-60))
			return eventJSON("evt_su1", "customer.subscription.updated", sid, map[string]any{"status": "active", "current_period_end": 1896134400})
		}, map[string]int{"SubscriptionStatusChanged": 2}},
		{"customer.subscription.deleted", func(t *testing.T, r *rig) []byte {
			sid := subscribed(t, r)
			return eventJSON("evt_sd", "customer.subscription.deleted", sid, map[string]any{"status": "canceled"})
		}, map[string]int{"SubscriptionStatusChanged": 1}},
	}
}

// The first delivery applies its effect and then fails to record itself in
// the ledger; the provider redelivers the same event. The redelivery must
// change nothing and announce nothing again, and be acknowledged.
func TestWebhook_ARedeliveryAfterAFailedLedgerWriteHasNoSecondEffect(t *testing.T) {
	for _, f := range webhookFamilies() {
		t.Run(f.name, func(t *testing.T) {
			r := newRig(t)
			body := f.setup(t, r)
			r.store.injectBefore("MarkWebhookProcessed", errTransient)
			_, err := r.deliver(body)
			wantCode(t, err, codes.Unavailable, "the delivery whose ledger write failed")
			resp, err := r.deliver(body)
			if err != nil {
				t.Fatalf("redelivery: %v", err)
			}
			if !resp.GetHandled() {
				t.Error("the redelivery is the event's first recorded handling: handled=true")
			}
			wantEvents(t, r, f.want)
		})
	}
}

// Copies of one event delivered at once (a slow handler and its retry
// overlap) all succeed and act once.
func TestWebhook_ConcurrentCopiesOfAnEventActOnce(t *testing.T) {
	for _, f := range webhookFamilies() {
		t.Run(f.name, func(t *testing.T) {
			r := newRig(t)
			body := f.setup(t, r)
			// Every copy passes the ledger read before any of them writes.
			const n = 4
			var reads sync.WaitGroup
			reads.Add(n)
			release := make(chan struct{})
			go func() { reads.Wait(); close(release) }()
			r.store.everyBefore("MarkWebhookProcessed", func() { <-release })
			r.store.everyAfter("GetProcessedWebhookEvent", reads.Done)
			var wg sync.WaitGroup
			errs := make(chan error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := r.deliver(body); err != nil {
						errs <- err
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Errorf("a concurrent copy failed: %v", err)
			}
			wantEvents(t, r, f.want)
		})
	}
}

// The model store refuses a copy the way MarkSubscriptionStatus's statement
// does; hold the statement to that guard, so the model cannot drift from it.
func TestMarkSubscriptionStatus_TheStatementRefusesACopy(t *testing.T) {
	src, err := os.ReadFile("../../proto/mutations/payment_mutation.proto")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(src, []byte("rpc MarkSubscriptionStatus("))
	if start < 0 {
		t.Fatal("MarkSubscriptionStatus not found in payment_mutation.proto")
	}
	end := bytes.Index(src[start:], []byte("RETURNING"))
	var dql strings.Builder
	for _, p := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(string(src[start:start+end]), -1) {
		dql.WriteString(p[1])
	}
	got := strings.Join(strings.Fields(dql.String()), " ")
	const guard = "AND status <> 4 AND (provider_event_at IS NULL OR provider_event_at < :provider_event_at " +
		"OR (provider_event_at = :provider_event_at AND (status <> :status OR current_period_end IS DISTINCT FROM :current_period_end)))"
	if !strings.Contains(got, guard) {
		t.Errorf("MarkSubscriptionStatus's guard is not the one the model store applies:\n got: %s\nwant: … %s", got, guard)
	}
}
