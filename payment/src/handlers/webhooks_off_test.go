package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// webhookFile is the file the stripe_webhooks feature stages (plugin.yaml
// go_files); with the feature off it is not compiled into the bundle.
const webhookFile = "webhook_stripe.go"

// Only the webhook moves a payment's status, apart from RefundPayment's
// REFUNDED (and its undo): every Payment status mutation outside the webhook
// file is one of those two. A MarkPaymentSucceeded / Failed / Canceled call
// anywhere else would move a status, and emit its event, in a bundle that has
// no webhook.
func TestStatusTransitions_OnlyTheWebhookMovesAPaymentBeyondRefunded(t *testing.T) {
	manifest, err := os.ReadFile("../../plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	feature := strings.Index(string(manifest), "- name: stripe_webhooks")
	staged := strings.Index(string(manifest), "- handlers/"+webhookFile)
	if feature < 0 || staged < feature {
		t.Fatalf("plugin.yaml no longer stages handlers/%s with stripe_webhooks; update this test", webhookFile)
	}

	allowed := map[string]bool{"MarkPaymentRefunded": true, "MarkPaymentRefundReversed": true}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seenInWebhook := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(sel.Sel.Name, "MarkPayment") {
				return true
			}
			if name == webhookFile {
				seenInWebhook[sel.Sel.Name] = true
			} else if !allowed[sel.Sel.Name] {
				t.Errorf("%s: %s outside %s moves a payment without the webhook", fset.Position(call.Pos()), sel.Sel.Name, webhookFile)
			}
			return true
		})
	}
	// The scan must see what it guards: the webhook's own transitions.
	for _, m := range []string{"MarkPaymentSucceeded", "MarkPaymentFailed", "MarkPaymentCanceled"} {
		if !seenInWebhook[m] {
			t.Errorf("%s not found in %s: the scan is reading the wrong thing", m, webhookFile)
		}
	}
}

// Without webhook deliveries a payment stays at the status it was created
// with, and a payment created SUCCEEDED can still become REFUNDED through
// RefundPayment. No PaymentSucceeded, PaymentFailed or PaymentCanceled is
// emitted by any of the base calls.
func TestFlow_WithoutWebhooks_OnlyARefundMovesAPayment(t *testing.T) {
	saved := webhooksStaged
	webhooksStaged = false
	t.Cleanup(func() { webhooksStaged = saved })
	r := newRig(t)

	pending := r.charge("user-a", "10.00", "k-pending")
	paid := r.charge("user-a", "4.00", "k-paid")
	// The provider answered succeeded at creation (a confirmed intent).
	r.store.mu.Lock()
	r.store.payments[paid.GetId()].Status = pb.Payment_SUCCEEDED
	r.store.mu.Unlock()

	if _, err := r.h.GetMyPayment(asCaller("user-a"), &pb.GetMyPaymentReq{Id: pending.GetId()}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "10.00", Currency: "usd", IdempotencyKey: "k-pending"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: paid.GetId(), IdempotencyKey: "r-paid"}); err != nil {
		t.Fatalf("refund: %v", err)
	}

	if got := r.store.paymentStatus(t, pending.GetProviderPaymentId()); got != pending.GetStatus() || got != pb.Payment_REQUIRES_ACTION {
		t.Errorf("unconfirmed payment = %v, want its initial %v", got, pending.GetStatus())
	}
	if got := r.store.paymentStatus(t, paid.GetProviderPaymentId()); got != pb.Payment_REFUNDED {
		t.Errorf("refunded payment = %v, want REFUNDED", got)
	}
	for _, e := range []string{"PaymentSucceeded", "PaymentFailed", "PaymentCanceled"} {
		if n := r.store.events(e); n != 0 {
			t.Errorf("%s emitted %d time(s) without a webhook", e, n)
		}
	}
	if n := r.store.events("PaymentRefunded"); n != 1 {
		t.Errorf("PaymentRefunded emitted %d time(s), want 1", n)
	}
}
