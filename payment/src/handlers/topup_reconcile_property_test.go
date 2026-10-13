package handlers

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// Property: whatever order a top-up's grant, its refunds (made, pending,
// succeeded, failed), its disputes (lost, won) and the owner's spends arrive
// in — and however often they are redelivered — once the last event has been
// reconciled the top-up holds exactly its target:
//
//	held − owed = target = max(0, amount − counted refunds − lost disputes)
//
// with owed ≥ 0, owed only while the balance is empty, and the balance equal
// to what is held less what was spent.
func TestTopupReconciliation_Property_RandomInterleavings(t *testing.T) {
	for seed := int64(1); seed <= 150; seed++ {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) { checkTopupInterleaving(t, seed) })
	}
}

func checkTopupInterleaving(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	r := newRig(t)
	p := r.topUp("user-a", "10.00", "top-x")
	pi := p.GetProviderPaymentId()
	success := eventJSON("evt_top", "payment_intent.succeeded", pi, nil)
	if rng.Intn(2) == 0 {
		r.store.injectBefore("ApplyCredit", errTransient) // the first grant fails
	}
	_, _ = r.deliver(success)

	type refund struct {
		id     string
		amount int64
		status string
	}
	var refunds []*refund
	var log []string
	refundable := func() int64 {
		left := int64(1000)
		for _, rf := range refunds {
			if rf.status != "failed" {
				left -= rf.amount
			}
		}
		return left
	}
	spent, lost, evt := 0, int64(0), 0
	next := func() string { evt++; return fmt.Sprintf("evt_%d", evt) }
	deliver := func(body []byte) {
		t.Helper()
		if _, err := r.deliver(body); err != nil {
			t.Fatalf("seed %d after %v: %v", seed, log, err)
		}
	}
	for step := 0; step < 14; step++ {
		switch op := rng.Intn(7); op {
		case 0: // the success, (re)delivered
			log = append(log, "grant")
			deliver(success)
		case 1: // a refund made at the provider, maybe still pending
			left := refundable()
			if left < 100 {
				continue
			}
			amt := int64(100 * (1 + rng.Intn(int(left/100))))
			rf := &refund{id: r.stripe.refundAtProvider(pi, amt), amount: amt, status: "succeeded"}
			if rng.Intn(2) == 0 {
				rf.status = "pending"
				r.stripe.setRefundStatus(rf.id, "pending")
			}
			refunds = append(refunds, rf)
			log = append(log, "refund "+rf.status+" "+strconv.FormatInt(amt, 10))
			deliver(refundEvent(next(), "refund.created", rf.id, pi))
		case 2, 3: // a refund settles or fails
			var open []*refund
			for _, rf := range refunds {
				if rf.status != "failed" {
					open = append(open, rf)
				}
			}
			if len(open) == 0 {
				continue
			}
			rf := open[rng.Intn(len(open))]
			rf.status = map[int]string{2: "succeeded", 3: "failed"}[op]
			r.stripe.setRefundStatus(rf.id, rf.status)
			log = append(log, "refund "+rf.id+" "+rf.status)
			typ := "refund.updated"
			if rf.status == "failed" {
				typ = "refund.failed"
			}
			deliver(refundEvent(next(), typ, rf.id, pi))
		case 4: // a dispute closes
			amt := int64(100 * (1 + rng.Intn(10)))
			st := "won"
			if rng.Intn(2) == 0 {
				st, lost = "lost", lost+amt
			}
			log = append(log, "dispute "+st+" "+strconv.FormatInt(amt, 10))
			deliver(disputeEvent(t, next(), "charge.dispute.closed", fmt.Sprintf("dp_%d", evt), pi, st, amt, time.Now().Unix()))
		case 5: // the owner spends
			amt := 1 + rng.Intn(4)
			if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: strconv.Itoa(amt), IdempotencyKey: next()}); err == nil {
				spent += amt
				log = append(log, "spend "+strconv.Itoa(amt))
			}
		case 6: // a redelivery of the last refund event
			log = append(log, "charge.refunded")
			deliver(refundEvent(next(), "charge.refunded", "ch_1", pi))
		}
	}
	// The last events: the success (if it never got through) and a refund
	// event, raced by a few duplicates.
	deliver(success)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.deliver(refundEvent(fmt.Sprintf("evt_final_%d", i), "charge.refunded", "ch_1", pi))
		}()
	}
	wg.Wait()
	deliver(refundEvent("evt_final", "charge.refunded", "ch_1", pi))

	counted := int64(0)
	for _, rf := range refunds {
		if rf.status != "failed" {
			counted += rf.amount
		}
	}
	target := 1000 - counted - lost
	if target < 0 {
		target = 0
	}
	sum, err := r.store.SumTopupCredit(bg, &pb.SumTopupCreditReq{UserId: "user-a", PaymentId: p.GetId(), ProviderPaymentId: pi,
		ReasonGrant: reasonTopupGrant, ReasonRefund: reasonTopupRefund, ReasonRefused: reasonTopupRefused, ReasonReconcile: reasonTopupReconcile})
	if err != nil {
		t.Fatal(err)
	}
	held, owed, bal := sum.GetTotal(), r.store.owed(t, pi), r.store.balance(t, "user-a")
	want := decimalSum(strconv.FormatFloat(float64(target)/100, 'f', 2, 64), "0")
	if got := decimalSub(held, owed); got != want {
		t.Errorf("seed %d %v: held %s − owed %s = %s, want the target %s", seed, log, held, owed, got, want)
	}
	if decimalSign(owed) < 0 || (decimalSign(owed) > 0 && decimalSign(bal) != 0) {
		t.Errorf("seed %d %v: owed %s with balance %s", seed, log, owed, bal)
	}
	if got := decimalSub(held, strconv.Itoa(spent)); got != bal {
		t.Errorf("seed %d %v: balance %s, want held %s − spent %d", seed, log, bal, held, spent)
	}
}
