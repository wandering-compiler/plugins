package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// The provider reconciliation (gated stripe_webhooks).
//
// Every provider-backed create writes the provider object first and the local
// row second, and the webhooks bring the provider's later changes in. Both
// halves can be lost for good: a local write that failed and was never
// retried leaves an object with no row, and a webhook endpoint that was down
// (or refused) longer than the provider redelivers — about three days —
// leaves a row whose status never moved again. A charge that succeeded then
// reads pending forever, and a top-up's credit is never granted.
//
// ReconcileProvider walks the provider's own lists instead and applies what
// it finds through the paths the webhook and the create calls use, so every
// invariant those paths keep — the transition guards, the events, a top-up's
// credit reconciliation keyed by step — holds here too, and a run is as safe
// beside a webhook delivery, or beside another run, as two deliveries are
// beside each other. Nothing is deleted: a row the provider no longer agrees
// with is moved by its guarded transitions, never removed.
//
// The plugin schedules nothing. The project calls it: a scheduled job of its
// own, an operator action. It is never REST-exposed.

// Bounds of one call: objects examined (any outcome).
const (
	reconcileDefaultLimit = 1000
	reconcileMaxLimit     = 10000
	reconcilePageSize     = 100 // the provider's largest list page
)

// reconcileKind is one provider list the walk covers, in walk order: a
// payment needs its customer's row, and a refund its payment's.
type reconcileKind int

const (
	kindCustomers reconcileKind = iota
	kindPayments
	kindRefunds
	kindSubscriptions
	kindsDone
)

var reconcileKindNames = [...]string{"customers", "payments", "refunds", "subscriptions"}

// ReconcileProvider walks the provider objects created at or after
// req.since, kind by kind (customers, payments, refunds, subscriptions), and
// brings the local rows in line with them; see the file comment. It answers
// the counts per kind and, when req.limit stopped the walk, the cursor the
// next call continues from.
func (h *PaymentServiceHandler) ReconcileProvider(ctx context.Context, req *pb.ReconcileProviderReq) (*pb.ReconcileProviderResp, error) {
	since, kind, after, err := reconcileStart(req)
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	switch {
	case limit < 0 || limit > reconcileMaxLimit:
		return nil, invalidArg(fmt.Sprintf("limit must be between 0 and %d", reconcileMaxLimit))
	case limit == 0:
		limit = reconcileDefaultLimit
	}
	// Without an installation id nothing is recognisably this
	// installation's (ValidateConfig requires the secret it derives from).
	if h.installID() == "" {
		return nil, status.Error(codes.FailedPrecondition, "payment: the provider reconciliation needs webhook_signing_secret, which identifies this installation's provider objects")
	}

	resp := &pb.ReconcileProviderResp{
		Customers: &pb.ReconcileCounts{}, Payments: &pb.ReconcileCounts{},
		Refunds: &pb.ReconcileCounts{}, Subscriptions: &pb.ReconcileCounts{},
	}
	left := limit
	for ; kind < kindsDone; kind, after = kind+1, "" {
		if kind == kindSubscriptions && reconcileSubscription == nil {
			continue // the subscriptions feature is off: no rows to keep
		}
		for {
			if left == 0 {
				resp.NextCursor = reconcileCursor(since, kind, after)
				return resp, nil
			}
			q := backend.ListQuery{Since: since, After: after, Limit: min(left, reconcilePageSize)}
			n, last, more, err := h.reconcilePage(ctx, kind, q, resp)
			if err != nil {
				return nil, providerFailure(err)
			}
			left -= n
			after = last
			if !more || n == 0 {
				break
			}
		}
	}
	return resp, nil
}

// reconcileStart reads where the walk starts: since (Unix seconds), and the
// kind and object to continue after, from the cursor when there is one.
func reconcileStart(req *pb.ReconcileProviderReq) (int64, reconcileKind, string, error) {
	var since int64
	if req.GetSince() != nil {
		if err := req.GetSince().CheckValid(); err != nil {
			return 0, 0, "", invalidArg("since is not a valid time")
		}
		since = req.GetSince().AsTime().Unix()
	}
	if req.GetCursor() == "" {
		if req.GetSince() == nil {
			// Unbounded, the first run would walk the account's whole
			// history; the caller says how far back.
			return 0, 0, "", invalidArg("since is required (the walk covers objects created at or after it)")
		}
		return since, kindCustomers, "", nil
	}
	parts := strings.SplitN(req.GetCursor(), ":", 3)
	if len(parts) != 3 {
		return 0, 0, "", invalidArg("cursor is not one this call returned")
	}
	cursorSince, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || cursorSince < 0 {
		return 0, 0, "", invalidArg("cursor is not one this call returned")
	}
	kind := kindsDone
	for k, name := range reconcileKindNames {
		if name == parts[1] {
			kind = reconcileKind(k)
		}
	}
	if kind == kindsDone {
		return 0, 0, "", invalidArg("cursor is not one this call returned")
	}
	if req.GetSince() != nil && since != cursorSince {
		return 0, 0, "", invalidArg("since differs from the cursor's; send the cursor alone to continue its walk")
	}
	return cursorSince, kind, parts[2], nil
}

// reconcileCursor is where a walk stopped: its since, the kind it was in and
// the last object it examined. Opaque to the caller.
func reconcileCursor(since int64, kind reconcileKind, after string) string {
	return strconv.FormatInt(since, 10) + ":" + reconcileKindNames[kind] + ":" + after
}

// reconcilePage examines one page of a kind's list. It answers how many
// objects the page held, the last one's id and whether more follow; err is a
// failure to list. A failure on one object is counted, logged and passed by:
// the next run sees the object again.
func (h *PaymentServiceHandler) reconcilePage(ctx context.Context, kind reconcileKind, q backend.ListQuery, resp *pb.ReconcileProviderResp) (int, string, bool, error) {
	readAt := time.Now()
	switch kind {
	case kindCustomers:
		objs, more, err := h.Backend.ListCustomerPage(ctx, q)
		if err != nil || len(objs) == 0 {
			return 0, q.After, more, err
		}
		for _, o := range objs {
			out, err := h.reconcileCustomer(ctx, o)
			tally(resp.GetCustomers(), kind, o.ProviderCustomerID, out, err)
		}
		return len(objs), objs[len(objs)-1].ProviderCustomerID, more, nil
	case kindPayments:
		objs, more, err := h.Backend.ListPaymentPage(ctx, q)
		if err != nil || len(objs) == 0 {
			return 0, q.After, more, err
		}
		for _, o := range objs {
			out, err := h.reconcilePayment(ctx, o)
			tally(resp.GetPayments(), kind, o.ProviderPaymentID, out, err)
		}
		return len(objs), objs[len(objs)-1].ProviderPaymentID, more, nil
	case kindRefunds:
		objs, more, err := h.Backend.ListRefundPage(ctx, q)
		if err != nil || len(objs) == 0 {
			return 0, q.After, more, err
		}
		h.reconcileRefundPage(ctx, objs, resp.GetRefunds())
		return len(objs), objs[len(objs)-1].ProviderRefundID, more, nil
	case kindSubscriptions:
		objs, more, err := h.Backend.ListSubscriptionPage(ctx, q)
		if err != nil || len(objs) == 0 {
			return 0, q.After, more, err
		}
		for _, o := range objs {
			out, err := reconcileSubscription(ctx, h, o, readAt)
			tally(resp.GetSubscriptions(), kind, o.ProviderSubscriptionID, out, err)
		}
		return len(objs), objs[len(objs)-1].ProviderSubscriptionID, more, nil
	}
	return 0, "", false, nil
}

// tally counts one object's outcome; a failure is logged with its cause, which
// stays server-side like every other.
func tally(c *pb.ReconcileCounts, kind reconcileKind, id string, out reconcileOutcome, err error) {
	if err != nil {
		out = reconcileFailed
		slog.Warn("payment: provider reconciliation failed for an object", "kind", reconcileKindNames[kind], "provider_id", id, "err", err)
	}
	switch out {
	case reconcileCreated:
		c.Created++
	case reconcileUpdated:
		c.Updated++
	case reconcileInSync:
		c.InSync++
	case reconcileForeign:
		c.Foreign++
	case reconcileSuperseded:
		c.Superseded++
	case reconcileFailed:
		c.Failed++
	}
}

// ── customers ───────────────────────────────────────────────────────

// reconcileCustomer records a provider customer this installation created and
// whose local link never landed (createCustomer writes the provider customer
// first). Its principal is the user_id the plugin wrote into its metadata.
//
// A principal already linked to ANOTHER provider customer keeps that link:
// this one is superseded — the loser of two concurrent first charges, or a
// create whose row failed and whose retry made a new customer. Either way
// nothing references it, and the link the principal's payments use stays.
// Customers made before the plugin marked them are foreign.
func (h *PaymentServiceHandler) reconcileCustomer(ctx context.Context, o backend.CustomerObject) (reconcileOutcome, error) {
	if o.Origin != backend.OriginCustomer || !h.markedHere(o.Marks) || o.UserID == "" {
		return reconcileForeign, nil
	}
	linked, err := h.customerByProviderID(ctx, o.ProviderCustomerID)
	if err != nil {
		return reconcileFailed, err
	}
	if linked != nil {
		return reconcileInSync, nil
	}
	byUser, err := h.Query.GetCustomerByUserId(ctx, &pb.GetCustomerByUserIdReq{UserId: o.UserID})
	if err != nil && !absent(err) {
		return reconcileFailed, err
	}
	if byUser.GetCustomer() != nil {
		return reconcileSuperseded, nil
	}
	_, err = h.Mutation.CreateCustomer(ctx, &pb.CreateCustomerReq{
		UserId:             o.UserID,
		ProviderCustomerId: o.ProviderCustomerID,
		Email:              o.Email,
	})
	if err == nil {
		return reconcileCreated, nil
	}
	if constraintCode(err) != codeUniqueViolation {
		return reconcileFailed, err
	}
	// A first charge (or a concurrent run) linked the principal meanwhile.
	if linked, err = h.customerByProviderID(ctx, o.ProviderCustomerID); err != nil {
		return reconcileFailed, err
	}
	if linked != nil {
		return reconcileInSync, nil
	}
	return reconcileSuperseded, nil
}

// ── payments ────────────────────────────────────────────────────────

// reconcilePayment brings one provider payment this installation created (a
// charge or a top-up) in line.
//
// No local row: one is written the way charge writes it (CreatePayment), at
// the status a fresh intent has — PROCESSING or REQUIRES_ACTION — and the
// provider's terminal status is then applied the way the webhook applies it.
// Written at the terminal status directly, the row would skip the
// transition, and PaymentSucceeded (or a top-up's grant) would never happen.
// A top-up also gets its CreditTopup row when that one is missing.
//
// Then the provider's status goes through the webhook's own reconciliation
// (reconcile, with the event the provider would have sent): its transition
// guards make it a no-op on a row already there, and a succeeded top-up's
// credit is reconciled (settleTopup) on every run, which grants it once.
func (h *PaymentServiceHandler) reconcilePayment(ctx context.Context, o backend.PaymentObject) (reconcileOutcome, error) {
	if (o.Origin != backend.OriginCharge && o.Origin != backend.OriginTopup) || !h.markedHere(o.Marks) {
		return reconcileForeign, nil
	}
	payment, err := h.paymentByProviderID(ctx, o.ProviderPaymentID)
	if err != nil {
		return reconcileFailed, err
	}
	created := false
	if payment == nil {
		if payment, created, err = h.recordOrphanPayment(ctx, o); err != nil {
			return reconcileFailed, err
		}
	}
	before, err := h.paymentState(ctx, payment)
	if err != nil {
		return reconcileFailed, err
	}
	if o.Origin == backend.OriginTopup && ensureTopupRecord != nil {
		cust, err := h.customerByProviderID(ctx, o.ProviderCustomerID)
		if err != nil {
			return reconcileFailed, err
		}
		if cust == nil {
			return reconcileFailed, fmt.Errorf("top-up %s: no local customer for %s", o.ProviderPaymentID, o.ProviderCustomerID)
		}
		if err := ensureTopupRecord(ctx, h, payment, cust.GetUserId()); err != nil {
			return reconcileFailed, err
		}
	}
	if typ := paymentEventType(o); typ != "" {
		err := h.reconcile(ctx, stripe.Event{
			Type: typ, ObjectID: o.ProviderPaymentID, PaymentIntentID: o.ProviderPaymentID,
			Origin: o.Origin, Install: o.Install,
		})
		if errors.Is(err, errNoLocalRecord) {
			err = fmt.Errorf("payment %s: its local records are incomplete", o.ProviderPaymentID)
		}
		if err != nil {
			return reconcileFailed, err
		}
	}
	if created {
		return reconcileCreated, nil
	}
	if payment, err = h.paymentByProviderID(ctx, o.ProviderPaymentID); err != nil {
		return reconcileFailed, err
	}
	after, err := h.paymentState(ctx, payment)
	if err != nil {
		return reconcileFailed, err
	}
	if after != before {
		return reconcileUpdated, nil
	}
	return reconcileInSync, nil
}

// recordOrphanPayment writes the local row of a provider payment whose own
// never landed, and reports whether this call wrote it (false: a concurrent
// writer — the caller's retry, the webhook path, another run — did, and its
// row is returned).
func (h *PaymentServiceHandler) recordOrphanPayment(ctx context.Context, o backend.PaymentObject) (*pb.Payment, bool, error) {
	cust, err := h.customerByProviderID(ctx, o.ProviderCustomerID)
	if err != nil {
		return nil, false, err
	}
	if cust == nil {
		// charge resolves the customer's row before it asks the provider, so
		// an intent of this installation always has one.
		return nil, false, fmt.Errorf("payment %s: no local customer for %s", o.ProviderPaymentID, o.ProviderCustomerID)
	}
	initial := pb.Payment_REQUIRES_ACTION
	if o.Status == "processing" {
		initial = pb.Payment_PROCESSING
	}
	created, err := h.Mutation.CreatePayment(ctx, &pb.CreatePaymentReq{
		CustomerId:        cust.GetId(),
		ProviderPaymentId: o.ProviderPaymentID,
		Amount:            o.Amount.Amount,
		Currency:          strings.ToLower(o.Amount.Currency),
		Status:            int32(initial),
		IdempotencyKey:    reconciledChargeKey(o.ProviderPaymentID),
		Description:       o.Description,
	})
	if err == nil {
		return created.GetPayment(), true, nil
	}
	if constraintCode(err) != codeUniqueViolation {
		return nil, false, err
	}
	p, err := h.paymentByProviderID(ctx, o.ProviderPaymentID)
	if err != nil {
		return nil, false, err
	}
	if p == nil {
		return nil, false, fmt.Errorf("payment %s: the insert was refused and no row holds it", o.ProviderPaymentID)
	}
	return p, false, nil
}

// paymentEventType is the webhook event that carries a provider payment's
// current status, "" while it is still open.
func paymentEventType(o backend.PaymentObject) string {
	switch {
	case o.Status == "succeeded":
		return "payment_intent.succeeded"
	case o.Status == "canceled":
		return "payment_intent.canceled"
	case o.Failed:
		return "payment_intent.payment_failed"
	}
	return ""
}

// paymentState is what a reconciliation of a payment can change: its status
// and a top-up's credit record.
func (h *PaymentServiceHandler) paymentState(ctx context.Context, p *pb.Payment) (string, error) {
	topup, err := topupState(ctx, h, p.GetProviderPaymentId())
	if err != nil {
		return "", err
	}
	return p.GetStatus().String() + "|" + topup, nil
}

// ── refunds ─────────────────────────────────────────────────────────

// reconcileRefundPage brings one page of the account's refunds in line. A
// refund belongs to this installation when its payment has a local row — the
// rule the refund webhooks follow, which record a refund made at the provider
// directly too. Each such payment's refunds are reconciled once per page the
// way the webhook does it (reconcileRefunds: every refund recorded, its
// outcome kept, the payment's status and a top-up's credit derived from the
// rows), so a refund missing locally is recorded and its top-up's credit
// taken back once, whichever of the webhook and this run gets there first.
//
// The counts are per refund row: its state before the page and after it.
func (h *PaymentServiceHandler) reconcileRefundPage(ctx context.Context, objs []backend.ListedRefund, c *pb.ReconcileCounts) {
	type seen struct {
		id, payment string
		before      string
		out         reconcileOutcome
		err         error
	}
	page := make([]seen, 0, len(objs))
	var payments []string
	done := map[string]error{}
	for _, o := range objs {
		s := seen{id: o.ProviderRefundID, payment: o.ProviderPaymentID, out: reconcileForeign}
		if o.ProviderPaymentID != "" {
			p, err := h.paymentByProviderID(ctx, o.ProviderPaymentID)
			switch {
			case err != nil:
				s.out, s.err = reconcileFailed, err
			case p != nil:
				s.out = reconcileInSync
				if s.before, s.err = h.refundState(ctx, o.ProviderRefundID); s.err == nil {
					if _, ok := done[o.ProviderPaymentID]; !ok {
						done[o.ProviderPaymentID] = nil
						payments = append(payments, o.ProviderPaymentID)
					}
				}
			}
		}
		page = append(page, s)
	}
	for _, pid := range payments {
		done[pid] = h.reconcileRefunds(ctx, pid)
	}
	for _, s := range page {
		if s.out == reconcileInSync && s.err == nil {
			if s.err = done[s.payment]; s.err == nil {
				var after string
				if after, s.err = h.refundState(ctx, s.id); s.err == nil {
					switch {
					case s.before == "" && after != "":
						s.out = reconcileCreated
					case s.before != after:
						s.out = reconcileUpdated
					}
				}
			}
		}
		tally(c, kindRefunds, s.id, s.out, s.err)
	}
}

// refundState is a refund row's status, "" when there is no row.
func (h *PaymentServiceHandler) refundState(ctx context.Context, providerRefundID string) (string, error) {
	got, err := h.Query.GetRefundByProviderId(ctx, &pb.GetRefundByProviderIdReq{ProviderRefundId: providerRefundID})
	if err != nil && !absent(err) {
		return "", err
	}
	if got.GetRefund() == nil {
		return "", nil
	}
	return got.GetRefund().GetStatus().String(), nil
}
