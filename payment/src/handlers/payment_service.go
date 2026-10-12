// Package handlers holds the payment plugin's authored business logic —
// the PaymentService implementation. Storage primitives (PaymentQuery /
// PaymentMutation) are codegen-emitted from DQL; this layer composes
// them with the backend driver (provider API calls).
package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// PaymentServiceHandler implements pb.PaymentServiceServer. Constructed
// once per activation by RegisterPlugin with the in-process storage
// clients + the configured backend driver.
type PaymentServiceHandler struct {
	Query    pb.PaymentQueryClient
	Mutation pb.PaymentMutationClient
	Backend  backend.Backend

	// WebhookSecret verifies inbound Stripe webhook signatures (read by
	// the stripe_webhooks-gated IngestStripe in webhook_stripe.go).
	WebhookSecret string
	// DefaultCurrency (ISO-4217, lowercase) applies when a charge omits
	// a currency.
	DefaultCurrency string
}

// ValidateConfig fails loud at startup on a mis-wired handler so a
// bundle never boots half-configured.
func ValidateConfig(h *PaymentServiceHandler) error {
	if h.Backend == nil {
		return fmt.Errorf("payment plugin: no backend configured")
	}
	if h.Query == nil || h.Mutation == nil {
		return fmt.Errorf("payment plugin: storage clients not wired")
	}
	// With webhooks on, a bundle without the signing secret boots and then
	// refuses every delivery: payments stay pending forever and nothing says
	// why until someone reads the provider's dashboard. A blank value (a
	// secret file holding only a newline) fails every delivery the same way.
	if webhooksStaged && strings.TrimSpace(h.WebhookSecret) == "" {
		return fmt.Errorf("payment plugin: webhook_signing_secret is required while stripe_webhooks is on")
	}
	return nil
}

// webhooksStaged is set by handlers/webhook_stripe.go, which is staged only
// with the stripe_webhooks feature.
var webhooksStaged bool

// Shutdown is the bundle drain hook. No background work.
func (h *PaymentServiceHandler) Shutdown(context.Context) error { return nil }

// CreateCustomer establishes the principal ↔ provider-customer link:
// create the provider customer object, then persist the local row.
//
// Idempotent per principal: an existing link is returned as is. It used
// to create a second provider customer on every call and then fail the
// local INSERT on the unique user_id — an orphan provider object per
// repeated call, and an error for a principal that was set up fine.
func (h *PaymentServiceHandler) CreateCustomer(ctx context.Context, req *pb.NewCustomerReq) (*pb.NewCustomerResp, error) {
	// Through the gateway this acts for the signed-in caller only; see
	// actingFor.
	uid, err := actingFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	req.UserId = uid
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	got, err := h.Query.GetCustomerByUserId(ctx, &pb.GetCustomerByUserIdReq{UserId: req.GetUserId()})
	if err != nil && !absent(err) {
		return nil, err
	}
	if c := got.GetCustomer(); c != nil {
		return &pb.NewCustomerResp{Customer: c}, nil
	}
	c, err := h.createCustomer(ctx, req.GetUserId(), req.GetEmail())
	if err != nil {
		return nil, err
	}
	return &pb.NewCustomerResp{Customer: c}, nil
}

// createCustomer creates the provider customer and persists the link.
// Two first-charges for one principal can race past the existence check;
// the loser's INSERT hits the unique user_id, and the winner's row is
// the answer (the loser's provider customer is left unreferenced — the
// provider offers no create-if-absent to avoid it).
func (h *PaymentServiceHandler) createCustomer(ctx context.Context, userID, email string) (*pb.Customer, error) {
	providerID, err := h.Backend.EnsureCustomer(ctx, backend.CustomerSpec{UserID: userID, Email: email})
	if err != nil {
		return nil, providerFailure(err)
	}
	created, err := h.Mutation.CreateCustomer(ctx, &pb.CreateCustomerReq{
		UserId:             userID,
		ProviderCustomerId: providerID,
		Email:              email,
	})
	if err == nil {
		return created.GetCustomer(), nil
	}
	if constraintCode(err) == codeUniqueViolation {
		if got, gerr := h.Query.GetCustomerByUserId(ctx, &pb.GetCustomerByUserIdReq{UserId: userID}); gerr == nil && got.GetCustomer() != nil {
			return got.GetCustomer(), nil
		}
	}
	return nil, err
}

// CreatePayment creates a charge: ensure the Customer exists, call the
// backend to create the provider payment (idempotency-keyed), then
// persist the local Payment at its initial status.
func (h *PaymentServiceHandler) CreatePayment(ctx context.Context, req *pb.ChargeReq) (*pb.ChargeResp, error) {
	// Through the gateway this acts for the signed-in caller only; see
	// actingFor.
	uid, err := actingFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	req.UserId = uid
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	amount := strings.TrimSpace(req.GetAmount())
	if amount == "" {
		return nil, invalidArg("amount is required")
	}
	// Reject a non-positive amount before the provider call — a
	// negative amount reaches Stripe as a credit/reversal (customer credited
	// instead of charged), a zero is a meaningless charge.
	if !isPositiveDecimal(amount) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	currency, err := h.chargeCurrency(req.GetCurrency())
	if err != nil {
		return nil, err
	}
	if err := idempotencyKeyTooLong(req.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	cust, err := h.resolveCustomer(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	payment, clientSecret, err := h.charge(ctx, cust, amount, currency, req.GetIdempotencyKey(), req.GetDescription(), backend.OriginCharge)
	if err != nil {
		return nil, err
	}
	return &pb.ChargeResp{Payment: payment, ClientSecret: clientSecret}, nil
}

// chargeCurrency normalises a request currency, falling back to the
// configured default, and refuses anything that is not a 3-letter code.
func (h *PaymentServiceHandler) chargeCurrency(reqCurrency string) (string, error) {
	currency := strings.ToLower(strings.TrimSpace(reqCurrency))
	if currency == "" {
		currency = h.DefaultCurrency
	}
	if currency == "" {
		return "", invalidArg("currency is required (no default_currency configured)")
	}
	if !isCurrencyCode(currency) {
		return "", invalidArg("currency must be a 3-letter ISO-4217 code")
	}
	return currency, nil
}

// charge creates the provider payment and persists the local Payment —
// the shared core of CreatePayment and TopUpCredit.
//
// A retry with the same idempotency key is answered with the payment the
// first attempt recorded. The provider replays the same object for the
// same key, so the local INSERT hits the unique provider_payment_id /
// idempotency_key; that used to come back to the caller as a raw
// InvalidArgument UNIQUE_VIOLATION — a retry of a charge that HAD
// worked read as a failure, the opposite of what the key promises.
//
// The replayed row is returned only when it is provably this request's:
// same provider object, same idempotency key, same customer. Anything
// else (the key reused after the provider's own idempotency window
// expired, so the provider minted a NEW object while the key still
// names an older local row) is AlreadyExists — never another payment.
//
// callerKey is the request's own key, empty when it sent none. See
// chargeKey for what is stored and sent to the provider.
func (h *PaymentServiceHandler) charge(ctx context.Context, cust *pb.Customer, amount, currency, callerKey, description, origin string) (*pb.Payment, string, error) {
	idemKey, err := h.chargeKey(ctx, cust, origin, callerKey)
	if err != nil {
		return nil, "", err
	}
	pr, err := h.Backend.CreatePayment(ctx, backend.PaymentSpec{
		ProviderCustomerID: cust.GetProviderCustomerId(),
		Amount:             backend.Money{Amount: amount, Currency: currency},
		IdempotencyKey:     idemKey,
		Description:        description,
		Origin:             origin,
		Install:            h.installID(),
	})
	if err != nil {
		return nil, "", providerFailure(err)
	}

	created, err := h.Mutation.CreatePayment(ctx, &pb.CreatePaymentReq{
		CustomerId:        cust.GetId(),
		ProviderPaymentId: pr.ProviderPaymentID,
		Amount:            amount,
		Currency:          currency,
		Status:            int32(mapInitialStatus(pr.Status)),
		IdempotencyKey:    idemKey,
		Description:       description,
	})
	if err == nil {
		return created.GetPayment(), pr.ClientSecret, nil
	}
	if constraintCode(err) != codeUniqueViolation {
		return nil, "", err
	}
	got, gerr := h.Query.GetPaymentByProviderId(ctx, &pb.GetPaymentByProviderIdReq{ProviderPaymentId: pr.ProviderPaymentID})
	if gerr != nil && !absent(gerr) {
		return nil, "", gerr
	}
	if p := got.GetPayment(); p != nil && p.GetIdempotencyKey() == idemKey && p.GetCustomerId() == cust.GetId() {
		return p, pr.ClientSecret, nil
	}
	return nil, "", status.Error(codes.AlreadyExists, "idempotency_key already used for a different payment")
}

// chargeKey is the key a charge is stored under and sent to the provider
// with: the caller's key scoped by the kind of charge and by the principal,
// or a fresh one when the caller sent none.
//
// A caller's key names one of THEIR charges. Stored and sent as it came, it
// was one key space for every principal and both kinds of charge: a key
// another account had used ("order-1" is an obvious choice) made the provider
// refuse the request as a reuse with different parameters, and so did a
// top-up under a key a payment had used.
//
// A payment an earlier version recorded under the caller's raw key keeps that
// key, so a retry of it is still the same payment rather than a second one.
// Only the caller's own payment of the same kind is such a retry: a top-up
// under the raw key of an earlier payment (or the reverse) is another charge,
// and sent under the raw key the provider would refuse it as a reuse.
func (h *PaymentServiceHandler) chargeKey(ctx context.Context, cust *pb.Customer, origin, callerKey string) (string, error) {
	if callerKey == "" {
		return idempotencyKeyOrNew(""), nil
	}
	if !strings.HasPrefix(callerKey, scopedKeyPrefix) {
		got, err := h.Query.GetPaymentByIdempotencyKey(ctx, &pb.GetPaymentByIdempotencyKeyReq{IdempotencyKey: callerKey})
		if err != nil && !absent(err) {
			return "", err
		}
		if p := got.GetPayment(); p != nil && cust.GetId() != "" && p.GetCustomerId() == cust.GetId() {
			other, err := otherKindOfCharge(ctx, h, p, origin)
			if err != nil {
				return "", err
			}
			if !other {
				return callerKey, nil
			}
		}
	}
	return scopedKey("charge", origin, cust.GetUserId(), callerKey), nil
}

// topupDescription is the description every version gave a top-up's payment.
const topupDescription = "credit top-up"

// otherKindOfCharge reports whether p is certainly not of the kind origin
// names. When that cannot be told, p counts as the same kind: adopting its
// key for another kind only makes the provider refuse the charge, while
// scoping a genuine retry would create a second intent for one charge.
//
// A top-up's payment always carries topupDescription, so a payment without it
// is no top-up. A payment with it may be either (a caller can describe a
// payment so); its CreditTopup row says it is a top-up (isTopupPayment).
func otherKindOfCharge(ctx context.Context, h *PaymentServiceHandler, p *pb.Payment, origin string) (bool, error) {
	if p.GetDescription() != topupDescription {
		return origin == backend.OriginTopup, nil
	}
	if origin == backend.OriginTopup {
		return false, nil
	}
	return isTopupPayment(ctx, h, p)
}

// isTopupPayment reports whether p is a recorded top-up. Base: false, since
// the top-up records exist only under `prepaid`; handlers/prepaid.go installs
// the real one.
var isTopupPayment = func(ctx context.Context, h *PaymentServiceHandler, p *pb.Payment) (bool, error) {
	return false, nil
}

// RefundPayment reverses a payment (full when amount is empty), via the
// provider, and records the local Refund.
func (h *PaymentServiceHandler) RefundPayment(ctx context.Context, req *pb.RefundPaymentReq) (*pb.RefundPaymentResp, error) {
	if req.GetPaymentId() == "" {
		return nil, invalidArg("payment_id is required")
	}
	// The idempotency key IS the provider Idempotency-Key for
	// the refund, so it must be unique per distinct refund and stable
	// across retries. Deriving it from (payment_id, amount) — as this
	// handler used to — collided two legitimate same-amount partial
	// refunds into one provider replay, silently shorting the customer.
	// The caller owns it now (mirrors GrantCredit / ReportUsage).
	if req.GetIdempotencyKey() == "" {
		return nil, invalidArg("idempotency_key is required (the refund must be idempotent; supply a unique key per distinct refund)")
	}
	if err := idempotencyKeyTooLong(req.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	// A partial amount is validated like every other amount: a negative
	// one used to go to the provider as is, and one past the column scale
	// was rounded on the local row.
	amount := strings.TrimSpace(req.GetAmount())
	if amount != "" && !isPositiveDecimal(amount) {
		return nil, invalidArg("amount must be a positive decimal (or empty for a full refund)")
	}
	got, err := h.Query.GetPayment(ctx, &pb.GetPaymentReq{Id: req.GetPaymentId()})
	if err != nil {
		return nil, err
	}
	payment := got.GetPayment()
	if payment == nil {
		return nil, notFound("payment not found")
	}
	if amount == "" {
		amount = payment.GetAmount() // full refund
	}

	// The key is looked up HERE, before the provider is asked. The provider
	// remembers an idempotency key for a day; a retry after that used to
	// refund a second time — the local row was found only by the provider's
	// NEW refund id, which matched nothing.
	storedKey := refundKey(req.GetIdempotencyKey())
	if prior, err := h.refundByKey(ctx, storedKey); err != nil || prior != nil {
		if err != nil {
			return nil, err
		}
		resp, err := sameRefund(prior, payment, amount)
		if err == nil {
			// A retry is where a first attempt's missed status settle is
			// caught up (no-op once REFUNDED).
			h.markRefundedIfFull(ctx, payment)
		}
		return resp, err
	}

	// The provider gets the caller's key VERBATIM, so one key names one
	// refund account-wide, and the stored key (refundKey) has the same scope.
	//
	// Not a payment-scoped key, although that would let one caller key name
	// a refund on each of several payments: every released version sent the
	// raw key, and its only replay protection was the provider's memory of
	// that key. A refund made before an upgrade and retried after it (within
	// the provider's day) would reach the provider under a NEW key, and the
	// provider would refund a second time — the pre-upgrade row has no stored
	// key to stop it. The raw key keeps that retry a replay. The cost is only
	// a refusal: a key reused on another payment is InvalidArgument (from the
	// lookup above, or — while the first refund's row is missing — from the
	// provider's own idempotency check), never money.
	//
	// No local row does not mean no refund: the provider may have made it on
	// an earlier attempt whose local insert then failed. Within a day the
	// provider's idempotency check replays it; after that only the key in the
	// refund's metadata recognises it, so ask before refunding again.
	res, found, err := h.Backend.FindRefund(ctx, payment.GetProviderPaymentId(), req.GetIdempotencyKey())
	if err != nil {
		return nil, providerFailure(err)
	}
	if found && !sameDecimal(res.Amount.Amount, amount) {
		// The key names a refund of another amount, which the provider's
		// idempotency check would refuse too: answered like sameRefund.
		return nil, status.Error(codes.AlreadyExists, "idempotency_key already used for a different refund")
	}
	if !found {
		// A top-up's credit leaves with its money (prepaid; no-op otherwise).
		// Taken before the provider is asked, so a refund of spent credit is
		// refused instead of paid out.
		undo, err := takeBackRefundedCredit(ctx, h, payment, amount, req.GetIdempotencyKey())
		if err != nil {
			return nil, err
		}
		res, err = h.Backend.RefundPayment(ctx, payment.GetProviderPaymentId(),
			backend.Money{Amount: amount, Currency: payment.GetCurrency()},
			req.GetIdempotencyKey())
		if err != nil {
			// A refusal the provider will repeat on every retry gives the
			// credit back; a transient failure keeps it taken, for the retry.
			// An undo that fails is reported as transient, so the caller
			// retries and the retry gives the credit back; reporting the
			// permanent refusal instead would strand it.
			if undo != nil && (errors.Is(err, backend.ErrInvalidRequest) || errors.Is(err, backend.ErrDeclined)) {
				if uerr := undo(); uerr != nil {
					// The provider's text stays in the log, like every other
					// provider failure: it can carry the request's details.
					slog.Warn("payment: refund refused, credit not given back yet", "err", err, "undo_err", uerr)
					return nil, status.Error(codes.Unavailable, "payment: the refund was refused and its credit could not be given back yet; retry")
				}
			}
			return nil, providerFailure(err)
		}
	}

	created, err := h.Mutation.CreateRefund(ctx, &pb.CreateRefundReq{
		PaymentId:        payment.GetId(),
		ProviderRefundId: res.ProviderRefundID,
		Amount:           amount,
		Currency:         payment.GetCurrency(),
		IdempotencyKey:   storedKey,
	})
	if err != nil {
		// A concurrent call with the same key recorded it first: its refund
		// is the answer only when it is the refund this request asks for.
		if constraintCode(err) == codeUniqueViolation {
			if prior, gerr := h.refundByKey(ctx, storedKey); gerr == nil && prior != nil {
				return sameRefund(prior, payment, amount)
			}
		}
		// A retried refund (same key) gets the same provider refund
		// replayed, and its local row already exists: that row is the
		// answer. Only when it belongs to THIS payment.
		if constraintCode(err) == codeUniqueViolation {
			r, gerr := h.Query.GetRefundByProviderId(ctx, &pb.GetRefundByProviderIdReq{ProviderRefundId: res.ProviderRefundID})
			if gerr != nil && !absent(gerr) {
				return nil, gerr
			}
			if r.GetRefund() != nil && r.GetRefund().GetPaymentId() == payment.GetId() {
				if err := h.stampRefundKey(ctx, r.GetRefund().GetId(), storedKey); err != nil {
					return nil, err
				}
				return &pb.RefundPaymentResp{Refund: r.GetRefund()}, nil
			}
			return nil, status.Error(codes.AlreadyExists, "idempotency_key already used for a different refund")
		}
		return nil, err
	}
	h.markRefundedIfFull(ctx, payment)
	return &pb.RefundPaymentResp{Refund: created.GetRefund()}, nil
}

// markRefundedIfFull moves a payment to REFUNDED once its recorded refunds
// reach its amount. Best effort: the refund itself is done and recorded, and
// the provider's charge.refunded webhook settles the status if this misses
// (a failed read, or partial refunds completing the amount concurrently).
func (h *PaymentServiceHandler) markRefundedIfFull(ctx context.Context, payment *pb.Payment) {
	if payment.GetStatus() != pb.Payment_SUCCEEDED {
		return // the mutation's own guard: only SUCCEEDED moves to REFUNDED
	}
	sum, err := h.Query.SumRefundsForPayment(ctx, &pb.SumRefundsForPaymentReq{PaymentId: payment.GetId()})
	if err != nil || !decimalAtLeast(sum.GetTotal(), payment.GetAmount()) {
		return
	}
	_, _ = h.Mutation.MarkPaymentRefunded(ctx, &pb.MarkPaymentRefundedReq{ProviderPaymentId: payment.GetProviderPaymentId()})
}

// takeBackRefundedCredit removes the credit a refunded top-up granted,
// before the money goes back. Base no-op; handlers/prepaid.go installs the
// real one, since the top-up records exist only under `prepaid`. The undo it
// returns gives the credit back; nil when nothing was taken.
var takeBackRefundedCredit = func(ctx context.Context, h *PaymentServiceHandler, payment *pb.Payment, amount, idem string) (undo func() error, err error) {
	return nil, nil
}

// stampRefundKey records the kept key on a refund row the key lookup could
// not find — one an earlier version wrote with no key, found here because the
// provider replayed it. Unstamped, the row stays invisible to the lookup, and
// a retry after the provider forgets the key (a day) refunds a second time.
//
// A row that already holds a key keeps it (the guard refuses; nothing to
// do). A key another row already holds names a different refund: refused as
// AlreadyExists, like every other key collision here. Any other failure
// surfaces — the caller's retry is a provider replay that stamps again.
func (h *PaymentServiceHandler) stampRefundKey(ctx context.Context, refundID, storedKey string) error {
	_, err := h.Mutation.SetRefundIdempotencyKey(ctx, &pb.SetRefundIdempotencyKeyReq{Id: refundID, IdempotencyKey: storedKey})
	switch {
	case err == nil, guardRefused(err):
		return nil
	case constraintCode(err) == codeUniqueViolation:
		return status.Error(codes.AlreadyExists, "idempotency_key already used for a different refund")
	}
	return err
}

// refundKey is the stored Refund.idempotency_key for a caller's refund key.
// Its scope is the caller's key alone — the scope the provider gives the key
// it is sent (see RefundPayment) — so a key reused on another payment is
// found here and refused, not only when the provider still remembers it.
func refundKey(callerKey string) string {
	return scopedKey("refund", callerKey)
}

// sameRefund answers a request whose key already names a recorded refund:
// that refund, when it is the one the request asks for (same payment, same
// amount by value — a full refund's amount is the payment's); otherwise a
// refusal. Returning it regardless (as the lookup used to) answered a retry
// for 6 under the key of a refund of 4 with the refund of 4 and no error —
// the caller believed 6 had gone back.
func sameRefund(prior *pb.Refund, payment *pb.Payment, amount string) (*pb.RefundPaymentResp, error) {
	if prior.GetPaymentId() != payment.GetId() {
		return nil, invalidArg("idempotency_key already used for a refund of another payment (a refund key must be unique per refund, across all payments)")
	}
	if !sameDecimal(prior.GetAmount(), amount) {
		return nil, status.Error(codes.AlreadyExists, "idempotency_key already used for a different refund")
	}
	return &pb.RefundPaymentResp{Refund: prior}, nil
}

// refundByKey returns the refund a stored key already produced, or nil.
func (h *PaymentServiceHandler) refundByKey(ctx context.Context, storedKey string) (*pb.Refund, error) {
	got, err := h.Query.GetRefundByIdempotencyKey(ctx, &pb.GetRefundByIdempotencyKeyReq{IdempotencyKey: storedKey})
	if err != nil && !absent(err) {
		return nil, err
	}
	return got.GetRefund(), nil
}

// resolveCustomer returns the principal's Customer row, creating it (and
// the provider customer object) on first charge.
func (h *PaymentServiceHandler) resolveCustomer(ctx context.Context, userID string) (*pb.Customer, error) {
	got, err := h.Query.GetCustomerByUserId(ctx, &pb.GetCustomerByUserIdReq{UserId: userID})
	if err != nil && !absent(err) {
		return nil, err
	}
	if got.GetCustomer() != nil {
		return got.GetCustomer(), nil
	}
	return h.createCustomer(ctx, userID, "")
}

// mapInitialStatus maps the provider's payment status string onto the
// local Payment.Status enum at intent time. Unknown → REQUIRES_ACTION
// (safe default: the webhook will reconcile the terminal state).
func mapInitialStatus(providerStatus string) pb.Payment_Status {
	switch providerStatus {
	case "succeeded":
		return pb.Payment_SUCCEEDED
	case "processing":
		return pb.Payment_PROCESSING
	case "canceled":
		return pb.Payment_CANCELED
	default:
		return pb.Payment_REQUIRES_ACTION
	}
}
