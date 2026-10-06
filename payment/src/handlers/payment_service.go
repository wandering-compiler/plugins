// Package handlers holds the payment plugin's authored business logic —
// the PaymentService implementation. Storage primitives (PaymentQuery /
// PaymentMutation) are codegen-emitted from DQL; this layer composes
// them with the backend driver (provider API calls).
package handlers

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
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
	return nil
}

// Shutdown is the bundle drain hook. No background work in Slice 1.
func (h *PaymentServiceHandler) Shutdown(context.Context) error { return nil }

// CreateCustomer establishes the principal ↔ provider-customer link:
// create the provider customer object, then persist the local row.
//
// Idempotent per principal: an existing link is returned as is. It used
// to create a second provider customer on every call and then fail the
// local INSERT on the unique user_id — an orphan provider object per
// repeated call, and an error for a principal that was set up fine.
func (h *PaymentServiceHandler) CreateCustomer(ctx context.Context, req *pb.NewCustomerReq) (*pb.NewCustomerResp, error) {
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
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	amount := strings.TrimSpace(req.GetAmount())
	if amount == "" {
		return nil, invalidArg("amount is required")
	}
	// Q45-pay-1: reject a non-positive amount before the provider call — a
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
	payment, clientSecret, err := h.charge(ctx, cust, amount, currency, idempotencyKeyOrNew(req.GetIdempotencyKey()), req.GetDescription(), backend.OriginCharge)
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
func (h *PaymentServiceHandler) charge(ctx context.Context, cust *pb.Customer, amount, currency, idemKey, description, origin string) (*pb.Payment, string, error) {
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

// RefundPayment reverses a payment (full when amount is empty), via the
// provider, and records the local Refund.
func (h *PaymentServiceHandler) RefundPayment(ctx context.Context, req *pb.RefundPaymentReq) (*pb.RefundPaymentResp, error) {
	if req.GetPaymentId() == "" {
		return nil, invalidArg("payment_id is required")
	}
	// Q43-pay-2: the idempotency key IS the provider Idempotency-Key for
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
		return sameRefund(prior, payment, amount)
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
	res, err := h.Backend.RefundPayment(ctx, payment.GetProviderPaymentId(),
		backend.Money{Amount: amount, Currency: payment.GetCurrency()},
		req.GetIdempotencyKey())
	if err != nil {
		return nil, providerFailure(err)
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
	return &pb.RefundPaymentResp{Refund: created.GetRefund()}, nil
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
