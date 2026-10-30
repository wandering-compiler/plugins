package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

func TestIsPositiveDecimal(t *testing.T) {
	cases := map[string]bool{
		"1": true, "0.0001": true, "19.99": true, " 5 ": true, "5.": true, ".5": true, "007.50": true,
		"9999999999999999.9999":             true,  // the DECIMAL(20, 4) maximum
		"00009999999999999999":              true,  // leading zeros are not digits of value
		"10000000000000000":                 false, // 17 integer digits: column overflow
		"0.00001":                           false, // 5th fractional digit: the column would round it
		"1.00000":                           false, // refused even when the extra digit is 0 — 4 is the contract
		"":                                  false,
		" ":                                 false,
		"0":                                 false,
		"0.0000":                            false,
		".":                                 false,
		"-1":                                false,
		"+1":                                false,
		"1.2.3":                             false,
		"1e3":                               false,
		"1,5":                               false,
		"١":                                 false, // a non-ASCII digit
		"0x10":                              false,
		"NaN":                               false,
		"Infinity":                          false,
		"1 000":                             false,
		strings.Repeat("9", 40):             false,
		"0." + strings.Repeat("0", 3) + "1": true,
	}
	for in, want := range cases {
		if got := isPositiveDecimal(in); got != want {
			t.Errorf("isPositiveDecimal(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsCurrencyCode(t *testing.T) {
	for in, want := range map[string]bool{"usd": true, "jpy": true, "": false, "us": false, "usdd": false, "US$": false, "u1d": false, "USD": false, "üsd": false} {
		if got := isCurrencyCode(in); got != want {
			t.Errorf("isCurrencyCode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSameDecimal(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"29", "29.0000", true}, {"29.00", "29", true}, {"029.5", "29.50", true}, {"0.5", ".5", true},
		{"29", "290", false}, {"29.01", "29.1", false}, {"2.9", "29", false}, {"0", "", true},
	} {
		if got := sameDecimal(c.a, c.b); got != c.want {
			t.Errorf("sameDecimal(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestScopedKey(t *testing.T) {
	a := scopedKey("credit", "grant", "user-a", "k")
	if len(a) != 67 || !strings.HasPrefix(a, "v2:") {
		t.Fatalf("scopedKey shape = %q", a)
	}
	if a != scopedKey("credit", "grant", "user-a", "k") {
		t.Error("not deterministic — a retry would not dedupe")
	}
	for _, other := range []string{
		scopedKey("credit", "spend", "user-a", "k"),
		scopedKey("credit", "grant", "user-b", "k"),
		scopedKey("credit", "grant", "user-a", "k2"),
		scopedKey("credit", "grant", "user-a:k"), // parts cannot shift across the separator
		scopedKey("usage", "grant", "user-a", "k"),
	} {
		if other == a {
			t.Errorf("distinct scopes collided: %q", other)
		}
	}
}

func TestIdempotencyKeyOrNew(t *testing.T) {
	if got := idempotencyKeyOrNew("mine"); got != "mine" {
		t.Errorf("caller key replaced: %q", got)
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k := idempotencyKeyOrNew("")
		if !strings.HasPrefix(k, "auto:") || len(k) != 5+32 || seen[k] {
			t.Fatalf("derived key %q (dup=%v)", k, seen[k])
		}
		seen[k] = true
	}
}

func TestIdempotencyKeyTooLong(t *testing.T) {
	if err := idempotencyKeyTooLong(strings.Repeat("k", 255)); err != nil {
		t.Errorf("255 bytes refused: %v", err)
	}
	if err := idempotencyKeyTooLong(strings.Repeat("k", 256)); status.Code(err) != codes.InvalidArgument {
		t.Errorf("256 bytes: %v", err)
	}
}

func TestProviderFailure_MapsByClass(t *testing.T) {
	for _, c := range []struct {
		cause error
		want  codes.Code
	}{
		{fmt.Errorf("stripe: /v1/x: declined: %w", backend.ErrDeclined), codes.FailedPrecondition},
		{fmt.Errorf("wrapped twice: %w", fmt.Errorf("stripe: %w", backend.ErrInvalidRequest)), codes.InvalidArgument},
		{errors.New("dial tcp: connection refused"), codes.Unavailable},
		{context.DeadlineExceeded, codes.Unavailable},
	} {
		err := providerFailure(c.cause)
		if status.Code(err) != c.want {
			t.Errorf("providerFailure(%v) = %v, want %v", c.cause, status.Code(err), c.want)
		}
		// The class reaches the caller; the provider's text does not (see
		// TestProviderFailure_DoesNotEchoTheProvider).
		if strings.Contains(status.Convert(err).Message(), c.cause.Error()) {
			t.Errorf("the cause reached the caller: %q", status.Convert(err).Message())
		}
	}
	// The caller's own input is the exception: its message names only that
	// input, and the caller needs it to correct the request.
	in := &backend.InputError{Msg: `amount "1.5" has more fractional digits than jpy allows (scale 0)`}
	err := providerFailure(fmt.Errorf("charge: %w", in))
	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != in.Msg {
		t.Errorf("input error = %v, want InvalidArgument with %q", err, in.Msg)
	}
}

func TestGuardRefusedAndConstraintCode(t *testing.T) {
	if guardRefused(nil) || guardRefused(errTransient) || !guardRefused(noRowsErr()) {
		t.Error("guardRefused misclassifies")
	}
	if constraintCode(errors.New("plain")) != "" || constraintCode(status.Error(codes.InvalidArgument, "no detail")) != "" {
		t.Error("constraintCode on a non-constraint error must be empty")
	}
	if constraintCode(uniqueErr("x")) != codeUniqueViolation || constraintCode(storeConstraintErr(codeInvalidValue, "c")) != codeInvalidValue {
		t.Error("constraintCode misreads the detail")
	}
}

func TestMapInitialStatus(t *testing.T) {
	for in, want := range map[string]pb.Payment_Status{
		"succeeded": pb.Payment_SUCCEEDED, "processing": pb.Payment_PROCESSING, "canceled": pb.Payment_CANCELED,
		"requires_payment_method": pb.Payment_REQUIRES_ACTION, "requires_action": pb.Payment_REQUIRES_ACTION, "": pb.Payment_REQUIRES_ACTION,
	} {
		if got := mapInitialStatus(in); got != want {
			t.Errorf("mapInitialStatus(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMapSubscriptionStatus(t *testing.T) {
	for in, want := range map[string]pb.Subscription_Status{
		"trialing": pb.Subscription_TRIALING, "active": pb.Subscription_ACTIVE, "past_due": pb.Subscription_PAST_DUE,
		"unpaid": pb.Subscription_UNPAID, "canceled": pb.Subscription_CANCELED, "incomplete_expired": pb.Subscription_CANCELED,
		"incomplete": pb.Subscription_INCOMPLETE, "paused": pb.Subscription_PAUSED,
		// Unknown → not entitling, and never the unstorable zero sentinel.
		"": pb.Subscription_UNRECOGNIZED_STATUS, "some_future_status": pb.Subscription_UNRECOGNIZED_STATUS,
	} {
		if got := mapSubscriptionStatus(in); got != want {
			t.Errorf("mapSubscriptionStatus(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUnixToTimestamp(t *testing.T) {
	if unixToTimestamp(0) != nil || unixToTimestamp(-5) != nil {
		t.Error("absent / negative provider timestamp must map to nil")
	}
	if got := unixToTimestamp(1893456000).AsTime(); !got.Equal(time.Unix(1893456000, 0)) || got.Location() != time.UTC {
		t.Errorf("unixToTimestamp = %v", got)
	}
}

func TestMetadataValue(t *testing.T) {
	if metadataValue(context.Background(), "stripe-signature") != "" {
		t.Error("no metadata → empty")
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("Stripe-Signature", "first", "stripe-signature", "second"))
	if got := metadataValue(ctx, "stripe-signature"); got != "first" {
		t.Errorf("got %q, want the first value (keys are case-folded)", got)
	}
	// Outgoing metadata is not the caller's: never read as a signature.
	out := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("stripe-signature", "x"))
	if metadataValue(out, "stripe-signature") != "" {
		t.Error("read a signature from OUTGOING metadata")
	}
}

func TestValidateConfigAndShutdown(t *testing.T) {
	h := &PaymentServiceHandler{Query: &fakeQuery{}, Mutation: &fakeMutation{}, Backend: &fakeBackend{}, DistTx: &fakeDistTx{}, WebhookSecret: "whsec_test"}
	if err := ValidateConfig(h); err != nil {
		t.Errorf("fully wired handler refused: %v", err)
	}
	if err := ValidateConfig(&PaymentServiceHandler{Query: &fakeQuery{}, Backend: &fakeBackend{}}); err == nil {
		t.Error("missing mutation client accepted")
	}
	if err := h.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// Required-field refusals that never reach the provider or the store.
func TestRequiredFieldRefusals(t *testing.T) {
	r := newRig(t)
	r.h.DefaultCurrency = ""
	calls := []struct {
		name string
		call func() error
	}{
		{"charge: no user", func() error {
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{Amount: "1", Currency: "usd"})
			return err
		}},
		{"charge: blank amount", func() error {
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "u", Amount: "  ", Currency: "usd"})
			return err
		}},
		{"charge: no currency and no default", func() error {
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "u", Amount: "1"})
			return err
		}},
		{"charge: 256-byte key", func() error {
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "u", Amount: "1", Currency: "usd", IdempotencyKey: strings.Repeat("k", 256)})
			return err
		}},
		{"top-up: no user", func() error {
			_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{Amount: "1", Currency: "usd"})
			return err
		}},
		{"top-up: bad amount", func() error {
			_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "u", Amount: "-1", Currency: "usd"})
			return err
		}},
		{"top-up: no currency and no default", func() error {
			_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "u", Amount: "1"})
			return err
		}},
		{"top-up: 256-byte key", func() error {
			_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "u", Amount: "1", Currency: "usd", IdempotencyKey: strings.Repeat("k", 256)})
			return err
		}},
		{"grant: no user", func() error {
			_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{Amount: "1", IdempotencyKey: "k"})
			return err
		}},
		{"grant: 256-byte key", func() error {
			_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "u", Amount: "1", IdempotencyKey: strings.Repeat("k", 256)})
			return err
		}},
		{"subscribe: no user", func() error {
			_, err := r.h.Subscribe(bg, &pb.SubscribeReq{PlanSlug: "pro", IdempotencyKey: "k"})
			return err
		}},
		{"subscribe: no plan", func() error {
			_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "u", PlanSlug: " ", IdempotencyKey: "k"})
			return err
		}},
		{"subscribe: 256-byte key", func() error {
			_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "u", PlanSlug: "pro", IdempotencyKey: strings.Repeat("k", 256)})
			return err
		}},
	}
	for _, c := range calls {
		if err := c.call(); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument, got %v", c.name, err)
		}
	}
	if n := r.stripe.count("/v1/payment_intents") + r.stripe.count("/v1/customers") + r.stripe.count("/v1/subscriptions"); n != 0 {
		t.Errorf("provider reached %d time(s)", n)
	}
}

// With stripe_webhooks staged, a bundle without the signing secret must not
// boot: it would refuse every delivery and leave payments pending forever.
func TestValidateConfig_RequiresTheWebhookSecretWhileWebhooksAreOn(t *testing.T) {
	h := &PaymentServiceHandler{Query: &fakeQuery{}, Mutation: &fakeMutation{}, Backend: &fakeBackend{}, DistTx: &fakeDistTx{}}
	if err := ValidateConfig(h); err == nil || !strings.Contains(err.Error(), "webhook_signing_secret") {
		t.Fatalf("err = %v, want the missing webhook secret refused", err)
	}
	h.WebhookSecret = "whsec_test"
	if err := ValidateConfig(h); err != nil {
		t.Fatalf("with the secret: %v", err)
	}
}

// A blank secret refuses every delivery exactly like a missing one.
func TestValidateConfig_RefusesABlankWebhookSecret(t *testing.T) {
	h := &PaymentServiceHandler{Query: &fakeQuery{}, Mutation: &fakeMutation{}, Backend: &fakeBackend{}, DistTx: &fakeDistTx{}, WebhookSecret: " \n"}
	if err := ValidateConfig(h); err == nil || !strings.Contains(err.Error(), "webhook_signing_secret") {
		t.Fatalf("err = %v, want the blank webhook secret refused", err)
	}
}

// With stripe_webhooks off, webhook_stripe.go is not staged and nothing sets
// webhooksStaged: the secret is not needed and its absence must not stop the
// bundle. This package always compiles that file, so the flag is cleared here.
func TestValidateConfig_NoWebhookSecretNeededWhileWebhooksAreOff(t *testing.T) {
	t.Cleanup(func() { webhooksStaged = true })
	webhooksStaged = false
	h := &PaymentServiceHandler{Query: &fakeQuery{}, Mutation: &fakeMutation{}, Backend: &fakeBackend{}, DistTx: &fakeDistTx{}}
	if err := ValidateConfig(h); err != nil {
		t.Fatalf("webhooks off, no secret: %v", err)
	}
}

// Without the webhook surface a top-up would charge and never grant the
// credit, so it is refused before anything reaches the provider.
func TestTopUpCredit_RefusesWithoutWebhooks(t *testing.T) {
	saved := webhooksStaged
	webhooksStaged = false
	t.Cleanup(func() { webhooksStaged = saved })
	h := &PaymentServiceHandler{Query: &fakeQuery{}, Mutation: &fakeMutation{}, Backend: &fakeBackend{}, DistTx: &fakeDistTx{}}
	_, err := h.TopUpCredit(context.Background(), &pb.TopUpCreditReq{UserId: "u1", Amount: "5.00", Currency: "usd"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

// The provider's text stays in the log: the caller sees the class and a fixed
// sentence, never the endpoint, the provider's diagnostics or a masked key.
func TestProviderFailure_DoesNotEchoTheProvider(t *testing.T) {
	for _, cause := range []error{
		errors.New("stripe: /v1/payment_intents: Invalid API Key provided: sk_test_****abcd (invalid_request_error)"),
		fmt.Errorf("stripe: /v1/refunds: No such charge (invalid_request_error): %w", backend.ErrInvalidRequest),
		fmt.Errorf("stripe: /v1/payment_intents: Your card was declined (card_error): %w", backend.ErrDeclined),
	} {
		msg := status.Convert(providerFailure(cause)).Message()
		for _, leak := range []string{"sk_", "/v1/", "stripe", "API Key"} {
			if strings.Contains(msg, leak) {
				t.Errorf("caller-facing message %q leaks %q", msg, leak)
			}
		}
	}
}

// A provider reason code reaches the caller as a w17.ErrorDetail code; the
// message stays the fixed sentence. A cancelled call is Canceled, not
// "try again later".
func TestProviderFailure_PassesTheReasonCode(t *testing.T) {
	cause := &backend.CodedError{Code: "insufficient_funds", Err: fmt.Errorf("stripe: /v1/payment_intents: Your card has insufficient funds. (card_error): %w", backend.ErrDeclined)}
	err := providerFailure(fmt.Errorf("charge: %w", cause))
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if got := constraintCode(err); got != "INSUFFICIENT_FUNDS" {
		t.Errorf("detail code = %q, want INSUFFICIENT_FUNDS", got)
	}
	if msg := status.Convert(err).Message(); msg != "the payment was declined" {
		t.Errorf("message = %q", msg)
	}
	if got := constraintCode(providerFailure(fmt.Errorf("x: %w", backend.ErrDeclined))); got != "" {
		t.Errorf("no code named, detail %q attached", got)
	}
	if got := status.Code(providerFailure(fmt.Errorf("stripe: /v1/refunds: %w", context.Canceled))); got != codes.Canceled {
		t.Errorf("cancelled call = %v, want Canceled", got)
	}
}
