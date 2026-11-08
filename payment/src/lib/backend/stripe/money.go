package stripe

import (
	"fmt"
	"math"
	"strings"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// zeroDecimalCurrencies are the ISO-4217 codes Stripe treats as having
// no minor unit (the amount is already an integer of the major unit): the
// whole of Stripe's documented zero-decimal list, less ISK and UGX, which it
// takes as two-decimal values (wholeUnitsSentAsCents). Every other currency
// Stripe charges is two-decimal, except the three-decimal ones below, so a
// currency absent from all three tables is two-decimal by Stripe's own rule,
// not by a guess (TestZeroDecimalTable_IsStripesList pins the list).
var zeroDecimalCurrencies = map[string]bool{
	"bif": true, "clp": true, "djf": true, "gnf": true, "jpy": true,
	"kmf": true, "krw": true, "mga": true, "pyg": true, "rwf": true,
	"vnd": true, "vuv": true, "xaf": true, "xof": true, "xpf": true,
}

// wholeUnitsSentAsCents are Stripe's documented special cases: zero-decimal
// currencies that its API still takes as two-decimal values whose decimal
// part is always 00 ("to charge 5 UGX, provide an amount value of 500"), and
// that cannot be charged in fractions. UGX used to sit in the zero-decimal
// table, so "5" ugx went out as 5 — a hundredth of what was asked.
var wholeUnitsSentAsCents = map[string]bool{"isk": true, "ugx": true}

// threeDecimalCurrencies are the three-decimal currencies. Stripe takes them
// in their own minor unit (5.120 KWD is 5120 fils) and requires the amount
// to be a multiple of ten — its last digit 0 — so an amount that is not is
// refused here rather than rounded on either side.
var threeDecimalCurrencies = map[string]bool{"bhd": true, "jod": true, "kwd": true, "omr": true, "tnd": true}

// invalidAmount is the error every amount refusal carries: the request
// cannot succeed as written, so it is a backend.InputError (which matches
// backend.ErrInvalidRequest). Its message may reach the caller: it names
// only the caller's own amount and currency.
func invalidAmount(format string, args ...any) error {
	return &backend.InputError{Msg: fmt.Sprintf(format, args...)}
}

// wireShape is how one currency travels to Stripe, from the plugin's
// scale-4 amount (ten-thousandths of the major unit): divide by `div`
// (which must leave no remainder), then multiply by `mul`, and the result
// must be a multiple of `step`.
type wireShape struct {
	div, mul, step int64
}

func shapeOf(cur string) wireShape {
	switch {
	case zeroDecimalCurrencies[cur]:
		return wireShape{div: 10000, mul: 1, step: 1}
	case wholeUnitsSentAsCents[cur]:
		return wireShape{div: 10000, mul: 100, step: 1}
	case threeDecimalCurrencies[cur]:
		return wireShape{div: 10, mul: 1, step: 10}
	}
	return wireShape{div: 100, mul: 1, step: 1}
}

// formatAmount renders a scale-4 amount for an error message ("19.9901").
func formatAmount(n int64) string {
	sign := ""
	u := uint64(n)
	if n < 0 {
		sign, u = "-", uint64(-(n+1))+1
	}
	return fmt.Sprintf("%s%d.%04d", sign, u/10000, u%10000)
}

// toMinorUnits converts an amount of ten-thousandths of the major unit
// (backend.Money.Amount, scale 4) to the integer minor units Stripe's API
// expects: 199900 usd is 1999, 150000 jpy is 15, 51200 kwd is 5120 fils,
// 50000 ugx is 500. It is exact — integer arithmetic only — and REFUSES an
// amount the currency cannot represent (199901 usd is 19.9901, a fraction of
// a cent) rather than rounding it, and a three-decimal amount Stripe would
// not take (not a multiple of ten fils). A result that does not fit an int64
// is refused too.
func toMinorUnits(amount int64, currency string) (int64, error) {
	cur := strings.ToLower(strings.TrimSpace(currency))
	sh := shapeOf(cur)
	if amount%sh.div != 0 {
		return 0, invalidAmount("amount %s has more fractional digits than %s allows", formatAmount(amount), cur)
	}
	n := amount / sh.div
	if n > math.MaxInt64/sh.mul || n < math.MinInt64/sh.mul {
		return 0, invalidAmount("amount %s overflows the provider's integer minor units", formatAmount(amount))
	}
	n *= sh.mul
	if n%sh.step != 0 {
		return 0, invalidAmount("amount %s %s must be a multiple of 0.010: the provider charges a three-decimal currency in tens of its minor unit", formatAmount(amount), cur)
	}
	return n, nil
}

// positiveMinorUnits is toMinorUnits for every amount the driver sends:
// a charge, a refund and a price are all strictly positive. A negative
// PaymentIntent / refund / unit_amount is never what a caller meant, and
// a zero one is meaningless — refuse it here too, so the driver does not
// depend on every caller having validated first.
func positiveMinorUnits(amount int64, currency string) (int64, error) {
	if amount <= 0 {
		return 0, invalidAmount("amount %s must be positive", formatAmount(amount))
	}
	return toMinorUnits(amount, currency)
}

// fromMinorUnits is toMinorUnits reversed, for an amount the provider
// reports: 1999 usd is 199900, 500 jpy is 5000000, 500 ugx is 50000, 5120 kwd
// is 51200. It refuses (an error, never a wrapped value) an amount whose
// scale-4 form does not fit an int64, and a whole-unit currency's amount that
// is not whole (Stripe sends those as two-decimal values ending in 00).
func fromMinorUnits(n int64, currency string) (int64, error) {
	cur := strings.ToLower(strings.TrimSpace(currency))
	sh := shapeOf(cur)
	if n%sh.mul != 0 {
		return 0, fmt.Errorf("stripe: amount %d %s is not a whole number of units", n, cur)
	}
	n /= sh.mul
	if n > math.MaxInt64/sh.div || n < math.MinInt64/sh.div {
		return 0, fmt.Errorf("stripe: amount %d %s overflows the plugin's amount range", n, cur)
	}
	return n * sh.div, nil
}

// moneyFrom is fromMinorUnits as a backend.Money.
func moneyFrom(n int64, currency string) (backend.Money, error) {
	a, err := fromMinorUnits(n, currency)
	if err != nil {
		return backend.Money{}, err
	}
	return backend.Money{Amount: a, Currency: currency}, nil
}
