package stripe

import (
	"fmt"
	"math"
	"strings"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
)

// zeroDecimalCurrencies are the ISO-4217 codes Stripe treats as having
// no minor unit (the amount is already an integer of the major unit).
// Not exhaustive — the common ones; extend as needed.
var zeroDecimalCurrencies = map[string]bool{
	"bif": true, "clp": true, "djf": true, "gnf": true, "jpy": true,
	"kmf": true, "krw": true, "mga": true, "pyg": true, "rwf": true,
	"ugx": true, "vnd": true, "vuv": true, "xaf": true, "xof": true, "xpf": true,
}

// invalidAmount is the error every amount refusal carries: the request
// cannot succeed as written, so it wraps backend.ErrInvalidRequest.
func invalidAmount(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{backend.ErrInvalidRequest}, args...)...)
}

// toMinorUnits converts a decimal-string amount ("19.99") to the
// integer minor units Stripe's API expects (1999 for a 2-decimal
// currency, 19 for a zero-decimal one). It is exact — no float64 — and
// REFUSES more fractional digits than the currency allows rather than
// silently dropping cents.
//
// It also refuses an amount whose minor units do not fit an int64. The
// accumulation used to wrap silently: "184467440737095516.17" usd is
// 2^64+1 cents and went out as amount=1 — the provider charged (or
// refunded) one cent while the caller, and the local row, held the
// amount it asked for.
func toMinorUnits(amount, currency string) (int64, error) {
	scale := 2
	if zeroDecimalCurrencies[strings.ToLower(strings.TrimSpace(currency))] {
		scale = 0
	}
	s := strings.TrimSpace(amount)
	if s == "" {
		return 0, invalidAmount("stripe: empty amount")
	}
	neg := false
	switch s[0] {
	case '+':
		s = s[1:]
	case '-':
		neg = true
		s = s[1:]
	}
	if s == "" {
		return 0, invalidAmount("stripe: invalid amount %q", amount)
	}
	intPart, fracPart := s, ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		intPart, fracPart = s[:dot], s[dot+1:]
	}
	if intPart == "" {
		intPart = "0"
	}
	// Trailing zeros past the scale carry no value: "12.3400" IS 12.34.
	// The DECIMAL(20, 4) columns hand every amount back in that form, so
	// refusing them refused every amount read back from storage — a full
	// refund (which sends the stored payment amount) failed for every
	// payment, on every 2-decimal and 0-decimal currency.
	for len(fracPart) > scale && fracPart[len(fracPart)-1] == '0' {
		fracPart = fracPart[:len(fracPart)-1]
	}
	if len(fracPart) > scale {
		return 0, invalidAmount("stripe: amount %q has more fractional digits than %s allows (scale %d)", amount, currency, scale)
	}
	for len(fracPart) < scale {
		fracPart += "0"
	}
	digits := intPart + fracPart
	var n int64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, invalidAmount("stripe: invalid amount %q", amount)
		}
		d := int64(c - '0')
		if n > (math.MaxInt64-d)/10 {
			return 0, invalidAmount("stripe: amount %q overflows the provider's integer minor units", amount)
		}
		n = n*10 + d
	}
	if neg {
		n = -n
	}
	return n, nil
}

// positiveMinorUnits is toMinorUnits for every amount the driver sends:
// a charge, a refund and a price are all strictly positive. A negative
// PaymentIntent / refund / unit_amount is never what a caller meant, and
// a zero one is meaningless — refuse it here too, so the driver does not
// depend on every caller having validated first.
func positiveMinorUnits(amount, currency string) (int64, error) {
	n, err := toMinorUnits(amount, currency)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, invalidAmount("stripe: amount %q must be positive", amount)
	}
	return n, nil
}
