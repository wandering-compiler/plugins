package stripe

import (
	"fmt"
	"strings"
)

// zeroDecimalCurrencies are the ISO-4217 codes Stripe treats as having
// no minor unit (the amount is already an integer of the major unit).
// Not exhaustive — the common ones; extend as needed.
var zeroDecimalCurrencies = map[string]bool{
	"bif": true, "clp": true, "djf": true, "gnf": true, "jpy": true,
	"kmf": true, "krw": true, "mga": true, "pyg": true, "rwf": true,
	"ugx": true, "vnd": true, "vuv": true, "xaf": true, "xof": true, "xpf": true,
}

// toMinorUnits converts a decimal-string amount ("19.99") to the
// integer minor units Stripe's API expects (1999 for a 2-decimal
// currency, 19 for a zero-decimal one). It is exact — no float64 — and
// REFUSES more fractional digits than the currency allows rather than
// silently dropping cents.
func toMinorUnits(amount, currency string) (int64, error) {
	scale := 2
	if zeroDecimalCurrencies[strings.ToLower(strings.TrimSpace(currency))] {
		scale = 0
	}

	s := strings.TrimSpace(amount)
	if s == "" {
		return 0, fmt.Errorf("stripe: empty amount")
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
		return 0, fmt.Errorf("stripe: invalid amount %q", amount)
	}

	intPart, fracPart := s, ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		intPart, fracPart = s[:dot], s[dot+1:]
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > scale {
		return 0, fmt.Errorf("stripe: amount %q has more fractional digits than %s allows (scale %d)", amount, currency, scale)
	}
	for len(fracPart) < scale {
		fracPart += "0"
	}

	digits := intPart + fracPart
	var n int64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("stripe: invalid amount %q", amount)
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}
