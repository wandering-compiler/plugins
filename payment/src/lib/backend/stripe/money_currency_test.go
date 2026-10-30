package stripe

import (
	"errors"
	"testing"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// Stripe's documented special cases: ISK and UGX are zero-decimal but sent as
// two-decimal values ending in 00, and cannot be charged in fractions.
func TestToMinorUnits_WholeUnitsSentAsCents(t *testing.T) {
	for _, c := range []struct {
		amount, cur string
		want        int64
	}{
		{"5", "ugx", 500}, {"5.0000", "UGX", 500}, {"1250", "isk", 125000},
		{"5", "jpy", 5}, {"5.00", "usd", 500},
	} {
		got, err := toMinorUnits(c.amount, c.cur)
		if err != nil || got != c.want {
			t.Errorf("%s %s: got %d, %v — want %d", c.amount, c.cur, got, err, c.want)
		}
	}
	for _, c := range [][2]string{{"5.50", "ugx"}, {"0.01", "isk"}} {
		if _, err := toMinorUnits(c[0], c[1]); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("%s %s: a fraction of a whole-unit currency must be refused, got %v", c[0], c[1], err)
		}
	}
}

// Three-decimal currencies used to go out as two-decimal: "5.00" kwd as
// 0.500 KWD. Refused rather than guessed.
func TestToMinorUnits_RefusesThreeDecimalCurrencies(t *testing.T) {
	for _, cur := range []string{"bhd", "jod", "KWD", "omr", "tnd"} {
		_, err := toMinorUnits("5.00", cur)
		if !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("%s: want a refusal, got %v", cur, err)
		}
	}
}

// A whole-unit amount that fits int64 but not once sent ×100.
func TestToMinorUnits_WholeUnitsOverflowOnTheWire(t *testing.T) {
	if _, err := toMinorUnits("92233720368547759", "ugx"); !errors.Is(err, backend.ErrInvalidRequest) {
		t.Errorf("want an overflow refusal, got %v", err)
	}
}

// base gap 5: the zero-decimal handling is Stripe's documented list, whole —
// the sixteen zero-decimal currencies, ISK and UGX among them as the two it
// takes as two-decimal values — so a currency outside it is two-decimal by
// Stripe's rule. A change to the list is a change to this test.
func TestZeroDecimalTable_IsStripesList(t *testing.T) {
	stripe := []string{"bif", "clp", "djf", "gnf", "isk", "jpy", "kmf", "krw", "mga", "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf"}
	covered := map[string]bool{}
	for c := range zeroDecimalCurrencies {
		covered[c] = true
	}
	for c := range wholeUnitsSentAsCents {
		if covered[c] {
			t.Errorf("%s is in both the zero-decimal and the whole-units table", c)
		}
		covered[c] = true
	}
	for _, c := range stripe {
		if !covered[c] {
			t.Errorf("Stripe's zero-decimal %s is in neither table — it would be charged as two-decimal", c)
		}
		delete(covered, c)
	}
	for c := range covered {
		t.Errorf("%s is treated as zero-decimal and is not on Stripe's list", c)
	}
}
