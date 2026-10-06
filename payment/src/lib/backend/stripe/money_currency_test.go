package stripe

import (
	"errors"
	"testing"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
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
