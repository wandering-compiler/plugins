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
		amount int64
		cur    string
		want   int64
	}{
		{50000, "ugx", 500}, {50000, "UGX", 500}, {12500000, "isk", 125000},
		{50000, "jpy", 5}, {50000, "usd", 500},
	} {
		got, err := toMinorUnits(c.amount, c.cur)
		if err != nil || got != c.want {
			t.Errorf("%d %s: got %d, %v — want %d", c.amount, c.cur, got, err, c.want)
		}
	}
	for _, c := range []struct {
		amount int64
		cur    string
	}{{55000, "ugx"}, {100, "isk"}} {
		if _, err := toMinorUnits(c.amount, c.cur); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("%d %s: a fraction of a whole-unit currency must be refused, got %v", c.amount, c.cur, err)
		}
	}
}

// Three-decimal currencies used to go out as two-decimal ("5.00" kwd as
// 0.500 KWD) and were then refused outright. They are charged in their own
// minor unit now, exactly: 5.120 KWD is 5120 fils, in tens as Stripe takes
// them.
func TestToMinorUnits_ThreeDecimalCurrencies(t *testing.T) {
	for _, cur := range []string{"bhd", "jod", "KWD", "omr", "tnd"} {
		got, err := toMinorUnits(51200, cur)
		if err != nil || got != 5120 {
			t.Errorf("%s: 5.12 → %d, %v; want 5120", cur, got, err)
		}
		if _, err := toMinorUnits(51210, cur); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("%s: 5.121 is not a multiple of ten minor units; want a refusal, got %v", cur, err)
		}
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
