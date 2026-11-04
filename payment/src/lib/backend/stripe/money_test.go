package stripe

import (
	"errors"
	"math"
	"testing"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// An amount is ten-thousandths of the major unit (scale 4); Stripe takes the
// currency's own minor units. Every conversion is exact.
func TestToMinorUnits(t *testing.T) {
	for _, c := range []struct {
		amount   int64
		currency string
		want     int64
	}{
		{199900, "usd", 1999},   // 19.99 USD
		{50000, "usd", 500},     // 5 USD
		{9900, "usd", 99},       // 0.99 USD
		{-15000, "usd", -150},   // signed amounts convert too
		{100, "eur", 1},         // one cent
		{150000, "jpy", 15},     // 15 JPY, zero-decimal
		{10000000, "JPY", 1000}, // case-insensitive
		{51200, "kwd", 5120},    // 5.12 KWD in fils
		{50000, "bhd", 5000},    // 5 BHD
		{50000, "ugx", 500},     // 5 UGX goes as a two-decimal 500
		{12500000, "isk", 125000},
	} {
		got, err := toMinorUnits(c.amount, c.currency)
		if err != nil || got != c.want {
			t.Errorf("toMinorUnits(%d, %s) = %d, %v; want %d", c.amount, c.currency, got, err, c.want)
		}
	}
}

// What the currency cannot represent is refused, never rounded: a fraction
// of a cent, of a yen, of a whole-unit currency, or a three-decimal amount
// that is not a multiple of ten fils (Stripe charges those in tens).
func TestToMinorUnits_RefusesPrecisionLoss(t *testing.T) {
	for _, c := range []struct {
		amount   int64
		currency string
	}{
		{199901, "usd"}, // 19.9901
		{1, "eur"},      // 0.0001
		{150001, "jpy"}, // 15.0001
		{155000, "jpy"}, // 15.5
		{55000, "ugx"},  // 5.5
		{100, "isk"},    // 0.01
		{51241, "kwd"},  // 5.1241: finer than a fil
		{51230, "kwd"},  // 5.123: a fil, but not a multiple of ten
		{10, "omr"},     // 0.001
	} {
		if _, err := toMinorUnits(c.amount, c.currency); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("toMinorUnits(%d, %s): want an ErrInvalidRequest refusal, got %v", c.amount, c.currency, err)
		}
	}
}

// The plugin's range ends before the wire's: a whole-unit currency is sent
// ×100, but only after the ÷10000 from scale 4, so the extremes convert
// exactly (and the guard against wrapping stays for a future shape).
func TestToMinorUnits_Extremes(t *testing.T) {
	whole := int64(math.MaxInt64/10000) * 10000
	if got, err := toMinorUnits(whole, "ugx"); err != nil || got != whole/100 {
		t.Errorf("toMinorUnits(%d, ugx) = %d, %v", whole, got, err)
	}
	if got, err := toMinorUnits(-whole, "isk"); err != nil || got != -whole/100 {
		t.Errorf("toMinorUnits(%d, isk) = %d, %v", -whole, got, err)
	}
	top := int64(math.MaxInt64/100) * 100
	if got, err := toMinorUnits(top, "usd"); err != nil || got != top/100 {
		t.Errorf("toMinorUnits(%d, usd) = %d, %v", top, got, err)
	}
}

func TestPositiveMinorUnits(t *testing.T) {
	for _, bad := range []int64{0, -1, -100, math.MinInt64} {
		if _, err := positiveMinorUnits(bad, "usd"); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("positiveMinorUnits(%d): want ErrInvalidRequest, got %v", bad, err)
		}
	}
	if n, err := positiveMinorUnits(100, "usd"); err != nil || n != 1 {
		t.Errorf("one cent: %d, %v", n, err)
	}
}

// fromMinorUnits is the exact reverse, for an amount the provider reports.
func TestFromMinorUnits(t *testing.T) {
	for _, c := range []struct {
		n    int64
		cur  string
		want int64
	}{
		{1999, "usd", 199900}, {5, "eur", 500}, {500, "jpy", 5000000},
		{500, "ugx", 50000}, {500, "ISK", 50000}, {5120, "kwd", 51200}, {-150, "usd", -15000},
	} {
		got, err := fromMinorUnits(c.n, c.cur)
		if err != nil || got != c.want {
			t.Errorf("fromMinorUnits(%d, %s) = %d, %v; want %d", c.n, c.cur, got, err, c.want)
		}
		back, err := toMinorUnits(got, c.cur)
		if err != nil || back != c.n {
			t.Errorf("round trip %d %s → %d → %d, %v", c.n, c.cur, got, back, err)
		}
	}
	// Past the plugin's range, or a whole-unit amount that is not whole: an
	// error, never a wrapped or truncated value.
	for _, c := range []struct {
		n   int64
		cur string
	}{{math.MaxInt64, "usd"}, {math.MinInt64, "usd"}, {math.MaxInt64 / 100, "jpy"}, {550, "ugx"}} {
		if got, err := fromMinorUnits(c.n, c.cur); err == nil {
			t.Errorf("fromMinorUnits(%d, %s) = %d, want an error", c.n, c.cur, got)
		}
	}
}

// The amount in a refusal reads as a decimal of the major unit.
func TestFormatAmount(t *testing.T) {
	for n, want := range map[int64]string{199900: "19.9900", 1: "0.0001", -15000: "-1.5000", 0: "0.0000", math.MinInt64: "-922337203685477.5808"} {
		if got := formatAmount(n); got != want {
			t.Errorf("formatAmount(%d) = %q, want %q", n, got, want)
		}
	}
}
