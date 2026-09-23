package stripe

import "testing"

func TestToMinorUnits(t *testing.T) {
	cases := []struct {
		amount, currency string
		want             int64
		wantErr          bool
	}{
		{"19.99", "usd", 1999, false},
		{"5", "usd", 500, false},
		{"5.00", "usd", 500, false},
		{"0.99", "usd", 99, false},
		{"10.5", "usd", 1050, false},
		{"-1.50", "usd", -150, false},
		{"1000", "jpy", 1000, false}, // zero-decimal currency
		{"1000", "JPY", 1000, false}, // case-insensitive
		{"19.999", "usd", 0, true},   // more precision than scale allows
		{"", "usd", 0, true},
		{"abc", "usd", 0, true},
		{"1.2.3", "usd", 0, true},
	}
	for _, c := range cases {
		got, err := toMinorUnits(c.amount, c.currency)
		if c.wantErr {
			if err == nil {
				t.Errorf("toMinorUnits(%q,%q): want error, got %d", c.amount, c.currency, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("toMinorUnits(%q,%q): %v", c.amount, c.currency, err)
			continue
		}
		if got != c.want {
			t.Errorf("toMinorUnits(%q,%q) = %d, want %d", c.amount, c.currency, got, c.want)
		}
	}
}
