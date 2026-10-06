package handlers

import (
	"testing"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
)

func line(cost *int64, currency string, priced int64) *pb.ScopeSpendLine {
	return &pb.ScopeSpendLine{CostMinor: cost, Currency: &currency, PricedCalls: priced}
}

func minor(v int64) *int64 { return &v }

// a consumer — the two changes that met.
//
// The usage rollup's currency fix made an absent `cost_minor` mean a SECOND
// thing: not only "nothing here was priced" but also "the currencies inside
// this line disagreed". The limiter's
// `if CostMinor != nil { total += … }` skipped both, so a scope priced in two
// currencies never reached its cap — real money, past a limit somebody set.
//
// And the limiter had no test at all, which is how two correct changes produced a
// third result nobody intended.
func TestTotalSpend(t *testing.T) {
	cases := []struct {
		name     string
		lines    []*pb.ScopeSpendLine
		want     int64
		ok       bool
		currency string
	}{
		{
			name:  "one currency adds up",
			lines: []*pb.ScopeSpendLine{line(minor(7580), "USD", 3), line(minor(300), "USD", 1)},
			want:  7880, ok: true, currency: "USD",
		},
		{
			// The original case, still contributing nothing: a model nobody
			// priced must not make a scope look cheap OR expensive.
			name:  "nothing priced contributes nothing",
			lines: []*pb.ScopeSpendLine{line(minor(500), "USD", 2), line(nil, "", 0)},
			want:  500, ok: true, currency: "USD",
		},
		{
			// The reported case itself. Absent cost WITH priced calls is a line
			// whose spend is real and whose amount cannot be expressed.
			name:  "a line whose currencies disagreed cannot be totalled",
			lines: []*pb.ScopeSpendLine{line(minor(500), "USD", 2), line(nil, "", 4)},
			ok:    false,
		},
		{
			// The sharper half, which the report did not name: the limiter was
			// adding minor units ACROSS lines in different currencies — the same
			// defect the rollup's currency fix closed inside one.
			name:  "two currencies across lines cannot be totalled",
			lines: []*pb.ScopeSpendLine{line(minor(1000), "USD", 1), line(minor(1000), "EUR", 1)},
			ok:    false,
		},
		{
			name:  "no lines is zero, not untotallable",
			lines: nil,
			want:  0, ok: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, currency, ok := totalSpend(tc.lines)
			if ok != tc.ok {
				t.Fatalf("totallable = %v, want %v (got %d)", ok, tc.ok, got)
			}
			if ok && currency != tc.currency {
				t.Errorf("currency = %q, want %q — a total is only comparable with a limit in the same currency", currency, tc.currency)
			}
			if ok && got != tc.want {
				t.Errorf("total = %d, want %d", got, tc.want)
			}
		})
	}
}
