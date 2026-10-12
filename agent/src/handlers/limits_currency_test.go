package handlers

import (
	"testing"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"google.golang.org/protobuf/proto"
)

// line is a spend line whose calls were all priced.
func line(cost *int64, currency string, priced int64) *pb.ScopeSpendLine {
	return &pb.ScopeSpendLine{CostMinor: cost, Currency: &currency, PricedCalls: priced, Calls: priced}
}

func minor(v int64) *int64 { return &v }

// Two changes that met.
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
		refused  string
		currency string
	}{
		{
			name:  "one currency adds up",
			lines: []*pb.ScopeSpendLine{line(minor(7580), "USD", 3), line(minor(300), "USD", 1)},
			want:  7880, currency: "USD",
		},
		{
			// Tokens nobody priced are not free: under a cap, calls on a
			// model with no price used to contribute nothing, so a scope on
			// unpriced models was never refused.
			name:    "calls on an unpriced model cannot be totalled",
			lines:   []*pb.ScopeSpendLine{line(minor(500), "USD", 2), {Calls: 3, InputTokens: 10}},
			refused: reasonUnpriced,
		},
		{
			// A failed call on a model name the caller made up spent nothing,
			// and is recorded under that name. Refusing it locked the scope
			// out over a typo.
			name:  "unpriced calls that spent no tokens contribute nothing",
			lines: []*pb.ScopeSpendLine{line(minor(500), "USD", 2), {Calls: 3}},
			want:  500, currency: "USD",
		},
		{
			name:    "a line priced only in part cannot be totalled",
			lines:   []*pb.ScopeSpendLine{{CostMinor: minor(500), Currency: proto.String("USD"), PricedCalls: 2, Calls: 5}},
			refused: reasonUnpriced,
		},
		{
			// The case this refusal exists for. Absent cost WITH priced calls is a line
			// whose spend is real and whose amount cannot be expressed.
			name:    "a line whose currencies disagreed cannot be totalled",
			lines:   []*pb.ScopeSpendLine{line(minor(500), "USD", 2), line(nil, "", 4)},
			refused: reasonMixedCurrency,
		},
		{
			// The sharper half, which the report did not name: the limiter was
			// adding minor units ACROSS lines in different currencies — the same
			// defect the rollup's currency fix closed inside one.
			name:    "two currencies across lines cannot be totalled",
			lines:   []*pb.ScopeSpendLine{line(minor(1000), "USD", 1), line(minor(1000), "EUR", 1)},
			refused: reasonMixedCurrency,
		},
		{
			name:  "no lines is zero, not untotallable",
			lines: nil,
			want:  0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, currency, refused := totalSpend(tc.lines)
			if refused != tc.refused {
				t.Fatalf("refusal = %q, want %q (got %d)", refused, tc.refused, got)
			}
			ok := refused == ""
			if ok && currency != tc.currency {
				t.Errorf("currency = %q, want %q — a total is only comparable with a limit in the same currency", currency, tc.currency)
			}
			if ok && got != tc.want {
				t.Errorf("total = %d, want %d", got, tc.want)
			}
		})
	}
}
