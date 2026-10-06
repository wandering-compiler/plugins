package workeradmit

import (
	"testing"

	"google.golang.org/grpc/metadata"
)

// An empty relay admits every worker its CA vouched for: the certificate is
// the admission, and the registry only holds the exceptions.
func TestNew_AdmitsUntilBanned(t *testing.T) {
	r := New()
	if !r.Admitted("aa") {
		t.Fatal("a fresh relay refused a worker nobody banned")
	}
	r.SetBanned([]string{"AA"})
	if r.Admitted("aa") {
		t.Error("a banned worker is admitted (ids compare case-insensitively)")
	}
}

// The set REPLACES, so lifting a ban is expressible: send the set without it.
func TestSetBanned_ReplacesRatherThanMerges(t *testing.T) {
	r := New()
	r.SetBanned([]string{"aa", "bb"})
	r.SetBanned([]string{"bb"})
	if !r.Admitted("aa") {
		t.Error("a ban lifted by the control plane is still in force")
	}
	if r.Admitted("bb") {
		t.Error("a ban still in the set was dropped")
	}
}

// Absent and empty are different answers: empty lifts every ban, absent says
// nothing. A relay reading absent as empty would let any call that happened to
// lack the header unban the whole fleet.
func TestBansFrom_EmptyIsAnAnswerAbsentIsNot(t *testing.T) {
	in := func(md metadata.MD) ([]string, bool) {
		return BansFrom(metadata.NewIncomingContext(t.Context(), md))
	}
	if _, ok := in(metadata.MD{}); ok {
		t.Error("no header read as a ban set")
	}
	if got, ok := in(metadata.Pairs(BannedHeader, "")); !ok || len(got) != 0 {
		t.Errorf("an empty header = %v, %v; want an empty set that counts", got, ok)
	}
	if got, ok := in(metadata.Pairs(BannedHeader, "AA, bb,")); !ok || len(got) != 2 || got[0] != "aa" || got[1] != "bb" {
		t.Errorf("parsed %v, %v; want [aa bb]", got, ok)
	}
}

// And what WithBans writes is what BansFrom reads.
func TestWithBans_RoundTrips(t *testing.T) {
	out := WithBans(t.Context(), []string{"aa", "bb"})
	md, _ := metadata.FromOutgoingContext(out)
	got, ok := BansFrom(metadata.NewIncomingContext(t.Context(), md))
	if !ok || len(got) != 2 {
		t.Fatalf("round trip = %v, %v", got, ok)
	}
	empty := WithBans(t.Context(), nil)
	md, _ = metadata.FromOutgoingContext(empty)
	if got, ok := BansFrom(metadata.NewIncomingContext(t.Context(), md)); !ok || len(got) != 0 {
		t.Errorf("an empty ban set did not travel as one: %v, %v", got, ok)
	}
}

func TestMet_LatestClaimsWin(t *testing.T) {
	r := New()
	r.Met(Worker{ID: "AA", Name: "old"})
	r.Met(Worker{ID: "aa", Name: "new"})
	r.Met(Worker{ID: "bb"})
	got := r.Known()
	if len(got) != 2 || got[0].Name != "new" {
		t.Errorf("known = %+v, want aa (named new) and bb", got)
	}
}
