package workeradmit

import (
	"os"
	"path/filepath"
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

// The ban hook runs after the set is replaced, and sees the new set.
func TestOnBansChanged_RunsWithTheNewSet(t *testing.T) {
	r := New()
	var sawBanned bool
	r.OnBansChanged(func() { sawBanned = !r.Admitted("w1") })
	r.SetBanned([]string{"W1"})
	if !sawBanned {
		t.Error("the hook did not run, or ran before the ban took effect")
	}
}

// The set arrives on every management call; the hook, which scans every
// tunnel, runs only when someone is newly banned.
func TestOnBansChanged_RunsOnlyForANewBan(t *testing.T) {
	r := New()
	runs := 0
	r.OnBansChanged(func() { runs++ })
	r.SetBanned([]string{"w1"})
	r.SetBanned([]string{"W1"})
	r.SetBanned(nil)
	if runs != 1 {
		t.Fatalf("hook ran %d times for one new ban, a repeat and a lift, want 1", runs)
	}
	r.SetBanned([]string{"w1"})
	if runs != 2 {
		t.Errorf("hook ran %d times, want 2 — banning again after a lift is a new ban", runs)
	}
}

// A set read earlier by another control-plane replica can arrive later; it
// must not undo the newer one.
func TestSetBannedAt_AnOlderSetIsIgnored(t *testing.T) {
	r := New()
	r.SetBannedAt([]string{"w1"}, 20)
	r.SetBannedAt(nil, 10) // older: would lift the ban
	if r.Admitted("w1") {
		t.Error("an older ban set lifted a newer ban")
	}
	r.SetBannedAt(nil, 30)
	if !r.Admitted("w1") {
		t.Error("a newer set did not apply")
	}
}

// The ban set is kept across a restart: a new registry loads it.
func TestKeepIn_SurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	r := New()
	if err := r.KeepIn(path); err != nil {
		t.Fatal(err)
	}
	r.SetBannedAt([]string{"W1"}, 42)
	again := New()
	if err := again.KeepIn(path); err != nil {
		t.Fatal(err)
	}
	if again.Admitted("w1") {
		t.Error("the restarted registry forgot the ban")
	}
	again.SetBannedAt(nil, 41) // older than what was saved
	if again.Admitted("w1") {
		t.Error("the saved version was not restored: an older set applied")
	}
}

// An unreadable saved set refuses to start rather than starting with no bans.
func TestKeepIn_AnUnreadableFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New().KeepIn(path); err == nil {
		t.Error("an unreadable saved ban set was accepted")
	}
}
