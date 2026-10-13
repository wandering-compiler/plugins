package resowner

import (
	"testing"

	"google.golang.org/grpc/metadata"
)

// With replaces an owner already on the context rather than adding a second
// value: the relay reads the first one, so an appended owner could lose.
func TestWith_ReplacesAnEarlierOwner(t *testing.T) {
	ctx := metadata.AppendToOutgoingContext(t.Context(), Header, "owner-earlier", "other-key", "kept")
	ctx = With(ctx, "owner-now")
	md, _ := metadata.FromOutgoingContext(ctx)
	if got := md.Get(Header); len(got) != 1 || got[0] != "owner-now" {
		t.Errorf("%s = %v, want only owner-now", Header, got)
	}
	if got := md.Get("other-key"); len(got) != 1 || got[0] != "kept" {
		t.Errorf("other metadata = %v, want it kept", got)
	}
	// What the relay reads is what was set.
	in := metadata.NewIncomingContext(t.Context(), md)
	if got := From(in); got != "owner-now" {
		t.Errorf("From = %q, want owner-now", got)
	}
}

// With does not change the context it was given: a caller reusing it for
// another holder sends that holder, not this one.
func TestWith_LeavesTheParentAlone(t *testing.T) {
	parent := metadata.AppendToOutgoingContext(t.Context(), Header, "owner-parent")
	_ = With(parent, "owner-child")
	md, _ := metadata.FromOutgoingContext(parent)
	if got := md.Get(Header); len(got) != 1 || got[0] != "owner-parent" {
		t.Errorf("the parent's %s = %v, want it unchanged", Header, got)
	}
}

func TestFrom_NoOwnerIsEmpty(t *testing.T) {
	if got := From(t.Context()); got != "" {
		t.Errorf("From with no metadata = %q", got)
	}
}
