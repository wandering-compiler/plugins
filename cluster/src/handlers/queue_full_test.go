package handlers

import (
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
)

// A relay whose queue is full is skipped like a draining one: another relay
// may have room, and the caller should not see this relay's limit.
func TestFallsThrough_AFullQueue(t *testing.T) {
	if !fallsThrough(refusal.New(codes.ResourceExhausted, refusal.QueueFull, "relay: the queue is full")) {
		t.Error("QUEUE_FULL does not fall through to the next relay")
	}
}
