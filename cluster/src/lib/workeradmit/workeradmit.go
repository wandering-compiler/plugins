// Package workeradmit is a relay's answer to "may this worker work here".
//
// A worker that completes a handshake on a worker listener holds a
// certificate this relay's CA issued and that has not expired — the TLS layer
// checked that. What remains is the one decision a certificate cannot carry:
// whether an operator has BANNED that worker since. That set, and the workers
// the relay has met, are what this holds.
//
// All of it is in memory and none of it survives a restart, which is safe only
// because the control plane sends the COMPLETE ban set on every call it makes
// to a relay (BannedHeader). A relay that just came up learns it from the first
// contact — and every placement begins with a contact, so no work is placed on
// a restarted relay before it knows whom to refuse.
package workeradmit

import (
	"context"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc/metadata"
)

// BannedHeader carries the complete ban set on every control-plane → relay
// call, as one comma-separated value of worker ids (SPKI fingerprints). An
// EMPTY value is a real answer — nobody is banned — and is different from the
// header being absent, which changes nothing.
const BannedHeader = "w17-cluster-banned"

// WithBans returns ctx carrying the complete ban set to a relay.
func WithBans(ctx context.Context, ids []string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, BannedHeader, strings.Join(ids, ","))
}

// BansFrom reads the ban set a control plane sent, and whether it sent one.
func BansFrom(ctx context.Context) ([]string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, false
	}
	vals := md.Get(BannedHeader)
	if len(vals) == 0 {
		return nil, false
	}
	var out []string
	for _, v := range vals {
		for _, id := range strings.Split(v, ",") {
			if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
				out = append(out, id)
			}
		}
	}
	return out, true
}

// Worker is what a relay knows about a worker it has met. The ID is evidence
// (the SPKI fingerprint of a key the worker proved it holds); the other two
// are what the worker said about itself, carried so an operator has something
// readable to look at, and authorise nothing.
type Worker struct {
	ID       string
	Name     string
	DeviceID string
}

// Registry is one relay's admission state.
type Registry struct {
	mu     sync.Mutex
	banned map[string]struct{}
	known  map[string]Worker
}

func New() *Registry {
	return &Registry{banned: map[string]struct{}{}, known: map[string]Worker{}}
}

// SetBanned replaces the ban set with what the control plane sent.
//
// WHOLESALE, not merged. Removing an id from the set is how a ban is lifted,
// and a merge would make that impossible to express.
func (r *Registry) SetBanned(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.banned = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		r.banned[strings.ToLower(id)] = struct{}{}
	}
}

// Admitted reports whether a worker may work right now — whether it is not
// banned. Asked on every piece of work, not just at connect: a ban taken while
// a worker is connected has to bite without waiting for it to reconnect.
func (r *Registry) Admitted(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, banned := r.banned[strings.ToLower(id)]
	return !banned
}

// Met records a worker the relay has seen — at enrolment, and on every attach
// — so the control plane can be told about it and an operator can ban it.
// The latest claims win; the id is the key.
func (r *Registry) Met(w Worker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	w.ID = strings.ToLower(w.ID)
	r.known[w.ID] = w
}

// Known lists every worker met since this relay started, ordered by id.
func (r *Registry) Known() []Worker {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Worker, 0, len(r.known))
	for _, w := range r.known {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
