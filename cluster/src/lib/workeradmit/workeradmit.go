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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc/metadata"
)

// BannedHeader carries the complete ban set on every control-plane → relay
// call, as one comma-separated value of worker ids (SPKI fingerprints). An
// EMPTY value is a real answer — nobody is banned — and is different from the
// header being absent, which changes nothing.
const BannedHeader = "w17-cluster-banned"

// BannedVersionHeader carries the ban set's version beside it: the time of
// the newest ban or unban decision, in Unix nanoseconds. A relay ignores a
// set older than one it has applied (see Registry.SetBannedAt).
const BannedVersionHeader = "w17-cluster-banned-version"

// WithBans returns ctx carrying the complete ban set to a relay.
func WithBans(ctx context.Context, ids []string) context.Context {
	return WithBansAt(ctx, ids, 0)
}

// WithBansAt returns ctx carrying the complete ban set and its version.
func WithBansAt(ctx context.Context, ids []string, version int64) context.Context {
	ctx = metadata.AppendToOutgoingContext(ctx, BannedHeader, strings.Join(ids, ","))
	if version != 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, BannedVersionHeader, strconv.FormatInt(version, 10))
	}
	return ctx
}

// BanVersionFrom reads the version sent with the ban set; 0 when absent or
// malformed.
func BanVersionFrom(ctx context.Context) int64 {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0
	}
	vals := md.Get(BannedVersionHeader)
	if len(vals) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(vals[0], 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
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
	onBans func() // see OnBansChanged
	mu     sync.Mutex
	banned map[string]struct{}
	known  map[string]Worker

	// version is the newest ban set's version seen (see BannedVersionHeader);
	// a set older than it is ignored. 0 = none seen yet.
	version int64
	// path, when set, is where the ban set is kept across restarts.
	path string
}

func New() *Registry {
	return &Registry{banned: map[string]struct{}{}, known: map[string]Worker{}}
}

// SetBanned replaces the ban set with what the control plane sent.
//
// WHOLESALE, not merged. Removing an id from the set is how a ban is lifted,
// and a merge would make that impossible to express.
func (r *Registry) SetBanned(ids []string) {
	r.SetBannedAt(ids, 0)
}

// SetBannedAt replaces the ban set with one of the given version, unless a
// newer one has already been applied. Control-plane replicas read the set at
// different moments, so the one that read it earlier can arrive later; its
// set would undo a ban the other already delivered.
//
// Version 0 (a control plane that sends none) is always applied, as before.
func (r *Registry) SetBannedAt(ids []string, version int64) {
	r.mu.Lock()
	if version != 0 && version < r.version {
		r.mu.Unlock()
		return
	}
	if version > r.version {
		r.version = version
	}
	old := r.banned
	r.banned = make(map[string]struct{}, len(ids))
	added := false
	for _, id := range ids {
		id = strings.ToLower(id)
		r.banned[id] = struct{}{}
		if _, was := old[id]; !was {
			added = true
		}
	}
	notify := r.onBans
	changed := added || len(old) != len(r.banned)
	snapshot := r.snapshotLocked()
	r.mu.Unlock()
	if changed {
		r.persist(snapshot)
	}
	// Only when someone is NEWLY banned. The set arrives on every management
	// call, almost always unchanged, and the hook scans every tunnel.
	if added && notify != nil {
		notify() // outside the lock: it asks Admitted
	}
}

// OnBansChanged registers f to run after a SetBanned that bans someone who
// was not banned before. The relay uses it to cut a banned worker's open
// tunnel, which an Admitted check at the next piece of work would leave
// serving whatever it is already running.
func (r *Registry) OnBansChanged(f func()) {
	r.mu.Lock()
	r.onBans = f
	r.mu.Unlock()
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

// savedBans is the on-disk form of the ban set.
type savedBans struct {
	Version int64    `json:"version"`
	Banned  []string `json:"banned"`
}

func (r *Registry) snapshotLocked() savedBans {
	out := savedBans{Version: r.version, Banned: make([]string, 0, len(r.banned))}
	for id := range r.banned {
		out.Banned = append(out.Banned, id)
	}
	sort.Strings(out.Banned)
	return out
}

// KeepIn makes the registry keep its ban set in path across restarts, and
// loads what is there. Without it a restarted relay knew no bans until the
// control plane next called it, and a banned worker could renew its
// certificate in that window. A missing file is an empty start; an
// unreadable one is an error, because starting with no bans is the failure
// this exists to prevent.
func (r *Registry) KeepIn(path string) error {
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("workeradmit: reading the saved ban set: %w", err)
	default:
		var saved savedBans
		if err := json.Unmarshal(raw, &saved); err != nil {
			return fmt.Errorf("workeradmit: the saved ban set %s is not readable: %w", path, err)
		}
		r.mu.Lock()
		r.banned = make(map[string]struct{}, len(saved.Banned))
		for _, id := range saved.Banned {
			r.banned[strings.ToLower(id)] = struct{}{}
		}
		r.version = saved.Version
		r.mu.Unlock()
	}
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
	return nil
}

// persist writes the set atomically (temp file, then rename). A failure is
// logged and not fatal: the set in memory is current, and the next change
// writes it again.
func (r *Registry) persist(s savedBans) {
	r.mu.Lock()
	path := r.path
	r.mu.Unlock()
	if path == "" {
		return
	}
	raw, err := json.Marshal(s)
	if err == nil {
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, raw, 0o600); err == nil {
			err = os.Rename(tmp, path)
		}
	}
	if err != nil {
		log.Printf("workeradmit: keeping the ban set in %s: %v", path, err)
	}
}
