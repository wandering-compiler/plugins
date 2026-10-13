// Package workeradmit is a relay's answer to "may this worker work here".
//
// A worker that completes a handshake on a worker listener holds a
// certificate this relay's CA issued and that has not expired — the TLS layer
// checked that. What remains is the one decision a certificate cannot carry:
// whether an operator has BANNED that worker since. That set, and the workers
// the relay has met, are what this holds.
//
// The control plane sends the COMPLETE ban set, with its version, on every
// call it makes to a relay (BannedHeader), and delivers it to every registered
// relay on each decision and periodically. A relay keeps the set in its
// identity directory when it has one (KeepIn). Until it holds a set — loaded
// from there, or delivered — it does not know whom to refuse, and says so
// (HoldsBanSet) instead of admitting everyone.
package workeradmit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// holds is whether a ban set is known at all: loaded by KeepIn or
	// delivered by a control plane. A fresh registry knows none.
	holds bool
	// delivered is when a control plane last delivered a set (not when one
	// was loaded from disk). Zero = never since start.
	delivered time.Time
	// path, when set, is where the ban set is kept across restarts.
	path string
	// persistMu serialises writes of path, so the last write is always of
	// the newest state (see persist).
	persistMu sync.Mutex
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
	// A delivery, even an ignored older one: the set held is at least as new
	// as what a control plane just read.
	r.delivered = time.Now()
	r.holds = true
	if version != 0 && version < r.version {
		r.mu.Unlock()
		return
	}
	versionChanged := version > r.version
	if versionChanged {
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
	// A new version is kept even when the set is unchanged: a restart that
	// forgot it would accept a set older than the one already applied.
	changed := added || len(old) != len(r.banned) || versionChanged
	r.mu.Unlock()
	if changed {
		r.persist()
	}
	// Only when someone is NEWLY banned. The set arrives on every management
	// call, almost always unchanged, and the hook scans every tunnel.
	if added && notify != nil {
		notify() // outside the lock: it asks Admitted
	}
}

// HoldsBanSet reports whether the relay knows a ban set at all — one loaded
// from its identity directory, or one a control plane delivered since it
// started. Until then a banned key cannot be told from any other, so the
// worker-facing calls refuse (fail closed) rather than admit everyone.
func (r *Registry) HoldsBanSet() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.holds
}

// LastDelivered is when a control plane last delivered a ban set, and false
// when none has since this relay started. A set loaded from disk does not
// count: it says nothing about decisions taken while the relay was down.
func (r *Registry) LastDelivered() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.delivered, !r.delivered.IsZero()
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
// this exists to prevent. A missing file loads nothing, so the relay holds no
// set (HoldsBanSet) until a control plane delivers one.
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
		r.holds = true
		r.mu.Unlock()
	}
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
	return nil
}

// persist writes the current set atomically (temp file, fsync, rename, fsync
// of the directory), so a crash leaves either the old file or the new one,
// never a torn one that would refuse the next start. Writes are serialised and
// each takes its snapshot under the write lock, so two concurrent changes
// cannot land in the wrong order or share the temp file. A failure is logged
// and not fatal: the set in memory is current, and the next change writes it
// again.
func (r *Registry) persist() {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	r.mu.Lock()
	path := r.path
	s := r.snapshotLocked()
	r.mu.Unlock()
	if path == "" {
		return
	}
	if err := writeAtomic(path, s); err != nil {
		log.Printf("workeradmit: keeping the ban set in %s: %v", path, err)
	}
}

func writeAtomic(path string, s savedBans) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
