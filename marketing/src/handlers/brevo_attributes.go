package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
)

// The brevo_attributes feature: each marketing record moves a date attribute
// on the user's contact — the day they last made that request — because
// Brevo's automations and segments start from contact attributes. An
// attribute holds only the last time; the request's context (organization,
// status, UTM) is the event's (brevo_events).
//
// The dates are kept per user and attribute (Activity) and only ever move
// forward, and Brevo is written from the rows as stored: a record redelivered
// after a newer one, or two replicas at once, cannot write an older date over
// a newer one.

func init() {
	writeActivity = (*brevoTool).writeActivity
	eraseActivity = (*brevoTool).eraseActivity
	activityAttributes = (*brevoTool).activityAttributes
}

// lastActivityAttr is the exact time of the user's last recorded request, as
// text (ISO 8601): a Brevo date attribute holds the day only.
const lastActivityAttr = "W17_LAST_ACTIVITY_AT"

// maxAttributeName is the longest attribute name the plugin asks Brevo for.
const maxAttributeName = 255

// activityAttr is the contact attribute a method's records move:
// W17_<SERVICE>_<METHOD> (`/e2e.app.tasks.TasksBusiness/CreateTask` →
// `W17_TASKSBUSINESS_CREATETASK`), upper-cased as Brevo keeps attributes, and
// at most 255 characters, prefix included (eventName alone is cut at 255).
func activityAttr(method string) string {
	a := "W17_" + strings.ToUpper(strings.ReplaceAll(eventName(method), "-", "_"))
	if len(a) > maxAttributeName {
		a = a[:maxAttributeName] // ASCII: eventName keeps [A-Za-z0-9_-]
	}
	return a
}

// activityAttributes are the attributes the records may move: one per method
// the selection sends, and the last activity's time.
func (t *brevoTool) activityAttributes() []attributeDef {
	var methods []string
	for m := range t.sel.reads {
		if t.sel.sends(m) {
			methods = append(methods, m)
		}
	}
	sort.Strings(methods)
	out := []attributeDef{{lastActivityAttr, "text"}}
	seen := map[string]bool{}
	for _, m := range methods {
		if a := activityAttr(m); !seen[a] {
			seen[a] = true
			out = append(out, attributeDef{a, "date"})
		}
	}
	return out
}

// maxActivityWrites bounds how often one user's attributes are written again
// because a newer record moved a row while they were being written.
const maxActivityWrites = 3

// writeActivity moves the rows of the batch's records, then writes each
// user's moved attributes to the contact from the rows as stored.
func (t *brevoTool) writeActivity(ctx context.Context, records []*w17pb.RequestEventMeta) error {
	type key struct{ user, attr string }
	latest := map[key]time.Time{}
	touched := map[string]map[string]bool{}
	for _, meta := range records {
		st := meta.GetStart()
		if st == nil {
			continue
		}
		k := key{meta.GetUserId(), activityAttr(meta.GetMethod())}
		if at := st.AsTime(); at.After(latest[k]) {
			latest[k] = at
		}
		if touched[k.user] == nil {
			touched[k.user] = map[string]bool{}
		}
		touched[k.user][k.attr] = true
	}
	if len(touched) == 0 {
		return nil
	}
	users := make([]string, 0, len(touched))
	for u := range touched {
		users = append(users, u)
	}
	sort.Strings(users)
	// The records of erased users were dropped by ConsumeMarketing, which
	// also undoes what an erasure landing during this write would lose.
	keys := make([]key, 0, len(latest))
	for k := range latest {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].user != keys[j].user {
			return keys[i].user < keys[j].user
		}
		return keys[i].attr < keys[j].attr
	})
	for _, k := range keys {
		req := &pb.ActivityReq{UserId: k.user, Attribute: k.attr, LastAt: timestampOf(latest[k])}
		if _, err := t.mutation.RecordActivity(ctx, req); err != nil {
			return fmt.Errorf("marketing plugin: keeping what user %s did: %w", k.user, err)
		}
		if _, err := t.mutation.BumpActivity(ctx, req); err != nil && !heldBack(err) {
			return fmt.Errorf("marketing plugin: keeping what user %s did: %w", k.user, err)
		}
	}
	for _, u := range users {
		if err := t.writeUserActivity(ctx, u, touched[u]); err != nil {
			return err
		}
	}
	return nil
}

// writeUserActivity writes the user's moved attributes, and the time of their
// last activity, from the rows as stored. When a row moved while they were
// written (a newer record, on another replica), they are written again from
// the newer rows, so the last write is never the older one.
func (t *brevoTool) writeUserActivity(ctx context.Context, user string, attrs map[string]bool) error {
	attrs[lastActivityAttr] = true
	var written map[string]any
	for range maxActivityWrites {
		now, err := t.activityValues(ctx, user, attrs)
		if err != nil {
			return err
		}
		if sameValues(now, written) {
			return nil
		}
		// A contact Brevo lacks is created blacklisted, as every contact the
		// plugin did not subscribe on a consent.
		if err := t.contactCall(ctx, "write the activity of", user, t.writeLeavingBlacklisted(ctx, user, "", now)); err != nil {
			return err
		}
		written = now
	}
	return nil
}

// activityValues are the user's attrs as their rows hold them: a method's
// day, and the exact time of the latest row of all.
func (t *brevoTool) activityValues(ctx context.Context, user string, attrs map[string]bool) (map[string]any, error) {
	resp, err := t.query.ListActivity(ctx, &pb.ListActivityReq{UserIds: []string{user}})
	if err != nil {
		return nil, fmt.Errorf("marketing plugin: reading what user %s did: %w", user, err)
	}
	out := map[string]any{}
	var last time.Time
	for _, r := range resp.GetRows() {
		if r.GetUserId() != user || r.GetLastAt() == nil {
			continue
		}
		at := r.GetLastAt().AsTime()
		if at.After(last) {
			last = at
		}
		if attrs[r.GetAttribute()] {
			out[r.GetAttribute()] = brevoDate(at)
		}
	}
	if !last.IsZero() && attrs[lastActivityAttr] {
		out[lastActivityAttr] = last.UTC().Format(time.RFC3339)
	}
	return out, nil
}

func sameValues(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// eraseActivity forgets what an erased user did.
func (t *brevoTool) eraseActivity(ctx context.Context, user string) error {
	if _, err := t.mutation.EraseActivity(ctx, &pb.EraseActivityReq{UserId: user}); err != nil {
		return fmt.Errorf("marketing plugin: erasing what user %s did: %w", user, err)
	}
	return nil
}
