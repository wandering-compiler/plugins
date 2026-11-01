package handlers

import (
	"slices"
	"strings"
	"testing"
	"unicode"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
	dbpb "github.com/wandering-compiler/sdk/go/pb/w17/db"
)

// A relay is ENDED, never deleted (SPEC base/relay-ended-not-deleted). The
// statements live in the plugin's protos, which no unit test can run against a
// database, so these tests read them from the generated descriptors and check
// their STRUCTURE — the statement kind, the SET targets, the WHERE predicates
// as token sequences — rather than looking for a substring anywhere in the
// text. What the statements do against a real Postgres is the live check in
// the pull request that introduced them.

// dqlTokens splits a DQL statement into words, `:param` / `:op.col`
// references, quoted strings and single punctuation characters. Keywords are
// upper-cased so a comparison does not depend on how a statement is spelled.
func dqlTokens(dql string) []string {
	var out []string
	rs := []rune(dql)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '\'':
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			out = append(out, string(rs[i:min(j+1, len(rs))]))
			i = j + 1
		case r == ':' || r == '@' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			j := i + 1
			for j < len(rs) && (rs[j] == '_' || rs[j] == '.' || unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j])) {
				j++
			}
			w := string(rs[i:j])
			if !strings.HasPrefix(w, ":") && !strings.HasPrefix(w, "@") && !strings.Contains(w, ".") {
				w = strings.ToUpper(w)
			}
			out = append(out, w)
			i = j
		default:
			out = append(out, string(r))
			i++
		}
	}
	return out
}

// clause returns the tokens of one clause: those after `from` up to the first
// of `until` (or the end).
func clause(toks []string, from string, until ...string) []string {
	start := slices.Index(toks, from)
	if start < 0 {
		return nil
	}
	rest := toks[start+1:]
	for i, t := range rest {
		if slices.Contains(until, t) {
			return rest[:i]
		}
	}
	return rest
}

// hasSeq reports whether seq occurs in toks as a contiguous run.
func hasSeq(toks, seq []string) bool {
	for i := 0; i+len(seq) <= len(toks); i++ {
		if slices.Equal(toks[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

// ops returns a method's declared operations, from the generated descriptor.
func ops(t *testing.T, service, method string) []*dbpb.Operation {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(service + "." + method))
	if err != nil {
		t.Fatalf("%s.%s: %v", service, method, err)
	}
	m, ok := proto.GetExtension(d.(protoreflect.MethodDescriptor).Options(), dbpb.E_Method).(*dbpb.Method)
	if !ok || len(m.GetOps()) == 0 {
		t.Fatalf("%s.%s declares no (w17.db.method) ops", service, method)
	}
	return m.GetOps()
}

func message(t *testing.T, name protoreflect.FullName) protoreflect.MessageDescriptor {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d.(protoreflect.MessageDescriptor)
}

func pkgOf(t *testing.T) string {
	t.Helper()
	// The package is the activation's once staged; read it from the
	// generated row rather than spelling it.
	return string((&pb.Relay{}).ProtoReflect().Descriptor().ParentFile().Package())
}

// DeleteRelay keeps its name and request, and ends the relay: one UPDATE
// that stamps removed_at and frees the name (ended_key = id), on a live row
// only, so ending twice changes nothing.
func TestDeleteRelay_EndsTheRelayAndDeletesNothing(t *testing.T) {
	pkg := pkgOf(t)
	o := ops(t, pkg+".RelayMutation", "DeleteRelay")
	if len(o) != 1 {
		t.Fatalf("DeleteRelay has %d ops, want 1", len(o))
	}
	toks := dqlTokens(o[0].GetDql())
	if toks[0] != "UPDATE" || toks[1] != "@module.Relay" {
		t.Fatalf("DeleteRelay is %q, want an UPDATE of @module.Relay", strings.Join(toks, " "))
	}
	set := clause(toks, "SET", "WHERE")
	if !hasSeq(set, []string{"REMOVED_AT", "=", "NOW", "(", ")"}) || !hasSeq(set, []string{"ENDED_KEY", "=", "ID"}) {
		t.Errorf("DeleteRelay SET = %q, want removed_at = NOW() and ended_key = id", strings.Join(set, " "))
	}
	where := clause(toks, "WHERE")
	if !hasSeq(where, []string{"ID", "=", ":id"}) || !hasSeq(where, []string{"REMOVED_AT", "IS", "NULL"}) {
		t.Errorf("DeleteRelay WHERE = %q, want id = :id AND removed_at IS NULL", strings.Join(where, " "))
	}
	// The surface callers and the admin page bind is unchanged.
	if f := message(t, protoreflect.FullName(pkg+".DeleteRelayReq")).Fields(); f.Len() != 1 || f.Get(0).Name() != "id" {
		t.Errorf("DeleteRelayReq changed shape: %v", f)
	}
}

// Nothing in the plugin deletes a row: rows are never deleted, growing
// tables are the record.
func TestNoStatementDeletesARow(t *testing.T) {
	pkg := pkgOf(t)
	checked := 0
	for _, svc := range []string{"RelayQuery", "RelayMutation", "WorkerQuery", "WorkerMutation"} {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(pkg + "." + svc))
		if err != nil {
			t.Fatal(err)
		}
		ms := d.(protoreflect.ServiceDescriptor).Methods()
		for i := 0; i < ms.Len(); i++ {
			for _, op := range ops(t, pkg+"."+svc, string(ms.Get(i).Name())) {
				checked++
				if toks := dqlTokens(op.GetDql()); toks[0] == "DELETE" {
					t.Errorf("%s.%s op %q deletes: %s", svc, ms.Get(i).Name(), op.GetName(), op.GetDql())
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no statement was checked")
	}
}

// Every read of the registry skips an ended relay, so every path that
// resolves one — placement and the sweep (ListEnabled), the ban delivery and
// connection pruning (ListAll), reservations, registration codes and drain
// (Get), the admin's list and detail — never sees it.
func TestEndedRelaysAreInvisibleToEveryRead(t *testing.T) {
	pkg := pkgOf(t)
	for _, m := range []string{"ListRelays", "GetRelay"} {
		o := ops(t, pkg+".RelayQuery", m)
		if len(o) != 1 {
			t.Fatalf("%s has %d ops, want 1", m, len(o))
		}
		toks := dqlTokens(o[0].GetDql())
		where := clause(toks, "WHERE", "ORDER", "LIMIT")
		if !hasSeq(where, []string{"r.removed_at", "IS", "NULL"}) {
			t.Errorf("%s WHERE = %q, want r.removed_at IS NULL", m, strings.Join(where, " "))
		}
		// ANDed at the top level: an OR beside it would let an ended row back in.
		if slices.Contains(where, "OR") && !hasSeq(where, []string{"r.removed_at", "IS", "NULL", "AND", "("}) {
			t.Errorf("%s WHERE = %q: the removed_at predicate is not ANDed outside the OR", m, strings.Join(where, " "))
		}
	}
	// The writes an ended relay must not take: an operator's edit, and the
	// observed state the control plane writes behind a placement.
	for _, m := range []string{"UpdateRelay", "RecordRelayReached", "RecordRelayFailed"} {
		where := clause(dqlTokens(ops(t, pkg+".RelayMutation", m)[0].GetDql()), "WHERE")
		if !hasSeq(where, []string{"REMOVED_AT", "IS", "NULL"}) {
			t.Errorf("%s WHERE = %q, want a live row only (removed_at IS NULL)", m, strings.Join(where, " "))
		}
	}
}

// Worker admission: RecordWorker files a worker only under a LIVE relay. Its
// first op locks the live relay row (a write, so a concurrent DeleteRelay of
// the same row is ordered before or after it) and refuses on relay_id when
// there is none; the upsert then writes the id that op returned.
func TestRecordWorker_RefusesAnEndedRelay(t *testing.T) {
	pkg := pkgOf(t)
	o := ops(t, pkg+".WorkerMutation", "RecordWorker")
	if len(o) != 2 {
		t.Fatalf("RecordWorker has %d ops, want 2 (the live-relay guard, then the upsert)", len(o))
	}
	guard, main := o[0], o[1]
	toks := dqlTokens(guard.GetDql())
	if toks[0] != "UPDATE" || toks[1] != "@module.Relay" {
		t.Errorf("guard op is %q, want a no-op UPDATE of @module.Relay (a lock, not a read)", guard.GetDql())
	}
	where := clause(toks, "WHERE", "RETURNING")
	if !hasSeq(where, []string{"ID", "=", ":relay_id"}) || !hasSeq(where, []string{"REMOVED_AT", "IS", "NULL"}) {
		t.Errorf("guard WHERE = %q, want id = :relay_id AND removed_at IS NULL", strings.Join(where, " "))
	}
	if !hasSeq(clause(toks, "RETURNING"), []string{"ID", "AS", "ID"}) {
		t.Errorf("guard op returns nothing the upsert reads: %s", guard.GetDql())
	}
	e := guard.GetOnEmpty()
	if e.GetCode() != dbpb.OnEmptyCode_ON_EMPTY_INVALID_ARGUMENT || e.GetField() != "relay_id" || e.GetErrorCode() != "RELAY_ENDED" {
		t.Errorf("guard on_empty = %v, want INVALID_ARGUMENT RELAY_ENDED on relay_id", e)
	}
	mt := dqlTokens(main.GetDql())
	if mt[0] != "UPSERT" || slices.Contains(mt, ":relay_id") || !slices.Contains(mt, ":relay.id") {
		t.Errorf("upsert = %q, want relay_id written from the guard (:relay.id), never from the request", main.GetDql())
	}
	// The refusal the guard answers is the relay's failure for the sweep,
	// never one bad worker after another.
	if got := classifyRecordError(wrapped(codes.InvalidArgument, e.GetErrorCode(), e.GetField())); got != refusedRelay {
		t.Errorf("the guard's refusal classifies as %v, want refusedRelay", got)
	}
}

// Re-creating a relay with the same name is a NEW row: the name is unique only
// together with ended_key, which is empty on every live row and the row's own id
// once DeleteRelay ended it. So an ended row frees its name, two live rows
// still collide, and the ended row is never revived.
func TestRelay_ANameIsUniqueAmongLiveRelaysOnly(t *testing.T) {
	pkg := pkgOf(t)
	relay := message(t, protoreflect.FullName(pkg+".Relay"))
	tbl, _ := proto.GetExtension(relay.Options(), dbpb.E_Table).(*dbpb.Table)
	found := false
	for _, ix := range tbl.GetIndexes() {
		var names []string
		for _, f := range ix.GetFields() {
			names = append(names, f.GetName())
		}
		if ix.GetUnique() && slices.Equal(names, []string{"name", "ended_key"}) {
			found = true
		}
	}
	if !found {
		t.Errorf("Relay has no unique index over (name, ended_key): %v", tbl.GetIndexes())
	}
	field := func(n protoreflect.Name) *w17pb.Field {
		fd := relay.Fields().ByName(n)
		if fd == nil {
			t.Fatalf("Relay has no field %s", n)
		}
		f, _ := proto.GetExtension(fd.Options(), w17pb.E_Field).(*w17pb.Field)
		return f
	}
	if field("name").GetUnique() {
		t.Error("Relay.name is unique on its own: an ended relay would hold its name forever and a relay could never be registered again under it")
	}
	if !field("removed_at").GetNull() {
		t.Error("Relay.removed_at is not nullable: a live relay is the NULL one")
	}
	if ek := field("ended_key"); ek.GetDefaultString() != "" || !ek.GetBlank() {
		t.Errorf("Relay.ended_key = %v, want blank with default '' (every live row shares it)", ek)
	}
	// CreateRelay is a plain INSERT: no conflict clause that could revive an
	// ended row.
	ct := dqlTokens(ops(t, pkg+".RelayMutation", "CreateRelay")[0].GetDql())
	if ct[0] != "INSERT" || slices.Contains(ct, "CONFLICT") {
		t.Errorf("CreateRelay = %q, want a plain INSERT", strings.Join(ct, " "))
	}
}

// Worker.relay_id names a row of this activation's Relay table, ON DELETE
// RESTRICT: nothing deletes a relay, so a delete that would strand a worker is
// refused rather than cascaded. It is the only reference between the plugin's
// tables (decided_by is free text by design).
func TestWorker_RelayIDIsAForeignKey(t *testing.T) {
	pkg := pkgOf(t)
	for _, name := range []string{"Relay", "Worker"} {
		fs := message(t, protoreflect.FullName(pkg+"."+name)).Fields()
		for i := 0; i < fs.Len(); i++ {
			fd := fs.Get(i)
			col, _ := proto.GetExtension(fd.Options(), dbpb.E_Column).(*dbpb.Column)
			want := name == "Worker" && fd.Name() == "relay_id"
			if !want {
				if col.GetFk() != "" {
					t.Errorf("%s.%s carries an unexpected foreign key %q", name, fd.Name(), col.GetFk())
				}
				continue
			}
			if col.GetFk() != "@module.Relay" || col.GetDeletionRule() != dbpb.DeletionRule_BLOCK {
				t.Errorf("Worker.relay_id fk = %q %v, want @module.Relay BLOCK", col.GetFk(), col.GetDeletionRule())
			}
		}
	}
}

// A relay ended between the sweep's relay list and its write is THAT relay
// failing — listed unreachable, its row noted failed — and the sweep goes on
// to the other relays; none of its workers is reported refused.
func TestCheckWorkers_ARelayEndedMidSweepIsThatRelaysFailure(t *testing.T) {
	logs := captureLog(t)
	ws := &validatingStore{workerStore: &workerStore{}, failRelay: map[string]error{
		"r-a": wrapped(codes.InvalidArgument, "RELAY_ENDED", "relay_id"),
	}}
	h, st := sweepTwoRelays(t, ws,
		[]workeradmit.Worker{{ID: "aa", Name: "acme-1"}},
		[]workeradmit.Worker{{ID: "bb", Name: "acme-4"}},
	)
	resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if err != nil {
		t.Fatalf("an ended relay failed the whole sweep: %v", err)
	}
	if got := resp.GetUnreachableRelays(); len(got) != 1 || got[0] != "acme-a" {
		t.Errorf("unreachable = %v, want [acme-a]", got)
	}
	if resp.GetSkippedWorkers() != 0 {
		t.Errorf("skipped_workers = %d, want 0", resp.GetSkippedWorkers())
	}
	if got := strings.Join(ws.recorded, ","); got != "r-b:bb" {
		t.Errorf("recorded = %q, want r-b:bb only", got)
	}
	if f := st.failedFor("r-a"); len(f) != 1 {
		t.Errorf("the ended relay was not noted failed: %v", f)
	}
	if strings.Contains(logs.String(), "refused it") {
		t.Errorf("the ended relay's workers were logged as refused for their own data:\n%s", logs.String())
	}
}
