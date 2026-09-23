package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/responses"
	gen "github.com/wandering-compiler/platform/plugins/agent/gen"
	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/llm"
)

type capturingSink struct{ events []UsageEvent }

func (s *capturingSink) Record(ev UsageEvent)  { s.events = append(s.events, ev) }
func (s *capturingSink) Close(context.Context) {}

type failingCompleter struct{}

func (failingCompleter) New(context.Context, responses.ResponseNewParams, ...option.RequestOption) (*responses.Response, error) {
	return nil, errors.New("provider said no")
}

// The case the first consumer got wrong, one level up: a call that FAILED is
// still a call that may have spent tokens at the provider. Recording only the
// happy path produces a bill that is short by exactly the calls nobody looks
// at.
func TestAFailedCallIsStillRecorded(t *testing.T) {
	sink := &capturingSink{}
	h := &AgentServiceHandler{Client: failingCompleter{}, Usage: sink, DefaultModel: "gpt-x"}

	_, err := h.Complete(context.Background(), &pb.CompleteReq{
		UsageScope:  "tenant-7",
		UsageLabels: map[string]string{"run": "r1"},
	})
	if err == nil {
		t.Fatal("expected the provider failure to surface")
	}
	if len(sink.events) != 1 {
		t.Fatalf("a failed call recorded %d events, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Status != OutcomeFailed {
		t.Errorf("status = %v, want OutcomeFailed", ev.Status)
	}
	// measured=false is the row saying "this happened and we do not know what
	// it cost". Without it, the failure is indistinguishable from free.
	if ev.Measured {
		t.Error("a failed call with no provider report must not claim to be measured")
	}
	if ev.Scope != "tenant-7" || ev.Labels["run"] != "r1" {
		t.Errorf("attribution was dropped: %+v", ev)
	}
}

// An activation without `usage_persistence` gets the no-op sink, and the call
// sites must not care. If they did, every one of them would be a place the
// feature check could be forgotten.
func TestTheNoopSinkSwallowsEverything(t *testing.T) {
	h := &AgentServiceHandler{Client: failingCompleter{}, Usage: noopUsageSink{}, DefaultModel: "gpt-x"}
	if _, err := h.Complete(context.Background(), &pb.CompleteReq{UsageScope: "t"}); err == nil {
		t.Fatal("expected the provider failure to surface")
	}
}

// The wiring guard: the generated constant and the staged file come from
// different places, and when they disagree every call succeeds while nothing
// is recorded — which reads as a quiet month rather than as a fault.
func TestVerifyUsageWiringAgreesWithTheActivation(t *testing.T) {
	err := VerifyUsageWiring(noopUsageSink{})
	if gen.FeatureUsagePersistence && err == nil {
		t.Error("the activation has usage_persistence ON and a no-op sink was accepted — nothing would be recorded")
	}
	if !gen.FeatureUsagePersistence && err != nil {
		t.Errorf("the activation has the feature OFF and the no-op sink was rejected: %v", err)
	}
	// A real sink is accepted either way: a project may record without the
	// constant claiming anything.
	if err := VerifyUsageWiring(&capturingSink{}); err != nil {
		t.Errorf("a real sink must always pass: %v", err)
	}
}

type denyingLimiter struct{ asked int }

func (d *denyingLimiter) Allow(context.Context, string) LimitDecision {
	d.asked++
	return LimitDecision{Allowed: false, Reason: "over budget"}
}

// The point of a limit rather than a report: out of credit fails the FIRST
// request. A check after the call would be a receipt, not a cap.
func TestAnOverBudgetScopeNeverReachesTheProvider(t *testing.T) {
	lim := &denyingLimiter{}
	sink := &capturingSink{}
	h := &AgentServiceHandler{Client: failingCompleter{}, Usage: sink, Limits: lim, DefaultModel: "gpt-x"}

	_, err := h.Complete(context.Background(), &pb.CompleteReq{UsageScope: "broke"})
	if err == nil {
		t.Fatal("an over-budget scope was allowed to call the model")
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted — a caller has to tell this apart from a provider outage", got)
	}
	if lim.asked != 1 {
		t.Errorf("the limiter was consulted %d times, want 1", lim.asked)
	}
	// Nothing was spent, so nothing is recorded: a refused call is not a call.
	if len(sink.events) != 0 {
		t.Errorf("a call that never happened was recorded: %+v", sink.events)
	}
}

// A scope with no cap, and an activation without the feature, both land here.
// They are different situations with the same answer, and neither is an error.
func TestTheAllowAllLimiterLetsEverythingThrough(t *testing.T) {
	d := allowAllLimiter{}.Allow(context.Background(), "anyone")
	if !d.Allowed {
		t.Error("the default limiter must allow — an activation without limits cannot call the model otherwise")
	}
}

// Every entry point that spends tokens must record. Two of three doing it
// would make "the caller cannot forget" false — the claim this whole layer
// rests on — and the two that would have been missed are exactly the ones a
// consumer reaches for when the answer is long.
func TestEveryEntryPointRecords(t *testing.T) {
	src, err := os.ReadFile("agent_stream.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "h.recordUsage(") {
		t.Error("CompleteStream does not record — a stream spends tokens like any other call")
	}
	run, err := os.ReadFile("agent_run.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(run), "h.recordUsageFor(") {
		t.Error("RunAgent does not record — a tool loop is the most expensive shape this plugin offers")
	}
}

func TestRunOutcome(t *testing.T) {
	if got := runOutcome(errors.New("boom"), nil); got != OutcomeFailed {
		t.Errorf("errored run = %v, want OutcomeFailed", got)
	}
	// No terminal status means nobody can say what it cost — which is a
	// different answer from "it went fine".
	if got := runOutcome(nil, &llm.Completion{}); got != OutcomeUnknown {
		t.Errorf("run cut short = %v, want OutcomeUnknown", got)
	}
	if got := runOutcome(nil, &llm.Completion{Status: "completed"}); got != OutcomeOK {
		t.Errorf("completed run = %v, want OutcomeOK", got)
	}
}

// TestUsageManifestNamesEveryTable — the manifest tells a consumer what
// switching the feature on costs them, and that is a migration, so the list
// has to be right. It said six while the protos held seven: the count was
// written once and a table was added after. Naming them makes the drift
// mechanical to catch rather than something a reader has to recount.
func TestUsageManifestNamesEveryTable(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join("..", "..", "plugin.yaml"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	protos, err := os.ReadFile(filepath.Join("..", "..", "proto", "types", "usage.proto"))
	if err != nil {
		t.Fatalf("read usage protos: %v", err)
	}

	var tables []string
	for _, line := range strings.Split(string(protos), "\n") {
		if name, ok := strings.CutPrefix(line, "message "); ok {
			tables = append(tables, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(name), "{")))
		}
	}
	if len(tables) == 0 {
		t.Fatal("found no messages in usage.proto — this test would pass over an empty file")
	}

	for _, tbl := range tables {
		if !bytes.Contains(manifest, []byte(tbl)) {
			t.Errorf("usage.proto declares table %q and the manifest never names it; a consumer reading the manifest does not know it is signing up for that table", tbl)
		}
	}
	counts := map[int]string{6: "six", 7: "seven", 8: "eight", 9: "nine"}
	if word, ok := counts[len(tables)]; ok && !bytes.Contains(manifest, []byte(word+" tables")) {
		t.Errorf("usage.proto declares %d tables but the manifest does not say %q tables", len(tables), word)
	}
}

// TestRecordUsage_AnEmptyScopeIsStillRecorded — `usage_scope` is optional in
// the contract, so a caller may omit it, and the layer's promise is that the
// caller cannot forget to record spend.
//
// An empty scope used to be queued as-is, fail the `external_id <> ”` check
// at insert and take its whole batch with it — so the one field a caller was
// allowed to leave out produced the silent nothing this layer exists to
// remove. A consumer found it with zero rows after hundreds of calls and no
// error anywhere.
func TestRecordUsage_AnEmptyScopeIsStillRecorded(t *testing.T) {
	sink := &capturingSink{}
	h := &AgentServiceHandler{Usage: sink}

	h.recordUsageFor("", nil, "gpt-x", nil, OutcomeOK, time.Now())

	if len(sink.events) != 1 {
		t.Fatalf("recorded %d event(s), want 1 — an unattributable call is still a call", len(sink.events))
	}
	if got := sink.events[0].Scope; got != ScopeUnattributed {
		t.Errorf("scope = %q, want %q — a row that cannot be attributed must still land, because aggregating later is possible and splitting back never is", got, ScopeUnattributed)
	}

	// The decoy: a scope the caller DID name must reach the sink untouched,
	// or the sentinel would be swallowing real attribution.
	h.recordUsageFor("tenant-42", nil, "gpt-x", nil, OutcomeOK, time.Now())
	if got := sink.events[1].Scope; got != "tenant-42" {
		t.Errorf("named scope = %q, want it unchanged", got)
	}
}

// TestRecordUsage_AnUnkeyedLabelIsDroppedNotFatal — `agent_label` checks
// `key <> ”` exactly as the scope table does, so one unkeyed label would sink
// the batch that carried it.
//
// The answer is the opposite of the scope's, and deliberately: a sentinel is
// right for a scope because the spend is real and has to land somewhere, while
// a label with no key names nothing and could never be queried back. It goes,
// and the event it rode in on is kept.
func TestRecordUsage_AnUnkeyedLabelIsDroppedNotFatal(t *testing.T) {
	sink := &capturingSink{}
	h := &AgentServiceHandler{Usage: sink}

	h.recordUsageFor("t", map[string]string{"": "orphan", "run": "r1"}, "gpt-x", nil, OutcomeOK, time.Now())

	if len(sink.events) != 1 {
		t.Fatalf("recorded %d event(s), want 1", len(sink.events))
	}
	got := sink.events[0].Labels
	if _, ok := got[""]; ok {
		t.Error("the unkeyed label survived — it fails the label table's own CHECK and takes the batch with it")
	}
	if got["run"] != "r1" {
		t.Errorf("the keyed label was lost along with it: %v — dropping the unusable one must not cost the usable ones", got)
	}
}

// TestModelCallFailure_NamesTheProvidersObjection — the failure a caller sees
// used to be the four words `agent: the model call failed`, with a comment
// claiming the detail was in the bundle's logs. Nothing logged it.
//
// A consumer turned one field on, got that sentence, and had to bisect the
// cause with two PAID runs against a live model — because the message named
// neither the status, nor the error type, nor the request field the provider
// objected to. All three were in the error the whole time.
func TestModelCallFailure_NamesTheProvidersObjection(t *testing.T) {
	apiErr := &openai.Error{
		StatusCode: 400,
		Type:       "invalid_request_error",
		Code:       "unsupported_value",
		Param:      "text.format",
	}

	got := modelCallFailure(fmt.Errorf("model call: %w", apiErr))
	for _, want := range []string{"400", "invalid_request_error", "unsupported_value", "text.format"} {
		if !strings.Contains(got, want) {
			t.Errorf("the message does not name %q — that is what a caller bisects for:\n  %s", want, got)
		}
	}

	// And it must NOT carry what the redaction exists for: the deployment URL
	// and the response body, which on some failures quotes the prompt.
	for _, forbidden := range []string{"http://", "https://"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the message leaks %q — the caller may be a browser:\n  %s", forbidden, got)
		}
	}

	// A failure that is NOT the provider's (a dial error, a timeout) has no
	// classification to quote, and must not pretend otherwise.
	plain := modelCallFailure(errors.New("dial tcp: i/o timeout"))
	if strings.Contains(plain, "the provider said") {
		t.Errorf("a non-provider failure claims the provider spoke:\n  %s", plain)
	}
}
