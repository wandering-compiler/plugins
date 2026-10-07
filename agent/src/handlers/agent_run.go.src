package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/llm"
)

// RunAgent drives the tool-calling loop against tools the CALLER runs.
//
// The shape is forced by what a plugin is: the tools are the caller's own gRPC
// methods, compiled into their project, and this code was compiled without
// knowing that project exists. So the loop asks over the stream and waits.
func (h *AgentServiceHandler) RunAgent(srv grpc.BidiStreamingServer[pb.RunAgentReq, pb.RunAgentEvent]) error {
	if h.StreamClient == nil {
		return status.Error(codes.Unimplemented, "agent: this deployment has no streaming client")
	}

	first, err := srv.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "agent: the first message must be Start")
	}

	// sends is serialised: the loop runs read-only tools in parallel, so
	// several goroutines reach Send at once and a gRPC stream is not safe for
	// concurrent sends.
	//
	// The first send failure is KEPT: it is the caller's side of the stream
	// failing, and a run that ends because of it must not be reported as the
	// model failing — see callerLeft.
	var sendMu sync.Mutex
	var sendErr error
	send := func(e *pb.RunAgentEvent) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		err := srv.Send(e)
		if err != nil && sendErr == nil {
			sendErr = err
		}
		return err
	}

	pending := newPendingCalls()
	// One reader owns Recv for the same reason one mutex owns Send.
	//
	// It is NOT waited for. Recv unblocks only when the RPC ends, which is when
	// this handler returns — so waiting here would have the handler wait for
	// the reader and the reader wait for the handler. gRPC guarantees the
	// goroutine is released when the handler returns; every waiter it might
	// have served is released explicitly by failAll below, which is the part
	// that actually matters.
	go func() {
		for {
			msg, rerr := srv.Recv()
			if rerr != nil {
				// EOF is the caller saying "no more results". Anything else is
				// the transport. Either way every waiter is released rather
				// than left blocking for a reply that cannot come.
				pending.failAll(rerr)
				return
			}
			if r := msg.GetToolResult(); r != nil {
				pending.deliver(r)
			}
		}
	}()

	// Asked BEFORE the run, the same way `Complete` and `CompleteStream` ask
	// before their call. This was MISSING, and a review of a consumer's PR
	// found it: three entry points take `usage_scope`, two consulted the
	// limit, and the third — the one that makes the MOST model calls per
	// invocation, because it loops with tool calls — did not.
	//
	// A reader of the contract could not have seen it: `agent_scopelimit` is
	// one table, `usage_scope` is one field, and nothing said the cap applied
	// to some methods. Whoever set a cap and reached for RunAgent learned it
	// from the invoice.
	//
	// Once at the start rather than per turn: a limit that fails mid-run would
	// abandon a conversation that has already spent tool calls, and the
	// per-turn budget a caller wants for that is `Limits` on the Start message.
	if h.Limits != nil {
		if d := h.Limits.Allow(srv.Context(), start.GetUsageScope()); !d.Allowed {
			return status.Error(codes.ResourceExhausted, d.Reason)
		}
	}

	tools := make([]llm.Tool, 0, len(start.GetTools()))
	for _, spec := range start.GetTools() {
		tools = append(tools, &remoteTool{spec: spec, send: send, pending: pending})
	}

	runStartedAt := time.Now()
	model := h.modelForSpec(start.GetModel())
	out, runErr := llm.Run(srv.Context(), h.StreamClient,
		model, start.GetInstructions(),
		messagesFrom(start.GetMessages()), tools, limitsFrom(start.GetLimits()),
		func(e llm.RunEvent) error { return sendRunEvent(send, e) })

	// ⚠️ A request the LLM layer refused BEFORE calling the provider is not a
	// failed call: no tokens were spent and nothing was unavailable, so
	// recording a usage row invents spend and the error sends the caller to the
	// provider's status page for what is an invalid argument. A consumer
	// reported exactly that, and the fix landed on the two unary paths
	// (agent_service.go, agent_stream.go) and missed here — the tool-calling
	// path, which is the one that reaches the provider most often.
	//
	// Before recordUsageFor, not after: the point is that no row is written.
	if llm.IsPreflight(runErr) {
		return status.Error(codes.InvalidArgument, runErr.Error())
	}

	// One row for the run's model spend. The loop's own turns are not
	// separately visible here — `out.Usage` is what the run reports in total —
	// so this records what the plugin can actually observe rather than
	// inventing per-turn numbers it does not have.
	//
	// Recorded on EVERY ending, the caller hanging up included: what the turns
	// before the hang-up spent was paid for whether or not anyone is left to
	// hear about it.
	h.recordUsageFor(start.GetUsageScope(), start.GetUsageLabels(),
		model.ID, spentOn(out, runErr), runOutcome(runErr, out), runStartedAt)

	// Read BEFORE the belt-and-braces failAll below, which would otherwise be
	// the first error the pending set holds.
	sendMu.Lock()
	sentErr := sendErr
	sendMu.Unlock()
	recvErr := pending.failure()

	// Belt and braces. The reader already calls failAll on every Recv error, and
	// that is the path a disconnect actually takes — break-proofing confirmed
	// removing THIS line breaks no test, because the reader gets there first.
	// It is kept for the case the reader cannot cover: a run that ends while a
	// waiter is still registered, where nothing else would release it.
	pending.failAll(io.EOF)

	if runErr != nil {
		// The caller going away is not the model failing. It used to reach
		// runError's default — `Unavailable`, "the run failed" — for a client
		// that hung up or whose own deadline passed: the wrong code, and an
		// operator reading it would look at the provider for something the
		// provider did not do. CompleteStream asks the same callerLeft.
		if left := callerLeft(srv.Context(), runErr, sentErr, recvErr); left != nil {
			return left
		}
		// The caller is still there but closed its SENDING side while a tool
		// result was owed. That is a protocol mistake on their side, not a
		// model failure and not a hang-up: it used to come back as a bare
		// codes.Unknown "EOF", which told them nothing about what they did.
		if errors.Is(runErr, errCallerClosedSend) {
			return status.Error(codes.FailedPrecondition, errCallerClosedSend.Error())
		}
		// The stream failed on OUR side while the caller is still there — a
		// Send of an event over the size limit, a Recv of a ToolResult over
		// it, a message that would not marshal. Not the model: these used to
		// reach runError's Unavailable "the model call failed", logged as a
		// model failure, and a caller retrying on Unavailable hit the same
		// oversize every time.
		if f := streamFailure(model.ID, runErr, sentErr, recvErr); f != nil {
			return f
		}
		mapped := runError(runErr)
		if status.Code(mapped) == codes.Unavailable {
			// As in Complete and CompleteStream: the classification and URL to
			// the log, never the body, which can quote the prompt.
			log.Printf("agent: model run failed (model %q): %s", model.ID, llm.ProviderLogLine(runErr))
		}
		return mapped
	}
	return send(&pb.RunAgentEvent{Event: &pb.RunAgentEvent_Finished{Finished: &pb.Finished{
		Text:             out.Text,
		Status:           statusOf(out.Status),
		IncompleteReason: reasonOf(out.IncompleteReason),
		Usage:            usageOf(out.Usage),
		StoppedRepeating: out.Status == "",
	}}})
}

// remoteTool is a tool whose work happens in the caller's process.
type remoteTool struct {
	spec    *pb.ToolSpec
	send    func(*pb.RunAgentEvent) error
	pending *pendingCalls
}

func (t *remoteTool) Name() string    { return t.spec.GetName() }
func (t *remoteTool) Purpose() string { return t.spec.GetPurpose() }
func (t *remoteTool) Mutating() bool  { return t.spec.GetMutating() }

func (t *remoteTool) Params() json.RawMessage {
	s := t.spec.GetParamsSchema()
	if s == "" {
		return nil
	}
	// Validated here rather than passed through: a schema the provider rejects
	// fails the whole turn, and the caller who wrote it would see only that.
	if !json.Valid([]byte(s)) {
		return nil
	}
	return json.RawMessage(s)
}

func (t *remoteTool) Call(ctx context.Context, args string) (string, error) {
	callID := llm.NewCallID()
	wait := t.pending.add(callID)
	defer t.pending.drop(callID)

	if err := t.send(&pb.RunAgentEvent{Event: &pb.RunAgentEvent_ToolCall{ToolCall: &pb.ToolCall{
		CallId: callID, Name: t.spec.GetName(), Arguments: args,
	}}}); err != nil {
		// The caller is gone. FATAL: a tool that cannot be asked will never be
		// answerable, and letting the loop treat it as an ordinary failure
		// would have the model retry it until the budget ran out.
		return "", llm.Fatal(err)
	}

	select {
	case <-ctx.Done():
		// FATAL, like the send failure above. The run's context ending is not
		// something the model can act on; returned plain, it became a tool
		// result ("The tool failed: context canceled") and the loop went on to
		// ask the model another turn for a caller who had already left.
		return "", llm.Fatal(ctx.Err())
	case res := <-wait:
		if errors.Is(res.err, io.EOF) {
			// Recv's io.EOF is the caller half-closing: "no more messages".
			// Named here, where it is still certain what it means — by the
			// time it reaches the handler an io.EOF could equally be a
			// provider's dropped connection (net/http's error for a reused
			// keep-alive the server closed wraps io.EOF).
			return "", llm.Fatal(errCallerClosedSend)
		}
		if res.err != nil {
			return "", llm.Fatal(res.err)
		}
		if res.failed {
			// The caller's own error text, which they chose to make
			// model-visible. Returned as an error too, so the activity says it
			// failed — the run still continues.
			return res.result, errors.New(res.result)
		}
		return res.result, nil
	}
}

// pendingCalls matches ToolResults to the calls waiting for them. Several are
// outstanding at once whenever read-only tools run in parallel.
type pendingCalls struct {
	mu   sync.Mutex
	ch   map[string]chan toolReply
	done error
}

type toolReply struct {
	result string
	failed bool
	err    error
}

func newPendingCalls() *pendingCalls { return &pendingCalls{ch: map[string]chan toolReply{}} }

func (p *pendingCalls) add(id string) <-chan toolReply {
	// Buffered: deliver must never block on a waiter that has already given up
	// on its context, or the single Recv reader stalls and every other call
	// waits forever behind it.
	c := make(chan toolReply, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done != nil {
		c <- toolReply{err: p.done}
		return c
	}
	p.ch[id] = c
	return c
}

func (p *pendingCalls) drop(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.ch, id)
}

func (p *pendingCalls) deliver(r *pb.RunAgentReq_ToolResult) {
	// Claimed and REMOVED in one step: a call is answered once.
	//
	// It used to stay registered until its waiter dropped it, so a SECOND
	// result for the same id — a caller retrying a send, a duplicated message —
	// found the channel again. The buffer holds one reply; if the waiter had
	// not yet taken the first, the second send blocked forever, and the
	// goroutine blocked was the single Recv reader: every other outstanding
	// call stopped being answered, and a disconnect was no longer noticed, so
	// nothing released them either.
	p.mu.Lock()
	c, ok := p.ch[r.GetCallId()]
	delete(p.ch, r.GetCallId())
	p.mu.Unlock()
	if !ok {
		// A result for a call nobody is waiting for: a late answer to a
		// timed-out call, or an id the caller invented. Dropped rather than
		// treated as an error — neither is worth ending a run over.
		return
	}
	c <- toolReply{result: r.GetResult(), failed: r.GetFailed()}
}

// failure is the first error failAll was given, or nil.
func (p *pendingCalls) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

// failAll releases every waiter. Without it a caller that disconnects leaves
// the loop blocked on a reply that cannot arrive, holding the run open.
func (p *pendingCalls) failAll(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done == nil {
		p.done = err
	}
	for id, c := range p.ch {
		select {
		case c <- toolReply{err: err}:
		default:
		}
		delete(p.ch, id)
	}
}

func sendRunEvent(send func(*pb.RunAgentEvent) error, e llm.RunEvent) error {
	switch {
	case e.Delta != "":
		return send(&pb.RunAgentEvent{Event: &pb.RunAgentEvent_Delta{Delta: &pb.TextDelta{Text: e.Delta}}})
	case e.ToolStarted != nil:
		return send(&pb.RunAgentEvent{Event: &pb.RunAgentEvent_Activity{Activity: &pb.Activity{
			ActivityId: e.ToolStarted.CallID,
			Text:       e.ToolStarted.Name,
		}}})
	case e.ToolFinished != nil:
		a := &pb.Activity{ActivityId: e.ToolFinished.CallID, Text: e.ToolFinished.Name, Finished: true}
		if e.ToolFinished.Err != nil {
			// Deliberately not the error's text: a tool's error is the caller's
			// own string and may quote anything. The activity says THAT it
			// failed; the caller already knows what they returned.
			a.Error = "the tool failed"
		}
		return send(&pb.RunAgentEvent{Event: &pb.RunAgentEvent_Activity{Activity: a}})
	}
	return nil
}

// errCallerClosedSend ends a run whose caller half-closed the stream — Recv
// returned io.EOF — while a tool call was still waiting for its result.
var errCallerClosedSend = errors.New("agent: the caller closed its side of the stream while a tool result was still owed")

// callerLeft returns the error to answer with when a run ended because the
// CALLER went away — their stream context ended (a hang-up, their own
// deadline), or the stream itself failed on their side (a Send or a Recv the
// transport refused) — and nil when the run ended for any other reason.
//
// The caller's own error comes back as-is: there is nobody to tell anything
// else, and re-coding it would only mislabel the log of whoever reads the
// server side.
//
// A Send or Recv error counts only when it is the caller leaving (see
// callerGone). Either can also fail on THIS side — a message over the size
// limit, one that would not marshal — and returning that as "the caller left"
// would hide a server-side defect behind a hang-up nobody made; streamFailure
// answers those. Recv's io.EOF does not count either: it is the caller
// half-closing, not leaving.
func callerLeft(ctx context.Context, runErr, sendErr, recvErr error) error {
	if sendErr != nil && errors.Is(runErr, sendErr) && callerGone(ctx, sendErr) {
		return sendErr
	}
	// The same filter for Recv. It used to be any Recv error but io.EOF — so a
	// ResourceExhausted "received message larger than max", an oversized
	// ToolResult from a caller who is still connected, came back as if they
	// had hung up, with nothing logged.
	if recvErr != nil && !errors.Is(recvErr, io.EOF) && errors.Is(runErr, recvErr) && callerGone(ctx, recvErr) {
		return recvErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}
	return nil
}

// callerGone reports whether a failed Send or Recv means the caller is gone:
// the stream's context has ended, the transport reported the stream cancelled,
// past its deadline or closing, or a send hit the end of the stream. Anything
// else — ResourceExhausted for an oversized message, Internal for one that
// would not marshal — is the stream failing on THIS side, and belongs to
// streamFailure. (Recv's io.EOF never gets here: callerLeft excludes it, as
// the caller half-closing.)
func callerGone(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, io.EOF) {
		return true
	}
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable:
		// Unavailable is grpc-go's code for a write on a transport that is
		// closing — the connection under the caller going away.
		return true
	}
	return false
}

// streamFailure is the answer for a run that ended because a Send or a Recv
// failed on THIS side of a stream whose caller is still connected — callerLeft
// has already answered every case where they are not. Nil when the run ended
// for another reason.
//
// The stream's own status is kept where it says something the caller can act
// on: ResourceExhausted, a message over the size limit, stays that — retrying
// it is pointless, which is exactly what the Unavailable it used to become
// invited. Anything else is our defect: Internal, with a short message. Logged
// as what it is, a stream failure, never a model failure; the run's spend was
// already recorded once, before this.
func streamFailure(model string, runErr, sendErr, recvErr error) error {
	switch {
	case sendErr != nil && errors.Is(runErr, sendErr):
		log.Printf("agent: sending to the caller failed (model %q): %v", model, sendErr)
		return ownSideFailure(sendErr, "agent: an event could not be sent to the caller")
	case recvErr != nil && !errors.Is(recvErr, io.EOF) && errors.Is(runErr, recvErr):
		log.Printf("agent: receiving from the caller failed (model %q): %v", model, recvErr)
		return ownSideFailure(recvErr, "agent: a message from the caller could not be received")
	}
	return nil
}

// ownSideFailure codes a stream failure on this side: see streamFailure.
func ownSideFailure(err error, msg string) error {
	if status.Code(err) == codes.ResourceExhausted {
		return err
	}
	return status.Error(codes.Internal, msg)
}

func runError(err error) error {
	switch {
	case errors.Is(err, llm.ErrBudgetExhausted):
		return status.Error(codes.ResourceExhausted, "agent: the run exceeded its tool-call budget")
	case errors.Is(err, llm.ErrTurnsExhausted):
		return status.Error(codes.DeadlineExceeded, "agent: the model did not finish within the turn limit")
	case errors.Is(err, llm.ErrRunawayOutput):
		return status.Error(codes.ResourceExhausted, "agent: the model produced more output than the limit allows")
	default:
		// No "the caller left" case here. callerLeft runs first and answers
		// every ending the caller caused, so an io.EOF or context.Canceled that
		// reaches this switch came from somewhere else while the caller was
		// still connected — typically the provider's transport: net/http
		// reports a keep-alive connection the provider closed as
		// `Post "<deployment url>": EOF`. Returned as-is it reached the caller
		// as codes.Unknown with the deployment URL in the text, and nothing
		// was logged.
		//
		// The same rendering as Complete and CompleteStream. A run used to
		// answer every model failure with the bare "agent: the run failed",
		// so a response the provider marked failed lost its CODE on this path
		// alone — the one path whose failures are the most expensive to
		// reproduce.
		return status.Error(codes.Unavailable, modelCallFailure(err))
	}
}

func limitsFrom(l *pb.Limits) llm.Limits {
	if l == nil {
		return llm.Limits{}
	}
	return llm.Limits{
		MaxTurns:     int(l.GetMaxTurns()),
		MaxToolCalls: int(l.GetMaxToolCalls()),
		MaxParallel:  int(l.GetMaxParallel()),
	}
}

func (h *AgentServiceHandler) modelForSpec(spec *pb.ModelSpec) llm.Model {
	return h.modelFor(&pb.CompleteReq{Model: spec})
}
