package handlers

import (
	"errors"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/llm"
)

// CompleteStream runs one model call and sends the text as it arrives.
func (h *AgentServiceHandler) CompleteStream(req *pb.CompleteReq, srv grpc.ServerStreamingServer[pb.CompleteEvent]) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "agent: empty request")
	}
	if h.StreamClient == nil {
		return status.Error(codes.Unimplemented, "agent: this deployment has no streaming client")
	}

	// Same cap as Complete, for the same reason: a stream spends tokens the
	// moment it starts.
	if h.Limits != nil {
		if d := h.Limits.Allow(srv.Context(), req.GetUsageScope()); !d.Allowed {
			return status.Error(codes.ResourceExhausted, d.Reason)
		}
	}

	m := h.modelFor(req)

	startedAt := time.Now()
	// The transport's own failure, kept so it can be told apart from the
	// model's below.
	var sendErr error
	out, err := llm.CompleteStream(srv.Context(), h.StreamClient, m,
		req.GetInstructions(), messagesFrom(req.GetMessages()),
		func(text string) error {
			// A send failure is the client going away, and it is returned so
			// the call ABORTS: continuing would keep paying the provider for
			// tokens with nowhere to put them.
			if sErr := srv.Send(&pb.CompleteEvent{
				Event: &pb.CompleteEvent_Delta{Delta: &pb.TextDelta{Text: text}},
			}); sErr != nil {
				sendErr = sErr
				return sErr
			}
			return nil
		})
	if err != nil {
		// BEFORE the usage row, not after it. A preflight refusal never reached
		// the provider, so there is nothing to have paid for — recording one
		// invents spend, and `Unavailable` sends the caller to a status page for
		// what is an invalid argument (reported by a consumer). The unary path got this and
		// the stream path did not: the branch sat below recordUsage, so the
		// event was already written by the time it ran.
		if llm.IsPreflight(err) {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		// Recorded before the error is shaped: a stream that died mid-flight
		// has already paid for whatever the provider produced, and a runaway
		// guard stopping it does not make those tokens free.
		h.recordUsage(req, m.ID, spentOn(out, err), OutcomeFailed, startedAt)
		// The client going away is not ours to re-wrap: there is nobody to
		// tell. The same rule as RunAgent (callerLeft): a Send that failed
		// because the client is gone comes back as-is, and so does the
		// stream's own context ending — the client hanging up, or its own
		// deadline passing, while the provider was still talking. Both used to
		// fall through to the Unavailable below, with a log line blaming the
		// model for something the client did; the deadline case survived the
		// first fix because only the send path was covered.
		//
		// A Send that failed on THIS side (an oversized or unmarshalable
		// message) is not the client leaving…
		if left := callerLeft(srv.Context(), err, sendErr, nil); left != nil {
			return left
		}
		// …and goes HERE: the send's own status (ResourceExhausted stays
		// ResourceExhausted), logged as a send failure. It used to reach the
		// Unavailable below, logged as the model failing, and a caller
		// retrying on Unavailable hit the same oversize every time.
		if f := streamFailure(m.ID, err, sendErr, nil); f != nil {
			return f
		}
		if errors.Is(err, llm.ErrRunawayOutput) {
			return status.Error(codes.ResourceExhausted, "agent: the model produced more output than the limit allows")
		}
		// As in Complete: the provider's own text renders the deployment URL
		// and can quote the prompt, so it stops here — and it stops before the
		// LOG too, which is the half this comment used to get wrong. "The whole
		// error to the log" covered the URL and carried the response body with
		// it (reported by a consumer). ProviderLogLine keeps the classification and the URL
		// and drops the body.
		//
		// The caller still gets the provider's classification. A stream that
		// dies with an unexplained Unavailable is if anything worse than a unary
		// one, because the caller has already consumed part of an answer.
		log.Printf("agent: model stream failed (model %q): %s", m.ID, llm.ProviderLogLine(err))
		return status.Error(codes.Unavailable, modelCallFailure(err))
	}

	// The guard stopped the stream: no terminal event arrived, so there is no
	// status and no usage. Saying so explicitly is the point — a consumer that
	// read this row as a completed free call would understate both the answer's
	// reliability and its own token spend.
	stopped := out.Status == ""

	// A stream the runaway guard stopped has no terminal event, so no status
	// and no usage — which is exactly the "we do not know what it cost" row
	// rather than a free one.
	outcome := OutcomeOK
	if stopped {
		outcome = OutcomeUnknown
	}
	h.recordUsage(req, m.ID, out, outcome, startedAt)

	return srv.Send(&pb.CompleteEvent{
		Event: &pb.CompleteEvent_Finished{Finished: &pb.Finished{
			Text:             out.Text,
			Status:           statusOf(out.Status),
			IncompleteReason: reasonOf(out.IncompleteReason),
			Usage:            usageOf(out.Usage),
			StoppedRepeating: stopped,
		}},
	})
}
