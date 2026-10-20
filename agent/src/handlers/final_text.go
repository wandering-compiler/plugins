package handlers

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/textfilter"
)

// TextFilterHook is one of the project's own final-text filters: a method
// the activation binds to the `text_filter` hook (gen.ClientSet.
// TextFilterHooks()).
type TextFilterHook = func(ctx context.Context, req *pb.TextFilterReq) (*pb.TextFilterResp, error)

// FinalTextFilters clean the final text of an answer (CompleteResp.text,
// Finished.text) — never the deltas, so a stream stays as fast as the model
// and a caller swaps the streamed text for the clean one at the end. Which
// filters run is the activation's: the built-in `final_text_*` features,
// then the project's own (the `text_filter` hook), in order. A call may
// allow other scripts or opt out (pb.FinalText).
//
// The zero value filters nothing.
type FinalTextFilters struct {
	// Scripts is the `final_text_scripts` filter with the activation's
	// allowed scripts; nil when the feature is off.
	Scripts *textfilter.Scripts
	// Invisible is the `final_text_invisible` filter.
	Invisible bool
	// Hooks are the project's filters, in the order the activation binds
	// them, and HookTimeout bounds each (0 = the call's deadline only).
	Hooks       []TextFilterHook
	HookTimeout time.Duration
}

// finalTextRun is the filters one call runs.
type finalTextRun struct {
	chain   textfilter.Chain
	hooks   []TextFilterHook
	timeout time.Duration
}

// textOrigin is what a project filter is told about the text it gets.
type textOrigin struct {
	method      string
	model       string
	usageScope  string
	usageLabels map[string]string
}

// run is the filters a call runs: the activation's, with the call's
// scripts instead when it names some. The call's options are checked here,
// before the model is called, so a call the filters would refuse costs
// nothing: an unknown script is InvalidArgument, scripts named to an
// activation that does not filter scripts FailedPrecondition.
func (f FinalTextFilters) run(opt *pb.FinalText) (finalTextRun, error) {
	if opt.GetRaw() {
		return finalTextRun{}, nil
	}
	var c textfilter.Chain
	if f.Invisible {
		c = append(c, textfilter.Invisible{})
	}
	scripts := f.Scripts
	if names := opt.GetAllowedScripts(); len(names) > 0 {
		if scripts == nil {
			return finalTextRun{}, status.Error(codes.FailedPrecondition,
				"final_text.allowed_scripts names scripts, but this activation does not filter them: switch on the agent plugin's `final_text_scripts` feature, or leave allowed_scripts empty")
		}
		s, err := textfilter.NewScripts(names)
		if err != nil {
			return finalTextRun{}, status.Error(codes.InvalidArgument, "final_text.allowed_scripts: "+err.Error())
		}
		scripts = s
	}
	if scripts != nil {
		c = append(c, scripts)
	}
	return finalTextRun{chain: c, hooks: f.Hooks, timeout: f.HookTimeout}, nil
}

// apply cleans text: the built-in filters, then each project filter on the
// previous one's text. A project filter that fails or does not answer in
// time is skipped and logged — never the text, which can quote the user —
// and the answer goes on with the text as it stood: the model's answer was
// paid for, and a filter being down must not take it away.
func (r finalTextRun) apply(ctx context.Context, text string, o textOrigin) string {
	text = r.chain.Apply(text)
	for i, hook := range r.hooks {
		hctx, cancel := ctx, context.CancelFunc(func() {})
		if r.timeout > 0 {
			hctx, cancel = context.WithTimeout(ctx, r.timeout)
		}
		resp, err := hook(hctx, &pb.TextFilterReq{
			Text: text, Method: o.method, Model: o.model,
			UsageScope: o.usageScope, UsageLabels: o.usageLabels,
		})
		cancel()
		if err != nil {
			log.Printf("agent: text_filter hook %d of %d skipped (%s): %s", i+1, len(r.hooks), o.method, status.Code(err))
			continue
		}
		text = resp.GetText()
	}
	return text
}
