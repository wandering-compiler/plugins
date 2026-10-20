package handlers

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/textfilter"
)

// FinalTextFilters clean the final text of an answer (CompleteResp.text,
// Finished.text) — never the deltas, so a stream stays as fast as the model
// and a caller swaps the streamed text for the clean one at the end. Which
// filters run is the activation's (the `final_text_*` features); a call may
// allow other scripts or opt out (pb.FinalText).
//
// The zero value filters nothing.
type FinalTextFilters struct {
	// Scripts is the `final_text_scripts` filter with the activation's
	// allowed scripts; nil when the feature is off.
	Scripts *textfilter.Scripts
	// Invisible is the `final_text_invisible` filter.
	Invisible bool
}

// chain is the filters a call runs: the activation's, with the call's
// scripts instead when it names some. The call's options are checked here,
// before the model is called, so a call the filters would refuse costs
// nothing: an unknown script is InvalidArgument, scripts named to an
// activation that does not filter scripts FailedPrecondition.
func (f FinalTextFilters) chain(opt *pb.FinalText) (textfilter.Chain, error) {
	if opt.GetRaw() {
		return nil, nil
	}
	var c textfilter.Chain
	if f.Invisible {
		c = append(c, textfilter.Invisible{})
	}
	scripts := f.Scripts
	if names := opt.GetAllowedScripts(); len(names) > 0 {
		if scripts == nil {
			return nil, status.Error(codes.FailedPrecondition,
				"final_text.allowed_scripts names scripts, but this activation does not filter them: switch on the agent plugin's `final_text_scripts` feature, or leave allowed_scripts empty")
		}
		s, err := textfilter.NewScripts(names)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "final_text.allowed_scripts: "+err.Error())
		}
		scripts = s
	}
	if scripts != nil {
		c = append(c, scripts)
	}
	return c, nil
}
