package handlers

import (
	"context"
	"strings"
	"testing"

	gen "github.com/wandering-compiler/plugins/agent/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A scope longer than the column is refused before anything is spent: it
// used to be served, never capped and never billed.
func TestAdmitSpend_RefusesAScopeOrLabelLongerThanItsColumn(t *testing.T) {
	h := &AgentServiceHandler{Limits: allowAllLimiter{}}
	if err := h.admitSpend(context.Background(), strings.Repeat("é", MaxUsageScopeLen), map[string]string{strings.Repeat("k", MaxUsageLabelKeyLen): strings.Repeat("v", MaxUsageLabelValueLen)}); err != nil {
		t.Fatalf("a %d-character scope was refused: %v", MaxUsageScopeLen, err)
	}
	for name, labels := range map[string]map[string]string{
		"key":   {strings.Repeat("k", MaxUsageLabelKeyLen+1): "v"},
		"value": {"k": strings.Repeat("v", MaxUsageLabelValueLen+1)},
	} {
		if err := h.admitSpend(context.Background(), "s", labels); status.Code(err) != codes.InvalidArgument {
			t.Errorf("label %s too long: err = %v, want InvalidArgument", name, err)
		}
	}
	err := h.admitSpend(context.Background(), strings.Repeat("a", MaxUsageScopeLen+1), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err = %v, want InvalidArgument", err)
	}
}

// With usage_persistence on, an allow-all limiter is a wiring defect and
// refuses the boot.
func TestVerifyLimiterWiring(t *testing.T) {
	err := VerifyLimiterWiring(allowAllLimiter{})
	if gen.FeatureUsagePersistence && err == nil {
		t.Error("the allow-all limiter booted with usage_persistence on")
	}
	if err := VerifyLimiterWiring(&dbLimiter{}); err != nil {
		t.Errorf("the database limiter was refused: %v", err)
	}
}
