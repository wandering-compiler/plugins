package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plugin writes a throwaway plugin tree and returns its directory.
func plugin(t *testing.T, manifest string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		p := filepath.Join(dir, "src", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("package handlers\n\n"+body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const twoFeatures = `
features:
  - name: alpha
    go_files:
      - handlers/alpha.go
  - name: beta
    go_files:
      - handlers/beta.go
`

// The failure this exists for: one feature's file naming another's symbol.
// Everything compiles in the author tree; the activation that enables beta
// without alpha is the one that breaks, and nobody tries it first.
func TestCheck_ARefusalAcrossTwoIndependentFeatures(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/alpha.go": "func shared() {}",
		"handlers/beta.go":  "func useIt() { shared() }",
	})
	err := check(dir)
	if err == nil {
		t.Fatal("a cross-feature reference was accepted")
	}
	if !strings.Contains(err.Error(), "shared") {
		t.Errorf("the message does not name the symbol: %v", err)
	}
}

// An always-staged file may not lean on a gated one either — that is the
// payment plugin's shape, where two helpers sat in a `prepaid` file and were
// called from the always-staged service.
func TestCheck_AnAlwaysStagedFileMayNotUseAGatedSymbol(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/alpha.go":   "func shared() {}",
		"handlers/service.go": "func always() { shared() }",
	})
	if err := check(dir); err == nil {
		t.Fatal("an always-staged file leaned on a feature's symbol and was accepted")
	}
}

// And the other direction is fine: a gated file may use always-staged symbols,
// which is what the whole seam pattern relies on.
func TestCheck_AGatedFileMayUseAlwaysStagedSymbols(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/service.go": "var seam = func() {}",
		"handlers/alpha.go":   "func init() { seam = func() {} }",
	})
	if err := check(dir); err != nil {
		t.Errorf("the seam pattern was refused: %v", err)
	}
}

// `requires` is the legitimate escape, and it is TRANSITIVE: a feature that
// requires B is staged only when B is, so it may use whatever B may use.
//
// Getting this wrong in either direction is costly — too strict and every
// plugin with a requires chain is permanently red, too loose and the gate
// stops catching anything.
func TestCheck_RequiresIsHonouredAndTransitive(t *testing.T) {
	const chain = `
features:
  - name: base
    go_files:
      - handlers/base.go
  - name: middle
    requires:
      - base
    go_files:
      - handlers/middle.go
  - name: top
    requires:
      - middle
    go_files:
      - handlers/top.go
`
	dir := plugin(t, chain, map[string]string{
		"handlers/base.go":   "func fromBase() {}",
		"handlers/middle.go": "func fromMiddle() { fromBase() }",
		"handlers/top.go":    "func useBoth() { fromBase(); fromMiddle() }",
	})
	if err := check(dir); err != nil {
		t.Errorf("a requires chain was refused: %v", err)
	}
}

// And requires does not work backwards: base may not use what middle declares.
func TestCheck_RequiresDoesNotRunBackwards(t *testing.T) {
	const chain = `
features:
  - name: base
    go_files:
      - handlers/base.go
  - name: middle
    requires:
      - base
    go_files:
      - handlers/middle.go
`
	dir := plugin(t, chain, map[string]string{
		"handlers/base.go":   "func fromBase() { fromMiddle() }",
		"handlers/middle.go": "func fromMiddle() {}",
	})
	if err := check(dir); err == nil {
		t.Fatal("base used middle's symbol and was accepted — requires points one way")
	}
}

// A plugin with no features at all is not an error.
func TestCheck_APluginWithNoFeaturesPasses(t *testing.T) {
	dir := plugin(t, "name: p\n", map[string]string{
		"handlers/a.go": "func x() {}",
		"handlers/b.go": "func y() { x() }",
	})
	if err := check(dir); err != nil {
		t.Errorf("an ungated plugin was refused: %v", err)
	}
}

const combined = `
features:
  - name: alpha
    go_files:
      - handlers/alpha.go
  - name: beta
    go_files:
      - handlers/beta.go
go_files_combined:
  - features: [alpha, beta]
    files:
      - handlers/both.go
`

// A combined file is staged only when alpha AND beta are, so it may use the
// symbols of both — the reason go_files_combined exists.
func TestCheck_ACombinedFileMayUseEveryOneOfItsFeatures(t *testing.T) {
	dir := plugin(t, combined, map[string]string{
		"handlers/alpha.go": "func fromAlpha() {}",
		"handlers/beta.go":  "func fromBeta() {}",
		"handlers/both.go":  "func useBoth() { fromAlpha(); fromBeta() }",
	})
	if err := check(dir); err != nil {
		t.Errorf("a combined file using its own features' symbols was refused: %v", err)
	}
}

// …and nothing may lean on IT: an activation with alpha alone stages
// alpha.go without both.go.
func TestCheck_NoFileMayUseACombinedFilesSymbol(t *testing.T) {
	dir := plugin(t, combined, map[string]string{
		"handlers/alpha.go": "func fromAlpha() { onlyWithBoth() }",
		"handlers/beta.go":  "func fromBeta() {}",
		"handlers/both.go":  "func onlyWithBoth() {}",
	})
	err := check(dir)
	if err == nil || !strings.Contains(err.Error(), "only with all of alpha, beta") {
		t.Errorf("a feature file using a combined file's symbol must be refused, naming the combination: %v", err)
	}
}

// A combination staged in every build another is — [alpha, beta] wherever
// [alpha, beta, gamma] is — is in reach of it; and [beta, alpha] is the same
// condition as [alpha, beta] (review of #139).
func TestCheck_ACombinationMayUseASubsetCombination(t *testing.T) {
	dir := plugin(t, `
features:
  - {name: alpha}
  - {name: beta}
  - {name: gamma}
go_files_combined:
  - {features: [alpha, beta], files: [handlers/ab.go]}
  - {features: [gamma, beta, alpha], files: [handlers/abc.go]}
  - {features: [beta, alpha, gamma], files: [handlers/abc2.go]}
`, map[string]string{
		"handlers/ab.go":   "func fromAB() {}",
		"handlers/abc.go":  "func fromABC() { fromAB(); fromABC2() }",
		"handlers/abc2.go": "func fromABC2() {}",
	})
	if err := check(dir); err != nil {
		t.Errorf("a subset (or reordered) combination's symbols were refused: %v", err)
	}
	// …but not the other way: ab.go is staged without gamma, abc.go is not.
	dir = plugin(t, `
features:
  - {name: alpha}
  - {name: beta}
  - {name: gamma}
go_files_combined:
  - {features: [alpha, beta], files: [handlers/ab.go]}
  - {features: [alpha, beta, gamma], files: [handlers/abc.go]}
`, map[string]string{
		"handlers/ab.go":  "func fromAB() { fromABC() }",
		"handlers/abc.go": "func fromABC() {}",
	})
	if err := check(dir); err == nil {
		t.Error("a combination using a SUPERSET combination's symbol was accepted")
	}
}

// A combination's gate is the SET of its features, not a name joined from
// them: ["a+b", c] and [a, "b+c"] once both became "+a+b+c" and could use
// each other's symbols although they stage under different activations
// (Copilot on #139).
func TestCheck_TwoCombinationsWhoseNamesJoinAlikeAreDistinct(t *testing.T) {
	dir := plugin(t, `
features:
  - {name: a}
  - {name: "a+b"}
  - {name: b}
  - {name: "b+c"}
  - {name: c}
go_files_combined:
  - {features: ["a+b", c], files: [handlers/one.go]}
  - {features: [a, "b+c"], files: [handlers/two.go]}
`, map[string]string{
		"handlers/one.go": "func fromOne() { fromTwo() }",
		"handlers/two.go": "func fromTwo() {}",
	})
	if err := check(dir); err == nil {
		t.Error("a combination used a different combination's symbol because their names joined alike")
	}
}

// The requires closure holds under a combination too: gamma requires alpha,
// so [gamma, beta] is staged only where [alpha, beta] is (Copilot on #139).
func TestCheck_ACombinationReachesThroughRequires(t *testing.T) {
	dir := plugin(t, `
features:
  - {name: alpha}
  - {name: beta}
  - {name: gamma, requires: [alpha]}
go_files_combined:
  - {features: [alpha, beta], files: [handlers/ab.go]}
  - {features: [gamma, beta], files: [handlers/gb.go]}
`, map[string]string{
		"handlers/ab.go": "func fromAB() {}",
		"handlers/gb.go": "func fromGB() { fromAB() }",
	})
	if err := check(dir); err != nil {
		t.Errorf("[gamma, beta] guarantees [alpha, beta] when gamma requires alpha, and was refused: %v", err)
	}
	// …and a single feature that requires both may use the combination.
	dir = plugin(t, `
features:
  - {name: alpha}
  - {name: beta}
  - {name: delta, requires: [alpha, beta], go_files: [handlers/delta.go]}
go_files_combined:
  - {features: [alpha, beta], files: [handlers/ab.go]}
`, map[string]string{
		"handlers/ab.go":    "func fromAB() {}",
		"handlers/delta.go": "func fromDelta() { fromAB() }",
	})
	if err := check(dir); err != nil {
		t.Errorf("delta requires alpha and beta, so [alpha, beta] is staged wherever it is; refused: %v", err)
	}
}

// A file under two features' go_files stays while EITHER is on — the
// manifest's rule. pluginstage kept only the last owner, so a file of the
// FIRST feature was refused the shared file it is always staged with.
func TestCheck_AFileTwoFeaturesOwnIsStagedWithEither(t *testing.T) {
	dir := plugin(t, `
features:
  - {name: alpha, go_files: [handlers/alpha.go, handlers/shared.go]}
  - {name: beta,  go_files: [handlers/beta.go, handlers/shared.go]}
`, map[string]string{
		"handlers/alpha.go":  "func fromAlpha() { fromShared() }",
		"handlers/beta.go":   "func fromBeta() { fromShared() }",
		"handlers/shared.go": "func fromShared() {}",
	})
	if err := check(dir); err != nil {
		t.Errorf("each owner of a shared file is staged with it; refused: %v", err)
	}
	// …but the shared file may not use either owner's own file: with only
	// beta on, shared.go is staged and alpha.go is not.
	dir = plugin(t, `
features:
  - {name: alpha, go_files: [handlers/alpha.go, handlers/shared.go]}
  - {name: beta,  go_files: [handlers/shared.go]}
`, map[string]string{
		"handlers/alpha.go":  "func fromAlpha() {}",
		"handlers/shared.go": "func fromShared() { fromAlpha() }",
	})
	err := check(dir)
	if err == nil || !strings.Contains(err.Error(), "with any of alpha, beta") {
		t.Errorf("a file staged with either owner used one owner's file and must be refused, naming both: %v", err)
	}
}

// go_files_unless removes a file while its feature is ON. pluginstage read
// such a file as always staged, so an always-staged file could use it and
// every activation with the feature failed to build.
func TestCheck_AFileAFeatureRemovesIsNotAlwaysStaged(t *testing.T) {
	dir := plugin(t, `
features:
  - {name: alpha, go_files_unless: [handlers/baseline.go]}
`, map[string]string{
		"handlers/baseline.go": "func fromBaseline() { fromCore() }",
		"handlers/core.go":     "func fromCore() { fromBaseline() }",
	})
	err := check(dir)
	if err == nil || !strings.Contains(err.Error(), "handlers/core.go (always staged)") ||
		!strings.Contains(err.Error(), "unless alpha") {
		t.Errorf("an always-staged file used a file alpha removes, and must be refused; the baseline using it is fine: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "\n  handlers/baseline.go (") {
		t.Errorf("the baseline may use always-staged code; it was refused: %v", err)
	}
}

// Activations that cannot exist are not counterexamples: beta conflicts
// with alpha, so beta's file is never staged while alpha's veto applies.
func TestCheck_ConflictsWithRulesOutImpossibleActivations(t *testing.T) {
	manifest := func(conflict string) string {
		return `
features:
  - {name: alpha, go_files_unless: [handlers/baseline.go]}
  - {name: beta, go_files: [handlers/beta.go]` + conflict + `}
`
	}
	files := map[string]string{
		"handlers/baseline.go": "func fromBaseline() {}",
		"handlers/beta.go":     "func fromBeta() { fromBaseline() }",
	}
	if err := check(plugin(t, manifest(", conflicts_with: [alpha]"), files)); err != nil {
		t.Errorf("beta never runs with alpha, so the baseline is always there for it; refused: %v", err)
	}
	if err := check(plugin(t, manifest(""), files)); err == nil {
		t.Error("without the conflict, beta + alpha drops the baseline under beta.go — must be refused")
	}
}
