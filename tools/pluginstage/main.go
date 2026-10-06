// Command pluginstage catches a reference that will not exist in somebody's build.
//
// # The failure it looks for
//
// A plugin's features stage INDEPENDENTLY. `go_files:` lists the Go a feature
// brings, and an activation that leaves the feature off gets a tree without
// those files. Nothing in the author's own module notices: `go build` there
// sees every file at once, and every combination compiles.
//
// The first build that disagrees is a CONSUMER's. A symbol declared in one
// feature's file and referenced from another's is fine here and undefined
// there — and only for the activations that enable one without the other,
// which is the combination nobody happens to try first.
//
// It has already shipped twice. The agent plugin went out unusable because its
// author-side RegisterPlugin took two arguments while the bundle-side wiring
// called three, and on PR #11 an invitation gate declared in `org_invite.go`
// was assigned from `emailverify.go` — breaking every project that wanted to
// confirm addresses without using invitations, a combination that has nothing
// to do with either feature's purpose.
//
// # The rule
//
// A file may reference a symbol from a file that is staged whenever it is —
// in every activation `requires` and `conflicts_with` allow. Staging follows
// the manifest exactly: `go_files` keeps a file while ANY owning feature is
// on, `go_files_combined` only while ALL of its features are, and
// `go_files_unless` removes it while its feature is on, beating both. So an
// always-staged file may use only always-staged symbols; a feature's file may
// use its own feature's symbols, always-staged ones, and another feature's
// only when its own feature `requires` that one.
//
// The fix is never to add a `requires` edge that forces an unrelated feature
// on: a seam spans the features it joins, so it belongs in a file above both.
//
// # What it does NOT catch
//
// Proto FIELDS that a feature adds, which vanish from a consumer's generated
// pb the same way. Those need the pb to be regenerated per activation, which
// this cannot do from source. A consumer build is still the only full proof;
// this closes the half that is checkable from here.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type manifest struct {
	Features []struct {
		Name          string   `yaml:"name"`
		Requires      []string `yaml:"requires"`
		ConflictsWith []string `yaml:"conflicts_with"`
		GoFiles       []string `yaml:"go_files"`
		GoFilesUnless []string `yaml:"go_files_unless"`
	} `yaml:"features"`
	// GoFilesCombined: files staged only when EVERY listed feature is.
	GoFilesCombined []struct {
		Features []string `yaml:"features"`
		Files    []string `yaml:"files"`
	} `yaml:"go_files_combined"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pluginstage <plugin-dir>...")
		os.Exit(2)
	}
	failed := false
	for _, dir := range os.Args[1:] {
		if err := check(dir); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", dir, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func check(dir string) error {
	body, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		return err
	}
	var m manifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		return err
	}

	// When each file is staged — the same rule ExcludedHandlerFiles applies
	// (the w17 compiler's manifest parser), in all three of its parts.
	// It once modelled only a single owner per file: a path under two
	// features' go_files kept the LAST, though it stays while EITHER is on,
	// and go_files_unless was read as always staged, though an active feature
	// removes it.
	gates := map[string]*stagedWhen{}
	at := func(path string) *stagedWhen {
		path = filepath.ToSlash(path)
		if gates[path] == nil {
			gates[path] = &stagedWhen{}
		}
		return gates[path]
	}
	for _, f := range m.Features {
		for _, g := range f.GoFiles {
			at(g).anyOf = append(at(g).anyOf, f.Name)
		}
		for _, g := range f.GoFilesUnless {
			at(g).unless = append(at(g).unless, f.Name)
		}
	}
	// The gate is the feature SET itself, never a name built from it:
	// feature names are free text, and a joined encoding let ["a+b", c] and
	// [a, "b+c"] collide (review of #139).
	for _, c := range m.GoFilesCombined {
		for _, g := range c.Files {
			at(g).allOf = append([]string(nil), c.Features...)
		}
	}
	requires := map[string][]string{}
	conflicts := map[[2]string]bool{}
	for _, f := range m.Features {
		requires[f.Name] = f.Requires
		for _, c := range f.ConflictsWith {
			conflicts[[2]string{f.Name, c}] = true
			conflicts[[2]string{c, f.Name}] = true
		}
	}
	// A file may use a declaration that is staged in EVERY activation it is:
	// checked exactly, over every activation of the features either file's
	// rule names, plus what those `require` (transitively), honouring
	// `requires` and `conflicts_with`. Features outside that set cannot
	// change either answer. That covers each case the rule has had to learn
	// one at a time — requires, a combination using its own features, a
	// subset combination, the requires closure under a combination — and the
	// two it had not: a file several features own, and one a feature removes.
	inReach := func(from, decl *stagedWhen) bool {
		vars := closure(requires, from.features(), decl.features())
		if len(vars) > 20 {
			// 2^20 activations. No real pair is near it (auth, the largest
			// plugin, has 17 features in all); refuse rather than pass
			// what was not checked.
			return false
		}
		for bits := 0; bits < 1<<len(vars); bits++ {
			on := map[string]bool{}
			for i, v := range vars {
				on[v] = bits&(1<<i) != 0
			}
			if !valid(on, requires, conflicts) {
				continue
			}
			if from.staged(on) && !decl.staged(on) {
				return false
			}
		}
		return true
	}

	declIn, refs, err := scan(filepath.Join(dir, "src"))
	if err != nil {
		return err
	}

	var problems []string
	for from, used := range refs {
		fromGate := gates[from]
		for _, name := range used {
			declFile, ok := declIn[name]
			if !ok || declFile == from {
				continue
			}
			declGate := gates[declFile]
			if inReach(fromGate, declGate) {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"  %s (%s)\n      uses %s, declared in %s (%s)",
				from, describe(fromGate), name, declFile, describe(declGate)))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("a reference crosses a feature boundary and will not exist in every build:\n%s\n\n"+
		"  An activation that enables the first feature without the second stages the\n"+
		"  file on the left without the one on the right, and its bundle build fails on\n"+
		"  an undefined identifier. Everything compiles HERE because the author tree has\n"+
		"  every file at once.\n\n"+
		"  fix: move the shared declaration to a file no feature gates. Adding a\n"+
		"  `requires` edge also silences this, and is usually wrong — it forces an\n"+
		"  unrelated feature on every project that wanted only the other one.",
		strings.Join(problems, "\n"))
}

// stagedWhen is a file's staging rule; nil means always staged.
type stagedWhen struct {
	anyOf  []string // go_files: staged while ANY of these is active
	allOf  []string // go_files_combined: only when ALL of these are
	unless []string // go_files_unless: never while any of these is
}

func (w *stagedWhen) features() []string {
	if w == nil {
		return nil
	}
	return append(append(append([]string(nil), w.anyOf...), w.allOf...), w.unless...)
}

func (w *stagedWhen) staged(on map[string]bool) bool {
	if w == nil {
		return true
	}
	for _, f := range w.unless {
		if on[f] {
			return false
		}
	}
	if len(w.anyOf) == 0 && len(w.allOf) == 0 {
		return true
	}
	for _, f := range w.anyOf {
		if on[f] {
			return true
		}
	}
	if len(w.allOf) == 0 {
		return false
	}
	for _, f := range w.allOf {
		if !on[f] {
			return false
		}
	}
	return true
}

// closure is every named feature plus what it requires, transitively, sorted.
func closure(requires map[string][]string, sets ...[]string) []string {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(f string) {
		if seen[f] {
			return
		}
		seen[f] = true
		for _, r := range requires[f] {
			walk(r)
		}
	}
	for _, set := range sets {
		for _, f := range set {
			walk(f)
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// valid reports whether an activation could exist: every active feature's
// requirements are active, and no two active features conflict.
func valid(on map[string]bool, requires map[string][]string, conflicts map[[2]string]bool) bool {
	for f, active := range on {
		if !active {
			continue
		}
		for _, r := range requires[f] {
			if !on[r] {
				return false
			}
		}
		for g, alsoOn := range on {
			if alsoOn && conflicts[[2]string{f, g}] {
				return false
			}
		}
	}
	return true
}

func describe(w *stagedWhen) string {
	if w == nil {
		return "always staged"
	}
	sorted := func(xs []string) string {
		c := append([]string(nil), xs...)
		sort.Strings(c)
		return strings.Join(c, ", ")
	}
	var parts []string
	switch {
	case len(w.allOf) > 0:
		parts = append(parts, "only with all of "+sorted(w.allOf))
	case len(w.anyOf) == 1:
		parts = append(parts, "feature "+w.anyOf[0])
	case len(w.anyOf) > 1:
		parts = append(parts, "with any of "+sorted(w.anyOf))
	default:
		parts = append(parts, "staged")
	}
	if len(w.unless) > 0 {
		parts = append(parts, "unless "+sorted(w.unless))
	}
	return strings.Join(parts, " ")
}

// scan maps every package-level name to the file declaring it, and every file
// to the names it mentions.
//
// Mentions rather than resolved uses: a plain identifier walk over-reports
// nothing that matters here, because only names this package declares are ever
// looked up, and a shadowed local with the same name is a reference to think
// about anyway.
func scan(root string) (map[string]string, map[string][]string, error) {
	declIn := map[string]string{}
	refs := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == root {
				return nil
			}
			return err
		}
		if d.IsDir() {
			if d.Name() == "gen" || d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("%s: %w", path, perr)
		}
		for _, name := range topLevelNames(f) {
			declIn[name] = rel
		}
		seen := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && !seen[id.Name] {
				seen[id.Name] = true
				refs[rel] = append(refs[rel], id.Name)
			}
			return true
		})
		return nil
	})
	return declIn, refs, err
}

func topLevelNames(f *ast.File) []string {
	var out []string
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil {
				// A method belongs to its receiver's type, and that type's
				// file is what decides staging. Methods on an always-staged
				// type declared in a gated file ARE a real hazard, but the
				// call site names the receiver, not the file — out of scope
				// for the identifier walk and left to the consumer build.
				continue
			}
			if d.Name.Name != "init" {
				out = append(out, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.Name != "_" {
							out = append(out, n.Name)
						}
					}
				case *ast.TypeSpec:
					out = append(out, s.Name.Name)
				}
			}
		}
	}
	return out
}
