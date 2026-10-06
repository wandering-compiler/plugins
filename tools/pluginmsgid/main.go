// Command pluginmsgid keeps a plugin's declared msgids and its Go in step.
//
// # Why a plugin declares anything at all
//
// A project's translatable strings are HARVESTED: validation defaults, enum
// labels, format literals and the runtime error vocabulary are all read at
// codegen time, on the console, out of proto descriptors or out of sdk/go.
// Every one of those is a source the compiler owns.
//
// A plugin's are not. Its handlers are compiled into the CONSUMER's binary and
// the console never runs them, so a sentence written in a plugin reaches no
// catalog and renders in English for every language a project declares — with
// nothing anywhere reporting it. `plugin.yaml`'s `msgids:` is how that set
// becomes visible to codegen.
//
// # Why this program exists
//
// Because the sentence now exists twice, and a second copy without a gate is
// not a detail to tidy later; it IS the defect, deferred. This repo spent one
// week on three of them — a certificate pin written three times, an error
// sentence written twice, feature constants drifted from their manifest.
//
// So the Go is the source of truth and the manifest is a mirror, exactly like
// the frozen locale table's Go → TS copies and their `cmp` gate. A plugin
// marks each user-facing sentence:
//
//	//w17:msgid
//	const MsgInvalidCredentials = "Wrong email or password."
//
// `-write` copies the marked set into `plugin.yaml`; the default `-check`
// fails when the two disagree, in EITHER direction — a sentence added to Go
// and never declared is invisible to translators, and one left in the manifest
// after the Go was reworded is a msgid translators are working on that nothing
// will ever look up.
//
// Usage:
//
//	pluginmsgid [-write] <plugin-dir>...
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// marker is the comment that makes a string constant translatable.
//
// A comment rather than a naming convention or a registry call: it is visible
// at the declaration, it cannot be true of a name by accident, and — unlike a
// registry — it needs nothing to RUN, which is the whole constraint (the
// console cannot execute a plugin's Go).
const marker = "w17:msgid"

func main() {
	write := flag.Bool("write", false, "rewrite each plugin.yaml's msgids: from the Go")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: pluginmsgid [-write] <plugin-dir>...")
		os.Exit(2)
	}
	failed := false
	for _, dir := range flag.Args() {
		if err := run(dir, *write); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", dir, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func run(dir string, write bool) error {
	if st, err := os.Stat(filepath.Join(dir, "plugin.yaml")); err != nil || st.IsDir() {
		return fmt.Errorf("not a plugin directory (no plugin.yaml)")
	}
	declared, err := fromGo(filepath.Join(dir, "src"))
	if err != nil {
		return err
	}
	yamlPath := filepath.Join(dir, "plugin.yaml")
	body, err := os.ReadFile(yamlPath)
	if err != nil {
		return err
	}
	mirrored, err := fromYAML(body)
	if err != nil {
		return err
	}

	if write {
		updated, err := rewrite(string(body), declared)
		if err != nil {
			return err
		}
		if updated == string(body) {
			return nil
		}
		return os.WriteFile(yamlPath, []byte(updated), 0o644)
	}

	missing := difference(declared, mirrored)
	stale := difference(mirrored, declared)
	if len(missing) == 0 && len(stale) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "plugin.yaml msgids: has drifted from the plugin's Go\n")
	for _, m := range missing {
		fmt.Fprintf(&b, "  + %s\n      in the Go, declared nowhere — no translator will ever see it\n", strconv.Quote(m))
	}
	for _, m := range stale {
		fmt.Fprintf(&b, "  - %s\n      declared, but no //%s constant has that value — translators are\n"+
			"      working on a string nothing looks up\n", strconv.Quote(m), marker)
	}
	fmt.Fprintf(&b, "  fix: make plugin-msgids-sync (the Go is the source of truth)")
	return fmt.Errorf("%s", b.String())
}

// fromGo collects the value of every string constant or variable marked with
// the magic comment, anywhere under the plugin's source tree.
//
// Test files and the generated tree are skipped: `gen/` is machine-written and
// a sentence only a test knows is not on anybody's wire.
func fromGo(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == root {
				return nil // proto-only plugin: no Go at all
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
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return fmt.Errorf("%s: %w", path, perr)
		}
		found, merr := markedIn(fset, f)
		if merr != nil {
			return merr
		}
		out = append(out, found...)
		return nil
	})
	return dedupeSorted(out), err
}

// markedIn reads one file's marked declarations.
//
// The marker is honoured on the GenDecl (a whole `const (…)` block) and on an
// individual spec inside one, because both read naturally and a rule that
// accepted only one of them would silently ignore the other spelling — which
// is the same "declared nowhere" failure this program exists to catch.
//
// A MARKED DECLARATION THAT IS NOT A PLAIN STRING LITERAL IS AN ERROR, not
// something to skip past. `const Msg = "Wrong " + "password."` is a perfectly
// good Go constant and its value never reaches a manifest, so skipping it let
// an empty `msgids:` pass the gate while the plugin emitted the sentence —
// silence exactly where this program is supposed to speak (caught in review
// on PR #10).
//
// Refused rather than evaluated. Every gettext extractor in existence wants a
// literal for the same reason: a msgid assembled at compile time is one nobody
// can grep for, and the next step after folding constants is somebody writing
// fmt.Sprintf and expecting it to work.
func markedIn(fset *token.FileSet, f *ast.File) ([]string, error) {
	var out []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		blockMarked := hasMarker(gd.Doc)
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if !blockMarked && !hasMarker(vs.Doc) && !hasMarker(vs.Comment) {
				continue
			}
			if len(vs.Values) == 0 {
				// A marked name with no value: an iota-style const, or a var
				// assigned elsewhere. Nothing to mirror, and saying so beats
				// leaving the author wondering why it never appeared.
				return nil, fmt.Errorf("%s: %s is marked //%s but has no value",
					fset.Position(vs.Pos()), names(vs), marker)
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return nil, fmt.Errorf(
						"%s: %s is marked //%s but is not a plain string literal\n"+
							"  a msgid assembled from expressions cannot be mirrored into "+
							"plugin.yaml,\n  and a translator cannot grep for it — write the "+
							"whole sentence as one literal",
						fset.Position(v.Pos()), names(vs), marker)
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", fset.Position(v.Pos()), err)
				}
				if s == "" {
					return nil, fmt.Errorf("%s: %s is marked //%s but is empty",
						fset.Position(v.Pos()), names(vs), marker)
				}
				out = append(out, s)
			}
		}
	}
	return out, nil
}

func names(vs *ast.ValueSpec) string {
	parts := make([]string, 0, len(vs.Names))
	for _, n := range vs.Names {
		parts = append(parts, n.Name)
	}
	return strings.Join(parts, ", ")
}

func hasMarker(g *ast.CommentGroup) bool {
	if g == nil {
		return false
	}
	for _, c := range g.List {
		if strings.Contains(c.Text, marker) {
			return true
		}
	}
	return false
}

// fromYAML reads the declared set with a real parser.
//
// READING and WRITING go different ways on purpose. Reading has to accept
// whatever valid YAML a person wrote — `['stale']`, a bare scalar, a folded
// string — because the gate's job is to compare what the file MEANS. The first
// version matched only the quoted block form this tool emits, so a manifest
// written any other way parsed as empty and a stale entry sailed through the
// two-way check that is the whole point (caught in review on PR #10).
//
// Writing stays textual, and that is not laziness: plugin.yaml is hand-written
// and full of comments carrying the reasoning for every field, so a round trip
// through a marshaller would strip them — a gate meant to protect the manifest
// becoming the thing that guts it.
func fromYAML(body []byte) ([]string, error) {
	var doc struct {
		Msgids []string `yaml:"msgids"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("plugin.yaml: %w", err)
	}
	return dedupeSorted(doc.Msgids), nil
}

// rewrite replaces the msgids: block, or appends one.
//
// The block it owns is: the generated header above `msgids:` (if one is
// already there), the key, and the indented items under it — and NOTHING
// else. Both bounds were wrong in the first version, in opposite directions.
//
// The lower bound swallowed every comment after the key, so a plugin that kept
// `msgids:` above another field lost that field's documentation on the next
// sync — the sync command eating manifest comments, which is precisely what
// the textual rewrite exists to avoid.
//
// The upper bound did not reach the generated header, so each run inserted a
// fresh one and left the old, and `-write -write` grew a header per run.
// A sync that is not idempotent is a sync nobody can put in a pre-commit hook.
func rewrite(body string, msgids []string) (string, error) {
	block := renderBlock(msgids)
	lines := strings.Split(body, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "msgids:") {
			start = i
			break
		}
	}
	if start < 0 {
		if len(msgids) == 0 {
			return body, nil
		}
		trimmed := strings.TrimRight(body, "\n")
		return trimmed + "\n\n" + block, nil
	}

	// Reach back over a header WE wrote, so it is replaced rather than
	// accumulated. A hand-written comment above msgids: is left alone: the run
	// has to carry the generated marker to be claimed.
	head := start
	for head > 0 && strings.HasPrefix(lines[head-1], "#") {
		head--
	}
	if head < start && !containsGeneratedMarker(lines[head:start]) {
		head = start
	}

	// The items, and only the items. A blank line, an unindented comment or
	// the next key all end the block.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "- ") {
			continue
		}
		end = i
		break
	}

	rebuilt := append([]string{}, lines[:head]...)
	if len(msgids) > 0 {
		rebuilt = append(rebuilt, strings.Split(strings.TrimRight(block, "\n"), "\n")...)
	} else {
		// Dropping the last msgid drops the block; a stray blank line where it
		// used to be would make the sync show up in every later diff.
		for end < len(lines) && strings.TrimSpace(lines[end]) == "" {
			end++
		}
	}
	rebuilt = append(rebuilt, lines[end:]...)
	return strings.Join(rebuilt, "\n"), nil
}

const generatedMarker = "GENERATED by `make plugin-msgids-sync`"

func containsGeneratedMarker(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, generatedMarker) {
			return true
		}
	}
	return false
}

func renderBlock(msgids []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — do not hand-edit.\n", generatedMarker)
	b.WriteString("#\n")
	b.WriteString("# The user-facing sentences this plugin's Go puts on the wire, mirrored here\n")
	b.WriteString("# so codegen can put them in a project's .po. The SOURCE is the Go constant\n")
	b.WriteString("# marked `//w17:msgid`; `make check-plugin-msgids` fails when the two drift.\n")
	b.WriteString("msgids:\n")
	for _, m := range msgids {
		fmt.Fprintf(&b, "  - %s\n", strconv.Quote(m))
	}
	return b.String()
}

func dedupeSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func difference(a, b []string) []string {
	have := map[string]struct{}{}
	for _, s := range b {
		have[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := have[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
