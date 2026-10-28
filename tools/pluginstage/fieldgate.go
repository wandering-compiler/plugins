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
	"unicode"
)

// fieldGetters maps a generated getter (GetMembershipKind) to the one feature
// every field behind it is gated on (plugin_feature_field), for the getters
// whose field is gated wherever it is declared. A field the same name
// declares ungated in another message — or gated on another feature — makes
// the getter ambiguous from source: the call site names the getter, not the
// message, so it is left out rather than guessed.
//
// This is the half the package doc called uncheckable: a feature's FIELD
// vanishes from a consumer's generated pb as its file does. auth's
// org_two_factor_policy read UserOrg.membership_kind (membership_kinds) and
// compiled here; the first consumer without membership_kinds did not build.
func fieldGetters(dir string) (map[string]string, error) {
	gated := map[string]map[string]bool{} // getter -> features
	ungated := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(dir, "proto"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".proto") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := reLineCommnt.ReplaceAllString(string(raw), "")
		for _, m := range reMessage.FindAllStringSubmatchIndex(src, -1) {
			msg := parseMessage(block(src, m[1]-1))
			for f, feature := range msg.gated {
				g := getterOf(f)
				if gated[g] == nil {
					gated[g] = map[string]bool{}
				}
				gated[g][feature] = true
			}
			for f := range msg.ungated {
				ungated[getterOf(f)] = true
			}
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]string{}
	for g, features := range gated {
		if ungated[g] || len(features) != 1 {
			continue
		}
		for f := range features {
			out[g] = f
		}
	}
	return out, nil
}

// getterOf is protoc-gen-go's getter for a field: Get + the CamelCase name.
func getterOf(field string) string {
	var b strings.Builder
	b.WriteString("Get")
	up := true
	for _, r := range field {
		if r == '_' {
			up = true
			continue
		}
		if up {
			b.WriteRune(unicode.ToUpper(r))
			up = false
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkGatedGetters reports a call of a feature-gated field's getter from a
// file that can be staged without that feature.
func checkGatedGetters(dir string, gates map[string]*stagedWhen, inReach func(from, decl *stagedWhen) bool) error {
	getters, err := fieldGetters(dir)
	if err != nil || len(getters) == 0 {
		return err
	}
	root := filepath.Join(dir, "src")
	var problems []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return fmt.Errorf("%s: %w", path, perr)
		}
		seen := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || seen[sel.Sel.Name] {
				return true
			}
			feature, gatedGetter := getters[sel.Sel.Name]
			if !gatedGetter {
				return true
			}
			seen[sel.Sel.Name] = true
			if !inReach(gates[rel], &stagedWhen{anyOf: []string{feature}}) {
				problems = append(problems, fmt.Sprintf("  %s (%s)\n      calls %s, a field only %s adds",
					rel, describe(gates[rel]), sel.Sel.Name, feature))
			}
			return true
		})
		return nil
	})
	if err != nil {
		return err
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("a field getter crosses a feature boundary and will not exist in every build:\n%s\n\n"+
		"  The field is generated only into an activation with its feature, so the call\n"+
		"  is an undefined method wherever the file stages without it.\n\n"+
		"  fix: read the field through a seam the feature's own file sets (a func var\n"+
		"  declared where both stage, assigned in the feature's init).",
		strings.Join(problems, "\n"))
}
