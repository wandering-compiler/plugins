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
)

// sinks are the calls that put a sentence in front of a person, and the
// argument that sentence is: grpcerr.ForUser / ForUserWith (userMsgid),
// grpcerr.OnEmpty (userMsgid), i18n.T (msgid) — and a struct literal's
// `userMsg:` field, the auth plugin's own channel to the same detail — and
// any function of the plugin's own package whose parameter is named one of
// msgParams (a local helper like auth's refusal(ctx, …, msgid, …)).
//
// A sentence passed to one of them that is NOT a //w17:msgid constant reaches
// a person and no catalog: English in every locale, and nothing reports it.
// This is the other half of the manifest gate — that one keeps the marked set
// and plugin.yaml in step; this one keeps every user sentence in the marked
// set.
var sinks = map[string]map[string]int{
	"grpcerr": {"ForUser": 5, "ForUserWith": 5, "OnEmpty": 10},
	"i18n":    {"T": 1},
}

// unmarkedSentences walks the plugin's Go, one package (directory) at a time,
// and reports every sink argument that is a string literal, or a constant of
// the same package that is not marked. Anything else — a variable, a struct
// field, a parameter, another package's constant — is a value this cannot
// follow statically and is let through: the sentence was written where it is
// declared, and that declaration is what the marker is checked on.
func unmarkedSentences(root string) ([]string, error) {
	pkgs := map[string][]string{}
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
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			pkgs[filepath.Dir(path)] = append(pkgs[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(pkgs))
	for d := range pkgs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	var out []string
	for _, d := range dirs {
		found, err := unmarkedInPackage(pkgs[d])
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

// msgParams are the parameter names that mark a local helper's argument as
// a sentence for a person.
var msgParams = map[string]bool{"msgid": true, "userMsgid": true, "userMsg": true}

func unmarkedInPackage(paths []string) ([]string, error) {
	fset := token.NewFileSet()
	var files []*ast.File
	marked, consts := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		files = append(files, f)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				isMarked := hasMarker(gd.Doc) || hasMarker(vs.Doc) || hasMarker(vs.Comment)
				for _, n := range vs.Names {
					if gd.Tok == token.CONST {
						consts[n.Name] = true
					}
					if isMarked {
						marked[n.Name] = true
					}
				}
			}
		}
	}
	// The package's own helpers that take a sentence, by name → arg index.
	local := map[string]int{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Type.Params == nil {
				continue
			}
			i := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					i++
					continue
				}
				for _, n := range names {
					if msgParams[n.Name] {
						local[fd.Name.Name] = i
					}
					i++
				}
			}
		}
	}
	var out []string
	check := func(arg ast.Expr, fn string) {
		where := fset.Position(arg.Pos()).String()
		switch a := arg.(type) {
		case *ast.BasicLit:
			if a.Kind == token.STRING {
				out = append(out, fmt.Sprintf("%s: %s is given the sentence %s as a literal — declare it as a //%s constant", where, fn, a.Value, marker))
			}
		case *ast.Ident:
			if consts[a.Name] && !marked[a.Name] {
				out = append(out, fmt.Sprintf("%s: %s is given %s, a constant not marked //%s", where, fn, a.Name, marker))
			}
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "userMsg" {
					check(kv.Value, "userMsg:")
				}
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				if idx, ok := local[id.Name]; ok && idx < len(call.Args) {
					check(call.Args[idx], id.Name)
				}
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			idx, ok := sinks[pkg.Name][sel.Sel.Name]
			if !ok || idx >= len(call.Args) {
				return true
			}
			check(call.Args[idx], pkg.Name+"."+sel.Sel.Name)
			return true
		})
	}
	return out, nil
}
