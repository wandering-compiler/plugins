package main

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// stagedImportRoots are the modules a consumer's bundle requires whatever the
// plugin: its go.mod names these and the plugin's own module, nothing else.
var stagedImportRoots = []string{
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
	"github.com/wandering-compiler/sdk/go",
}

// checkStagedImports reports a module a STAGED file imports that the consumer's
// bundle does not require.
//
// handlers/ and gen/ are copied into the consumer's bundle module; lib/ stays
// in the plugin's own module, which the bundle requires and resolves through
// the plugin's go.mod. So a third-party package imported from lib/ arrives
// with the plugin, and the same import in a staged file is a package of the
// bundle's own module that its go.mod never names: "imports X from implicitly
// required module", in every consumer build. Here the author's module requires
// it and everything compiles. (auth 0.1.0-rc.50 shipped that way: age imported
// from handlers/.)
func checkStagedImports(dir string) error {
	own := goModulePath(filepath.Join(dir, "src", "go.mod"))
	var problems []string
	for _, sub := range []string{"handlers", "gen"} {
		root := filepath.Join(dir, "src", sub)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) && path == root {
					return nil
				}
				return err
			}
			rel, _ := filepath.Rel(filepath.Join(dir, "src"), path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				// The author's local pb stubs are never staged (the bundle
				// has its own), nor is anything under testdata.
				if rel == "gen/pb" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if !bundleResolves(p, own) {
					problems = append(problems, fmt.Sprintf("  %s imports %s", rel, p))
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("a staged file imports a module the consumer's bundle does not require:\n%s\n\n"+
		"  handlers/ and gen/ are copied INTO the consumer's bundle, whose go.mod requires\n"+
		"  only %s and this plugin's module.\n"+
		"  The build there fails with \"imports ... from implicitly required module\";\n"+
		"  here it compiles, because this module requires it.\n\n"+
		"  fix: put the code that uses it in a package under lib/ — lib/ stays in this\n"+
		"  plugin's module, so the bundle reaches it, and its requirements, through\n"+
		"  the plugin.",
		strings.Join(problems, "\n"), strings.Join(stagedImportRoots, ", "))
}

// bundleResolves reports whether a consumer's bundle resolves an import path:
// the standard library, a module every bundle requires, or the plugin's own.
func bundleResolves(p, own string) bool {
	if first, _, _ := strings.Cut(p, "/"); !strings.Contains(first, ".") {
		return true
	}
	roots := stagedImportRoots
	if own != "" {
		roots = append(append([]string(nil), roots...), own)
	}
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// goModulePath is the module a go.mod declares, or "" without one.
func goModulePath(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if m, ok := strings.CutPrefix(strings.TrimSpace(s.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(m), `"`)
		}
	}
	return ""
}
