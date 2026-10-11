package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// # A statement that names a column some activations do not have
//
// The same failure as a Go reference across a feature boundary, one layer
// down. A feature can add a COLUMN to a table (`plugin_feature_field` on a
// model field), and an activation without that feature gets the table without
// it. A statement in an rpc staged for that activation which names the column
// fails the consumer's code generation — and only that combination's.
//
// A statement may name a feature's column when the rpc is staged only with the
// feature (its own feature is it, or `requires` it), or behind a
// `?feature(<it>)` gate on the item that names it. Everything else is reported.
//
// It reads the protos as text, not through a DQL parser: it splits each
// statement into items at commas, AND/OR and clause keywords, and looks for the
// column's name as a word. A parameter (`:col`) and a projection target
// (`AS x.col`) are not column references and are skipped. A name that another
// table in the same statement also has, ungated, is skipped as ambiguous.

var (
	reMessage    = regexp.MustCompile(`(?m)^message (\w+) \{`)
	reField      = regexp.MustCompile(`(?s)^\s*(?:repeated\s+|optional\s+)?[\w.]+\s+(\w+)\s*=\s*\d+\s*(\[.*)?$`)
	reFieldGate  = regexp.MustCompile(`plugin_feature_field\)\s*=\s*"(\w+)"`)
	reRPC        = regexp.MustCompile(`(?m)^\s*rpc (\w+)\(`)
	reRPCGate    = regexp.MustCompile(`plugin_feature_rpc\)\s*=\s*"(\w+)"`)
	reDQL        = regexp.MustCompile(`dql:\s*((?:"(?:[^"\\]|\\.)*"\s*)+)`)
	reLiteral    = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	reTable      = regexp.MustCompile(`@module\.(\w+)`)
	reItemSplit  = regexp.MustCompile(`(?i),|\bAND\b|\bOR\b|\bWHERE\b|\bSET\b|\bRETURNING\b|\bSELECT\b|\bFROM\b|\bJOIN\b|\bON\b`)
	reLineCommnt = regexp.MustCompile(`(?m)//.*$`)
)

type tableCols struct {
	gated   map[string]string // column -> feature
	ungated map[string]bool
}

// checkDQLColumns reports statements naming a feature-gated column from an
// rpc that can be staged without that feature, ungated.
func checkDQLColumns(dir string, requires map[string][]string) error {
	var protos []string
	if err := filepath.WalkDir(filepath.Join(dir, "proto"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".proto") {
			protos = append(protos, p)
		}
		return nil
	}); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	tables := map[string]*tableCols{}
	type rpc struct{ file, name, feature, dql string }
	var rpcs []rpc
	for _, p := range protos {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := reLineCommnt.ReplaceAllString(string(raw), "")
		for _, m := range reMessage.FindAllStringSubmatchIndex(src, -1) {
			body := block(src, m[1]-1) // m[1] is just past the message's `{`
			if !strings.Contains(body, "(w17.db.table)") {
				continue
			}
			t := &tableCols{gated: map[string]string{}, ungated: map[string]bool{}}
			for _, stmt := range strings.Split(body, ";") {
				f := reField.FindStringSubmatch(stmt)
				if f == nil {
					continue
				}
				if g := reFieldGate.FindStringSubmatch(stmt); g != nil {
					t.gated[f[1]] = g[1]
				} else {
					t.ungated[f[1]] = true
				}
			}
			tables[src[m[2]:m[3]]] = t
		}
		for _, m := range reRPC.FindAllStringSubmatchIndex(src, -1) {
			body := block(src, m[1])
			r := rpc{file: p, name: src[m[2]:m[3]]}
			if g := reRPCGate.FindStringSubmatch(body); g != nil {
				r.feature = g[1]
			}
			for _, d := range reDQL.FindAllStringSubmatch(body, -1) {
				for _, lit := range reLiteral.FindAllStringSubmatch(d[1], -1) {
					r.dql += lit[1]
				}
				r.dql += "\n"
			}
			if r.dql != "" {
				rpcs = append(rpcs, r)
			}
		}
	}

	var problems []string
	for _, r := range rpcs {
		reach := map[string]bool{}
		if r.feature != "" {
			for _, f := range closure(requires, []string{r.feature}) {
				reach[f] = true
			}
		}
		named := map[string]bool{}
		for _, t := range reTable.FindAllStringSubmatch(r.dql, -1) {
			named[t[1]] = true
		}
		for tname := range named {
			t := tables[tname]
			if t == nil {
				continue
			}
			for col, feature := range t.gated {
				if reach[feature] || ambiguous(col, tname, named, tables) {
					continue
				}
				for _, item := range reItemSplit.Split(r.dql, -1) {
					if namesColumn(item, col) && !strings.Contains(item, "?feature("+feature+")") {
						problems = append(problems, fmt.Sprintf("  %s rpc %s (%s)\n      names %s.%s (added by %s): %q",
							rel(dir, r.file), r.name, stagedWith(r.feature), tname, col, feature, strings.TrimSpace(item)))
						break
					}
				}
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("a statement names a column that some activations do not have:\n%s\n\n"+
		"  An activation with the rpc's feature but without the column's stages the\n"+
		"  table without the column, and its code generation fails on the statement.\n\n"+
		"  fix: gate the item that names it — `?feature(<column's feature>) <item>` —\n"+
		"  or move the statement to an rpc staged only with that feature.",
		strings.Join(problems, "\n"))
}

// block returns the text from just after an opening brace at or after `from`
// to its matching close.
func block(src string, from int) string {
	open := strings.IndexByte(src[from:], '{')
	if open < 0 {
		return ""
	}
	depth, start := 0, from+open
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start+1 : i]
			}
		}
	}
	return src[start+1:]
}

// namesColumn reports whether item names col as a column: as a word, not as a
// `:col` parameter and not as an `AS …col` projection target.
func namesColumn(item, col string) bool {
	re := regexp.MustCompile(`(^|[^\w:.])(\w+\.)?` + regexp.QuoteMeta(col) + `\b`)
	for _, loc := range re.FindAllStringIndex(item, -1) {
		before := strings.TrimRight(strings.ToUpper(item[:loc[0]+1]), " ")
		if strings.HasSuffix(before, " AS") || strings.HasSuffix(before, "AS") && len(before) == 2 {
			continue
		}
		return true
	}
	return false
}

func ambiguous(col, table string, named map[string]bool, tables map[string]*tableCols) bool {
	for other := range named {
		if other != table && tables[other] != nil && tables[other].ungated[col] {
			return true
		}
	}
	return false
}

func stagedWith(feature string) string {
	if feature == "" {
		return "always staged"
	}
	return "staged with " + feature
}

func rel(dir, p string) string {
	if r, err := filepath.Rel(dir, p); err == nil {
		return r
	}
	return p
}
