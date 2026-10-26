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

// # A statement that names something some activations do not have
//
// The same failure as a Go reference across a feature boundary, one layer
// down. A feature can add a TABLE (`plugin_feature` on a model message) or a
// COLUMN to a table (`plugin_feature_field` on a model field), and an
// activation without that feature gets no table, or the table without the
// column. A feature can also add a FIELD to an rpc's request, and a statement
// binding it as a `:param` has nothing to bind. A statement in an rpc staged
// for that activation which names any of them fails the consumer's code
// generation — and only that combination's.
//
// A statement may name a feature's table, column or request field when the
// rpc is staged only with the feature (its own feature — on the rpc, or
// inherited from the service — is it, or `requires` it). A column or a
// parameter may also be named behind a `?feature(<g>)` gate on the item that
// names it, where <g> is the feature or requires it. A table cannot be gated:
// DQL has no gated FROM or JOIN. Everything else is reported.
//
// It reads the protos as text, not through a DQL parser: it splits each
// statement into items at top-level commas, AND/OR and clause keywords (not
// inside parentheses, not at BETWEEN's AND or IS DISTINCT FROM's FROM), and
// looks for the column's name as a word. A parameter (`:col`) and a projection
// target (`AS x.col`) are not column references and are skipped. A reference
// qualified by an alias resolves through the statement's FROM / JOIN aliases;
// an unqualified name that another table in the same statement also has,
// ungated, is skipped as ambiguous.

var (
	reMessage     = regexp.MustCompile(`(?m)^message (\w+) \{`)
	reNested      = regexp.MustCompile(`(?m)^\s*(?:message|enum)\s+\w+\s*\{`)
	reField       = regexp.MustCompile(`(?s)^\s*(?:repeated\s+|optional\s+)?[\w.]+\s+(\w+)\s*=\s*\d+\s*(\[.*)?$`)
	reFieldGate   = regexp.MustCompile(`plugin_feature_field\)\s*=\s*"(\w+)"`)
	reMessageGate = regexp.MustCompile(`option\s+\(w17\.contrib\.plugin_feature\)\s*=\s*"(\w+)"`)
	reService     = regexp.MustCompile(`(?m)^service (\w+) \{`)
	reServiceGate = regexp.MustCompile(`plugin_feature_svc\)\s*=\s*"(\w+)"`)
	reRPC         = regexp.MustCompile(`(?m)^\s*rpc (\w+)\(\s*(?:stream\s+)?([\w.]+)\s*\)`)
	reRPCGate     = regexp.MustCompile(`plugin_feature_rpc\)\s*=\s*"(\w+)"`)
	reDQL         = regexp.MustCompile(`dql:\s*((?:"(?:[^"\\]|\\.)*"\s*)+)`)
	reLiteral     = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	reTable       = regexp.MustCompile(`@module\.(\w+)(?:\s+(?:(?i:AS)\s+)?(\w+))?`)
	reParam       = regexp.MustCompile(`(?:^|[^:\w]):(\w+)`)
	reItemGate    = regexp.MustCompile(`\?feature\((\w+)\)`)
	reLineCommnt  = regexp.MustCompile(`(?m)//.*$`)
)

// Words that end an item, and words that may follow a table name but are not
// its alias.
var (
	itemKeywords = setOf("AND", "OR", "WHERE", "SET", "RETURNING", "SELECT", "FROM", "JOIN", "ON",
		"GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET", "VALUES", "INTO", "USING")
	notAlias = setOf("WHERE", "SET", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "FULL", "CROSS", "ON",
		"GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET", "RETURNING", "VALUES", "USING", "UNION",
		"AS", "FOR", "NATURAL", "LATERAL")
)

func setOf(words ...string) map[string]bool {
	s := map[string]bool{}
	for _, w := range words {
		s[w] = true
	}
	return s
}

type message struct {
	feature string            // message-level gate; "" = staged whenever its file is
	table   bool              // a model: (w17.db.table)
	gated   map[string]string // field -> feature
	ungated map[string]bool
}

type dqlRPC struct {
	file, name, feature, req string
	stmts                    []string
}

// checkDQLColumns reports statements naming a feature-gated table, column or
// request field from an rpc that can be staged without that feature, ungated.
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

	messages := map[string]*message{}
	var rpcs []dqlRPC
	for _, p := range protos {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := reLineCommnt.ReplaceAllString(string(raw), "")
		for _, m := range reMessage.FindAllStringSubmatchIndex(src, -1) {
			body := block(src, m[1]-1) // m[1] is just past the message's `{`
			messages[src[m[2]:m[3]]] = parseMessage(body)
		}
		for _, s := range reService.FindAllStringSubmatchIndex(src, -1) {
			svc := block(src, s[1]-1)
			svcFeature := ""
			if g := reServiceGate.FindStringSubmatch(svc); g != nil {
				svcFeature = g[1]
			}
			for _, m := range reRPC.FindAllStringSubmatchIndex(svc, -1) {
				r := dqlRPC{file: p, name: svc[m[2]:m[3]], req: lastSegment(svc[m[4]:m[5]]), feature: svcFeature}
				body := rpcBody(svc, m[1])
				// A method-level tag overrides the service's.
				if g := reRPCGate.FindStringSubmatch(body); g != nil {
					r.feature = g[1]
				}
				for _, d := range reDQL.FindAllStringSubmatch(body, -1) {
					var stmt strings.Builder
					for _, lit := range reLiteral.FindAllStringSubmatch(d[1], -1) {
						stmt.WriteString(lit[1])
					}
					r.stmts = append(r.stmts, stmt.String())
				}
				if len(r.stmts) > 0 {
					rpcs = append(rpcs, r)
				}
			}
		}
	}

	var problems []string
	report := func(r dqlRPC, what, item string) {
		problems = append(problems, fmt.Sprintf("  %s rpc %s (%s)\n      %s: %q",
			rel(dir, r.file), r.name, stagedWith(r.feature), what, strings.TrimSpace(item)))
	}
	for _, r := range rpcs {
		reach := map[string]bool{}
		if r.feature != "" {
			for _, f := range closure(requires, []string{r.feature}) {
				reach[f] = true
			}
		}
		for _, stmt := range r.stmts {
			for _, bad := range misplacedGates(stmt) {
				report(r, "a ?feature gate where staging cannot resolve one — it may prefix a SET assignment, a RETURNING target, a SELECT projection target, or a top-level AND operand of an UPDATE / DELETE WHERE (dropping a conjunct of a SELECT's WHERE would return MORE rows)", bad)
			}
			named, alias := tablesOf(stmt)
			items := splitItems(stmt)
			for _, tname := range sortedKeys(named) {
				t := messages[tname]
				if t == nil {
					continue
				}
				if t.feature != "" && !reach[t.feature] {
					report(r, fmt.Sprintf("names table %s (added by %s)", tname, t.feature), stmt)
				}
				for _, col := range sortedKeys(t.gated) {
					feature := t.gated[col]
					if reach[feature] {
						continue
					}
					re := columnRef(col)
					for _, item := range items {
						if namesColumn(re, col, item, tname, alias, named, messages) && !gateCovers(item, feature, requires) {
							report(r, fmt.Sprintf("names %s.%s (added by %s)", tname, col, feature), item)
							break
						}
					}
				}
			}
			if req := messages[r.req]; req != nil {
				for _, item := range items {
					for _, pm := range reParam.FindAllStringSubmatch(item, -1) {
						feature, ok := req.gated[pm[1]]
						if !ok || reach[feature] || gateCovers(item, feature, requires) {
							continue
						}
						report(r, fmt.Sprintf("binds :%s, a field of %s added by %s", pm[1], r.req, feature), item)
					}
				}
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("a statement names a table, column or request field that some activations do not have, or gates an item where staging cannot cut it:\n%s\n\n"+
		"  An activation with the rpc's feature but without the other one stages the\n"+
		"  rpc without what it names, and its code generation fails on the statement.\n\n"+
		"  fix: gate the item that names a column or a parameter —\n"+
		"  `?feature(<its feature>) <item>` — or move the statement to an rpc staged\n"+
		"  only with that feature (a table cannot be gated: require its feature).",
		strings.Join(problems, "\n"))
}

// # A gate where staging cannot resolve one
//
// Staging resolves a `?feature(<g>)` gate by cutting the item it prefixes, and
// only four positions are cuttable: a SET assignment, a RETURNING target, a
// SELECT projection target, and a top-level AND operand of a mutation's
// (UPDATE / DELETE) WHERE. Anywhere else the consumer's code generation stops
// on the statement ("feature gate … is not in a position that can be gated").
// A SELECT's WHERE is the trap: the gate reads like a filter, but cutting it
// with the feature off would return more rows, so it is refused — filter in
// the handler on a gated projection instead. `w17ctl plugin gen` does not
// resolve gates, so nothing else here sees it; it shipped once in auth
// (CountOtherOrgSuperadmins) and failed the first consumer that staged it.

// misplacedGates returns the text around every gate of stmt that is not in one
// of the four positions.
func misplacedGates(stmt string) []string {
	var bad []string
	kind, clause, prev := "", "", ""
	depth := 0
	inQuote := false
	for i := 0; i < len(stmt); i++ {
		c := stmt[i]
		switch {
		case inQuote:
			if c == '\'' {
				inQuote = false
			}
		case c == '\'':
			inQuote = true
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == ',' && depth == 0:
			prev = ","
		case c == '?' && strings.HasPrefix(stmt[i:], "?feature("):
			legal := depth == 0 && (clause == "SET" || clause == "RETURNING" ||
				(clause == "SELECT" && kind == "SELECT") ||
				(clause == "WHERE" && (kind == "UPDATE" || kind == "DELETE") && (prev == "AND" || prev == "WHERE")))
			if !legal {
				from, to := max(0, i-40), min(len(stmt), i+60)
				bad = append(bad, stmt[from:to])
			}
			i += len("?feature(") - 1
			depth++ // the gate's own parenthesis
		case isWordByte(c) && (i == 0 || !isWordByte(stmt[i-1])):
			j := i
			for j < len(stmt) && isWordByte(stmt[j]) {
				j++
			}
			w := strings.ToUpper(stmt[i:j])
			if depth == 0 {
				if kind == "" {
					kind = w
				}
				switch w {
				case "SELECT", "FROM", "JOIN", "ON", "WHERE", "SET", "RETURNING", "GROUP", "ORDER",
					"HAVING", "LIMIT", "OFFSET", "VALUES", "INTO", "USING":
					clause = w
				}
				prev = w
			}
			i = j - 1
		}
	}
	return bad
}

// parseMessage reads a message body's gate and its fields. Nested messages
// and enums are cut out first: their bodies are not this message's fields,
// and the text after one would otherwise glue onto the next field.
func parseMessage(body string) *message {
	m := &message{gated: map[string]string{}, ungated: map[string]bool{}}
	for {
		loc := reNested.FindStringIndex(body)
		if loc == nil {
			break
		}
		inner := block(body, loc[0])
		end := loc[1] - 1 + len(inner) + 2 // past the nested block's `}`
		if end > len(body) {
			end = len(body)
		}
		body = body[:loc[0]] + ";" + body[end:]
	}
	if g := reMessageGate.FindStringSubmatch(body); g != nil {
		m.feature = g[1]
	}
	m.table = strings.Contains(body, "(w17.db.table)")
	for _, stmt := range strings.Split(body, ";") {
		f := reField.FindStringSubmatch(stmt)
		if f == nil {
			continue
		}
		if g := reFieldGate.FindStringSubmatch(stmt); g != nil {
			m.gated[f[1]] = g[1]
		} else {
			m.ungated[f[1]] = true
		}
	}
	return m
}

// tablesOf returns the tables a statement names and its aliases (alias ->
// table; each table also answers to its own name).
func tablesOf(stmt string) (map[string]bool, map[string]string) {
	named, alias := map[string]bool{}, map[string]string{}
	for _, t := range reTable.FindAllStringSubmatch(stmt, -1) {
		named[t[1]] = true
		alias[t[1]] = t[1]
		if a := t[2]; a != "" && !notAlias[strings.ToUpper(a)] {
			alias[a] = t[1]
		}
	}
	return named, alias
}

// splitItems cuts a statement into the items a `?feature` gate can cover: at
// commas and item keywords outside parentheses and string literals — but not
// at BETWEEN's AND, and not at the FROM of IS [NOT] DISTINCT FROM.
func splitItems(stmt string) []string {
	var items []string
	depth, start := 0, 0
	inQuote, between := false, false
	prev := ""
	cut := func(at, resume int) {
		items = append(items, stmt[start:at])
		start = resume
	}
	for i := 0; i < len(stmt); i++ {
		c := stmt[i]
		switch {
		case inQuote:
			if c == '\'' {
				inQuote = false
			}
		case c == '\'':
			inQuote = true
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == ',' && depth == 0:
			cut(i, i+1)
		case isWordByte(c) && (i == 0 || !isWordByte(stmt[i-1])):
			j := i
			for j < len(stmt) && isWordByte(stmt[j]) {
				j++
			}
			w := strings.ToUpper(stmt[i:j])
			if depth == 0 && i > 0 && (stmt[i-1] == ':' || stmt[i-1] == '.' || stmt[i-1] == '?') {
				// a parameter, a qualified name, a gate keyword: never a cut
			} else if depth == 0 && itemKeywords[w] {
				switch {
				case w == "AND" && between:
					between = false
				case w == "FROM" && prev == "DISTINCT":
				default:
					cut(i, j)
				}
			}
			if w == "BETWEEN" && depth == 0 {
				between = true
			}
			prev = w
			i = j - 1
		}
	}
	items = append(items, stmt[start:])
	return items
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// columnRef matches col as a word, optionally qualified (group 2 is the
// qualifier, without its dot).
func columnRef(col string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^\w:.])(?:(\w+)\.)?` + regexp.QuoteMeta(col) + `\b`)
}

// namesColumn reports whether item names col (matched by re) as a column of
// table: not as a `:col` parameter, not as an `AS …col` projection target,
// not qualified by another table's alias, and — unqualified, or qualified by
// a name the statement does not declare — not when another table of the
// statement has an ungated column of the same name.
func namesColumn(re *regexp.Regexp, col, item, table string, alias map[string]string, named map[string]bool, messages map[string]*message) bool {
	for _, loc := range re.FindAllStringSubmatchIndex(item, -1) {
		before := strings.ToUpper(strings.TrimRight(item[:loc[3]], " \t\n"))
		if before == "AS" || strings.HasSuffix(before, " AS") || strings.HasSuffix(before, "\tAS") || strings.HasSuffix(before, "\nAS") {
			continue
		}
		if loc[4] >= 0 {
			if t, ok := alias[item[loc[4]:loc[5]]]; ok {
				if t == table {
					return true
				}
				continue
			}
		}
		if !ambiguous(col, table, named, messages) {
			return true
		}
	}
	return false
}

// ambiguous: another table the statement names has an ungated column of the
// same name, so an unqualified reference may be that one.
func ambiguous(col, table string, named map[string]bool, messages map[string]*message) bool {
	for other := range named {
		if other != table && messages[other] != nil && messages[other].ungated[col] {
			return true
		}
	}
	return false
}

// gateCovers reports whether item carries a `?feature(<g>)` gate under which
// feature is on: g is the feature or requires it.
func gateCovers(item, feature string, requires map[string][]string) bool {
	for _, g := range reItemGate.FindAllStringSubmatch(item, -1) {
		for _, f := range closure(requires, []string{g[1]}) {
			if f == feature {
				return true
			}
		}
	}
	return false
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

// rpcBody returns an rpc's option block, or "" for `rpc X(A) returns (B);`,
// which has none — block alone would read on into the next rpc's.
func rpcBody(svc string, from int) string {
	brace, semi := strings.IndexByte(svc[from:], '{'), strings.IndexByte(svc[from:], ';')
	if brace < 0 || (semi >= 0 && semi < brace) {
		return ""
	}
	return block(svc, from)
}

func lastSegment(name string) string {
	return name[strings.LastIndex(name, ".")+1:]
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
