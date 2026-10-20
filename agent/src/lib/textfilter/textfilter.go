// Package textfilter cleans the final text of a model's answer: the text a
// caller keeps, not the deltas it shows while the answer is written. Models
// leak tokens — a Thai word glued to the end of a Czech sentence, a
// zero-width space, a bidi override — and a caller that replaces the streamed
// text with the final one gets a clean answer from one place instead of a
// filter in every consumer.
//
// Each filter is algorithmic and deterministic: the same text in, the same
// text out, no model call. A filter never invents text; it only removes.
package textfilter

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Filter rewrites a final text.
type Filter interface {
	// Name is how configuration and logs refer to the filter.
	Name() string
	// Apply returns text with what the filter removes removed.
	Apply(text string) string
}

// Chain applies its filters in order.
type Chain []Filter

// Apply runs every filter of c over text, in order.
func (c Chain) Apply(text string) string {
	for _, f := range c {
		text = f.Apply(text)
	}
	return text
}

// Scripts removes the letters of every Unicode script it does not allow,
// with the marks and joiners that belong to them: a run of Thai inside a
// Czech answer goes, the Czech word it was glued to stays. Common (digits,
// punctuation, symbols, emoji) and Inherited (combining marks) are always
// allowed, so diacritics, numbers and punctuation of any language survive.
// A space a removal leaves doubled, or trailing at the end of a line, is
// removed with it.
type Scripts struct {
	allowed []*unicode.RangeTable
	names   []string
}

// NewScripts allows the named scripts (Go's unicode.Scripts names: Latin,
// Cyrillic, Greek, Arabic, Hebrew, Han, Hiragana, Katakana, Hangul, Thai,
// Devanagari, …; case-insensitive). An unknown name, or none at all, is an
// error: a filter that allows nothing would delete every letter.
func NewScripts(names []string) (*Scripts, error) {
	s := &Scripts{}
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		key, table := lookupScript(n)
		if table == nil {
			return nil, fmt.Errorf("textfilter: unknown script %q (one of %s)", n, strings.Join(ScriptNames(), ", "))
		}
		if seen[key] || key == "Common" || key == "Inherited" {
			continue
		}
		seen[key] = true
		s.allowed = append(s.allowed, table)
		s.names = append(s.names, key)
	}
	if len(s.allowed) == 0 {
		return nil, fmt.Errorf("textfilter: no script allowed — name at least one (e.g. Latin)")
	}
	return s, nil
}

// lookupScript finds name in unicode.Scripts, ignoring case.
func lookupScript(name string) (string, *unicode.RangeTable) {
	if t, ok := unicode.Scripts[name]; ok {
		return name, t
	}
	for k, t := range unicode.Scripts {
		if strings.EqualFold(k, name) {
			return k, t
		}
	}
	return "", nil
}

// ScriptNames lists every script NewScripts accepts, sorted.
func ScriptNames() []string {
	names := make([]string, 0, len(unicode.Scripts))
	for k := range unicode.Scripts {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Name implements Filter.
func (s *Scripts) Name() string { return "scripts(" + strings.Join(s.names, ",") + ")" }

// keep reports whether r survives: not a letter of a script s refuses.
func (s *Scripts) keep(r rune) bool {
	if unicode.In(r, unicode.Common, unicode.Inherited) {
		return true
	}
	for _, t := range s.allowed {
		if unicode.Is(t, r) {
			return true
		}
	}
	return false
}

// Apply implements Filter.
func (s *Scripts) Apply(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	removed := false
	dropping := false // inside a run of a refused script
	// after: a run was just dropped, and the space that preceded it is
	// pending — written only if what follows needs a separator.
	after := false
	for _, r := range text {
		switch {
		case !s.keep(r):
			removed, dropping, after = true, true, true
			continue
		case dropping && (unicode.Is(unicode.Inherited, r) || r == '\u200d' || r == '\u200c'):
			// A combining mark or joiner belongs to the letter before it.
			continue
		}
		dropping = false
		if after {
			after = false
			// The removal must not leave two spaces, or a space before
			// punctuation or a line break: "foo <run> bar" → "foo bar",
			// "foo <run>." → "foo.".
			if out := b.String(); strings.HasSuffix(out, " ") && (r == ' ' || r == '\n' || strings.ContainsRune(".,;:!?)]}", r)) {
				b.Reset()
				b.WriteString(strings.TrimRight(out, " "))
			}
		}
		b.WriteRune(r)
	}
	if !removed {
		return text
	}
	out := b.String()
	if after {
		out = strings.TrimRight(out, " ")
	}
	return out
}

// Invisible removes characters a reader cannot see and a model has no reason
// to write: control characters other than tab and line breaks, the
// replacement character U+FFFD (a broken byte sequence), zero-width spaces
// and the byte-order mark, and the bidirectional embedding, override and
// isolate controls (which can reorder what a reader sees). The zero-width
// joiner and non-joiner stay — emoji sequences and several scripts need
// them — and so do the left-to-right and right-to-left marks.
type Invisible struct{}

// Name implements Filter.
func (Invisible) Name() string { return "invisible" }

// invisible reports whether Invisible removes r.
func invisible(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case unicode.IsControl(r):
		return true
	}
	switch r {
	case '\ufffd', '\u200b', '\u2060', '\ufeff',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	}
	return false
}

// Apply implements Filter.
func (Invisible) Apply(text string) string {
	if strings.IndexFunc(text, invisible) < 0 {
		return text
	}
	return strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, text)
}
