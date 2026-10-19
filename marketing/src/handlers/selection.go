package handlers

import (
	"fmt"
	"sort"
	"strings"
)

// selection decides which recorded methods become events: a default by kind
// (`send`), then methods added (`include`) and removed (`exclude`, which wins
// over both).
type selection struct {
	mode    string
	include map[string]bool
	exclude map[string]bool
	reads   map[string]bool // every recorded method → whether it only reads
}

// newSelection reads the activation's send / include / exclude against the
// methods the stream records. A method name it does not record is refused:
// the lists are typed by hand, and a typo would send nothing, silently.
func newSelection(mode, include, exclude string, reads map[string]bool) (selection, error) {
	s := selection{mode: strings.ToLower(strings.TrimSpace(mode)), reads: reads}
	if s.mode == "" {
		s.mode = "mutations"
	}
	switch s.mode {
	case "mutations", "queries", "all", "off":
	default:
		return selection{}, fmt.Errorf("marketing plugin: send %q: want mutations, queries, all or off", mode)
	}
	var err error
	if s.include, err = methodList("include", include, reads); err != nil {
		return selection{}, err
	}
	if s.exclude, err = methodList("exclude", exclude, reads); err != nil {
		return selection{}, err
	}
	return s, nil
}

func methodList(name, list string, reads map[string]bool) (map[string]bool, error) {
	out := map[string]bool{}
	var unknown []string
	for _, m := range strings.Split(list, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := reads[m]; !ok {
			unknown = append(unknown, m)
			continue
		}
		out[m] = true
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(reads))
		for m := range reads {
			known = append(known, m)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("marketing plugin: %s names %s, which the request stream does not record\n"+
			"  fix: name methods as a record does (/<package>.<Service>/<Method>); recorded: %s",
			name, strings.Join(unknown, ", "), strings.Join(known, ", "))
	}
	return out, nil
}

// sends reports whether a record of method becomes an event.
func (s selection) sends(method string) bool {
	if s.exclude[method] {
		return false
	}
	if s.include[method] {
		return true
	}
	switch s.mode {
	case "all":
		return true
	case "mutations":
		return !s.reads[method]
	case "queries":
		return s.reads[method]
	}
	return false
}
