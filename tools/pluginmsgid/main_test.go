package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func parseGo(t *testing.T, src string) ([]string, error) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return markedIn(fset, f)
}

// The marker is honoured on a block and on a single spec, because both read
// naturally and accepting only one would silently ignore the other spelling.
func TestMarkedIn_BothSpellings(t *testing.T) {
	got, err := parseGo(t, `package p
//w17:msgid
const ( A = "block form" )

//w17:msgid
const B = "single form"

const C = "unmarked, and must stay out"
`)
	if err != nil {
		t.Fatalf("markedIn: %v", err)
	}
	if len(got) != 2 || !contains(got, "block form") || !contains(got, "single form") {
		t.Errorf("got %v, want exactly the two marked sentences", got)
	}
}

// A marked declaration that is not a plain literal is an ERROR.
//
// Skipping it is what the first version did, and it is the failure this whole
// program exists to prevent: `const Msg = "Wrong " + "password."` is valid Go,
// its value never reaches the manifest, and an empty msgids: then passed the
// gate while the plugin emitted the sentence (caught in review on PR #10).
func TestMarkedIn_ANonLiteralIsRefusedNotSkipped(t *testing.T) {
	for _, src := range []string{
		`package p
//w17:msgid
const A = "Wrong " + "password."`,
		`package p
var greeting = "hi"

//w17:msgid
var A = greeting`,
		`package p
//w17:msgid
const A = ""`,
	} {
		got, err := parseGo(t, src)
		if err == nil {
			t.Errorf("a marked non-literal was accepted, yielding %v — it would be "+
				"invisible to the manifest and to every translator", got)
		}
	}
}

// Reading accepts whatever valid YAML a person wrote.
//
// The first version matched only the quoted block form this tool emits, so a
// manifest written any other way parsed as EMPTY and a stale entry passed the
// two-way check that is the point of the gate.
func TestFromYAML_AcceptsAnyValidSpelling(t *testing.T) {
	for name, body := range map[string]string{
		"block, double quoted": "msgids:\n  - \"a sentence\"\n",
		"block, single quoted": "msgids:\n  - 'a sentence'\n",
		"block, bare":          "msgids:\n  - a sentence\n",
		"flow, single quoted":  "msgids: ['a sentence']\n",
		"flow, double quoted":  "msgids: [\"a sentence\"]\n",
		"items at column zero": "msgids:\n- a sentence\n",
	} {
		got, err := fromYAML([]byte("name: p\n" + body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(got) != 1 || got[0] != "a sentence" {
			t.Errorf("%s: parsed %v — a spelling this tool does not emit still has "+
				"to be COMPARED, or a stale entry passes", name, got)
		}
	}
}

// -write leaves unrelated manifest comments alone.
func TestRewrite_KeepsCommentsThatBelongToOtherFields(t *testing.T) {
	const in = `name: p
msgids:
  - "old"

# Documents the field below, not the msgids.
description: p
`
	out, err := rewrite(in, []string{"new"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Documents the field below") {
		t.Errorf("the sync ate a comment belonging to another field:\n%s", out)
	}
	if !strings.Contains(out, `"new"`) || strings.Contains(out, `"old"`) {
		t.Errorf("the block was not replaced:\n%s", out)
	}
}

// -write is idempotent. A sync that grows its own header each run is one
// nobody can put in a pre-commit hook.
func TestRewrite_IsIdempotent(t *testing.T) {
	out, err := rewrite("name: p\n", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		next, err := rewrite(out, []string{"a"})
		if err != nil {
			t.Fatal(err)
		}
		if next != out {
			t.Fatalf("run %d changed the file again:\n--- before ---\n%s\n--- after ---\n%s", i, out, next)
		}
	}
	if n := strings.Count(out, generatedMarker); n != 1 {
		t.Errorf("%d generated headers after repeated syncs, want 1", n)
	}
}

// A comment ABOVE msgids: that we did not write is not ours to replace.
func TestRewrite_LeavesAHandWrittenHeaderAlone(t *testing.T) {
	const in = `name: p
# A human wrote this and it explains something.
msgids:
  - "old"
`
	out, err := rewrite(in, []string{"new"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "A human wrote this") {
		t.Errorf("a hand-written comment above the block was replaced:\n%s", out)
	}
}

// Dropping the last sentence drops the block, with no stray blank left behind.
func TestRewrite_EmptySetRemovesTheBlock(t *testing.T) {
	in, err := rewrite("name: p\ndescription: d\n", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := rewrite(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "msgids:") || strings.Contains(out, generatedMarker) {
		t.Errorf("the block survived an empty set:\n%s", out)
	}
	if strings.Contains(out, "\n\n\n") {
		t.Errorf("removal left blank lines behind, so the next diff shows the sync:\n%q", out)
	}
}

func contains(h []string, n string) bool {
	for _, s := range h {
		if s == n {
			return true
		}
	}
	return false
}
