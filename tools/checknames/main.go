// Command checknames refuses a tracked file that names a project this
// repository must not name.
//
// The repository is public, and fixtures, comments and examples are written to
// stay anonymous. The list of names to refuse cannot live here — a public
// denylist publishes the very names it protects, and short names are easy to
// recover from a hash — so it arrives in the W17_DENIED_NAMES environment
// variable (a CI secret): comma-separated `sha256-of-lowercased-name:length`
// pairs, the same form the w17 platform's own gate uses.
//
// EVERY tracked file is read, whatever its extension (only binary files are
// skipped), and every tracked PATH is checked too. A finding prints the file and
// line, never the line itself, because the line holds the name and CI logs are
// public; a name in a path is reported by the file's position in
// `git ls-files`, since printing the path would print the name.
//
// Words are split on anything not a letter or digit and on camelCase, and every
// pair of adjacent words is also tried joined, so `acmeClient`, `Acme-Corp` and
// `acme_corp` all reach a list entry `acme` or `acmecorp`.
//
//	usage: checknames [-require] [repo-root]
//
// Without the variable it says so and passes, unless -require is set (CI on
// this repository's own branches, where the secret is present).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

func main() {
	require := flag.Bool("require", false, "fail when W17_DENIED_NAMES is not set")
	flag.Parse()
	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}
	denied, lengths, err := parseDenied(os.Getenv("W17_DENIED_NAMES"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "checknames:", err)
		os.Exit(2)
	}
	if len(denied) == 0 {
		if *require {
			fmt.Fprintln(os.Stderr, "checknames: W17_DENIED_NAMES is not set — refusing to report a scan that checked nothing")
			os.Exit(2)
		}
		fmt.Println("checknames: W17_DENIED_NAMES is not set (a fork, or a local run) — skipped")
		return
	}
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "checknames: git ls-files:", err)
		os.Exit(2)
	}
	match := func(text string) bool {
		for _, tok := range tokens(text) {
			if lengths[len(tok)] {
				if want, ok := denied[hash(tok)]; ok && want == len(tok) {
					return true
				}
			}
		}
		return false
	}
	var scanned, hits int
	for i, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if rel == "" {
			continue
		}
		if match(rel) {
			hits++
			fmt.Printf("tracked file #%d (git ls-files order) has a PATH that names a project this repository must not name — rename it\n", i+1)
		}
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil || isBinary(body) {
			continue
		}
		scanned++
		for n, line := range strings.Split(string(body), "\n") {
			if match(line) {
				hits++
				fmt.Printf("%s:%d names a project this repository must not name — say what happened instead, or use an obviously fake name\n", rel, n+1)
			}
		}
	}
	fmt.Printf("checknames: %d files scanned, %d findings\n", scanned, hits)
	if scanned == 0 {
		fmt.Fprintln(os.Stderr, "checknames: nothing was scanned — a check over no files proves nothing")
		os.Exit(2)
	}
	if hits > 0 {
		os.Exit(1)
	}
}

func parseDenied(env string) (map[string]int, map[int]bool, error) {
	denied, lengths := map[string]int{}, map[int]bool{}
	for _, pair := range strings.FieldsFunc(env, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		h, l, ok := strings.Cut(pair, ":")
		n, err := strconv.Atoi(l)
		if !ok || err != nil || len(h) != 64 {
			return nil, nil, fmt.Errorf("W17_DENIED_NAMES: entry %d is not hash:length", len(denied)+1)
		}
		denied[strings.ToLower(h)] = n
		lengths[n] = true
	}
	return denied, lengths, nil
}

// tokens are the lowercased words of a line — split on anything not a letter or
// digit and on camelCase boundaries — plus every adjacent pair joined.
func tokens(line string) []string {
	var words []string
	for _, field := range strings.FieldsFunc(line, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		words = append(words, strings.ToLower(field))
		if parts := camelParts(field); len(parts) > 1 {
			words = append(words, parts...)
		}
	}
	out := append([]string(nil), words...)
	for i := 0; i+1 < len(words); i++ {
		out = append(out, words[i]+words[i+1])
	}
	return out
}

// camelParts splits `acmeClient` / `ACMEClient` into lowercased words.
func camelParts(s string) []string {
	rs := []rune(s)
	var parts []string
	start := 0
	for i := 1; i < len(rs); i++ {
		lowerToUpper := unicode.IsLower(rs[i-1]) && unicode.IsUpper(rs[i])
		acronymEnd := i+1 < len(rs) && unicode.IsUpper(rs[i-1]) && unicode.IsUpper(rs[i]) && unicode.IsLower(rs[i+1])
		if lowerToUpper || acronymEnd {
			parts = append(parts, strings.ToLower(string(rs[start:i])))
			start = i
		}
	}
	return append(parts, strings.ToLower(string(rs[start:])))
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

func hash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
