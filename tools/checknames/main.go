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
// A finding prints the file and line only, never the line itself, because the
// line holds the name and CI logs are public.
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

var scanExts = map[string]bool{
	".go": true, ".proto": true, ".md": true, ".yaml": true, ".yml": true,
	".sh": true, ".ts": true, ".tsx": true, ".json": true, ".tmpl": true,
	".src": true, ".mod": true, ".txt": true, "": true,
}

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
	var scanned, hits int
	for _, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if rel == "" || !scanExts[strings.ToLower(filepath.Ext(rel))] {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		scanned++
		for n, line := range strings.Split(string(body), "\n") {
			for _, tok := range tokens(line) {
				if !lengths[len(tok)] {
					continue
				}
				if want, ok := denied[hash(tok)]; ok && want == len(tok) {
					hits++
					fmt.Printf("%s:%d names a project this repository must not name — say what happened instead, or use an obviously fake name\n", rel, n+1)
				}
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

func tokens(line string) []string {
	return strings.FieldsFunc(strings.ToLower(line), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func hash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
