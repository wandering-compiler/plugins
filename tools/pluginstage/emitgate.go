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

// # An event emitted from two places
//
// The w17 compiler gives an event exactly ONE emit site across a domain — one
// `(w17.event_emit)` or one `(w17.event_emit_gateway)` — and refuses a second
// at code generation ("is emitted from more than one site"). Several triggers
// of one event are modelled by funnelling them through the one method that
// emits it.
//
// Nothing in the author tree notices a second site: `make gen` generates the
// pb, which knows nothing about events, and the adoption examples generate
// only the features they activate. When the two sites belong to features
// nobody activates together, the first activation that does — `plugin dev
// --all-features`, or a consumer's — is the first to fail. auth's
// MarketingConsentChanged went out on main that way: SetUserMarketingConsent
// and WithdrawUserMarketingConsent, both under marketing_consent.
//
// Two sites collide when some activation `requires` and `conflicts_with`
// allow stages both rpcs. An rpc's feature is its `plugin_feature_rpc`, or its
// service's `plugin_feature_svc`; neither means always staged.

var reEmit = regexp.MustCompile(`option\s+\(w17\.(event_emit(?:_gateway)?)\)\s*=\s*\{\s*event:\s*"([\w.]+)"`)

type emitSite struct {
	file, rpc, feature, tier string
}

func checkEmitSites(dir string, requires map[string][]string, conflicts map[[2]string]bool) error {
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
	sort.Strings(protos)

	sites := map[string][]emitSite{}
	for _, p := range protos {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := reLineCommnt.ReplaceAllString(string(raw), "")
		for _, s := range reService.FindAllStringSubmatchIndex(src, -1) {
			svc := block(src, s[1]-1)
			svcFeature := ""
			if g := reServiceGate.FindStringSubmatch(svc); g != nil {
				svcFeature = g[1]
			}
			for _, m := range reRPC.FindAllStringSubmatchIndex(svc, -1) {
				body := rpcBody(svc, m[1])
				feature := svcFeature
				if g := reRPCGate.FindStringSubmatch(body); g != nil {
					feature = g[1]
				}
				for _, e := range reEmit.FindAllStringSubmatch(body, -1) {
					event := lastSegment(e[2])
					sites[event] = append(sites[event], emitSite{
						file: rel(dir, p), rpc: src[s[2]:s[3]] + "." + svc[m[2]:m[3]], feature: feature, tier: e[1],
					})
				}
			}
		}
	}

	var problems []string
	for _, event := range sortedKeys(sites) {
		list := sites[event]
		for i := 0; i < len(list); i++ {
			for j := i + 1; j < len(list); j++ {
				a, b := list[i], list[j]
				if !stagedTogether(a.feature, b.feature, requires, conflicts) {
					continue
				}
				problems = append(problems, fmt.Sprintf("  event %s\n      %s (%s, %s) in %s\n      %s (%s, %s) in %s",
					event, a.rpc, a.tier, stagedWith(a.feature), a.file, b.rpc, b.tier, stagedWith(b.feature), b.file))
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("an event has more than one emit site in an activation:\n%s\n\n"+
		"  The w17 compiler allows an event ONE emit site and refuses the activation that\n"+
		"  stages both — at code generation, in the first project that enables them together.\n\n"+
		"  fix: keep the emit on one method and have the other path go through it (a\n"+
		"  statement made conditional by an optional request field, `?`), or declare two\n"+
		"  events if the triggers are genuinely different facts",
		strings.Join(problems, "\n"))
}

// stagedTogether reports whether some valid activation stages an rpc of
// feature a and one of feature b ("" = always staged) at once.
func stagedTogether(a, b string, requires map[string][]string, conflicts map[[2]string]bool) bool {
	var named []string
	for _, f := range []string{a, b} {
		if f != "" {
			named = append(named, f)
		}
	}
	vars := closure(requires, named)
	if len(vars) > 20 {
		return true // too wide to enumerate: report rather than pass unchecked
	}
	for bits := 0; bits < 1<<len(vars); bits++ {
		on := map[string]bool{}
		for i, v := range vars {
			on[v] = bits&(1<<i) != 0
		}
		if (a != "" && !on[a]) || (b != "" && !on[b]) {
			continue
		}
		if valid(on, requires, conflicts) {
			return true
		}
	}
	return false
}
