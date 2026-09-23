package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A gate cannot read a column its query never selected.
//
// This has now happened three times with the SAME column. IssueBotToken
// refuses any target that is not `kind = BOT`; GetUserById did not project
// `kind`, so it arrived as its zero value — HUMAN — and every mint was refused
// as if the target were a person (found live, 2026-09-20). A test was written
// then, naming that one rpc. Two more instances were sitting beside it:
// GetUserByEmail, so signInBotGate never fired and a machine account that set
// itself a password signed in as a person (marb #58/1); and GetUser, so
// labelMachineAccount never stamped the machine-account ACL label and every
// rule written against it matched nothing.
//
// So the rule is DISCOVERED, not listed. Naming one rpc is what let the other
// two hide: a reviewer reads the passing test, sees the column mentioned, and
// has no reason to look at the query next to it.
//
// The rule: every query that fills a `User` message projects `kind`, gated.
// The gates are written against the MESSAGE, not against the query, so any
// User a gate might be handed must be a complete one. A projection a gate
// reads and the query never filled is not a failure — it is a wrong answer
// delivered with no error at all, and it is HUMAN every time, which is the
// permissive side of every one of these gates.
func TestEveryUserProjectionFillsTheFieldsItsGatesRead(t *testing.T) {
	proto := readProto(t, filepath.Join("..", "..", "proto", "queries", "auth_query.proto"))

	rpcs := userReturningRPCs(t, proto)
	t.Logf("User-filling queries under the rule: %v", rpcs)
	if len(rpcs) < 7 {
		// The discovery is the test. If it stops finding queries, it stops
		// asserting anything, and would go green for the wrong reason.
		t.Fatalf("only %d User-filling queries found (%v) — the scan is broken, not the proto", len(rpcs), rpcs)
	}
	for _, name := range rpcs {
		dql := methodDQL(t, proto, "rpc "+name+"(")
		// `u.kind AS`, not `u.kind`: ListBotUsers had the column in its WHERE
		// clause and in no projection at all, and a looser check reads that
		// as compliance. A predicate narrows the rows; it fills no field.
		if !strings.Contains(dql, "u.kind AS") {
			t.Errorf("%s fills a User but does not project `kind` — every gate reading it "+
				"gets HUMAN, which is the permissive answer:\n%s", name, dql)
			continue
		}
		// The column only exists with the feature on, so the projection needs
		// a gate — UNLESS the whole rpc is already gated to that feature, in
		// which case an activation without it has no such rpc to run.
		rpcGated := strings.Contains(dql, `plugin_feature_rpc) = "service_account"`)
		if !rpcGated && !strings.Contains(dql, "?feature(service_account) u.kind") {
			t.Errorf("%s projects `kind` unconditionally — a build without service_account "+
				"has no such column:\n%s", name, dql)
		}
	}
}

// userReturningRPCs finds the queries that fill a `pb.User`, by their DECLARED
// return type rather than by what their SQL looks like. The SQL is the wrong
// discriminator: ListOrgMembersByOrg also selects u.email from @module.User,
// but it fills an OrgMemberRow — a gate written against pb.User is never
// handed one of those, and a rule that flags it teaches the reader to ignore
// this test.
func userReturningRPCs(t *testing.T, proto string) []string {
	t.Helper()
	var out []string
	for _, chunk := range strings.Split(proto, "\n  rpc ")[1:] {
		name, rest, ok := strings.Cut(chunk, "(")
		if !ok {
			continue
		}
		_, after, ok := strings.Cut(rest, "returns (")
		if !ok {
			continue
		}
		respName, _, ok := strings.Cut(after, ")")
		if !ok {
			continue
		}
		if respName == "User" || messageCarriesAUser(proto, respName) {
			out = append(out, name)
		}
	}
	return out
}

// messageCarriesAUser reports whether a response message has a User field —
// singular or repeated.
func messageCarriesAUser(proto, msg string) bool {
	i := strings.Index(proto, "message "+msg+" {")
	if i < 0 {
		return false
	}
	// Start AFTER the opening brace: `message GetUserByEmailResp { User user
	// = 1; }` is one line, and a line-oriented scan that includes the header
	// reads it as the word "message" and finds no field. That shape is most
	// of this file, and skipping it silently shrank the rule to the handful
	// of multi-line messages — which is exactly the failure this test is
	// about, one level up.
	body := proto[i+len("message "+msg+" {"):]
	if end := strings.Index(body, "\n}"); end >= 0 {
		body = body[:end]
	}
	for _, field := range strings.Split(body, ";") {
		f := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(field), "repeated "))
		if strings.HasPrefix(f, "User ") {
			return true
		}
	}
	return false
}

func readProto(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// methodDQL returns the text between an rpc's declaration and the end of its
// options block — enough to assert what a method's query selects.
func methodDQL(t *testing.T, proto, marker string) string {
	t.Helper()
	i := strings.Index(proto, marker)
	if i < 0 {
		t.Fatalf("no %q in the proto", marker)
	}
	rest := proto[i:]
	end := strings.Index(rest, "\n  }\n")
	if end < 0 {
		t.Fatalf("no end of block after %q", marker)
	}
	return rest[:end]
}
