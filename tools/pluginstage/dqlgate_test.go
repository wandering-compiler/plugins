package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dqlManifest = `
features:
  - name: tokens
  - name: change
  - name: needs_tokens
    requires: [tokens]
`

// A table with one column the `tokens` feature adds.
const dqlModel = `message Token {
  option (w17.db.table) = {};
  string id      = 1 [(w17.field) = { type: UUID, pk: true }];
  string user_id = 2 [(w17.field) = { type: UUID }];
  // The realm; exists only with tokens.
  int32  kind    = 3 [
    (w17.field) = { type: ENUM },
    (w17.contrib.plugin_feature_field) = "tokens"
  ];
}
`

func dqlPlugin(t *testing.T, feature, dql string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("plugin.yaml", dqlManifest)
	write("proto/types/models.proto", dqlModel)
	gate := ""
	if feature != "" {
		gate = `    option (w17.contrib.plugin_feature_rpc) = "` + feature + `";` + "\n"
	}
	write("proto/mutations/m.proto", "service M {\n  rpc Sweep(SweepReq) returns (SweepResp) {\n"+gate+
		"    option (w17.db.method) = {\n      ops: {\n        name: \"main\"\n        dql:\n          \""+dql+"\"\n      }\n    };\n  }\n}\n")
	return dir
}

func TestDQL_AnUngatedColumnOfAnotherFeatureIsReported(t *testing.T) {
	err := checkDQLColumns(dqlPlugin(t, "change", "DELETE FROM @module.Token WHERE user_id = :user_id AND kind = :kind"),
		map[string][]string{"needs_tokens": {"tokens"}})
	if err == nil || !strings.Contains(err.Error(), "Token.kind (added by tokens)") {
		t.Fatalf("err = %v, want the ungated column reported", err)
	}
}

func TestDQL_AnAlwaysStagedRPCMayNotNameAGatedColumn(t *testing.T) {
	if err := checkDQLColumns(dqlPlugin(t, "", "SELECT t.kind AS kind FROM @module.Token t"), nil); err == nil {
		t.Fatal("an always-staged rpc naming a gated column passed")
	}
}

func TestDQL_AGatedItemPasses(t *testing.T) {
	if err := checkDQLColumns(dqlPlugin(t, "change", "DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(tokens) kind = 1"), nil); err != nil {
		t.Fatalf("a ?feature-gated item was reported: %v", err)
	}
}

func TestDQL_TheColumnsOwnFeatureAndWhatRequiresItPass(t *testing.T) {
	for _, f := range []string{"tokens", "needs_tokens"} {
		if err := checkDQLColumns(dqlPlugin(t, f, "DELETE FROM @module.Token WHERE kind = :kind"),
			map[string][]string{"needs_tokens": {"tokens"}}); err != nil {
			t.Errorf("rpc staged with %s was reported: %v", f, err)
		}
	}
}

// A parameter and a projection target that share the column's name are not
// references to the column.
func TestDQL_ParametersAndProjectionTargetsAreNotColumns(t *testing.T) {
	if err := checkDQLColumns(dqlPlugin(t, "change", "SELECT t.id AS kind FROM @module.Token t WHERE t.user_id = :kind"), nil); err != nil {
		t.Fatalf("a parameter / projection target was reported: %v", err)
	}
}

// dqlTree writes a plugin with the given manifest and proto files.
func dqlTree(t *testing.T, manifest string, protos map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"plugin.yaml": manifest}
	for name, body := range protos {
		files["proto/"+name] = body
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const dqlModels = `message Token {
  option (w17.db.table) = {};
  enum Realm {
    REALM_UNSPECIFIED = 0;
    REALM_SESSION     = 1;
  }
  string id      = 1 [(w17.field) = { type: UUID, pk: true }];
  string user_id = 2 [(w17.field) = { type: UUID }];
  int32  kind    = 3 [
    (w17.field) = { type: ENUM },
    (w17.contrib.plugin_feature_field) = "tokens"
  ];
}
message Grant {
  option (w17.db.table) = {};
  option (w17.contrib.plugin_feature) = "tokens";
  string id   = 1 [(w17.field) = { type: UUID, pk: true }];
  int32  kind = 2;
}
message SweepReq {
  string user_id = 1;
  int32  kind    = 2 [(w17.contrib.plugin_feature_field) = "tokens"];
}
`

func dqlService(svcGate, rpcGate string, dqls ...string) string {
	var b strings.Builder
	b.WriteString("service M {\n")
	if svcGate != "" {
		b.WriteString(`  option (w17.contrib.plugin_feature_svc) = "` + svcGate + "\";\n")
	}
	b.WriteString("  rpc Bare(SweepReq) returns (SweepResp);\n")
	b.WriteString("  rpc Sweep(SweepReq) returns (SweepResp) {\n")
	if rpcGate != "" {
		b.WriteString(`    option (w17.contrib.plugin_feature_rpc) = "` + rpcGate + "\";\n")
	}
	b.WriteString("    option (w17.db.method) = {\n")
	for i, d := range dqls {
		b.WriteString("      ops: {\n        name: \"op" + string(rune('a'+i)) + "\"\n        dql:\n          \"" + d + "\"\n      }\n")
	}
	b.WriteString("    };\n  }\n}\n")
	return b.String()
}

func dqlCheck(t *testing.T, svcGate, rpcGate string, dqls ...string) error {
	t.Helper()
	return checkDQLColumns(dqlTree(t, dqlManifest, map[string]string{
		"types/models.proto": dqlModels,
		"mutations/m.proto":  dqlService(svcGate, rpcGate, dqls...),
	}), map[string][]string{"needs_tokens": {"tokens"}})
}

// A whole table a feature adds cannot be gated in a statement: an rpc of
// another feature naming it is reported; the feature's own rpc is not.
func TestDQL_ATableOfAnotherFeatureIsReported(t *testing.T) {
	err := dqlCheck(t, "", "change", "SELECT g.id AS id FROM @module.Grant g")
	if err == nil || !strings.Contains(err.Error(), "names table Grant (added by tokens)") {
		t.Fatalf("err = %v, want the gated table reported", err)
	}
	if err := dqlCheck(t, "", "needs_tokens", "SELECT g.id AS id FROM @module.Grant g"); err != nil {
		t.Fatalf("an rpc requiring the table's feature was reported: %v", err)
	}
}

// A method without its own tag inherits the service's.
func TestDQL_TheServiceGateIsInherited(t *testing.T) {
	if err := dqlCheck(t, "tokens", "", "DELETE FROM @module.Token WHERE kind = 1"); err != nil {
		t.Fatalf("an rpc inheriting the column's feature from its service was reported: %v", err)
	}
	if err := dqlCheck(t, "tokens", "change", "DELETE FROM @module.Token WHERE kind = 1"); err == nil {
		t.Fatal("the rpc's own tag must override the service's")
	}
}

// A qualified reference resolves through the alias, so another table's
// ungated column of the same name does not hide it.
func TestDQL_AnAliasedReferenceIsNotAmbiguous(t *testing.T) {
	err := dqlCheck(t, "", "change", "SELECT t.id AS id FROM @module.Token t JOIN @module.Grant g ON g.id = t.id WHERE t.kind = 1")
	if err == nil || !strings.Contains(err.Error(), "Token.kind (added by tokens)") {
		t.Fatalf("err = %v, want t.kind reported despite Grant.kind", err)
	}
}

// Each op is its own statement: a table in one op does not make a column in
// another ambiguous.
func TestDQL_OpsAreSeparateStatements(t *testing.T) {
	err := dqlCheck(t, "", "change",
		"SELECT id FROM @module.Token WHERE kind = 1",
		"SELECT id FROM @module.Grant")
	if err == nil || !strings.Contains(err.Error(), "Token.kind (added by tokens)") {
		t.Fatalf("err = %v, want Token.kind reported", err)
	}
}

// A gate covers the whole conjunct it prefixes, parentheses, BETWEEN and
// IS DISTINCT FROM included; and a gate on a feature that requires the
// column's covers it too.
func TestDQL_AGateCoversItsWholeItem(t *testing.T) {
	for _, d := range []string{
		"DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(tokens) (kind = 1 OR kind = 2)",
		"DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(tokens) kind BETWEEN 1 AND 2",
		"DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(tokens) kind IS NOT DISTINCT FROM 1",
		"DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(needs_tokens) kind = 1",
	} {
		if err := dqlCheck(t, "", "change", d); err != nil {
			t.Errorf("%s: reported: %v", d, err)
		}
	}
}

// A parameter bound to a request field another feature adds has nothing to
// bind without it.
func TestDQL_AGatedRequestFieldBoundUngatedIsReported(t *testing.T) {
	err := dqlCheck(t, "", "change", "DELETE FROM @module.Token WHERE user_id = :kind")
	if err == nil || !strings.Contains(err.Error(), "binds :kind, a field of SweepReq added by tokens") {
		t.Fatalf("err = %v, want the gated request field reported", err)
	}
	if err := dqlCheck(t, "", "change", "DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(tokens) kind = :kind"); err != nil {
		t.Fatalf("a gated item binding the field was reported: %v", err)
	}
}

// Staging can cut a gate only from a SET assignment, a RETURNING target, a
// SELECT projection target and a top-level AND operand of a mutation's WHERE;
// a gated conjunct of a SELECT's WHERE fails the consumer's code generation.
func TestDQL_AGateOnlyWhereStagingCanCutIt(t *testing.T) {
	ok := []string{
		"SELECT t.id AS id, ?feature(tokens) t.kind AS kind FROM @module.Token t WHERE t.user_id = :user_id",
		"UPDATE @module.Token SET user_id = :user_id, ?feature(tokens) kind = :kind WHERE id = :id",
		"DELETE FROM @module.Token WHERE user_id = :user_id AND ?feature(tokens) kind = 1",
		"UPDATE @module.Token SET user_id = :user_id WHERE id = :id RETURNING id, ?feature(tokens) kind",
	}
	for _, stmt := range ok {
		if bad := misplacedGates(stmt); len(bad) != 0 {
			t.Errorf("a legal gate reported in %q: %q", stmt, bad)
		}
	}
	refused := []string{
		"SELECT t.id AS id FROM @module.Token t WHERE t.user_id = :user_id AND ?feature(tokens) t.kind = 1",
		"SELECT t.id AS id FROM @module.Token t JOIN @module.Token u ON u.id = t.id AND ?feature(tokens) u.kind = 1",
		"DELETE FROM @module.Token WHERE (user_id = :user_id OR ?feature(tokens) kind = 1)",
		"DELETE FROM @module.Token WHERE user_id = :user_id OR ?feature(tokens) kind = 1",
	}
	for _, stmt := range refused {
		if bad := misplacedGates(stmt); len(bad) != 1 {
			t.Errorf("%q: %d gates reported, want 1", stmt, len(bad))
		}
	}
	err := checkDQLColumns(dqlPlugin(t, "tokens", "SELECT t.id AS id FROM @module.Token t WHERE t.user_id = :user_id AND ?feature(tokens) t.kind = 1"), nil)
	if err == nil || !strings.Contains(err.Error(), "where staging cannot resolve one") {
		t.Fatalf("err = %v, want the gate in a SELECT's WHERE reported", err)
	}
}
