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
