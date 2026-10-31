package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withGoMod(t *testing.T, dir, module string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "src", "go.mod"), []byte("module "+module+"\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The failure this exists for: a third-party package imported from a staged
// file. The author's module requires it and compiles; every consumer's bundle
// is missing it.
func TestCheck_AStagedFileImportingAThirdPartyModule(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/alpha.go": "import _ \"filippo.io/age\"",
		"gen/wire.go":       "import _ \"github.com/example/other/pkg\"",
	})
	withGoMod(t, dir, "github.com/wandering-compiler/plugins/x")
	err := check(dir)
	if err == nil {
		t.Fatal("nil error, want both staged imports reported")
	}
	for _, want := range []string{"handlers/alpha.go imports filippo.io/age", "gen/wire.go imports github.com/example/other/pkg", "under lib/"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err does not say %q:\n%v", want, err)
		}
	}
}

// What every bundle requires is fine: the standard library, gRPC, protobuf,
// the SDK, and the plugin's own module (its lib/ is reached through it).
func TestCheck_WhatEveryBundleRequiresIsFine(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/alpha.go": `import (
	_ "context"
	_ "google.golang.org/grpc/status"
	_ "google.golang.org/protobuf/proto"
	_ "github.com/wandering-compiler/sdk/go/service/secret"
	_ "github.com/wandering-compiler/plugins/x/lib/sealing"
)`,
	})
	withGoMod(t, dir, "github.com/wandering-compiler/plugins/x")
	if err := check(dir); err != nil {
		t.Fatalf("check: %v", err)
	}
}

// What is never staged may import anything: lib/, tests, and the author's
// local pb stubs. A prefix of an allowed root is not that root.
func TestCheck_UnstagedFilesAndLookalikeRoots(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"lib/sealing/sealing.go": "import _ \"filippo.io/age\"",
		"handlers/alpha_test.go": "import _ \"filippo.io/age\"",
		"gen/pb/stub.go":         "import _ \"filippo.io/age\"",
		"handlers/testdata/x.go": "import _ \"filippo.io/age\"",
	})
	withGoMod(t, dir, "github.com/wandering-compiler/plugins/x")
	if err := check(dir); err != nil {
		t.Fatalf("check: %v", err)
	}
	dir = plugin(t, twoFeatures, map[string]string{
		"handlers/alpha.go": "import _ \"google.golang.org/grpcx\"\nimport _ \"github.com/wandering-compiler/plugins/xy/lib\"",
	})
	withGoMod(t, dir, "github.com/wandering-compiler/plugins/x")
	err := check(dir)
	if err == nil || !strings.Contains(err.Error(), "grpcx") || !strings.Contains(err.Error(), "plugins/xy/lib") {
		t.Fatalf("err = %v, want both lookalikes reported", err)
	}
}
