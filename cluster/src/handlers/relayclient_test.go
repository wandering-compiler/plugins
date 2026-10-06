package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// The path relayClient dials is the service the relay REGISTERS (cmd/relay
// serves the plugin's own pb, whose package is never rewritten).
func TestRelayService_IsTheServiceTheRelayRegisters(t *testing.T) {
	if want := "/" + pb.ClusterService_ServiceDesc.ServiceName + "/"; relayService != want {
		t.Fatalf("relayService = %q, the relay serves %q", relayService, want)
	}
}

// A handler that reaches a relay through the GENERATED client dials the
// activation's package — `/console.codegen.ClusterService/…` once staged — and
// every relay answers Unimplemented. Only relayClient may call a relay.
func TestHandlers_NeverDialARelayThroughTheGeneratedClient(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if strings.Contains(string(b), "NewClusterServiceClient(") {
			t.Errorf("%s calls pb.NewClusterServiceClient — use newRelayClient: the generated client names the activation's package, not the relay's", f)
		}
	}
	if checked == 0 {
		t.Fatal("no handler sources found — the scan checked nothing")
	}
}
