package handlers

import (
	"regexp"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// relayPattern is the (w17.field).pattern a message declares on one field — read
// from the generated descriptor, so the test checks what the code was generated
// from and not a copy that can drift.
func relayPattern(t *testing.T, m proto.Message, field protoreflect.Name) string {
	t.Helper()
	fd := m.ProtoReflect().Descriptor().Fields().ByName(field)
	if fd == nil {
		t.Fatalf("%s has no field %s", m.ProtoReflect().Descriptor().FullName(), field)
	}
	f, _ := proto.GetExtension(fd.Options(), w17pb.E_Field).(*w17pb.Field)
	if f.GetPattern() == "" {
		t.Fatalf("%s.%s declares no pattern", m.ProtoReflect().Descriptor().FullName(), field)
	}
	return f.GetPattern()
}

// TestARelayAddressTheFormAcceptsCanBeDialled pins the promise the url pattern
// makes: an address it lets through is one the control plane can dial. The
// relay is dialled with grpc.NewClient(url) (lib/relaydial), which parses the
// target before it connects — so an accepted address that fails here would be
// stored, enabled, and fail on every placement. 0.2.0-rc.8 accepted an IPv6
// zone (`[fe80::1%eth0]`) that grpc cannot parse; this is the test that would
// have refused it.
func TestARelayAddressTheFormAcceptsCanBeDialled(t *testing.T) {
	pat := relayPattern(t, &pb.Relay{}, "url")
	for _, m := range []proto.Message{&pb.CreateRelayReq{}, &pb.UpdateRelayReq{}} {
		if got := relayPattern(t, m, "url"); got != pat {
			t.Fatalf("%s.url pattern differs from the table's: %q vs %q", m.ProtoReflect().Descriptor().FullName(), got, pat)
		}
	}
	re := regexp.MustCompile(pat)

	accepted := []string{
		"clusterrelay:13444", "w17_clusterrelay:13444", "project_svc_1:13444",
		"relay.eu-west.example.com:13444", "relay.example.com.:443",
		"10.0.0.7:13444", "[::1]:13444", "[2001:db8::7]:443", "r:1", "r:65535",
	}
	refused := []string{
		"https://relay.example.com:13444", "relay.example.com", "relay.example.com:",
		":13444", "relay .com:1", "-relay:1", "relay-:1", "r:0", "r:65536", "r:01",
		"[fe80::1%eth0]:13444", "[fe80::1%25eth0]:13444", "",
	}
	for _, a := range accepted {
		if !re.MatchString(a) {
			t.Errorf("the pattern refuses %q, an address the control plane can dial", a)
		}
	}
	for _, a := range refused {
		if re.MatchString(a) {
			t.Errorf("the pattern accepts %q", a)
		}
	}
	// The property, over every candidate above: accepted ⇒ dialable.
	for _, a := range append(append([]string{}, accepted...), refused...) {
		if !re.MatchString(a) {
			continue
		}
		cc, err := grpc.NewClient(a, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Errorf("the pattern accepts %q, but grpc cannot dial it: %v", a, err)
			continue
		}
		_ = cc.Close()
	}
}

// TestARelayFingerprintIsSixtyFourLowercaseHex — the pin relaydial compares is
// hex.EncodeToString of a SHA-256: lowercase, 64 characters.
func TestARelayFingerprintIsSixtyFourLowercaseHex(t *testing.T) {
	pat := relayPattern(t, &pb.Relay{}, "cert_fingerprint")
	for _, m := range []proto.Message{&pb.CreateRelayReq{}, &pb.UpdateRelayReq{}} {
		if got := relayPattern(t, m, "cert_fingerprint"); got != pat {
			t.Fatalf("%s.cert_fingerprint pattern differs from the table's", m.ProtoReflect().Descriptor().FullName())
		}
	}
	re := regexp.MustCompile(pat)
	good := "f988deae8e09e7d5969cedf030e67b7cb86cdc2fcebaa3bd9f55d3c403269139"
	if !re.MatchString(good) {
		t.Errorf("the pattern refuses a real fingerprint %q", good)
	}
	for _, bad := range []string{"F988DEAE8E09E7D5969CEDF030E67B7CB86CDC2FCEBAA3BD9F55D3C403269139", good[1:], good + "0", "f9:88:de", ""} {
		if re.MatchString(bad) {
			t.Errorf("the pattern accepts %q", bad)
		}
	}
}
