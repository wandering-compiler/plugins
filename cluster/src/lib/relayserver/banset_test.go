package relayserver

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// --- a relay that holds no ban set fails closed ---

// A relay that started without a saved set refuses every worker's attach —
// retryably, not as banned — and still records it, until a control plane
// delivers a set.
func TestAttach_WithNoBanSetEveryWorkerIsRefusedButSeen(t *testing.T) {
	r := serveWorkersWith(t, workeradmit.New())
	w := r.issue(t, time.Hour)
	stream, err := r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(announce(2, workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.Unavailable || refusal.ReasonOf(err) != refusal.BanSetUnknown {
		t.Fatalf("err = %v (reason %q), want Unavailable/%s", err, refusal.ReasonOf(err), refusal.BanSetUnknown)
	}
	if known := r.reg.Known(); len(known) != 1 || known[0].ID != w.id {
		t.Errorf("known = %+v, want the refused worker recorded", known)
	}
	if r.backends.Capacity() != 0 {
		t.Error("a worker refused for want of a ban set added capacity")
	}

	r.reg.SetBanned(nil) // the control plane's first call
	stream, err = r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(announce(2, workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	if ev, err := stream.Recv(); err != nil || ev.GetAdmitted() == nil {
		t.Fatalf("after the set arrived: %v, %v; want admitted", ev, err)
	}
}

// The tunnel listener fails closed the same way.
func TestServeTunnels_WithNoBanSetATunnelIsRefused(t *testing.T) {
	r := serveTunnelsWith(t, tls.RequireAndVerifyClientCert, false, serveWorkersWith(t, workeradmit.New()))
	w := r.issue(t, time.Hour)
	c := r.dialTunnel(t, &w)
	r.awaitRefusal(t, "no ban set")
	awaitClosed(t, c)
	if r.backends.Count() != 0 {
		t.Error("a tunnel became a backend on a relay that holds no ban set")
	}
}

// Renewal needs a ban set the relay holds AND one a control plane delivered
// within MaxBanSetAge; both refusals are retryable (Unavailable), unlike a
// ban. A relay that restarted without a saved set, and one no control plane
// has reached for a while (disabled, or cut off), may be missing a ban.
func TestRenew_NeedsARecentlyDeliveredBanSet(t *testing.T) {
	r := newEnrolRig(t)
	r.e.Lifetime = 24 * time.Hour
	r.e.MaxBanSetAge = 10 * time.Minute
	keyPEM, cert := enrol(t, r)
	csr, _ := identity.CSRFor(keyPEM, "w1")
	renew := func() error {
		_, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: csr})
		return err
	}

	r.e.Workers = workeradmit.New() // restarted, nothing saved
	if err := renew(); status.Code(err) != codes.Unavailable || refusal.ReasonOf(err) != refusal.BanSetUnknown {
		t.Fatalf("no ban set: %v (reason %q), want Unavailable/%s", err, refusal.ReasonOf(err), refusal.BanSetUnknown)
	}
	r.e.Workers.SetBanned(nil)
	if err := renew(); err != nil {
		t.Fatalf("a fresh delivery: %v, want the renewal", err)
	}

	r.now = time.Now().Add(11 * time.Minute) // no delivery since
	if err := renew(); status.Code(err) != codes.Unavailable || refusal.ReasonOf(err) != refusal.BanSetStale {
		t.Fatalf("a stale set: %v (reason %q), want Unavailable/%s", err, refusal.ReasonOf(err), refusal.BanSetStale)
	}
	r.now = time.Now()
	r.e.Workers.SetBanned(nil)
	if err := renew(); err != nil {
		t.Errorf("after the set was delivered again: %v, want the renewal", err)
	}
}

// Zero MaxBanSetAge is the default, an hour.
func TestRenew_TheDefaultBanSetAgeIsAnHour(t *testing.T) {
	r := newEnrolRig(t)
	r.e.Lifetime = 24 * time.Hour
	keyPEM, cert := enrol(t, r)
	csr, _ := identity.CSRFor(keyPEM, "w1")
	r.now = time.Now().Add(DefaultBanSetMaxAge - time.Minute)
	if _, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: csr}); err != nil {
		t.Fatalf("within the default age: %v", err)
	}
	r.now = time.Now().Add(DefaultBanSetMaxAge + time.Minute)
	if _, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: csr}); refusal.ReasonOf(err) != refusal.BanSetStale {
		t.Errorf("past the default age: %v, want %s", err, refusal.BanSetStale)
	}
}

// Right after a restart with a saved set, a banned key hears that it is
// banned (final), not that the set is stale; an unbanned one waits for the
// first delivery.
func TestRenew_AfterARestartTheSavedBanRefusesTheKey(t *testing.T) {
	r := newEnrolRig(t)
	keyPEM, cert := enrol(t, r)
	csr, _ := identity.CSRFor(keyPEM, "w1")
	path := filepath.Join(t.TempDir(), "bans.json")
	before := workeradmit.New()
	if err := before.KeepIn(path); err != nil {
		t.Fatal(err)
	}
	before.SetBannedAt([]string{identity.WorkerID(cert)}, 7)

	restarted := workeradmit.New()
	if err := restarted.KeepIn(path); err != nil {
		t.Fatal(err)
	}
	r.e.Workers = restarted
	if _, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: csr}); refusal.ReasonOf(err) != refusal.WorkerBanned {
		t.Fatalf("a key banned in the saved set: %v, want %s", err, refusal.WorkerBanned)
	}

	before2 := workeradmit.New()
	path2 := filepath.Join(t.TempDir(), "bans.json")
	if err := before2.KeepIn(path2); err != nil {
		t.Fatal(err)
	}
	before2.SetBannedAt(nil, 7)
	unbanned := workeradmit.New()
	if err := unbanned.KeepIn(path2); err != nil {
		t.Fatal(err)
	}
	r.e.Workers = unbanned
	if _, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: csr}); refusal.ReasonOf(err) != refusal.BanSetStale {
		t.Errorf("an unbanned key before the first delivery: %v, want %s", err, refusal.BanSetStale)
	}
}

// --- a tunnel ends with its certificate ---

// A tunnel opened with a certificate that then expires stops being a backend:
// its capacity goes, and the idle tunnel is closed.
func TestServeTunnels_AnExpiredCertificatesTunnelStopsBeingABackend(t *testing.T) {
	r := serveTunnels(t, tls.RequireAndVerifyClientCert, false)
	w := r.issue(t, 3*time.Second)
	r.backends.SetProfile(w.id, r.backends.NewAttachment(), 2, true)
	c := r.dialTunnel(t, &w)
	srv := grpc.NewServer(tunnel.WorkServerOptions()...)
	go func() { _ = srv.Serve(tunnel.NewSingleConnListener(c)) }()
	defer srv.Stop()

	r.awaitCapacity(t, 2)
	r.awaitCapacity(t, 0)
	eventually(t, "the expired tunnel leaves", func() bool { return r.backends.Count() == 0 })
}

// An idle tunnel is closed the moment its certificate expires.
func TestBackends_ExpiryClosesAnIdleTunnelAtOnce(t *testing.T) {
	b := NewBackends()
	b.SetExpiryGrace(time.Minute)
	attach(t, b, "w", 2, true)
	c := connOf(b, "w")
	b.ExpireAt("w", c, time.Now())
	eventually(t, "the expired tunnel closes", func() bool { return c.GetState() == connectivity.Shutdown })
	if n, cp := b.Count(), b.Capacity(); n != 0 || cp != 0 {
		t.Errorf("Count = %d, Capacity = %d after expiry, want 0 and 0", n, cp)
	}
}

// Work already running when the certificate expires may finish within the
// grace: the tunnel takes nothing new at once, and closes with its last call.
func TestBackends_ExpiryLetsRunningWorkFinishThenCloses(t *testing.T) {
	b := NewBackends()
	b.SetExpiryGrace(time.Minute)
	pool := poolWith(t, 2)
	srv := tunnelTo(t, b, "w")
	defer srv.Stop()
	b.SetProfile("w", b.NewAttachment(), 2, true) // room left after the first call
	pick := TicketPicker(pool, b, nil)
	be, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	b.ExpireAt("w", be.Conn, time.Now())
	eventually(t, "the expired tunnel's capacity goes", func() bool { return b.Capacity() == 0 })
	if _, err := pickWith(pick, grantTicket(t, pool)); refusal.ReasonOf(err) != refusal.NoWorker {
		t.Errorf("new work on an expired tunnel: %v, want %s", err, refusal.NoWorker)
	}
	if st := be.Conn.GetState(); st == connectivity.Shutdown {
		t.Fatal("the tunnel closed under running work before the grace")
	}
	be.Release()
	eventually(t, "the tunnel closes with its last call", func() bool { return be.Conn.GetState() == connectivity.Shutdown })
	if n := b.Count(); n != 0 {
		t.Errorf("Count = %d, want the expired tunnel gone", n)
	}
}

// Past the grace the tunnel is closed under whatever still runs, and the
// call's slot still comes back.
func TestBackends_ExpiryGraceEndsWorkStillRunning(t *testing.T) {
	b := NewBackends()
	b.SetExpiryGrace(50 * time.Millisecond)
	pool := poolWith(t, 1)
	srv := tunnelTo(t, b, "w")
	defer srv.Stop()
	be, err := pickWith(TicketPicker(pool, b, nil), grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	b.ExpireAt("w", be.Conn, time.Now())
	eventually(t, "the grace closes the tunnel", func() bool { return be.Conn.GetState() == connectivity.Shutdown })
	if n := b.Count(); n != 0 {
		t.Errorf("Count = %d after the grace, want 0", n)
	}
	be.Release()
	if st := pool.Stats(); st.Held() != 0 {
		t.Errorf("pool = %+v, want the cut call's slot back", st)
	}
}

// The old tunnel's expiry does not touch the worker's replacement: neither
// its timer, nor a retirement already under way when the replacement came.
func TestBackends_AnOldTunnelsExpiryLeavesItsReplacement(t *testing.T) {
	b := NewBackends()
	attach(t, b, "w", 2, true)
	old := connOf(b, "w")
	b.ExpireAt("w", old, time.Now().Add(20*time.Millisecond))
	b.Add("w", conn(t))
	time.Sleep(100 * time.Millisecond)
	b.expire("w", old) // a timer that fired as the replacement arrived
	if n, c := b.Count(), b.Capacity(); n != 1 || c != 2 {
		t.Errorf("Count = %d, Capacity = %d, want the replacement kept with its 2 slots", n, c)
	}
}

// The tunnel ends with the first certificate in its chain to expire.
func TestChainNotAfter_IsTheEarliestInTheChain(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{NotAfter: now.Add(2 * time.Hour)}
	ca := &x509.Certificate{NotAfter: now.Add(time.Hour)}
	if got := chainNotAfter([]*x509.Certificate{leaf, ca}); !got.Equal(ca.NotAfter) {
		t.Errorf("chainNotAfter = %v, want the CA's %v", got, ca.NotAfter)
	}
}

// --- a newer tunnel from the same key ---

// A worker that renewed opens a second tunnel while work runs on the first:
// new work goes to the new one, the old one finishes its call undisturbed and
// closes with it. An idle old tunnel closes at once.
func TestBackends_ANewerTunnelTakesNewWorkAndTheOldOneFinishesItsOwn(t *testing.T) {
	b := NewBackends()
	pool := poolWith(t, 2)
	oldSrv := tunnelTo(t, b, "w")
	defer oldSrv.Stop()
	pick := TicketPicker(pool, b, nil)
	running, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	newSrv := tunnelTo(t, b, "w")
	defer newSrv.Stop()
	fresh, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatalf("new work with a newer tunnel attached: %v", err)
	}
	if fresh.Conn == running.Conn {
		t.Fatal("new work went to the replaced tunnel")
	}
	time.Sleep(50 * time.Millisecond)
	if st := running.Conn.GetState(); st == connectivity.Shutdown {
		t.Fatal("the replaced tunnel was closed under its running call")
	}
	if n := b.Count(); n != 1 {
		t.Errorf("Count = %d, want one worker", n)
	}
	running.Release()
	eventually(t, "the replaced tunnel closes with its last call", func() bool {
		return running.Conn.GetState() == connectivity.Shutdown
	})
	if st := fresh.Conn.GetState(); st == connectivity.Shutdown {
		t.Error("the old tunnel's close took the new one with it")
	}
	fresh.Release()

	idle := fresh.Conn
	third := tunnelTo(t, b, "w")
	defer third.Stop()
	eventually(t, "an idle replaced tunnel closes at once", func() bool { return idle.GetState() == connectivity.Shutdown })
}

// A ban while a renewed worker holds two tunnels closes both at once, the
// one still finishing old work included.
func TestBackends_ABanDuringTheOverlapClosesBothTunnels(t *testing.T) {
	b := NewBackends()
	b.SetExpiryGrace(time.Minute)
	pool := poolWith(t, 2)
	oldSrv := tunnelTo(t, b, "w")
	defer oldSrv.Stop()
	pick := TicketPicker(pool, b, nil)
	running, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	newSrv := tunnelTo(t, b, "w")
	defer newSrv.Stop()
	fresh, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	b.DropWhere(func(fp string) bool { return fp == "w" })
	eventually(t, "both tunnels close", func() bool {
		return running.Conn.GetState() == connectivity.Shutdown && fresh.Conn.GetState() == connectivity.Shutdown
	})
	running.Release()
	fresh.Release()
	if st := pool.Stats(); st.Held() != 0 {
		t.Errorf("pool = %+v, want both cut calls' slots back", st)
	}
}

// A replaced tunnel still running work at its own certificate's expiry gets
// the grace, then closes; the new tunnel is untouched.
func TestBackends_AReplacedTunnelStillEndsWithItsCertificate(t *testing.T) {
	b := NewBackends()
	b.SetExpiryGrace(50 * time.Millisecond)
	pool := poolWith(t, 2)
	oldSrv := tunnelTo(t, b, "w")
	defer oldSrv.Stop()
	pick := TicketPicker(pool, b, nil)
	running, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	b.ExpireAt("w", running.Conn, time.Now().Add(100*time.Millisecond))
	newSrv := tunnelTo(t, b, "w")
	defer newSrv.Stop()
	eventually(t, "the replaced tunnel closes after its expiry and grace", func() bool {
		return running.Conn.GetState() == connectivity.Shutdown
	})
	if n, c := b.Count(), b.Capacity(); n != 1 || c != 1 {
		t.Errorf("Count = %d, Capacity = %d, want the new tunnel kept", n, c)
	}
	running.Release()
}
