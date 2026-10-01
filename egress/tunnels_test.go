package egress

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// CW-20260930-0031: spawn racing shutdown. Every tunnel goroutine either
// registers before shutdown starts waiting, and is drained by it, or is
// refused. None may start after shutdown has returned, and none may still
// be running when shutdown returns before its drain window.
func TestTunnelsSpawnRacingShutdown(t *testing.T) {
	for i := 0; i < 500; i++ {
		tn := newTunnels()
		start := make(chan struct{})
		var spawned bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			spawned = tn.spawn("test", func(ctx context.Context) { <-ctx.Done() })
		}()
		go func() {
			defer wg.Done()
			<-start
			tn.shutdown(5 * time.Second)
		}()
		close(start)
		wg.Wait()
		if n := tn.activeCount(); n != 0 {
			t.Fatalf("iteration %d: %d tunnel goroutine(s) still running after shutdown returned (spawned=%v)", i, n, spawned)
		}
	}
}

func TestTunnelsSpawnAfterShutdownIsRefused(t *testing.T) {
	tn := newTunnels()
	tn.shutdown(time.Second)
	ran := make(chan struct{}, 1)
	if tn.spawn("test", func(context.Context) { ran <- struct{}{} }) {
		t.Fatal("spawn after shutdown reported a spawned goroutine")
	}
	select {
	case <-ran:
		t.Fatal("spawn after shutdown ran its function")
	case <-time.After(50 * time.Millisecond):
	}
}

// A CONNECT that reaches runTunnel after Stop has begun gets no copy
// goroutines. runTunnel must still return and close both conns rather than
// wait forever for copies that were never started.
func TestRunTunnelReturnsWhenTunnelsAreShutDown(t *testing.T) {
	p := New(Config{})
	p.tunnels = newTunnels()
	p.tunnels.shutdown(time.Second)

	client, clientPeer := net.Pipe()
	target, targetPeer := net.Pipe()
	defer func() { _ = clientPeer.Close() }()
	defer func() { _ = targetPeer.Close() }()
	p.trackConn(client)
	p.trackConn(target)

	done := make(chan struct{})
	go func() {
		p.runTunnel(client, target)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runTunnel did not return after the tunnels were shut down")
	}
	// Both ends are closed: the peers see EOF or a closed pipe.
	if _, err := clientPeer.Write([]byte("x")); err == nil {
		t.Error("client conn still open after runTunnel returned")
	}
	if _, err := targetPeer.Write([]byte("x")); err == nil {
		t.Error("target conn still open after runTunnel returned")
	}
	p.connsMu.Lock()
	n := len(p.conns)
	p.connsMu.Unlock()
	if n != 0 {
		t.Errorf("%d conn(s) still tracked after runTunnel returned", n)
	}
}
