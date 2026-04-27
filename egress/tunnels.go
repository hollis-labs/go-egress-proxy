package egress

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// tunnels coordinates the goroutines spawned by CONNECT tunnel handlers.
// It provides a context that is cancelled on shutdown, a WaitGroup that
// shutdown drains with a bounded window, and an active-count for tests
// that assert no tunnel leaked.
//
// The internal/lifecycle + internal/safego packages in nanite played this
// role originally; this is a stripped-down stdlib equivalent so this lib
// has zero third-party deps. Panics are not silently swallowed — tunnel
// goroutines do not run user code, only stdlib io.Copy, so the cost of
// adding a recover wrapper outweighs the benefit.
type tunnels struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	active atomic.Int64
	closed atomic.Bool
}

func newTunnels() *tunnels {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunnels{ctx: ctx, cancel: cancel}
}

// go_ spawns fn as a tracked goroutine. fn receives the tunnels' context,
// which is cancelled on shutdown. If shutdown has already been called,
// go_ returns without spawning. The trailing underscore avoids shadowing
// the Go keyword.
func (t *tunnels) go_(_ string, fn func(ctx context.Context)) {
	if t.closed.Load() {
		return
	}
	t.wg.Add(1)
	t.active.Add(1)
	go func() {
		defer t.wg.Done()
		defer t.active.Add(-1)
		fn(t.ctx)
	}()
}

// shutdown cancels the tunnels' context and waits up to maxWait for all
// tracked goroutines to exit. Safe to call multiple times.
func (t *tunnels) shutdown(maxWait time.Duration) {
	t.closed.Store(true)
	t.cancel()
	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(maxWait):
	}
}

// activeCount returns the current number of running tunnel goroutines.
// Used by tests to assert no leak after shutdown.
func (t *tunnels) activeCount() int64 { return t.active.Load() }
