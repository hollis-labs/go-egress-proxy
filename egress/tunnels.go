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
// This is a stdlib-only goroutine coordinator so the package has zero
// third-party dependencies. Panics are not silently swallowed — tunnel
// goroutines do not run user code, only stdlib io.Copy, so the cost of
// adding a recover wrapper outweighs the benefit.
type tunnels struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	active atomic.Int64

	// mu orders go_'s closed check and wg.Add against shutdown setting
	// closed, so every Add happens before shutdown's Wait or is refused.
	// Without it an Add could land while Wait was already running on a zero
	// counter (CW-20260930-0031): a documented WaitGroup misuse, and a
	// tunnel shutdown never waited for.
	mu     sync.Mutex
	closed bool
}

func newTunnels() *tunnels {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunnels{ctx: ctx, cancel: cancel}
}

// go_ spawns fn as a tracked goroutine and reports whether it did. fn
// receives the tunnels' context, which is cancelled on shutdown. Once
// shutdown has been called, go_ spawns nothing and returns false. The
// trailing underscore avoids shadowing the Go keyword.
func (t *tunnels) go_(_ string, fn func(ctx context.Context)) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	t.wg.Add(1)
	t.active.Add(1)
	t.mu.Unlock()
	go func() {
		defer t.wg.Done()
		defer t.active.Add(-1)
		fn(t.ctx)
	}()
	return true
}

// shutdown cancels the tunnels' context and waits up to maxWait for all
// tracked goroutines to exit. Safe to call multiple times.
func (t *tunnels) shutdown(maxWait time.Duration) {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
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
