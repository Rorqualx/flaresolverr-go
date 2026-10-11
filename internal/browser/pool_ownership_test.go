package browser

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
)

// waitFor polls cond until it returns true or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}

// acquireAll checks out every browser in the pool and fails if the pool hands
// out the same browser twice or more browsers than it has slots.
func acquireAll(t *testing.T, pool *Pool) []*rod.Browser {
	t.Helper()
	seen := make(map[*rod.Browser]struct{})
	var out []*rod.Browser
	for i := 0; i < pool.Size(); i++ {
		b, err := pool.Acquire(context.Background())
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		if _, dup := seen[b]; dup {
			t.Fatalf("pool handed out the same browser twice")
		}
		seen[b] = struct{}{}
		out = append(out, b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if extra, err := pool.Acquire(ctx); err == nil {
		pool.Release(extra)
		t.Fatalf("pool handed out more browsers than its size %d", pool.Size())
	}
	return out
}

// canOpenPage reports whether the browser is still alive and usable.
func canOpenPage(b *rod.Browser) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	page, err := b.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return false
	}
	return page.Context(ctx).Close() == nil
}

func newTestPool(t *testing.T) *Pool {
	t.Helper()
	pool, err := NewPool(testConfig())
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func TestPoolDuplicateReleaseIgnored(t *testing.T) {
	skipCI(t)
	pool := newTestPool(t)

	b, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	pool.Release(b)
	pool.Release(b) // must not queue the browser a second time

	if got := pool.Available(); got != pool.Size() {
		t.Errorf("Available() = %d after duplicate release, want %d", got, pool.Size())
	}
	for _, b := range acquireAll(t, pool) {
		pool.Release(b)
	}
}

func TestPoolReleaseForeignBrowserClosesIt(t *testing.T) {
	skipCI(t)
	pool := newTestPool(t)

	foreign, err := pool.SpawnWithProxy(context.Background(), "")
	if err != nil {
		t.Fatalf("SpawnWithProxy failed: %v", err)
	}
	pool.Release(foreign) // not a pool member: must be closed, never queued

	if _, tracked := pool.launchers.Load(foreign); tracked {
		t.Error("foreign browser was not cleaned up by Release")
	}
	if got := pool.Available(); got != pool.Size() {
		t.Errorf("Available() = %d, want %d", got, pool.Size())
	}
	for _, b := range acquireAll(t, pool) {
		if b == foreign {
			t.Error("foreign browser entered the shared pool")
		}
		pool.Release(b)
	}
}

func TestPoolRecycleNeverClosesInUseBrowser(t *testing.T) {
	skipCI(t)
	pool := newTestPool(t)

	inUse, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	pool.recycleAll() // memory-pressure path: every slot qualifies

	// The idle slot is replaced; the checked-out browser must survive.
	waitFor(t, 60*time.Second, "idle slot to be replaced", func() bool {
		return pool.Available() == pool.Size()-1 && pool.Stats().Recycled >= 1
	})
	if !canOpenPage(inUse) {
		t.Fatal("checked-out browser was closed by recycleAll")
	}

	// Releasing it performs the deferred recycle.
	pool.Release(inUse)
	waitFor(t, 60*time.Second, "released browser to be replaced", func() bool {
		return pool.Available() == pool.Size() && pool.Stats().Recycled >= 2
	})
	for _, b := range acquireAll(t, pool) {
		if b == inUse {
			t.Error("browser flagged for recycle was returned to the pool")
		}
		pool.Release(b)
	}
}

func TestRecycleBrowserDefersUntilRelease(t *testing.T) {
	skipCI(t)
	pool := newTestPool(t)

	foreign, err := pool.SpawnWithProxy(context.Background(), "")
	if err != nil {
		t.Fatalf("SpawnWithProxy failed: %v", err)
	}
	defer pool.CleanupBrowser(foreign)
	pool.RecycleBrowser(foreign) // not pooled: must not spawn a pool browser

	b, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	pool.RecycleBrowser(b)
	if !canOpenPage(b) {
		t.Fatal("RecycleBrowser closed a browser that is still checked out")
	}
	if got := pool.Stats().Recycled; got != 0 {
		t.Errorf("Recycled = %d before release, want 0", got)
	}

	pool.Release(b)
	waitFor(t, 60*time.Second, "deferred recycle to finish", func() bool {
		return pool.Available() == pool.Size()
	})
	if got := pool.Stats().Recycled; got != 1 {
		t.Errorf("Recycled = %d, want exactly 1", got)
	}
	for _, pooled := range acquireAll(t, pool) {
		if pooled == b || pooled == foreign {
			t.Error("recycled or foreign browser found in the pool")
		}
		pool.Release(pooled)
	}
}

func TestPoolDeadSlotIsRetried(t *testing.T) {
	skipCI(t)
	pool := newTestPool(t)

	allInState := func(want entryState) bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		for _, entry := range pool.browsers {
			if entry.state != want {
				return false
			}
		}
		return true
	}

	// Make every replacement launch fail, then recycle everything.
	goodPath := pool.config.BrowserPath
	pool.config.BrowserPath = "/nonexistent/browser-binary"
	pool.recycleAll()
	waitFor(t, 60*time.Second, "all slots to be marked dead", func() bool {
		return allInState(entryDead)
	})
	if got := pool.Available(); got != 0 {
		t.Errorf("Available() = %d with all slots dead, want 0", got)
	}

	// Once launching works again, the next health pass must refill the pool.
	pool.config.BrowserPath = goodPath
	pool.recycleWhere(func(*browserEntry) bool { return false })
	waitFor(t, 90*time.Second, "dead slots to be respawned", func() bool {
		return pool.Available() == pool.Size()
	})
	for _, b := range acquireAll(t, pool) {
		pool.Release(b)
	}
}

func TestSpawnWithOptionsFallsBackToDefaultProxy(t *testing.T) {
	skipCI(t)
	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	cfg.ProxyURL = "http://127.0.0.1:9" // nothing listens here; only the flag matters
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	b, err := pool.SpawnWithOptions(context.Background(), LaunchOptions{WindowSize: "1280,720"})
	if err != nil {
		t.Fatalf("SpawnWithOptions failed: %v", err)
	}
	defer pool.CleanupBrowser(b)

	v, ok := pool.launchers.Load(b)
	if !ok {
		t.Fatal("launcher not tracked for spawned browser")
	}
	l, ok := v.(*launcher.Launcher)
	if !ok {
		t.Fatalf("unexpected launcher type %T", v)
	}
	if got := l.Get(flags.ProxyServer); !strings.Contains(got, "127.0.0.1:9") {
		t.Errorf("proxy-server flag = %q, want the configured default proxy", got)
	}
}
