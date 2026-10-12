package browser

import (
	"context"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

// TestClosePage_StuckRenderer checks that a page running a script that never
// returns cannot hold its request: closing it gives up, disposing its browser
// context removes it, and the pooled browser goes back and serves again.
func TestClosePage_StuckRenderer(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	poolBrowser, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}

	isolated, dispose, err := NewIsolatedContext(poolBrowser, "")
	if err != nil {
		pool.Release(poolBrowser)
		t.Fatalf("Failed to create browser context: %v", err)
	}

	page, err := isolated.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		dispose()
		pool.Release(poolBrowser)
		t.Fatalf("Failed to create page: %v", err)
	}

	// The eval never returns; only its deadline ends it.
	if _, err := page.Timeout(time.Second).Eval(`() => { while (true) {} }`); err == nil {
		t.Fatal("expected the endless script to time out")
	}

	start := time.Now()
	ClosePage(page)
	dispose()
	pool.Release(poolBrowser)
	if elapsed := time.Since(start); elapsed > pageCloseTimeout+browserContextTimeout+releaseCleanupTimeout {
		t.Errorf("cleanup of a stuck page took %v", elapsed)
	}

	// Whether the browser was returned or replaced, the slot must serve again.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	next, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("pool did not recover after a stuck page: %v", err)
	}
	defer pool.Release(next)

	nextPage, err := next.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page after recovery: %v", err)
	}
	defer ClosePage(nextPage)
	res, err := nextPage.Timeout(10 * time.Second).Eval(`() => 1 + 1`)
	if err != nil || res.Value.Int() != 2 {
		t.Fatalf("browser not usable after a stuck page: %v", err)
	}
}
