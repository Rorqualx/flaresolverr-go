package browser

import (
	"context"
	"os"
	"testing"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
)

// TestCleanupBrowserClearsLauncherMap verifies the launcher tracking wiring:
// every spawn stores a launcher in p.launchers, and CleanupBrowser removes it
// along with the controlURLs entry. This is the structural prerequisite for
// the on-disk cleanup in TestCleanupBrowserRemovesUserDataDir below.
//
// Regression guard for GitHub issue #6: prior to the fix, the launcher was
// discarded after Launch(), so Cleanup() could never be called.
func TestCleanupBrowserClearsLauncherMap(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	browser, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}

	if _, ok := pool.launchers.Load(browser); !ok {
		t.Fatal("expected launcher to be stored in p.launchers after spawn")
	}
	if _, ok := pool.controlURLs.Load(browser); !ok {
		t.Fatal("expected control URL to be stored in p.controlURLs after spawn")
	}

	pool.CleanupBrowser(browser)

	if _, ok := pool.launchers.Load(browser); ok {
		t.Error("expected launcher entry to be cleared after CleanupBrowser")
	}
	if _, ok := pool.controlURLs.Load(browser); ok {
		t.Error("expected controlURLs entry to be cleared after CleanupBrowser")
	}
}

// TestCleanupBrowserRemovesUserDataDir is the end-to-end behavioral test for
// GitHub issue #6. It captures the on-disk user-data dir path from Rod's
// launcher, calls CleanupBrowser, and asserts the dir is gone.
//
// Before the fix, this dir was never deleted and accumulated under /tmp/rod
// until the container's writable layer filled up.
func TestCleanupBrowserRemovesUserDataDir(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	browser, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}

	v, ok := pool.launchers.Load(browser)
	if !ok {
		t.Fatal("expected launcher to be stored in p.launchers")
	}
	l, ok := v.(*launcher.Launcher)
	if !ok {
		t.Fatalf("expected *launcher.Launcher in map, got %T", v)
	}

	dir := l.Get(flags.UserDataDir)
	if dir == "" {
		t.Fatal("expected non-empty user-data dir from launcher")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected user-data dir %s to exist before cleanup: %v", dir, err)
	}

	pool.CleanupBrowser(browser)

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected user-data dir %s to be removed after CleanupBrowser, got Stat err=%v", dir, err)
	}
}
