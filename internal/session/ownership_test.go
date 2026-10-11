package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// newPoolAndManager starts a real 2-browser pool and a session manager on it.
// The background TTL cleanup is effectively disabled so tests drive it directly.
func newPoolAndManager(t *testing.T) (*browser.Pool, *Manager) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	cfg := &config.Config{
		Headless:               true,
		BrowserPoolSize:        2,
		BrowserPoolTimeout:     10 * time.Second,
		MaxMemoryMB:            1024,
		SessionTTL:             time.Hour,
		SessionCleanupInterval: time.Hour,
		MaxSessions:            1,
	}
	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	manager := NewManager(cfg, pool)
	t.Cleanup(func() {
		manager.Close()
		pool.Close()
	})
	return pool, manager
}

func mustAcquire(t *testing.T, pool *browser.Pool) *rod.Browser {
	t.Helper()
	b, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	return b
}

// TestCreateLeavesBrowserWithCallerOnError verifies Create has no release side
// effects: on every error path the caller still owns the browser.
func TestCreateLeavesBrowserWithCallerOnError(t *testing.T) {
	pool, manager := newPoolAndManager(t) // MaxSessions is 1

	first := mustAcquire(t, pool)
	if _, err := manager.Create("session-a", first, 0); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{name: "duplicate id", id: "session-a", wantErr: types.ErrSessionAlreadyExists},
		{name: "session limit", id: "session-b", wantErr: types.ErrTooManySessions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			second := mustAcquire(t, pool)

			_, err := manager.Create(tt.id, second, 0)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Create error = %v, want %v", err, tt.wantErr)
			}
			if got := pool.Available(); got != 0 {
				t.Fatalf("Available() = %d after failed Create, want 0 (Create must not release)", got)
			}

			pool.Release(second) // the caller's single release
			if got := pool.Available(); got != 1 {
				t.Errorf("Available() = %d after caller release, want 1", got)
			}
		})
	}
}

// TestConcurrentDestroyReleasesBrowserOnce verifies only one of several
// concurrent Destroy calls tears the session down.
func TestConcurrentDestroyReleasesBrowserOnce(t *testing.T) {
	pool, manager := newPoolAndManager(t)

	if _, err := manager.Create("session-a", mustAcquire(t, pool), 0); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	const callers = 8
	var wg sync.WaitGroup
	results := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = manager.Destroy("session-a")
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Errorf("%d Destroy calls succeeded, want exactly 1", succeeded)
	}
	if got := pool.Stats().Released; got != 1 {
		t.Errorf("pool Released = %d, want 1", got)
	}
	if got := pool.Available(); got != pool.Size() {
		t.Errorf("Available() = %d, want %d", got, pool.Size())
	}
}

// TestCleanupExpiredSkipsSessionInUse verifies the TTL cleanup never closes a
// session's page while a request still holds it.
func TestCleanupExpiredSkipsSessionInUse(t *testing.T) {
	pool, manager := newPoolAndManager(t)

	sess, err := manager.Create("session-a", mustAcquire(t, pool), time.Millisecond)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	page, release := sess.AcquirePageWithRelease()
	if page == nil {
		t.Fatal("AcquirePage returned nil")
	}
	time.Sleep(20 * time.Millisecond) // well past the 1ms TTL

	manager.cleanupExpired()

	if _, err := manager.Get("session-a"); err != nil {
		t.Fatalf("in-use session was expired: %v", err)
	}
	if _, err := page.Info(); err != nil {
		t.Fatalf("in-use session page was closed: %v", err)
	}
	if got := pool.Stats().Released; got != 0 {
		t.Errorf("pool Released = %d while session in use, want 0", got)
	}

	// Once idle and past its TTL again, it is cleaned up normally.
	release()
	sess.lastUsed.Store(time.Now().Add(-time.Minute).UnixNano())
	manager.cleanupExpired()

	if _, err := manager.Get("session-a"); !errors.Is(err, types.ErrSessionNotFound) {
		t.Errorf("Get after expiry = %v, want ErrSessionNotFound", err)
	}
	if got := pool.Stats().Released; got != 1 {
		t.Errorf("pool Released = %d after expiry, want 1", got)
	}
}

// TestDestroyTimeoutLeavesSessionUsable verifies a Destroy that gives up
// because the session is busy does not strand it in a half-destroyed state.
func TestDestroyTimeoutLeavesSessionUsable(t *testing.T) {
	pool, manager := newPoolAndManager(t)

	sess, err := manager.Create("session-a", mustAcquire(t, pool), 0)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	page, release := sess.AcquirePageWithRelease()
	if page == nil {
		t.Fatal("AcquirePage returned nil")
	}

	if err := manager.Destroy("session-a"); !errors.Is(err, types.ErrSessionInUse) {
		t.Fatalf("Destroy of busy session = %v, want ErrSessionInUse", err)
	}
	if _, err := manager.Get("session-a"); err != nil {
		t.Fatalf("session unusable after failed Destroy: %v", err)
	}

	release()
	if err := manager.Destroy("session-a"); err != nil {
		t.Fatalf("Destroy after release failed: %v", err)
	}
	if got := pool.Available(); got != pool.Size() {
		t.Errorf("Available() = %d, want %d", got, pool.Size())
	}
}
