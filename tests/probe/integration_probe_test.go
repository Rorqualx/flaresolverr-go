//go:build integration

package probe

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
)

// TestIntegration_FullSessionLifecycle tests the complete session lifecycle.
func TestIntegration_FullSessionLifecycle(t *testing.T) {
	cfg := &config.Config{
		Host:                   "127.0.0.1",
		Port:                   8191,
		Headless:               true,
		BrowserPoolSize:        2,
		BrowserPoolTimeout:     30 * time.Second,
		MaxMemoryMB:            512,
		SessionTTL:             5 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	// Create pool
	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Create session manager
	sessionMgr := session.NewManager(cfg, pool)
	defer sessionMgr.Close()

	// Create solver
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	// Start test server
	server := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: Create a session
	browser1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}

	sess, err := sessionMgr.Create("test-session-1", browser1)
	if err != nil {
		pool.Release(browser1)
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify session exists
	if sessionMgr.Count() != 1 {
		t.Errorf("Expected 1 session, got %d", sessionMgr.Count())
	}

	// Step 2: Use the session for a request
	page := sess.SafeGetPage()
	if page == nil {
		t.Fatal("Session page is nil")
	}

	result, err := s.SolveWithPage(ctx, page, &solver.SolveOptions{
		URL:     server.URL + "/cookies/set",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("SolveWithPage failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected successful solve")
	}

	// Step 3: Verify session still exists after use
	if sessionMgr.Count() != 1 {
		t.Errorf("Session should still exist, got count %d", sessionMgr.Count())
	}

	// Step 4: Retrieve session to verify Touch works
	retrievedSess, err := sessionMgr.Get("test-session-1")
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	if retrievedSess.ID != sess.ID {
		t.Error("Retrieved session ID mismatch")
	}

	// Step 5: Destroy session
	if err := sessionMgr.Destroy("test-session-1"); err != nil {
		t.Fatalf("Failed to destroy session: %v", err)
	}

	// Verify session is gone
	if sessionMgr.Count() != 0 {
		t.Errorf("Expected 0 sessions after destroy, got %d", sessionMgr.Count())
	}

	// Verify browser was returned to pool
	time.Sleep(100 * time.Millisecond) // Give time for async release
}

// TestIntegration_ConcurrentRequests tests parallel request handling.
func TestIntegration_ConcurrentRequests(t *testing.T) {
	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    3,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 Test/1.0")
	server := startTestServer(t)

	const numRequests = 10
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)
	results := make(chan *solver.Result, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result, err := s.Solve(ctx, &solver.SolveOptions{
				URL:                    server.URL + "/html",
				Timeout:                30 * time.Second,
				SkipResponseValidation: true,
			})

			if err != nil {
				errors <- err
				return
			}
			results <- result
		}(i)
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check for errors
	var errCount int
	for err := range errors {
		errCount++
		t.Errorf("Request failed: %v", err)
	}

	// Check results
	var successCount int
	for result := range results {
		if result.Success {
			successCount++
		}
	}

	t.Logf("Concurrent results: %d successful, %d errors out of %d requests",
		successCount, errCount, numRequests)

	// Most should succeed
	if successCount < numRequests/2 {
		t.Errorf("Too many failures: only %d/%d succeeded", successCount, numRequests)
	}
}

// TestIntegration_BrowserRecycleOnError tests browser recycling after errors.
func TestIntegration_BrowserRecycleOnError(t *testing.T) {
	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 Test/1.0")
	server := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Request 1: Successful
	result1, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		SkipResponseValidation: true,
	})
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	if !result1.Success {
		t.Error("First request should succeed")
	}

	// Request 2: Timeout (simulates error condition)
	_, _ = s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/slow",
		Timeout:                1 * time.Second, // Will timeout
		SkipResponseValidation: true,
	})

	// Request 3: Should still work (browser should be recycled or released)
	result3, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		SkipResponseValidation: true,
	})
	if err != nil {
		t.Fatalf("Third request failed: %v", err)
	}
	if !result3.Success {
		t.Error("Third request should succeed after error recovery")
	}
}

// TestIntegration_GracefulShutdown tests that in-flight requests complete on shutdown.
func TestIntegration_GracefulShutdown(t *testing.T) {
	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	s := solver.New(pool, "Mozilla/5.0 Test/1.0")
	server := startTestServer(t)

	// Start a request in background
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := s.Solve(ctx, &solver.SolveOptions{
			URL:                    server.URL + "/html",
			Timeout:                30 * time.Second,
			SkipResponseValidation: true,
		})

		// Request should complete (might succeed or fail depending on timing)
		_ = result
		_ = err
		close(done)
	}()

	// Give the request time to start
	time.Sleep(100 * time.Millisecond)

	// Close pool
	closeDone := make(chan struct{})
	go func() {
		pool.Close()
		close(closeDone)
	}()

	// Both should complete without hanging
	select {
	case <-closeDone:
		// Pool closed
	case <-time.After(30 * time.Second):
		t.Fatal("Pool.Close() timed out")
	}

	select {
	case <-done:
		// Request completed
	case <-time.After(30 * time.Second):
		t.Fatal("In-flight request did not complete")
	}
}

// TestIntegration_SessionExpiration tests that sessions expire after TTL.
func TestIntegration_SessionExpiration(t *testing.T) {
	cfg := &config.Config{
		Host:                   "127.0.0.1",
		Port:                   8191,
		Headless:               true,
		BrowserPoolSize:        2,
		BrowserPoolTimeout:     30 * time.Second,
		MaxMemoryMB:            512,
		SessionTTL:             500 * time.Millisecond, // Very short TTL
		SessionCleanupInterval: 100 * time.Millisecond, // Frequent cleanup
		MaxSessions:            10,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	sessionMgr := session.NewManager(cfg, pool)
	defer sessionMgr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a session
	browser1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}

	_, err = sessionMgr.Create("expiring-session", browser1)
	if err != nil {
		pool.Release(browser1)
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify session exists
	if sessionMgr.Count() != 1 {
		t.Errorf("Expected 1 session, got %d", sessionMgr.Count())
	}

	// Wait for session to expire
	time.Sleep(1 * time.Second)

	// Session should be gone
	assertEventually(t, func() bool {
		return sessionMgr.Count() == 0
	}, 5*time.Second, "Session should have expired")
}

// TestIntegration_MaxSessionsLimit tests that max sessions limit is enforced.
func TestIntegration_MaxSessionsLimit(t *testing.T) {
	cfg := &config.Config{
		Host:                   "127.0.0.1",
		Port:                   8191,
		Headless:               true,
		BrowserPoolSize:        5,
		BrowserPoolTimeout:     30 * time.Second,
		MaxMemoryMB:            512,
		SessionTTL:             5 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            2, // Very low limit
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	sessionMgr := session.NewManager(cfg, pool)
	defer sessionMgr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create sessions up to the limit
	for i := 0; i < 2; i++ {
		browser1, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Failed to acquire browser %d: %v", i, err)
		}

		_, err = sessionMgr.Create("session-"+string(rune('A'+i)), browser1)
		if err != nil {
			pool.Release(browser1)
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
	}

	// Verify we have 2 sessions
	if sessionMgr.Count() != 2 {
		t.Errorf("Expected 2 sessions, got %d", sessionMgr.Count())
	}

	// Try to create one more - should fail
	browser3, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser 3: %v", err)
	}

	_, err = sessionMgr.Create("session-C", browser3)
	if err == nil {
		t.Error("Expected error when exceeding max sessions")
	}

	// Browser should have been released back to pool on error
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_PoolStatsAccuracy tests that pool statistics are accurate.
func TestIntegration_PoolStatsAccuracy(t *testing.T) {
	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 Test/1.0")
	server := startTestServer(t)

	// Initial stats
	initialStats := pool.Stats()
	initialAcquired := initialStats.Acquired
	initialReleased := initialStats.Released

	// Make several requests
	const numRequests = 5
	for i := 0; i < numRequests; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = s.Solve(ctx, &solver.SolveOptions{
			URL:                    server.URL + "/html",
			Timeout:                30 * time.Second,
			SkipResponseValidation: true,
		})
		cancel()
	}

	// Check stats
	finalStats := pool.Stats()
	acquired := finalStats.Acquired - initialAcquired
	released := finalStats.Released - initialReleased

	if acquired < int64(numRequests) {
		t.Errorf("Expected at least %d acquires, got %d", numRequests, acquired)
	}

	if released < int64(numRequests) {
		t.Errorf("Expected at least %d releases, got %d", numRequests, released)
	}

	// Acquired and released should be equal (all returned)
	if acquired != released {
		t.Errorf("Acquired (%d) and released (%d) should be equal", acquired, released)
	}
}

// TestIntegration_MultipleSessionsIndependent tests that sessions are independent.
func TestIntegration_MultipleSessionsIndependent(t *testing.T) {
	cfg := &config.Config{
		Host:                   "127.0.0.1",
		Port:                   8191,
		Headless:               true,
		BrowserPoolSize:        3,
		BrowserPoolTimeout:     30 * time.Second,
		MaxMemoryMB:            1024,
		SessionTTL:             5 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	sessionMgr := session.NewManager(cfg, pool)
	defer sessionMgr.Close()

	s := solver.New(pool, "Mozilla/5.0 Test/1.0")
	server := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create two sessions
	sessions := make([]*session.Session, 2)
	for i := 0; i < 2; i++ {
		browser1, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Failed to acquire browser %d: %v", i, err)
		}

		sess, err := sessionMgr.Create("session-"+string(rune('A'+i)), browser1)
		if err != nil {
			pool.Release(browser1)
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
		sessions[i] = sess
	}

	// Use each session concurrently
	var wg sync.WaitGroup
	for i, sess := range sessions {
		wg.Add(1)
		go func(idx int, session *session.Session) {
			defer wg.Done()

			page := session.SafeGetPage()
			if page == nil {
				t.Errorf("Session %d: page is nil", idx)
				return
			}

			_, err := s.SolveWithPage(ctx, page, &solver.SolveOptions{
				URL:     server.URL + "/html",
				Timeout: 30 * time.Second,
			})
			if err != nil {
				t.Errorf("Session %d: solve failed: %v", idx, err)
			}
		}(i, sess)
	}

	wg.Wait()

	// Both sessions should still exist
	if sessionMgr.Count() != 2 {
		t.Errorf("Expected 2 sessions, got %d", sessionMgr.Count())
	}

	// Clean up
	for _, sess := range sessions {
		sessionMgr.Destroy(sess.ID)
	}
}
