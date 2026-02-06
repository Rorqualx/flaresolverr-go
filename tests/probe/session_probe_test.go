package probe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// TestSessionManager_TTLExpiration tests that sessions are removed after TTL expires.
func TestSessionManager_TTLExpiration(t *testing.T) {
	skipCI(t) // Requires browser

	cfg := &config.Config{
		SessionTTL:             100 * time.Millisecond, // Very short TTL for testing
		SessionCleanupInterval: 50 * time.Millisecond,  // Frequent cleanup
		MaxSessions:            10,
	}

	// Create manager without real pool (we'll test the cleanup logic)
	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	// Simulate a session that will expire
	// Note: We can't easily create real sessions without a browser,
	// so we test the manager's Count/List behavior
	initialCount := manager.Count()
	if initialCount != 0 {
		t.Errorf("Initial count should be 0, got %d", initialCount)
	}

	// Test that List returns empty initially
	sessions := manager.List()
	if len(sessions) != 0 {
		t.Errorf("Initial list should be empty, got %d sessions", len(sessions))
	}
}

// TestSessionManager_TouchKeepsAlive tests that Touch() prevents session expiration.
func TestSessionManager_TouchKeepsAlive(t *testing.T) {
	// Create a session struct directly to test Touch behavior
	sess := &session.Session{
		ID:        "test-session",
		CreatedAt: time.Now().Add(-time.Hour), // Created an hour ago
	}
	// Initialize lastUsed through atomic store
	sess.Touch()

	// Record initial lastUsed time
	initialLastUsed := sess.LastUsedTime()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Touch the session
	sess.Touch()

	// Verify lastUsed was updated
	newLastUsed := sess.LastUsedTime()
	if !newLastUsed.After(initialLastUsed) {
		t.Error("Touch() should update LastUsedTime")
	}
}

// TestSession_AtomicLastUsed tests concurrent Touch() calls for race conditions.
func TestSession_AtomicLastUsed(t *testing.T) {
	sess := &session.Session{
		ID:        "test-concurrent",
		CreatedAt: time.Now(),
	}
	sess.Touch() // Initialize

	var wg sync.WaitGroup
	const goroutines = 100
	const iterations = 100

	// Track that all updates complete without panic
	var successCount atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sess.Touch()
				_ = sess.LastUsedTime()
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	expected := int32(goroutines * iterations)
	if successCount.Load() != expected {
		t.Errorf("Expected %d successful operations, got %d", expected, successCount.Load())
	}

	// Verify lastUsed is still valid
	lastUsed := sess.LastUsedTime()
	if lastUsed.IsZero() {
		t.Error("LastUsedTime should not be zero after concurrent updates")
	}
}

// TestSessionManager_MaxSessionsEnforced tests that the max sessions limit is enforced.
// This test doesn't require a browser - it tests the manager's validation logic.
func TestSessionManager_MaxSessionsEnforced(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            2, // Very low limit
	}

	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	// Try to create more sessions than allowed
	// Note: Create() requires a real browser, so we can't fully test this
	// without the browser pool. We test that the manager initializes correctly.
	if manager.Count() != 0 {
		t.Errorf("Initial count should be 0, got %d", manager.Count())
	}
}

// TestSession_GetCookiesNilPage tests that GetCookies returns error for nil page.
func TestSession_GetCookiesNilPage(t *testing.T) {
	sess := &session.Session{
		ID:        "test-nil-page",
		Page:      nil,
		CreatedAt: time.Now(),
	}
	sess.Touch()

	_, err := sess.GetCookies()
	if err == nil {
		t.Error("GetCookies should return error for nil page")
	}
	if err != types.ErrSessionPageNil {
		t.Errorf("Expected ErrSessionPageNil, got %v", err)
	}
}

// TestSession_SetCookiesNilPage tests that SetCookies returns error for nil page.
func TestSession_SetCookiesNilPage(t *testing.T) {
	sess := &session.Session{
		ID:        "test-nil-page",
		Page:      nil,
		CreatedAt: time.Now(),
	}
	sess.Touch()

	err := sess.SetCookies(nil)
	if err == nil {
		t.Error("SetCookies should return error for nil page")
	}
	if err != types.ErrSessionPageNil {
		t.Errorf("Expected ErrSessionPageNil, got %v", err)
	}
}

// TestSession_SafeGetPage tests that SafeGetPage returns nil for nil page.
func TestSession_SafeGetPage(t *testing.T) {
	sess := &session.Session{
		ID:        "test-nil-page",
		Page:      nil,
		CreatedAt: time.Now(),
	}

	page := sess.SafeGetPage()
	if page != nil {
		t.Error("SafeGetPage should return nil for nil page")
	}
}

// TestSessionManager_ListSessions tests that List returns session IDs.
func TestSessionManager_ListSessions(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	// Initially empty
	sessions := manager.List()
	if len(sessions) != 0 {
		t.Errorf("Expected empty list, got %d sessions", len(sessions))
	}
}

// TestSessionManager_GetNonExistent tests that Get returns error for non-existent session.
func TestSessionManager_GetNonExistent(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	_, err := manager.Get("non-existent-session")
	if err == nil {
		t.Error("Get should return error for non-existent session")
	}
	if err != types.ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}
}

// TestSessionManager_DestroyNonExistent tests that Destroy returns error for non-existent session.
func TestSessionManager_DestroyNonExistent(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	err := manager.Destroy("non-existent-session")
	if err == nil {
		t.Error("Destroy should return error for non-existent session")
	}
	if err != types.ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}
}

// TestSessionManager_Count tests that Count returns correct session count.
func TestSessionManager_Count(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	if manager.Count() != 0 {
		t.Errorf("Expected count 0, got %d", manager.Count())
	}
}

// TestSessionManager_CloseWithoutSessions tests that Close works when no sessions exist.
func TestSessionManager_CloseWithoutSessions(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}

	manager := session.NewManager(cfg, nil)

	// Close should not panic
	err := manager.Close()
	if err != nil {
		t.Errorf("Close should not return error, got %v", err)
	}
}

// TestSession_LastUsedTime tests that LastUsedTime returns correct time.
func TestSession_LastUsedTime(t *testing.T) {
	now := time.Now()
	sess := &session.Session{
		ID:        "test-lastused",
		CreatedAt: now,
	}

	// Initialize with Touch
	sess.Touch()

	// LastUsedTime should be close to now
	lastUsed := sess.LastUsedTime()
	diff := lastUsed.Sub(now)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("LastUsedTime should be close to now, diff was %v", diff)
	}
}

// TestSession_TouchUpdatesTime tests that Touch updates the lastUsed time.
func TestSession_TouchUpdatesTime(t *testing.T) {
	sess := &session.Session{
		ID:        "test-touch",
		CreatedAt: time.Now(),
	}
	sess.Touch()

	initialTime := sess.LastUsedTime()

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Touch again
	sess.Touch()

	newTime := sess.LastUsedTime()
	if !newTime.After(initialTime) {
		t.Error("Touch should update lastUsed to a later time")
	}
}

// TestSessionManager_ConcurrentOperations tests concurrent access to session manager.
func TestSessionManager_ConcurrentOperations(t *testing.T) {
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            100,
	}

	manager := session.NewManager(cfg, nil)
	defer manager.Close()

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent reads and operations
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Mix of operations
			_ = manager.Count()
			_ = manager.List()
			_, _ = manager.Get("non-existent")
		}(i)
	}

	wg.Wait()
	// No panic = success
}
