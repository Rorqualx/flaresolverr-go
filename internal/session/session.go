// Package session provides session management for persistent browser contexts.
// Sessions allow clients to maintain state (cookies, local storage) across requests.
package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Maximum number of concurrent page references allowed per session.
// This prevents unbounded growth from bugs or malicious usage.
const maxPageReferences = 100

// Session represents a persistent browser session.
// Sessions maintain their own page and cookies across multiple requests.
//
// Fix #23: Lock ordering documentation:
// When acquiring multiple locks, always acquire opMu before mu.
// - opMu: Serializes solve operations on the session (coarse-grained)
// - mu: Protects Page field access (fine-grained)
// Never hold mu while performing slow I/O operations.
type Session struct {
	ID        string
	Browser   *rod.Browser
	Page      *rod.Page
	CreatedAt time.Time
	lastUsed  atomic.Int64 // Unix nano timestamp for lock-free access
	mu        sync.Mutex   // Only used for page operations (GetCookies/SetCookies)

	// Reference counting for safe page access during concurrent destroy
	refCount atomic.Int32 // Number of active page references
	closing  atomic.Bool  // Set to true when session is being destroyed

	// Operation mutex to prevent concurrent solve operations on the same session
	// This ensures only one request can use the page at a time, preventing
	// page state corruption from concurrent navigation/actions
	// Fix #23: Always acquire opMu BEFORE mu when both are needed.
	opMu sync.Mutex
}

// Manager handles session lifecycle and cleanup.
// It maintains a map of active sessions and periodically cleans up expired ones.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	config   *config.Config
	pool     *browser.Pool // Pool reference for returning browsers on cleanup
	stopCh   chan struct{}
	wg       sync.WaitGroup // Track background goroutines for clean shutdown
}

// NewManager creates a new session manager.
// It starts a background goroutine for session cleanup.
// The pool parameter is used to return browsers when sessions are destroyed.
func NewManager(cfg *config.Config, pool *browser.Pool) *Manager {
	m := &Manager{
		sessions: make(map[string]*Session),
		config:   cfg,
		pool:     pool,
		stopCh:   make(chan struct{}),
	}

	// Start cleanup routine with WaitGroup tracking for clean shutdown
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.cleanupRoutine()
	}()

	log.Info().
		Dur("ttl", cfg.SessionTTL).
		Dur("cleanup_interval", cfg.SessionCleanupInterval).
		Int("max_sessions", cfg.MaxSessions).
		Msg("Session manager initialized")

	return m
}

// Create creates a new session with the given ID.
// Returns an error if the session already exists or max sessions is reached.
// The browser is returned to the pool on any error.
func (m *Manager) Create(id string, brow *rod.Browser) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session already exists
	if _, exists := m.sessions[id]; exists {
		// Return browser since we didn't use it
		if m.pool != nil {
			m.pool.Release(brow)
		}
		return nil, types.ErrSessionAlreadyExists
	}

	// Check max sessions limit
	if len(m.sessions) >= m.config.MaxSessions {
		// Return browser since we can't create session
		if m.pool != nil {
			m.pool.Release(brow)
		}
		return nil, types.ErrTooManySessions
	}

	// Create a new page for this session
	page, err := brow.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		// CRITICAL: Return browser on page creation failure
		if m.pool != nil {
			m.pool.Release(brow)
		}
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        id,
		Browser:   brow,
		Page:      page,
		CreatedAt: now,
	}
	session.lastUsed.Store(now.UnixNano())

	m.sessions[id] = session

	log.Info().
		Str("session_id", id).
		Int("total_sessions", len(m.sessions)).
		Msg("Session created")

	return session, nil
}

// Get retrieves a session by ID.
// Returns ErrSessionNotFound if the session doesn't exist or is being destroyed.
// Updates the LastUsed timestamp on access using atomic operation.
// Fix: Check closing flag while holding lock to prevent race with Destroy().
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.RLock()
	session, exists := m.sessions[id]
	if !exists {
		m.mu.RUnlock()
		return nil, types.ErrSessionNotFound
	}

	// Check if session is being destroyed while holding lock
	// This prevents the race where Destroy() sets closing=true between our
	// map lookup and closing check
	isClosing := session.closing.Load()
	m.mu.RUnlock()

	if isClosing {
		return nil, types.ErrSessionNotFound
	}

	// Update last used time atomically - no lock needed
	session.Touch()

	return session, nil
}

// Destroy removes a session and closes its resources.
// The browser is returned to the pool after cleanup.
// Uses reference counting to safely wait for in-flight page operations.
// Returns ErrSessionInUse if the session is still being used after timeout.
func (m *Manager) Destroy(id string) error {
	m.mu.Lock()
	session, exists := m.sessions[id]
	if exists {
		// Mark session as closing BEFORE removing from map
		// This prevents new AcquirePage calls from succeeding
		session.closing.Store(true)
		// NOTE: Keep session in map while waiting for references to drain.
		// This prevents a race where another goroutine could create a new session
		// with the same ID while we're waiting.
	}
	m.mu.Unlock()

	if !exists {
		return types.ErrSessionNotFound
	}

	// Wait for any in-flight page operations to complete (up to 5 seconds)
	if !session.waitForReferences(5 * time.Second) {
		// Fix #12: Keep closing=true on timeout to prevent new operations
		// from starting. The session will be cleaned up by the next cleanup
		// cycle. DON'T reset closing flag - this prevents a race where
		// new operations start while we're still trying to destroy.
		log.Warn().
			Str("session_id", id).
			Int32("ref_count", session.refCount.Load()).
			Msg("Session destroy: timed out waiting for page references, session marked for cleanup")

		// Note: We intentionally keep closing=true here. The cleanup routine
		// will eventually clean up this session when references are released.
		return types.ErrSessionInUse
	}

	// Now safe to remove from map
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()

	// Close the page - now safe since all references are released
	session.mu.Lock()
	page := session.Page
	session.Page = nil // Clear reference to prevent double-close
	session.mu.Unlock()

	if page != nil {
		if err := page.Close(); err != nil {
			log.Warn().Err(err).Str("session_id", id).Msg("Error closing session page during destroy")
		}
	}

	// CRITICAL: Return browser to pool
	if session.Browser != nil && m.pool != nil {
		m.pool.Release(session.Browser)
	}

	log.Info().
		Str("session_id", id).
		Dur("lifetime", time.Since(session.CreatedAt)).
		Msg("Session destroyed")

	return nil
}

// List returns all active session IDs.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// cleanupRoutine periodically removes expired sessions.
func (m *Manager) cleanupRoutine() {
	ticker := time.NewTicker(m.config.SessionCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpired()
		case <-m.stopCh:
			return
		}
	}
}

// cleanupExpired removes sessions that have exceeded their TTL.
// Uses two-phase cleanup to avoid holding lock during slow I/O.
// Uses errgroup for parallel session cleanup.
// Fix #3: Marks sessions as closing BEFORE removing from map to prevent races.
// Fix #4: Waits for references to drain before closing page.
// Fix #13: Atomically clears Page under lock to prevent double-free.
func (m *Manager) cleanupExpired() {
	now := time.Now()

	// Phase 1: Collect expired sessions and mark them as closing under lock
	m.mu.Lock()
	var expiredSessions []*Session
	for id, session := range m.sessions {
		// Use atomic LastUsedTime - no nested lock needed
		lastUsed := session.LastUsedTime()

		if now.Sub(lastUsed) > m.config.SessionTTL {
			// Mark session as closing BEFORE removing from map
			// This prevents new AcquirePage calls from succeeding
			session.closing.Store(true)
			expiredSessions = append(expiredSessions, session)
			delete(m.sessions, id)
		}
	}
	remaining := len(m.sessions)
	m.mu.Unlock() // Release lock BEFORE slow I/O

	if len(expiredSessions) == 0 {
		return
	}

	// Phase 2: Clean up resources in parallel WITHOUT holding lock
	eg := new(errgroup.Group)
	eg.SetLimit(4) // Limit concurrent cleanups

	for _, session := range expiredSessions {
		sess := session // Capture for closure
		eg.Go(func() error {
			// Fix #4: Wait for references to drain before closing page
			// Use a shorter timeout for cleanup since we're in background
			if !sess.waitForReferences(2 * time.Second) {
				log.Warn().
					Str("session_id", sess.ID).
					Int32("ref_count", sess.refCount.Load()).
					Msg("Cleanup: references still held, proceeding with cleanup anyway")
			}

			// Fix #13: Safely extract and clear page reference under lock to prevent double-free
			sess.mu.Lock()
			page := sess.Page
			sess.Page = nil // Clear reference atomically under lock
			sess.mu.Unlock()

			// Close page outside lock (slow I/O)
			if page != nil {
				if err := page.Close(); err != nil {
					log.Warn().Err(err).Str("session_id", sess.ID).Msg("Error closing expired session page")
				}
			}

			// CRITICAL: Return browser to pool
			if sess.Browser != nil && m.pool != nil {
				m.pool.Release(sess.Browser)
			}

			log.Info().
				Str("session_id", sess.ID).
				Dur("lifetime", now.Sub(sess.CreatedAt)).
				Msg("Session expired and cleaned up")
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		log.Error().Err(err).Msg("Session cleanup encountered errors")
	}

	log.Debug().
		Int("expired_count", len(expiredSessions)).
		Int("remaining", remaining).
		Msg("Session cleanup completed")
}

// Close shuts down the session manager and cleans up all sessions.
// Returns all session browsers to the pool.
// Uses errgroup for parallel session cleanup to speed up shutdown.
func (m *Manager) Close() error {
	close(m.stopCh)

	// Wait for cleanup goroutine to finish
	m.wg.Wait()

	// Collect sessions under lock
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	// Fix 3.8: Use empty map instead of nil to avoid nil pointer panics on concurrent access
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()

	if len(sessions) == 0 {
		log.Info().Msg("Session manager closed")
		return nil
	}

	// Clean up resources in parallel outside lock
	eg := new(errgroup.Group)
	eg.SetLimit(4) // Limit concurrent cleanups

	for _, session := range sessions {
		sess := session // Capture for closure
		eg.Go(func() error {
			// Safely extract and clear page reference under lock to prevent races
			sess.mu.Lock()
			page := sess.Page
			sess.Page = nil
			sess.mu.Unlock()

			// Close page outside lock (slow I/O)
			if page != nil {
				if err := page.Close(); err != nil {
					log.Warn().Err(err).Str("session_id", sess.ID).Msg("Error closing session page during shutdown")
				}
			}
			// CRITICAL: Return browser to pool
			if sess.Browser != nil && m.pool != nil {
				m.pool.Release(sess.Browser)
			}
			log.Debug().Str("session_id", sess.ID).Msg("Session closed during shutdown")
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		log.Error().Err(err).Msg("Session shutdown encountered errors")
	}

	log.Info().Msg("Session manager closed")
	return nil
}

// Touch updates the LastUsed timestamp for a session atomically.
// This is useful for keeping sessions alive during long operations.
func (s *Session) Touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

// LastUsedTime returns the last used time as a time.Time.
func (s *Session) LastUsedTime() time.Time {
	return time.Unix(0, s.lastUsed.Load())
}

// SafeGetPage returns the session's page reference while holding the lock.
// This prevents race conditions when accessing the page from multiple goroutines.
// Returns nil if the page has been closed or is unavailable.
// Deprecated: Use AcquirePage/ReleasePage for proper reference counting.
func (s *Session) SafeGetPage() *rod.Page {
	return s.AcquirePage()
}

// AcquirePage returns the session's page with reference counting.
// This prevents the page from being closed while it's in use.
// Returns nil if the session is closing, the page is unavailable,
// or the maximum reference count has been reached.
// Caller MUST call ReleasePage when done with the page.
//
// Thread-safety: This method holds the mutex during the entire operation
// to prevent TOCTOU race conditions where the page could be closed between
// checking the closing flag and accessing the page.
func (s *Session) AcquirePage() *rod.Page {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session is closing or page is unavailable
	if s.closing.Load() || s.Page == nil {
		return nil
	}

	// Check if we've hit the maximum reference count
	if s.refCount.Load() >= maxPageReferences {
		log.Warn().
			Str("session_id", s.ID).
			Int32("ref_count", s.refCount.Load()).
			Int("max", maxPageReferences).
			Msg("AcquirePage: maximum page references reached")
		return nil
	}

	// Increment reference count while holding lock
	s.refCount.Add(1)
	return s.Page
}

// AcquirePageWithRelease returns the session's page along with a release function.
// This provides a safer API that ensures ReleasePage is called exactly once,
// even if the caller forgets or the code path changes.
//
// Usage:
//
//	page, release := session.AcquirePageWithRelease()
//	if page == nil {
//	    return errors.New("page not available")
//	}
//	defer release()
//	// use page...
func (s *Session) AcquirePageWithRelease() (page *rod.Page, release func()) {
	page = s.AcquirePage()
	if page == nil {
		return nil, func() {} // No-op release for nil page
	}
	var once sync.Once
	return page, func() {
		once.Do(s.ReleasePage)
	}
}

// ReleasePage decrements the reference count after using a page.
// Must be called after AcquirePage when done with the page.
// Fix 2.5: Uses atomic Add with underflow check instead of CAS loop to avoid busy-wait.
// Fix #39: Logs stack trace for debugging underflow issues.
//
// Deprecated: Use AcquirePageWithRelease() instead which provides a safer API
// that ensures exactly one release per acquire via sync.Once.
func (s *Session) ReleasePage() {
	// Atomically decrement and check result
	newCount := s.refCount.Add(-1)
	if newCount < 0 {
		// Underflow occurred - this indicates a bug (more releases than acquires)
		// Restore to 0 to prevent cascading issues
		s.refCount.Store(0)
		log.Error().
			Str("session_id", s.ID).
			Int32("ref_count", newCount).
			Msg("ReleasePage: ref count went negative, resetting to 0 (BUG: more releases than acquires - check call sites)")
	}
}

// waitForReferences waits for all page references to be released.
// Returns true if all references were released within the timeout.
// Uses a ticker for efficient polling with proper cleanup.
func (s *Session) waitForReferences(timeout time.Duration) bool {
	// Fast path: no references held
	if s.refCount.Load() <= 0 {
		return true
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			// Timeout expired
			return false
		case <-ticker.C:
			if s.refCount.Load() <= 0 {
				return true
			}
		}
	}
}

// GetCookies retrieves all cookies from the session's page.
// Returns an error if the session page is nil (closed or corrupted).
// Uses AcquirePage/ReleasePage for proper reference counting to prevent
// race conditions where page is closed during cookie retrieval.
func (s *Session) GetCookies() ([]*proto.NetworkCookie, error) {
	page := s.AcquirePage()
	if page == nil {
		return nil, types.ErrSessionPageNil
	}
	defer s.ReleasePage()

	return page.Cookies(nil)
}

// SetCookies sets cookies on the session's page.
// Returns an error if the session page is nil (closed or corrupted).
// Uses AcquirePage/ReleasePage for proper reference counting to prevent
// race conditions where page is closed during cookie setting.
func (s *Session) SetCookies(cookies []*proto.NetworkCookieParam) error {
	page := s.AcquirePage()
	if page == nil {
		return types.ErrSessionPageNil
	}
	defer s.ReleasePage()

	return page.SetCookies(cookies)
}

// LockOperation acquires the operation mutex to prevent concurrent operations
// on the same session. This should be called before any solve operation.
// The caller MUST call UnlockOperation when done.
func (s *Session) LockOperation() {
	s.opMu.Lock()
}

// UnlockOperation releases the operation mutex after a solve operation completes.
func (s *Session) UnlockOperation() {
	s.opMu.Unlock()
}
