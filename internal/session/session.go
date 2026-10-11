// Package session provides session management for persistent browser contexts.
// Sessions allow clients to maintain state (cookies, local storage) across requests.
package session

import (
	"fmt"
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

// sessionPageCloseTimeout bounds closing a session's page during teardown.
const sessionPageCloseTimeout = 10 * time.Second

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
	TTL       time.Duration // Per-session TTL override; 0 means use global config TTL
	lastUsed  atomic.Int64  // Unix nano timestamp for lock-free access
	mu        sync.Mutex    // Only used for page operations (GetCookies/SetCookies)

	// Reference counting for safe page access during concurrent destroy
	refCount atomic.Int32 // Number of active page references
	closing  atomic.Bool  // Set to true when session is being destroyed

	// Operation mutex to prevent concurrent solve operations on the same session
	// This ensures only one request can use the page at a time, preventing
	// page state corruption from concurrent navigation/actions
	// Fix #23: Always acquire opMu BEFORE mu when both are needed.
	opMu sync.Mutex

	// OwnsBrowser is true when the session owns a dedicated browser (not from pool).
	// On destroy, the browser is Close()'d instead of returned to the pool.
	OwnsBrowser bool

	// Timezone is the IANA timezone applied to this session's page via CDP at creation.
	// Empty means no per-session override; callers may apply a global default instead.
	Timezone string
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
//
// Ownership: the session takes over brow only when Create succeeds. On any
// error the caller still owns the browser and must release it (pooled) or
// clean it up (dedicated). Create never releases it itself, because it cannot
// know which kind it was given.
func (m *Manager) Create(id string, brow *rod.Browser, ttl time.Duration) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session already exists
	if _, exists := m.sessions[id]; exists {
		return nil, types.ErrSessionAlreadyExists
	}

	// Check max sessions limit
	if len(m.sessions) >= m.config.MaxSessions {
		return nil, types.ErrTooManySessions
	}

	// Create a new page for this session. The page must be created on the
	// browser's own context: go-rod binds the page's event stream to the
	// context it was created with, so a timeout context here would kill the
	// session page's events when it expired.
	page, err := brow.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, fmt.Errorf("failed to create session page: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:        id,
		Browser:   brow,
		Page:      page,
		CreatedAt: now,
		TTL:       ttl,
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
	// Mark session as closing BEFORE removing from map. This prevents new
	// AcquirePage calls from succeeding, and the compare-and-swap makes exactly
	// one of several concurrent teardowns the owner of the session's resources.
	// NOTE: The session stays in the map while references drain, so another
	// goroutine cannot create a session with the same ID in the meantime.
	won := exists && session.closing.CompareAndSwap(false, true)
	m.mu.Unlock()

	if !exists {
		return types.ErrSessionNotFound
	}
	if !won {
		// Another Destroy, the TTL cleanup, or Close is already tearing it down
		return types.ErrSessionInUse
	}

	// Wait for any in-flight page operations to complete (up to 5 seconds)
	if !session.waitForReferences(5 * time.Second) {
		// The session is still in use, so the destroy did not happen. Reopen it:
		// leaving closing=true would strand a session that Get reports as missing
		// but that still holds its browser and blocks re-creating the ID.
		session.closing.Store(false)
		log.Warn().
			Str("session_id", id).
			Int32("ref_count", session.refCount.Load()).
			Msg("Session destroy: timed out waiting for page references, session left active")
		return types.ErrSessionInUse
	}

	// Now safe to remove from map
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()

	m.teardown(session)

	log.Info().
		Str("session_id", id).
		Dur("lifetime", time.Since(session.CreatedAt)).
		Msg("Session destroyed")

	return nil
}

// teardown closes a session's page and hands its browser back: dedicated
// browsers are cleaned up, pooled ones released. The caller must have won the
// session's closing flag and removed it from the map, so teardown runs exactly
// once per session.
func (m *Manager) teardown(session *Session) {
	// Safely extract and clear page reference under lock to prevent double-close
	session.mu.Lock()
	page := session.Page
	session.Page = nil
	session.mu.Unlock()

	// Close page outside lock (slow I/O)
	if page != nil {
		if err := page.Timeout(sessionPageCloseTimeout).Close(); err != nil {
			log.Warn().Err(err).Str("session_id", session.ID).Msg("Error closing session page")
		}
	}

	// CRITICAL: Return browser to pool, or fully tear down if session owns it.
	// CleanupBrowser also removes the on-disk user-data dir; plain Close() leaks it.
	if session.Browser == nil {
		return
	}
	switch {
	case session.OwnsBrowser && m.pool != nil:
		m.pool.CleanupBrowser(session.Browser)
	case session.OwnsBrowser:
		if err := session.Browser.Close(); err != nil {
			log.Warn().Err(err).Str("session_id", session.ID).Msg("Error closing session-owned browser")
		}
	case m.pool != nil:
		m.pool.Release(session.Browser)
	}
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

// TouchAndExtend refreshes a session's last-used timestamp and optionally updates its TTL.
// If newTTL is 0, only the timestamp is refreshed.
func (m *Manager) TouchAndExtend(id string, newTTL time.Duration) error {
	session, err := m.Get(id)
	if err != nil {
		return err
	}
	if newTTL > 0 {
		session.SetTTL(newTTL)
	}
	session.Touch()
	return nil
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

		if now.Sub(lastUsed) > session.EffectiveTTL(m.config.SessionTTL) {
			// Mark session as closing BEFORE removing from map. This prevents
			// new AcquirePage calls from succeeding. Losing the swap means a
			// Destroy already owns the teardown.
			if !session.closing.CompareAndSwap(false, true) {
				continue
			}
			// A session with a request in flight is not idle, whatever its
			// last-used time says: a solve can outlast a short TTL. Leave it
			// for a later cycle instead of closing the page mid-solve.
			if session.refCount.Load() > 0 {
				session.closing.Store(false)
				session.Touch()
				continue
			}
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

			m.teardown(sess)

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
//
// Fix HIGH: Properly handles concurrent close calls and waits for references.
func (m *Manager) Close() error {
	// Fix HIGH: Use sync.Once pattern to prevent double-close panic
	// We acquire the lock and check if already closing to provide idempotent close
	m.mu.Lock()
	select {
	case <-m.stopCh:
		// Already closed or closing
		m.mu.Unlock()
		return nil
	default:
		// Not yet closed, proceed with close
		close(m.stopCh)
	}

	// Collect sessions and mark them as closing while holding lock
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		// Fix HIGH: Mark session as closing BEFORE removing from map
		// This prevents new AcquirePage calls from succeeding. A session whose
		// flag is already set is being torn down by an in-flight Destroy.
		if session.closing.CompareAndSwap(false, true) {
			sessions = append(sessions, session)
		}
	}
	// Fix 3.8: Use empty map instead of nil to avoid nil pointer panics on concurrent access
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()

	// Wait for cleanup goroutine to finish
	m.wg.Wait()

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
			// Fix HIGH: Wait for references to drain before closing page
			// Use a shorter timeout for shutdown since we want to complete quickly
			if !sess.waitForReferences(2 * time.Second) {
				log.Warn().
					Str("session_id", sess.ID).
					Int32("ref_count", sess.refCount.Load()).
					Msg("Close: references still held, proceeding with cleanup anyway")
			}

			m.teardown(sess)
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

// EffectiveTTL returns the session's TTL, falling back to the given default if no per-session TTL is set.
func (s *Session) EffectiveTTL(defaultTTL time.Duration) time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return defaultTTL
}

// SetTTL updates the session's per-session TTL.
func (s *Session) SetTTL(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TTL = ttl
}

// RemainingTTL returns the time remaining before the session expires.
func (s *Session) RemainingTTL(defaultTTL time.Duration) time.Duration {
	elapsed := time.Since(s.LastUsedTime())
	ttl := s.EffectiveTTL(defaultTTL)
	remaining := ttl - elapsed
	if remaining < 0 {
		return 0
	}
	return remaining
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
