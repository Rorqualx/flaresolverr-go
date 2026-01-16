// Package session provides session management for persistent browser contexts.
// Sessions allow clients to maintain state (cookies, local storage) across requests.
package session

import (
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Session represents a persistent browser session.
// Sessions maintain their own page and cookies across multiple requests.
type Session struct {
	ID        string
	Browser   *rod.Browser
	Page      *rod.Page
	CreatedAt time.Time
	LastUsed  time.Time
	mu        sync.Mutex
}

// Manager handles session lifecycle and cleanup.
// It maintains a map of active sessions and periodically cleans up expired ones.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	config   *config.Config
	pool     *browser.Pool // Pool reference for returning browsers on cleanup
	stopCh   chan struct{}
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

	go m.cleanupRoutine()

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

	session := &Session{
		ID:        id,
		Browser:   brow,
		Page:      page,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	m.sessions[id] = session

	log.Info().
		Str("session_id", id).
		Int("total_sessions", len(m.sessions)).
		Msg("Session created")

	return session, nil
}

// Get retrieves a session by ID.
// Returns ErrSessionNotFound if the session doesn't exist.
// Updates the LastUsed timestamp on access.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[id]
	if !exists {
		return nil, types.ErrSessionNotFound
	}

	// Update last used time - safe while holding manager's read lock
	// because cleanup holds write lock
	session.mu.Lock()
	session.LastUsed = time.Now()
	session.mu.Unlock()

	return session, nil
}

// Destroy removes a session and closes its resources.
// The browser is returned to the pool after cleanup.
func (m *Manager) Destroy(id string) error {
	m.mu.Lock()
	session, exists := m.sessions[id]
	if exists {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	if !exists {
		return types.ErrSessionNotFound
	}

	// Close the page
	if session.Page != nil {
		_ = session.Page.Close()
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
func (m *Manager) cleanupExpired() {
	now := time.Now()

	// Phase 1: Collect expired sessions under lock
	m.mu.Lock()
	var expiredSessions []*Session
	for id, session := range m.sessions {
		session.mu.Lock()
		lastUsed := session.LastUsed
		session.mu.Unlock()

		if now.Sub(lastUsed) > m.config.SessionTTL {
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
			if sess.Page != nil {
				_ = sess.Page.Close()
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

	_ = eg.Wait()

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

	// Collect sessions under lock
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = nil
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
			if sess.Page != nil {
				_ = sess.Page.Close()
			}
			// CRITICAL: Return browser to pool
			if sess.Browser != nil && m.pool != nil {
				m.pool.Release(sess.Browser)
			}
			log.Debug().Str("session_id", sess.ID).Msg("Session closed during shutdown")
			return nil
		})
	}

	_ = eg.Wait()

	log.Info().Msg("Session manager closed")
	return nil
}

// Touch updates the LastUsed timestamp for a session.
// This is useful for keeping sessions alive during long operations.
func (s *Session) Touch() {
	s.mu.Lock()
	s.LastUsed = time.Now()
	s.mu.Unlock()
}

// GetCookies retrieves all cookies from the session's page.
func (s *Session) GetCookies() ([]*proto.NetworkCookie, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Page.Cookies(nil)
}

// SetCookies sets cookies on the session's page.
func (s *Session) SetCookies(cookies []*proto.NetworkCookieParam) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Page.SetCookies(cookies)
}
