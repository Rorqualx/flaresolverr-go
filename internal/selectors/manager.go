// Package selectors provides challenge detection pattern loading and management.
package selectors

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// Maximum size for remote selectors response (10MB)
const maxRemoteResponseSize = 10 * 1024 * 1024

// ReloadStats contains statistics about selector reloads.
type ReloadStats struct {
	LastReloadTime     time.Time `json:"lastReloadTime,omitempty"`
	ReloadCount        int64     `json:"reloadCount"`
	LastError          error     `json:"-"`
	LastErrorStr       string    `json:"lastError,omitempty"`
	RemoteSuccesses    int64     `json:"remoteSuccesses,omitempty"`
	RemoteFailures     int64     `json:"remoteFailures,omitempty"`
	LastRemoteFetch    time.Time `json:"lastRemoteFetch,omitempty"`
	LastRemoteError    error     `json:"-"`
	LastRemoteErrorStr string    `json:"lastRemoteError,omitempty"`
}

// Manager provides hot-reload capable selector management.
// It maintains embedded default selectors and optionally watches an external
// file for runtime updates. Reads are lock-free using atomic.Value.
type Manager struct {
	embedded        *Selectors   // Compiled-in defaults (immutable)
	current         atomic.Value // *Selectors - atomic swap for lock-free reads
	externalPath    string       // Path to external override file
	watcher         *fsnotify.Watcher
	stopCh          chan struct{}
	wg              sync.WaitGroup
	mu              sync.Mutex  // Protects reload operations
	stats           ReloadStats
	closed          bool        // Tracks if Close has been called

	// Remote fetch fields
	remoteURL       string
	refreshInterval time.Duration
	httpClient      *http.Client
	refreshTicker   *time.Ticker
}

// NewManager creates a new SelectorsManager.
// If externalPath is empty, only embedded selectors are used.
// If hotReload is true and externalPath is set, file changes trigger reloads.
func NewManager(externalPath string, hotReload bool) (*Manager, error) {
	return NewManagerWithRemote(externalPath, hotReload, "", 0)
}

// NewManagerWithRemote creates a new SelectorsManager with optional remote fetch support.
// If remoteURL is set and refreshInterval > 0, selectors will be periodically fetched from the URL.
// File selectors take priority over remote; remote supplements if file is not available.
func NewManagerWithRemote(externalPath string, hotReload bool, remoteURL string, refreshInterval time.Duration) (*Manager, error) {
	m := &Manager{
		embedded:        Get(), // Use the singleton embedded selectors
		externalPath:    externalPath,
		stopCh:          make(chan struct{}),
		remoteURL:       remoteURL,
		refreshInterval: refreshInterval,
	}

	// Initialize HTTP client for remote fetch
	if remoteURL != "" {
		m.httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	// Start with embedded selectors
	m.current.Store(m.embedded)

	// If external path is provided, try to load it
	if externalPath != "" {
		if err := m.loadExternal(); err != nil {
			// Log warning but continue with embedded selectors
			log.Warn().
				Err(err).
				Str("path", externalPath).
				Msg("Failed to load external selectors, using embedded defaults")
		} else {
			log.Info().
				Str("path", externalPath).
				Msg("Loaded external selectors file")
		}

		// Set up file watcher if hot-reload is enabled
		if hotReload {
			if err := m.startWatcher(); err != nil {
				log.Warn().
					Err(err).
					Str("path", externalPath).
					Msg("Failed to start file watcher, hot-reload disabled")
			} else {
				log.Info().
					Str("path", externalPath).
					Msg("Hot-reload enabled for selectors file")
			}
		}
	}

	// If remote URL is provided, try initial fetch and start refresh loop
	if remoteURL != "" && refreshInterval > 0 {
		// Try initial remote fetch (non-blocking, just log on failure)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel() // Fix: Always defer cancel to ensure cleanup on all exit paths
		if sel, err := m.loadRemote(ctx); err != nil {
			m.mu.Lock()
			m.stats.RemoteFailures++
			m.stats.LastRemoteError = err
			m.stats.LastRemoteFetch = time.Now()
			m.mu.Unlock()
			log.Warn().
				Err(err).
				Str("url", remoteURL).
				Msg("Initial remote selector fetch failed, using current selectors")
		} else {
			m.mu.Lock()
			m.stats.RemoteSuccesses++
			m.stats.LastRemoteFetch = time.Now()
			m.stats.LastRemoteError = nil
			m.mu.Unlock()
			// Only use remote if we don't have external file loaded
			if externalPath == "" {
				merged := m.mergeWithEmbedded(sel)
				m.current.Store(merged)
				log.Info().
					Str("url", remoteURL).
					Msg("Loaded selectors from remote URL")
			} else {
				log.Debug().
					Str("url", remoteURL).
					Msg("Remote selectors fetched but file selectors take priority")
			}
		}

		// Start refresh loop
		m.startRemoteRefresh()
	}

	return m, nil
}

// Get returns the current Selectors instance.
// This is a lock-free O(1) operation safe for concurrent use.
func (m *Manager) Get() *Selectors {
	return m.current.Load().(*Selectors)
}

// Reload manually reloads selectors from the external file.
// Returns an error if no external path is configured or reload fails.
// On failure, the previous selectors remain in use (graceful degradation).
func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.externalPath == "" {
		return fmt.Errorf("no external selectors path configured")
	}

	return m.loadExternalLocked()
}

// Stats returns the current reload statistics.
func (m *Manager) Stats() ReloadStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := m.stats
	if stats.LastError != nil {
		stats.LastErrorStr = stats.LastError.Error()
	}
	if stats.LastRemoteError != nil {
		stats.LastRemoteErrorStr = stats.LastRemoteError.Error()
	}
	return stats
}

// Close stops the file watcher and cleans up resources.
// Safe to call multiple times.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	close(m.stopCh)
	m.wg.Wait()

	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}

// loadExternal loads selectors from the external file.
func (m *Manager) loadExternal() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadExternalLocked()
}

// loadExternalLocked loads selectors from the external file.
// Must be called with m.mu held.
func (m *Manager) loadExternalLocked() error {
	data, err := os.ReadFile(m.externalPath)
	if err != nil {
		m.stats.LastError = err
		return fmt.Errorf("failed to read selectors file: %w", err)
	}

	selectors, err := parseAndValidate(data)
	if err != nil {
		m.stats.LastError = err
		return fmt.Errorf("failed to parse selectors file: %w", err)
	}

	// Merge with embedded selectors (external overrides, embedded fills gaps)
	merged := m.mergeWithEmbedded(selectors)

	// Atomic swap
	m.current.Store(merged)

	// Update stats
	m.stats.LastReloadTime = time.Now()
	m.stats.ReloadCount++
	m.stats.LastError = nil

	log.Info().
		Int64("reload_count", m.stats.ReloadCount).
		Msg("Selectors hot-reloaded successfully")

	return nil
}

// parseAndValidate parses YAML data and validates the selectors.
func parseAndValidate(data []byte) (*Selectors, error) {
	var s Selectors
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	// Validate that we have at least some patterns
	if err := s.Validate(); err != nil {
		return nil, err
	}

	return &s, nil
}

// loadRemote fetches selectors from the remote URL.
func (m *Manager) loadRemote(ctx context.Context) (*Selectors, error) {
	if m.remoteURL == "" {
		return nil, fmt.Errorf("no remote URL configured")
	}
	if m.httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.remoteURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add User-Agent header
	req.Header.Set("User-Agent", "FlareSolverr-Go/1.0")
	req.Header.Set("Accept", "application/yaml, application/x-yaml, text/yaml, text/x-yaml, */*")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Limit response size to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	selectors, err := parseAndValidate(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote selectors: %w", err)
	}

	return selectors, nil
}

// startRemoteRefresh starts the periodic remote selector refresh loop.
func (m *Manager) startRemoteRefresh() {
	if m.remoteURL == "" || m.refreshInterval <= 0 {
		return
	}

	m.refreshTicker = time.NewTicker(m.refreshInterval)

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			if m.refreshTicker != nil {
				m.refreshTicker.Stop()
			}
		}()

		log.Info().
			Str("url", m.remoteURL).
			Dur("interval", m.refreshInterval).
			Msg("Started remote selector refresh loop")

		for {
			select {
			case <-m.stopCh:
				log.Debug().Msg("Remote selector refresh loop stopped")
				return
			case <-m.refreshTicker.C:
				m.refreshFromRemote()
			}
		}
	}()
}

// refreshFromRemote fetches selectors from remote and updates if successful.
func (m *Manager) refreshFromRemote() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sel, err := m.loadRemote(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats.LastRemoteFetch = time.Now()

	if err != nil {
		m.stats.RemoteFailures++
		m.stats.LastRemoteError = err
		log.Warn().
			Err(err).
			Str("url", m.remoteURL).
			Int64("failures", m.stats.RemoteFailures).
			Msg("Remote selector fetch failed, keeping previous selectors")
		return
	}

	// Only update if no external file is configured (file takes priority)
	if m.externalPath == "" {
		merged := m.mergeWithEmbedded(sel)
		m.current.Store(merged)
		m.stats.RemoteSuccesses++
		m.stats.LastRemoteError = nil
		log.Info().
			Int64("successes", m.stats.RemoteSuccesses).
			Msg("Remote selectors refreshed successfully")
	} else {
		m.stats.RemoteSuccesses++
		m.stats.LastRemoteError = nil
		log.Debug().
			Str("url", m.remoteURL).
			Msg("Remote selectors fetched but file selectors take priority")
	}
}

// Validate checks that the Selectors have minimum required patterns.
func (s *Selectors) Validate() error {
	// We require at least one pattern in each critical category
	if len(s.AccessDenied) == 0 && len(s.Turnstile) == 0 && len(s.JavaScript) == 0 {
		return fmt.Errorf("selectors must have at least one pattern in access_denied, turnstile, or javascript")
	}
	return nil
}

// mergeWithEmbedded creates a new Selectors by merging external with embedded.
// External patterns take precedence; embedded fills in missing fields.
func (m *Manager) mergeWithEmbedded(external *Selectors) *Selectors {
	merged := &Selectors{}

	// Use external if available, otherwise fall back to embedded
	if len(external.AccessDenied) > 0 {
		merged.AccessDenied = external.AccessDenied
	} else {
		merged.AccessDenied = m.embedded.AccessDenied
	}

	if len(external.Turnstile) > 0 {
		merged.Turnstile = external.Turnstile
	} else {
		merged.Turnstile = m.embedded.Turnstile
	}

	if len(external.JavaScript) > 0 {
		merged.JavaScript = external.JavaScript
	} else {
		merged.JavaScript = m.embedded.JavaScript
	}

	if len(external.TurnstileSelectors) > 0 {
		merged.TurnstileSelectors = external.TurnstileSelectors
	} else {
		merged.TurnstileSelectors = m.embedded.TurnstileSelectors
	}

	if external.TurnstileFramePattern != "" {
		merged.TurnstileFramePattern = external.TurnstileFramePattern
	} else {
		merged.TurnstileFramePattern = m.embedded.TurnstileFramePattern
	}

	if len(external.ShadowHosts) > 0 {
		merged.ShadowHosts = external.ShadowHosts
	} else {
		merged.ShadowHosts = m.embedded.ShadowHosts
	}

	if len(external.ShadowInnerSelectors) > 0 {
		merged.ShadowInnerSelectors = external.ShadowInnerSelectors
	} else {
		merged.ShadowInnerSelectors = m.embedded.ShadowInnerSelectors
	}

	return merged
}

// startWatcher starts the file watcher for hot-reload.
func (m *Manager) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	if err := watcher.Add(m.externalPath); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch file: %w", err)
	}

	m.watcher = watcher

	m.wg.Add(1)
	go m.watchFile()

	return nil
}

// watchFile watches for file changes and triggers reloads.
func (m *Manager) watchFile() {
	defer m.wg.Done()

	// Debounce timer to coalesce rapid file changes
	const debounceDelay = 100 * time.Millisecond
	var debounceTimer *time.Timer
	var debouncing bool

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Only reload on write or create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			log.Debug().
				Str("event", event.Op.String()).
				Str("file", event.Name).
				Msg("Selectors file changed")

			// Debounce: wait for rapid changes to settle
			if debouncing {
				// Reset timer
				if !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
				debounceTimer.Reset(debounceDelay)
			} else {
				debouncing = true
				debounceTimer = time.AfterFunc(debounceDelay, func() {
					if err := m.Reload(); err != nil {
						log.Warn().
							Err(err).
							Str("path", m.externalPath).
							Msg("Hot-reload failed, keeping previous selectors")
					}
					debouncing = false
				})
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.Warn().Err(err).Msg("File watcher error")

		case <-m.stopCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		}
	}
}

// GetManager is a convenience function that returns a Manager using only
// embedded selectors (no external file, no hot-reload).
func GetManager() *Manager {
	m := &Manager{
		embedded: Get(),
		stopCh:   make(chan struct{}),
	}
	m.current.Store(m.embedded)
	return m
}
