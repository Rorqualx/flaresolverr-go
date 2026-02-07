// Package selectors provides challenge detection pattern loading and management.
package selectors

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// ReloadStats contains statistics about selector reloads.
type ReloadStats struct {
	LastReloadTime time.Time `json:"lastReloadTime,omitempty"`
	ReloadCount    int64     `json:"reloadCount"`
	LastError      error     `json:"-"`
	LastErrorStr   string    `json:"lastError,omitempty"`
}

// Manager provides hot-reload capable selector management.
// It maintains embedded default selectors and optionally watches an external
// file for runtime updates. Reads are lock-free using atomic.Value.
type Manager struct {
	embedded     *Selectors      // Compiled-in defaults (immutable)
	current      atomic.Value    // *Selectors - atomic swap for lock-free reads
	externalPath string          // Path to external override file
	watcher      *fsnotify.Watcher
	stopCh       chan struct{}
	wg           sync.WaitGroup
	mu           sync.Mutex // Protects reload operations
	stats        ReloadStats
	closed       bool       // Tracks if Close has been called
}

// NewManager creates a new SelectorsManager.
// If externalPath is empty, only embedded selectors are used.
// If hotReload is true and externalPath is set, file changes trigger reloads.
func NewManager(externalPath string, hotReload bool) (*Manager, error) {
	m := &Manager{
		embedded:     Get(), // Use the singleton embedded selectors
		externalPath: externalPath,
		stopCh:       make(chan struct{}),
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
