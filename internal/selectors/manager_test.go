package selectors

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewManager_EmbeddedOnly(t *testing.T) {
	m, err := NewManager("", false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	sel := m.Get()
	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Should have embedded selectors
	if len(sel.AccessDenied) == 0 {
		t.Error("Expected access denied patterns from embedded selectors")
	}
	if len(sel.Turnstile) == 0 {
		t.Error("Expected turnstile patterns from embedded selectors")
	}
	if len(sel.JavaScript) == 0 {
		t.Error("Expected JavaScript patterns from embedded selectors")
	}
}

func TestNewManager_ExternalFile(t *testing.T) {
	// Create temporary selectors file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "selectors.yaml")

	content := `
access_denied:
  - "custom denied"
  - "test blocked"
turnstile:
  - "custom-turnstile"
javascript:
  - "custom challenge"
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	m, err := NewManager(tmpFile, false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	sel := m.Get()
	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Should have custom selectors
	if len(sel.AccessDenied) != 2 {
		t.Errorf("Expected 2 access denied patterns, got %d", len(sel.AccessDenied))
	}
	if sel.AccessDenied[0] != "custom denied" {
		t.Errorf("Expected 'custom denied', got %s", sel.AccessDenied[0])
	}

	// Embedded fields should fill in missing ones
	if len(sel.TurnstileSelectors) == 0 {
		t.Error("Expected embedded TurnstileSelectors to be used")
	}
}

func TestManager_Get_LockFree(t *testing.T) {
	m, err := NewManager("", false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	// Run many concurrent reads
	const goroutines = 100
	const iterations = 1000

	done := make(chan bool)
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				sel := m.Get()
				if sel == nil {
					t.Error("Get() returned nil")
					return
				}
				if len(sel.AccessDenied) == 0 {
					t.Error("Expected patterns")
					return
				}
			}
			done <- true
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

func TestManager_Reload(t *testing.T) {
	// Create temporary selectors file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "selectors.yaml")

	content := `
access_denied:
  - "initial pattern"
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	m, err := NewManager(tmpFile, false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	// Verify initial content
	sel := m.Get()
	if sel.AccessDenied[0] != "initial pattern" {
		t.Errorf("Expected 'initial pattern', got %s", sel.AccessDenied[0])
	}

	// Update file
	newContent := `
access_denied:
  - "updated pattern"
  - "another pattern"
`
	if err := os.WriteFile(tmpFile, []byte(newContent), 0644); err != nil {
		t.Fatalf("Failed to update temp file: %v", err)
	}

	// Manual reload
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	// Verify updated content
	sel = m.Get()
	if len(sel.AccessDenied) != 2 {
		t.Errorf("Expected 2 access denied patterns, got %d", len(sel.AccessDenied))
	}
	if sel.AccessDenied[0] != "updated pattern" {
		t.Errorf("Expected 'updated pattern', got %s", sel.AccessDenied[0])
	}

	// Check stats - initial load + manual reload = 2
	stats := m.Stats()
	if stats.ReloadCount != 2 {
		t.Errorf("Expected ReloadCount = 2, got %d", stats.ReloadCount)
	}
	if stats.LastError != nil {
		t.Errorf("Expected no error, got %v", stats.LastError)
	}
}

func TestManager_Reload_InvalidYAML(t *testing.T) {
	// Create temporary selectors file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "selectors.yaml")

	validContent := `
access_denied:
  - "valid pattern"
`
	if err := os.WriteFile(tmpFile, []byte(validContent), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	m, err := NewManager(tmpFile, false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	// Write invalid YAML
	invalidContent := `
access_denied:
  - not valid yaml {{{
    incomplete:
`
	if err := os.WriteFile(tmpFile, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to update temp file: %v", err)
	}

	// Reload should fail
	if err := m.Reload(); err == nil {
		t.Error("Expected Reload() to fail with invalid YAML")
	}

	// Original selectors should still be in use (graceful degradation)
	sel := m.Get()
	if sel.AccessDenied[0] != "valid pattern" {
		t.Errorf("Expected original pattern to be preserved, got %s", sel.AccessDenied[0])
	}

	// Stats should record error
	stats := m.Stats()
	if stats.LastError == nil {
		t.Error("Expected LastError to be set")
	}
}

func TestManager_Reload_NoExternalPath(t *testing.T) {
	m, err := NewManager("", false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	err = m.Reload()
	if err == nil {
		t.Error("Expected Reload() to fail when no external path is configured")
	}
}

func TestManager_HotReload(t *testing.T) {
	// Skip if running in CI or short mode
	if testing.Short() {
		t.Skip("Skipping hot-reload test in short mode")
	}

	// Create temporary selectors file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "selectors.yaml")

	content := `
access_denied:
  - "hot reload test"
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	m, err := NewManager(tmpFile, true) // Enable hot-reload
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	// Verify initial content
	sel := m.Get()
	if sel.AccessDenied[0] != "hot reload test" {
		t.Errorf("Expected 'hot reload test', got %s", sel.AccessDenied[0])
	}

	// Update file
	newContent := `
access_denied:
  - "auto reloaded"
`
	if err := os.WriteFile(tmpFile, []byte(newContent), 0644); err != nil {
		t.Fatalf("Failed to update temp file: %v", err)
	}

	// Wait for hot-reload (debounce delay + some buffer)
	time.Sleep(300 * time.Millisecond)

	// Verify auto-reloaded content
	sel = m.Get()
	if sel.AccessDenied[0] != "auto reloaded" {
		t.Errorf("Expected 'auto reloaded' after hot-reload, got %s", sel.AccessDenied[0])
	}
}

func TestSelectors_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sel     *Selectors
		wantErr bool
	}{
		{
			name: "valid with all patterns",
			sel: &Selectors{
				AccessDenied: []string{"denied"},
				Turnstile:    []string{"turnstile"},
				JavaScript:   []string{"challenge"},
			},
			wantErr: false,
		},
		{
			name: "valid with only access_denied",
			sel: &Selectors{
				AccessDenied: []string{"denied"},
			},
			wantErr: false,
		},
		{
			name: "valid with only turnstile",
			sel: &Selectors{
				Turnstile: []string{"turnstile"},
			},
			wantErr: false,
		},
		{
			name: "valid with only javascript",
			sel: &Selectors{
				JavaScript: []string{"challenge"},
			},
			wantErr: false,
		},
		{
			name:    "invalid - empty",
			sel:     &Selectors{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sel.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetManager(t *testing.T) {
	m := GetManager()
	if m == nil {
		t.Fatal("GetManager() returned nil")
	}
	defer m.Close()

	sel := m.Get()
	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Should have embedded selectors
	if len(sel.AccessDenied) == 0 {
		t.Error("Expected access denied patterns")
	}
}

func TestManager_MergeWithEmbedded(t *testing.T) {
	m, err := NewManager("", false)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	// Partial external selectors
	external := &Selectors{
		AccessDenied: []string{"custom denied"},
		// Other fields empty - should use embedded
	}

	merged := m.mergeWithEmbedded(external)

	// Custom should override
	if len(merged.AccessDenied) != 1 || merged.AccessDenied[0] != "custom denied" {
		t.Errorf("Expected custom access_denied pattern, got %v", merged.AccessDenied)
	}

	// Embedded should fill in
	if len(merged.Turnstile) == 0 {
		t.Error("Expected embedded turnstile patterns to be used")
	}
	if len(merged.JavaScript) == 0 {
		t.Error("Expected embedded javascript patterns to be used")
	}
	if len(merged.TurnstileSelectors) == 0 {
		t.Error("Expected embedded turnstile_selectors to be used")
	}
	if merged.TurnstileFramePattern == "" {
		t.Error("Expected embedded turnstile_frame_pattern to be used")
	}
}

func TestManager_Close(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "selectors.yaml")

	content := `access_denied: ["test"]`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	m, err := NewManager(tmpFile, true) // With hot-reload
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Close should not panic and should stop watcher
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Double close should be safe
	if err := m.Close(); err != nil {
		// May get an error for closing already-closed watcher, that's OK
		t.Logf("Double Close() returned: %v (expected)", err)
	}
}

// ============================================================
// Remote selector fetch tests
// ============================================================

func TestManager_LoadRemote(t *testing.T) {
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(`
access_denied:
  - "remote denied"
turnstile:
  - "remote turnstile"
javascript:
  - "remote challenge"
`))
	}))
	defer server.Close()

	m, err := NewManagerWithRemote("", false, server.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewManagerWithRemote() error = %v", err)
	}
	defer m.Close()

	sel := m.Get()
	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Should have remote selectors
	if len(sel.AccessDenied) != 1 || sel.AccessDenied[0] != "remote denied" {
		t.Errorf("Expected 'remote denied', got %v", sel.AccessDenied)
	}
	if len(sel.Turnstile) != 1 || sel.Turnstile[0] != "remote turnstile" {
		t.Errorf("Expected 'remote turnstile', got %v", sel.Turnstile)
	}

	// Stats should show success
	stats := m.Stats()
	if stats.RemoteSuccesses < 1 {
		t.Errorf("Expected at least 1 remote success, got %d", stats.RemoteSuccesses)
	}
}

func TestManager_RemoteTimeout(t *testing.T) {
	// Create a slow mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the timeout
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Use a very short timeout by creating manager with custom http client
	m := &Manager{
		embedded:        Get(),
		stopCh:          make(chan struct{}),
		remoteURL:       server.URL,
		refreshInterval: 1 * time.Hour,
		httpClient: &http.Client{
			Timeout: 100 * time.Millisecond, // Very short timeout
		},
	}
	m.current.Store(m.embedded)
	defer m.Close()

	// Try to load remote - should timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := m.loadRemote(ctx)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestManager_RemoteMalformed(t *testing.T) {
	// Create a mock server returning invalid YAML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(`
this is not valid yaml {{{
  - incomplete:
`))
	}))
	defer server.Close()

	// Create manager - should fall back to embedded
	m, err := NewManagerWithRemote("", false, server.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewManagerWithRemote() error = %v", err)
	}
	defer m.Close()

	// Should still have embedded selectors
	sel := m.Get()
	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Should have embedded selectors (not empty)
	if len(sel.AccessDenied) == 0 {
		t.Error("Expected embedded access denied patterns")
	}
}

func TestManager_RemoteRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping refresh test in short mode")
	}

	// Track how many times the server was called
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		currentCount := callCount
		mu.Unlock()

		w.Header().Set("Content-Type", "application/yaml")
		// Return different data each time
		_, _ = fmt.Fprintf(w, `
access_denied:
  - "refresh %d"
`, currentCount)
	}))
	defer server.Close()

	// Create manager with very short refresh interval
	m, err := NewManagerWithRemote("", false, server.URL, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewManagerWithRemote() error = %v", err)
	}
	defer m.Close()

	// Wait for a couple of refreshes
	time.Sleep(350 * time.Millisecond)

	mu.Lock()
	finalCount := callCount
	mu.Unlock()

	// Should have been called at least twice (initial + refreshes)
	if finalCount < 2 {
		t.Errorf("Expected at least 2 calls, got %d", finalCount)
	}

	// Stats should show successful refreshes
	stats := m.Stats()
	if stats.RemoteSuccesses < 2 {
		t.Errorf("Expected at least 2 remote successes, got %d", stats.RemoteSuccesses)
	}
}

func TestManager_RemoteFallback(t *testing.T) {
	// Create a server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	// Create manager - should fall back to embedded
	m, err := NewManagerWithRemote("", false, server.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewManagerWithRemote() error = %v", err)
	}
	defer m.Close()

	// Should still have embedded selectors (graceful degradation)
	sel := m.Get()
	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Should have embedded selectors
	if len(sel.AccessDenied) == 0 {
		t.Error("Expected embedded access denied patterns from graceful degradation")
	}
}

func TestManager_RemoteWithFileOverride(t *testing.T) {
	// Create a local file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "selectors.yaml")

	content := `
access_denied:
  - "file pattern"
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(`
access_denied:
  - "remote pattern"
`))
	}))
	defer server.Close()

	// Create manager with both file and remote
	m, err := NewManagerWithRemote(tmpFile, false, server.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewManagerWithRemote() error = %v", err)
	}
	defer m.Close()

	sel := m.Get()

	// File should take priority
	if len(sel.AccessDenied) != 1 || sel.AccessDenied[0] != "file pattern" {
		t.Errorf("Expected 'file pattern' (file takes priority), got %v", sel.AccessDenied)
	}
}

func TestManager_RemoteNoURL(t *testing.T) {
	m := &Manager{
		embedded:   Get(),
		stopCh:     make(chan struct{}),
		remoteURL:  "",
		httpClient: nil,
	}
	m.current.Store(m.embedded)

	ctx := context.Background()
	_, err := m.loadRemote(ctx)
	if err == nil {
		t.Error("Expected error when no remote URL configured")
	}
}

func TestManager_RemoteStats(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: return valid data
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write([]byte(`access_denied: ["test"]`))
		} else {
			// Subsequent calls: return error
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	m, err := NewManagerWithRemote("", false, server.URL, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewManagerWithRemote() error = %v", err)
	}
	defer m.Close()

	// Wait for some refreshes
	time.Sleep(150 * time.Millisecond)

	stats := m.Stats()

	// Should have at least 1 success (initial fetch)
	if stats.RemoteSuccesses < 1 {
		t.Errorf("Expected at least 1 remote success, got %d", stats.RemoteSuccesses)
	}

	// Should have some failures from subsequent refreshes
	if stats.RemoteFailures < 1 {
		t.Errorf("Expected at least 1 remote failure, got %d", stats.RemoteFailures)
	}

	// Last remote fetch time should be set
	if stats.LastRemoteFetch.IsZero() {
		t.Error("Expected LastRemoteFetch to be set")
	}
}
