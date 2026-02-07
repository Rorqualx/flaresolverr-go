package selectors

import (
	"os"
	"path/filepath"
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
