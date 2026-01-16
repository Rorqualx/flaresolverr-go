package session

import (
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// testConfig returns a configuration suitable for testing.
func testConfig() *config.Config {
	return &config.Config{
		SessionTTL:             1 * time.Second,
		SessionCleanupInterval: 500 * time.Millisecond,
		MaxSessions:            5,
	}
}

func TestNewManager(t *testing.T) {
	cfg := testConfig()
	m := NewManager(cfg, nil)
	defer m.Close()

	if m == nil {
		t.Fatal("Expected non-nil manager")
	}

	if m.Count() != 0 {
		t.Errorf("Expected 0 sessions, got %d", m.Count())
	}
}

func TestManagerList(t *testing.T) {
	cfg := testConfig()
	m := NewManager(cfg, nil)
	defer m.Close()

	// Initially should be empty
	ids := m.List()
	if len(ids) != 0 {
		t.Errorf("Expected empty list, got %d items", len(ids))
	}
}

func TestManagerClose(t *testing.T) {
	cfg := testConfig()
	m := NewManager(cfg, nil)

	// Close should not error
	if err := m.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}
