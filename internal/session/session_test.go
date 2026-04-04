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

func TestSessionEffectiveTTL(t *testing.T) {
	tests := []struct {
		name       string
		sessionTTL time.Duration
		defaultTTL time.Duration
		want       time.Duration
	}{
		{name: "zero uses default", sessionTTL: 0, defaultTTL: 30 * time.Minute, want: 30 * time.Minute},
		{name: "custom overrides default", sessionTTL: 10 * time.Minute, defaultTTL: 30 * time.Minute, want: 10 * time.Minute},
		{name: "custom shorter than default", sessionTTL: 5 * time.Minute, defaultTTL: 30 * time.Minute, want: 5 * time.Minute},
		{name: "custom longer than default", sessionTTL: 60 * time.Minute, defaultTTL: 30 * time.Minute, want: 60 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{TTL: tt.sessionTTL}
			got := s.EffectiveTTL(tt.defaultTTL)
			if got != tt.want {
				t.Errorf("EffectiveTTL() = %v, want %v", got, tt.want)
			}
		})
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
