package captcha

import (
	"testing"
	"time"
)

func TestAvailable(t *testing.T) {
	// All 3 providers should be registered via init()
	available := Available()
	if len(available) < 3 {
		t.Fatalf("Expected at least 3 registered providers, got %d: %v", len(available), available)
	}

	expected := map[string]bool{
		"2captcha":    false,
		"capsolver":   false,
		"anticaptcha": false,
	}
	for _, name := range available {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("Expected provider %q to be registered", name)
		}
	}
}

func TestGetFactory(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantNil  bool
	}{
		{name: "2captcha exists", provider: "2captcha", wantNil: false},
		{name: "capsolver exists", provider: "capsolver", wantNil: false},
		{name: "anticaptcha exists", provider: "anticaptcha", wantNil: false},
		{name: "unknown returns nil", provider: "unknown", wantNil: true},
		{name: "empty returns nil", provider: "", wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := GetFactory(tt.provider)
			if (factory == nil) != tt.wantNil {
				t.Errorf("GetFactory(%q) nil=%v, want nil=%v", tt.provider, factory == nil, tt.wantNil)
			}
		})
	}
}

func TestGetFactory_ReturnsWorkingProvider(t *testing.T) {
	factory := GetFactory("2captcha")
	if factory == nil {
		t.Fatal("Expected factory for 2captcha")
	}

	// Create a provider with the factory
	provider := factory("test-key", 30*time.Second)
	if provider == nil {
		t.Fatal("Factory returned nil provider")
	}
	if provider.Name() != "2captcha" {
		t.Errorf("Expected name '2captcha', got %q", provider.Name())
	}
	if !provider.IsConfigured() {
		t.Error("Expected provider to be configured with non-empty API key")
	}
}

func TestBuildPriorityOrder(t *testing.T) {
	tests := []struct {
		name      string
		primary   string
		available []string
		want      []string
	}{
		{
			name:      "default primary",
			primary:   "2captcha",
			available: []string{"2captcha", "anticaptcha", "capsolver"},
			want:      []string{"2captcha", "anticaptcha", "capsolver"},
		},
		{
			name:      "capsolver primary",
			primary:   "capsolver",
			available: []string{"2captcha", "anticaptcha", "capsolver"},
			want:      []string{"capsolver", "2captcha", "anticaptcha"},
		},
		{
			name:      "unknown primary",
			primary:   "unknown",
			available: []string{"2captcha", "anticaptcha", "capsolver"},
			want:      []string{"2captcha", "anticaptcha", "capsolver"},
		},
		{
			name:      "empty available",
			primary:   "2captcha",
			available: []string{},
			want:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildPriorityOrder(tt.primary, tt.available)
			if len(got) != len(tt.want) {
				t.Fatalf("BuildPriorityOrder() len=%d, want len=%d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("BuildPriorityOrder()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAvailable_Sorted(t *testing.T) {
	available := Available()
	for i := 1; i < len(available); i++ {
		if available[i] < available[i-1] {
			t.Errorf("Available() not sorted: %v", available)
			break
		}
	}
}
