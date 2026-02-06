package solver

import (
	"testing"
	"time"
)

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{
			name:   "contains substring",
			s:      "challenges.cloudflare.com/turnstile/v0/abc123",
			substr: "challenges.cloudflare.com",
			want:   true,
		},
		{
			name:   "does not contain substring",
			s:      "example.com/page",
			substr: "challenges.cloudflare.com",
			want:   false,
		},
		{
			name:   "empty string",
			s:      "",
			substr: "test",
			want:   false,
		},
		{
			name:   "empty substring",
			s:      "test",
			substr: "",
			want:   true,
		},
		{
			name:   "exact match",
			s:      "test",
			substr: "test",
			want:   true,
		},
		{
			name:   "substring at start",
			s:      "test string",
			substr: "test",
			want:   true,
		},
		{
			name:   "substring at end",
			s:      "this is a test",
			substr: "test",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestFindSubstring(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   int
	}{
		{
			name:   "found at start",
			s:      "hello world",
			substr: "hello",
			want:   0,
		},
		{
			name:   "found in middle",
			s:      "hello world",
			substr: "wor",
			want:   6,
		},
		{
			name:   "found at end",
			s:      "hello world",
			substr: "world",
			want:   6,
		},
		{
			name:   "not found",
			s:      "hello world",
			substr: "xyz",
			want:   -1,
		},
		{
			name:   "empty substring",
			s:      "test",
			substr: "",
			want:   0,
		},
		{
			name:   "substring longer than string",
			s:      "hi",
			substr: "hello",
			want:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findSubstring(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("findSubstring(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestContainsTurnstilePattern(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		pattern string
		want    bool
	}{
		{
			name:    "valid turnstile URL",
			url:     "https://challenges.cloudflare.com/turnstile/v0/abc123",
			pattern: "challenges.cloudflare.com",
			want:    true,
		},
		{
			name:    "non-turnstile URL",
			url:     "https://example.com/page",
			pattern: "challenges.cloudflare.com",
			want:    false,
		},
		{
			name:    "empty URL",
			url:     "",
			pattern: "challenges.cloudflare.com",
			want:    false,
		},
		{
			name:    "empty pattern",
			url:     "https://example.com",
			pattern: "",
			want:    false,
		},
		{
			name:    "both empty",
			url:     "",
			pattern: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsTurnstilePattern(tt.url, tt.pattern)
			if got != tt.want {
				t.Errorf("containsTurnstilePattern(%q, %q) = %v, want %v", tt.url, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestNewShadowRootTraverser(t *testing.T) {
	// Test that NewShadowRootTraverser creates a valid traverser
	// Note: We can't test actual shadow DOM traversal without a real browser
	traverser := NewShadowRootTraverser(nil)
	if traverser == nil {
		t.Fatal("NewShadowRootTraverser returned nil")
	}
	if traverser.timeout != 5*time.Second {
		t.Errorf("Default timeout = %v, want 5s", traverser.timeout)
	}
}

func TestShadowRootTraverser_WithTimeout(t *testing.T) {
	traverser := NewShadowRootTraverser(nil)
	customTimeout := 10 * time.Second

	result := traverser.WithTimeout(customTimeout)

	if result != traverser {
		t.Error("WithTimeout should return the same traverser for chaining")
	}
	if traverser.timeout != customTimeout {
		t.Errorf("Timeout = %v, want %v", traverser.timeout, customTimeout)
	}
}

func TestShadowErrors(t *testing.T) {
	// Test that error variables are properly defined
	if ErrShadowHostNotFound == nil {
		t.Error("ErrShadowHostNotFound should not be nil")
	}
	if ErrShadowRootNotAccessible == nil {
		t.Error("ErrShadowRootNotAccessible should not be nil")
	}
	if ErrCheckboxNotFound == nil {
		t.Error("ErrCheckboxNotFound should not be nil")
	}

	// Test error messages
	if ErrShadowHostNotFound.Error() != "shadow host element not found" {
		t.Errorf("ErrShadowHostNotFound message = %q", ErrShadowHostNotFound.Error())
	}
	if ErrShadowRootNotAccessible.Error() != "shadow root not accessible" {
		t.Errorf("ErrShadowRootNotAccessible message = %q", ErrShadowRootNotAccessible.Error())
	}
	if ErrCheckboxNotFound.Error() != "checkbox not found in shadow DOM" {
		t.Errorf("ErrCheckboxNotFound message = %q", ErrCheckboxNotFound.Error())
	}
}
