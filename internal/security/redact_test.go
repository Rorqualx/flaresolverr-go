package security

import (
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		contains []string // strings that should be in output
		excludes []string // strings that should NOT be in output
	}{
		{
			name:     "no sensitive data",
			url:      "https://example.com/page?foo=bar",
			contains: []string{"example.com", "foo=bar"},
			excludes: []string{"REDACTED"},
		},
		{
			name:     "user credentials",
			url:      "https://user:password@example.com/",
			contains: []string{"REDACTED", "example.com"},
			excludes: []string{"password"},
		},
		{
			name:     "api key in query",
			url:      "https://api.example.com?api_key=secret123",
			contains: []string{"api.example.com", "REDACTED"},
			excludes: []string{"secret123"},
		},
		{
			name:     "token in query",
			url:      "https://example.com?access_token=abc123&page=1",
			contains: []string{"example.com", "page=1", "REDACTED"},
			excludes: []string{"abc123"},
		},
		{
			name:     "password in query",
			url:      "https://example.com/login?username=john&password=secret",
			contains: []string{"username=john", "REDACTED"},
			excludes: []string{"secret"},
		},
		{
			name:     "empty url",
			url:      "",
			contains: []string{},
			excludes: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactURL(tt.url)

			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("RedactURL(%q) = %q, expected to contain %q", tt.url, result, s)
				}
			}

			for _, s := range tt.excludes {
				if strings.Contains(result, s) {
					t.Errorf("RedactURL(%q) = %q, should NOT contain %q", tt.url, result, s)
				}
			}
		})
	}
}

func TestRedactProxyURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		contains string
		excludes string
	}{
		{
			name:     "no credentials",
			url:      "http://proxy.example.com:8080",
			contains: "proxy.example.com",
			excludes: "",
		},
		{
			name:     "with password",
			url:      "http://user:secret@proxy.example.com:8080",
			contains: "user:",
			excludes: "secret",
		},
		{
			name:     "empty",
			url:      "",
			contains: "",
			excludes: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactProxyURL(tt.url)

			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("RedactProxyURL(%q) = %q, expected to contain %q", tt.url, result, tt.contains)
			}

			if tt.excludes != "" && strings.Contains(result, tt.excludes) {
				t.Errorf("RedactProxyURL(%q) = %q, should NOT contain %q", tt.url, result, tt.excludes)
			}
		})
	}
}
