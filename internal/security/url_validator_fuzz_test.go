package security

import (
	"strings"
	"testing"
)

// FuzzValidateURL tests URL validation with fuzzed inputs.
// Run with: go test -fuzz=FuzzValidateURL -fuzztime=60s ./internal/security/
func FuzzValidateURL(f *testing.F) {
	// Seed corpus with known test cases
	seedURLs := []string{
		// Valid URLs
		"https://example.com",
		"https://example.com/path",
		"https://example.com/path?query=value",
		"http://subdomain.example.com",
		"https://example.com:8080/path",

		// SSRF attack vectors
		"file:///etc/passwd",
		"http://127.0.0.1",
		"http://localhost",
		"http://0.0.0.0",
		"http://169.254.169.254/latest/meta-data",
		"http://[::1]",
		"http://192.168.1.1",
		"http://10.0.0.1",
		"http://172.16.0.1",

		// URL encoding attacks
		"http://%6c%6f%63%61%6c%68%6f%73%74",
		"http://localhost%00.example.com",

		// IPv6 variations
		"http://[0:0:0:0:0:0:0:1]",
		"http://[::ffff:127.0.0.1]",

		// Scheme attacks
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"ftp://example.com",
		"gopher://example.com",

		// Empty and malformed
		"",
		"not-a-url",
		"://missing-scheme",
		"http://",
		"http:// ",
		"http://[",

		// DNS rebinding variations
		"http://1.0.0.127.nip.io",
		"http://localtest.me",

		// Long URLs
		"https://example.com/" + strings.Repeat("a", 1000),
	}

	for _, url := range seedURLs {
		f.Add(url)
	}

	f.Fuzz(func(t *testing.T, url string) {
		// The function should never panic
		err := ValidateURL(url)

		// Basic invariants to verify
		if url == "" && err == nil {
			t.Error("empty URL should return error")
		}

		// SSRF protection checks - these should always be blocked
		if err == nil {
			lowURL := strings.ToLower(url)
			// Check that localhost variants are blocked
			if strings.Contains(lowURL, "localhost") && !strings.Contains(lowURL, "localhost.") {
				// localhost.example.com might be allowed, but not localhost itself
				if strings.HasPrefix(lowURL, "http://localhost") || strings.HasPrefix(lowURL, "https://localhost") {
					parts := strings.Split(lowURL, "/")
					if len(parts) >= 3 {
						host := strings.Split(parts[2], ":")[0]
						if host == "localhost" {
							t.Errorf("localhost URL should be blocked: %s", url)
						}
					}
				}
			}

			// Check that metadata IPs are blocked
			if strings.Contains(url, "169.254.169.254") {
				t.Errorf("metadata IP should be blocked: %s", url)
			}

			// Check that file:// scheme is blocked
			if strings.HasPrefix(lowURL, "file://") {
				t.Errorf("file:// URLs should be blocked: %s", url)
			}
		}
	})
}

// FuzzSanitizeCookieDomain tests cookie domain sanitization.
func FuzzSanitizeCookieDomain(f *testing.F) {
	// Add seed corpus with domain/target pairs
	seeds := []struct {
		domain string
		target string
	}{
		{".example.com", "sub.example.com"},
		{"example.com", "example.com"},
		{"evil.com", "example.com"},
		{"", "example.com"},
		{".com", "example.com"},
		{"com", "example.com"},
		{"..example.com", "example.com"},
	}

	for _, seed := range seeds {
		f.Add(seed.domain, seed.target)
	}

	f.Fuzz(func(t *testing.T, domain, targetHost string) {
		// Should never panic
		result := SanitizeCookieDomain(domain, targetHost)

		// Result should never be empty if targetHost is non-empty
		if targetHost != "" && result == "" {
			t.Errorf("SanitizeCookieDomain returned empty for non-empty target: domain=%q, target=%q", domain, targetHost)
		}

		// Result should be lowercase
		if result != strings.ToLower(result) {
			t.Errorf("SanitizeCookieDomain returned non-lowercase result: %q", result)
		}
	})
}
