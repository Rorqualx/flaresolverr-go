package security

import (
	"net"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		// Valid URLs
		{"valid https", "https://example.com", nil},
		{"valid http", "http://example.com/page", nil},
		{"valid with port", "https://example.com:8080/path", nil},
		{"valid with query", "https://example.com?foo=bar", nil},

		// Invalid schemes
		{"file scheme", "file:///etc/passwd", ErrBlockedScheme},
		{"javascript scheme", "javascript:alert(1)", ErrBlockedScheme},
		{"data scheme", "data:text/html,<script>alert(1)</script>", ErrBlockedScheme},
		{"ftp scheme", "ftp://example.com", ErrBlockedScheme},
		{"no scheme", "example.com", ErrBlockedScheme},

		// Localhost blocking
		{"localhost", "http://localhost/admin", ErrLocalhostBlocked},
		{"localhost with port", "http://localhost:8080", ErrLocalhostBlocked},
		{"127.0.0.1", "http://127.0.0.1", ErrLocalhostBlocked},
		{"127.0.0.1 with port", "http://127.0.0.1:3000", ErrLocalhostBlocked},
		{"IPv6 loopback", "http://[::1]/", ErrLocalhostBlocked},
		{"0.0.0.0", "http://0.0.0.0", ErrPrivateIPBlocked}, // Unspecified address

		// SSRF bypass attempts - decimal IP encoding
		{"decimal loopback", "http://2130706433/", ErrLocalhostBlocked},     // 127.0.0.1
		{"decimal private", "http://3232235777/", ErrPrivateIPBlocked},      // 192.168.1.1
		{"decimal metadata", "http://2852039166/", ErrPrivateIPBlocked},     // 169.254.169.254

		// SSRF bypass attempts - alternative loopback range
		{"alt loopback 127.0.0.2", "http://127.0.0.2/", ErrLocalhostBlocked},
		{"alt loopback 127.1.1.1", "http://127.1.1.1/", ErrLocalhostBlocked},
		{"alt loopback 127.255.255.254", "http://127.255.255.254/", ErrLocalhostBlocked},

		// SSRF bypass attempts - shortened IP forms
		{"shortened loopback", "http://127.1/", ErrLocalhostBlocked},        // 127.0.0.1

		// SSRF bypass attempts - localhost variations
		{"localhost subdomain", "http://foo.localhost/", ErrLocalhostBlocked},
		{"ip6-localhost", "http://ip6-localhost/", ErrLocalhostBlocked},

		// Private IP blocking
		{"private 10.x", "http://10.0.0.1", ErrPrivateIPBlocked},
		{"private 172.16.x", "http://172.16.0.1", ErrPrivateIPBlocked},
		{"private 192.168.x", "http://192.168.1.1", ErrPrivateIPBlocked},

		// Cloud metadata blocking (link-local IPs caught by IsLinkLocalUnicast first)
		{"AWS metadata", "http://169.254.169.254/latest/meta-data/", ErrPrivateIPBlocked},
		{"GCP metadata host", "http://metadata.google.internal/", ErrLocalhostBlocked},
		{"AWS instance-data", "http://instance-data/", ErrLocalhostBlocked},

		// Empty/invalid
		{"empty", "", ErrInvalidURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url)
			if err != tt.wantErr {
				t.Errorf("ValidateURL(%q) = %v, want %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeCookieDomain(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		targetHost string
		want       string
	}{
		{"empty domain uses target", "", "example.com", "example.com"},
		{"exact match", "example.com", "example.com", "example.com"},
		{"subdomain match", "example.com", "sub.example.com", "example.com"},
		{"leading dot removed", ".example.com", "example.com", "example.com"},
		{"mismatched domain uses target", "evil.com", "example.com", "example.com"},
		{"parent domain attack blocked", "com", "example.com", "example.com"},
		{"unrelated subdomain blocked", "other.com", "sub.example.com", "sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeCookieDomain(tt.domain, tt.targetHost)
			if got != tt.want {
				t.Errorf("SanitizeCookieDomain(%q, %q) = %q, want %q",
					tt.domain, tt.targetHost, got, tt.want)
			}
		})
	}
}

func TestIsCloudMetadataIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"169.254.169.254", true},
		{"100.100.100.200", true},
		{"8.8.8.8", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			got := isCloudMetadataIP(ip)
			if got != tt.expected {
				t.Errorf("isCloudMetadataIP(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}
