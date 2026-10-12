package security

import (
	"errors"
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
		{"decimal loopback", "http://2130706433/", ErrLocalhostBlocked}, // 127.0.0.1
		{"decimal private", "http://3232235777/", ErrPrivateIPBlocked},  // 192.168.1.1
		{"decimal metadata", "http://2852039166/", ErrPrivateIPBlocked}, // 169.254.169.254

		// SSRF bypass attempts - alternative loopback range
		{"alt loopback 127.0.0.2", "http://127.0.0.2/", ErrLocalhostBlocked},
		{"alt loopback 127.1.1.1", "http://127.1.1.1/", ErrLocalhostBlocked},
		{"alt loopback 127.255.255.254", "http://127.255.255.254/", ErrLocalhostBlocked},

		// SSRF bypass attempts - shortened IP forms
		{"shortened loopback", "http://127.1/", ErrLocalhostBlocked}, // 127.0.0.1

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
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateURL(%q) = %v, want nil", tt.url, err)
				}
			} else if !errors.Is(err, tt.wantErr) {
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

// TestValidateProxyURL tests proxy URL validation including edge cases
// with special characters in credentials.
func TestValidateProxyURL(t *testing.T) {
	tests := []struct {
		name            string
		proxyURL        string
		allowPrivateIPs bool
		wantErr         error
	}{
		// Valid proxy URLs
		{"empty proxy allowed", "", false, nil},
		{"http proxy", "http://proxy.example.com:8080", false, nil},
		{"https proxy", "https://proxy.example.com:443", false, nil},
		{"socks4 proxy", "socks4://proxy.example.com:1080", false, nil},
		{"socks5 proxy", "socks5://proxy.example.com:1080", false, nil},

		// Invalid schemes
		{"ftp scheme", "ftp://proxy.example.com:21", false, ErrBlockedProxyScheme},
		{"file scheme", "file:///etc/passwd", false, ErrBlockedProxyScheme},
		{"javascript scheme", "javascript:alert(1)", false, ErrBlockedProxyScheme},
		{"no scheme", "proxy.example.com:8080", false, ErrBlockedProxyScheme},

		// Invalid URLs
		{"missing host", "http://", false, ErrInvalidProxyURL},
		{"malformed", "http://[invalid", false, ErrInvalidProxyURL},

		// Localhost blocking (when not allowed)
		{"localhost", "http://localhost:8080", false, ErrLocalhostBlocked},
		{"127.0.0.1", "http://127.0.0.1:8080", false, ErrLocalhostBlocked},
		{"loopback range", "http://127.0.0.2:8080", false, ErrLocalhostBlocked},

		// Private IP blocking (when not allowed)
		{"private 192.168.x", "http://192.168.1.1:8080", false, ErrPrivateIPBlocked},
		{"private 10.x", "http://10.0.0.1:8080", false, ErrPrivateIPBlocked},
		{"private 172.16.x", "http://172.16.0.1:8080", false, ErrPrivateIPBlocked},

		// Private IPs allowed for local proxies
		{"localhost allowed", "http://localhost:8080", true, nil},
		{"127.0.0.1 allowed", "http://127.0.0.1:8080", true, nil},
		{"192.168.x allowed", "http://192.168.1.1:8080", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyURL(tt.proxyURL, tt.allowPrivateIPs)
			if err != tt.wantErr {
				t.Errorf("ValidateProxyURL(%q, %v) = %v, want %v",
					tt.proxyURL, tt.allowPrivateIPs, err, tt.wantErr)
			}
		})
	}
}

// TestValidateProxyURLWithCredentials tests that proxy URLs with credentials
// in various formats are properly handled. Note: URL-encoded credentials in
// the proxy URL itself are parsed by url.Parse - the actual credential handling
// happens separately via CDP or extension.
func TestValidateProxyURLWithCredentials(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		wantErr  bool
	}{
		// Credentials with special characters in URL (url.Parse handles these)
		{"simple credentials", "http://user:pass@proxy.example.com:8080", false},
		{"url-encoded at sign", "http://user%40domain:pass@proxy.example.com:8080", false},
		{"url-encoded colon", "http://user:p%3Ass@proxy.example.com:8080", false},
		{"url-encoded quote", "http://user:p%22ss@proxy.example.com:8080", false},
		{"url-encoded backslash", "http://user:p%5Css@proxy.example.com:8080", false},
		{"url-encoded percent", "http://user:p%25ss@proxy.example.com:8080", false},
		{"complex encoded", "http://user%40domain.com:p%40ss%3Aword@proxy.example.com:8080", false},

		// Edge cases
		{"empty password", "http://user:@proxy.example.com:8080", false},
		{"empty username", "http://:pass@proxy.example.com:8080", false},
		{"only at sign", "http://@proxy.example.com:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyURL(tt.proxyURL, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProxyURL(%q) error = %v, wantErr %v",
					tt.proxyURL, err, tt.wantErr)
			}
		})
	}
}

// TestValidateProxyURL_CloudMetadataBlocked tests that cloud metadata endpoints
// are always blocked, even when allowPrivateIPs is true.
// This prevents SSRF attacks against cloud metadata services.
func TestValidateProxyURL_CloudMetadataBlocked(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		wantErr  error
	}{
		// Cloud metadata hosts should be blocked even with allowPrivateIPs=true
		{"GCP metadata", "http://metadata.google.internal:8080", ErrMetadataBlocked},
		{"generic metadata", "http://metadata:8080", ErrMetadataBlocked},
		{"AWS instance-data", "http://instance-data:8080", ErrMetadataBlocked},
		// But localhost should be allowed with allowPrivateIPs=true
		{"localhost allowed", "http://localhost:8080", nil},
		{"127.0.0.1 allowed", "http://127.0.0.1:8080", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyURL(tt.proxyURL, true) // second arg allows private IPs
			if err != tt.wantErr {
				t.Errorf("ValidateProxyURL(%q, true) = %v, want %v",
					tt.proxyURL, err, tt.wantErr)
			}
		})
	}
}

// TestValidateProxyURLSpecialCharacterPasswords tests that passwords with
// characters that commonly cause issues don't break URL parsing.
// The actual credential values are handled by CDP/extension, not URL parsing.
func TestValidateProxyURLSpecialCharacterPasswords(t *testing.T) {
	// These passwords contain characters that need URL encoding if embedded in URL
	specialPasswords := []string{
		"simple",
		"with space",
		"with@at",
		"with:colon",
		"with/slash",
		"with?question",
		"with#hash",
		"with\"quote",
		"with'apostrophe",
		"with\\backslash",
		"with%percent",
	}

	for _, pass := range specialPasswords {
		t.Run(pass, func(t *testing.T) {
			// URL without credentials (credentials are handled separately)
			proxyURL := "http://proxy.example.com:8080"
			err := ValidateProxyURL(proxyURL, false)
			if err != nil {
				t.Errorf("ValidateProxyURL failed for proxy URL: %v", err)
			}
		})
	}
}

// TestParseIPWithNormalization_BrowserParity verifies numeric hosts are read the
// way the WHATWG URL parser (and therefore Chrome) reads them. A mismatch lets a
// host validate as public while the browser connects to a private address.
func TestParseIPWithNormalization_BrowserParity(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string // empty means "not an IP literal"
	}{
		{name: "dotted decimal", host: "192.168.1.1", want: "192.168.1.1"},
		{name: "single decimal", host: "2130706433", want: "127.0.0.1"},
		{name: "single octal 10.0.0.1", host: "01200000001", want: "10.0.0.1"},
		{name: "single octal 10.99.0.2", host: "01230600002", want: "10.99.0.2"},
		{name: "single octal loopback", host: "017700000001", want: "127.0.0.1"},
		{name: "single hex", host: "0x7f000001", want: "127.0.0.1"},
		{name: "dotted octal", host: "010.0.0.1", want: "8.0.0.1"},
		{name: "two part", host: "127.1", want: "127.0.0.1"},
		{name: "trailing dot", host: "127.0.0.1.", want: "127.0.0.1"},
		{name: "octal trailing dot", host: "01200000001.", want: "10.0.0.1"},
		{name: "invalid octal digits", host: "089", want: ""},
		{name: "number too large", host: "4294967296", want: ""},
		{name: "hostname", host: "example.com", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIPWithNormalization(tt.host)
			if tt.want == "" {
				if got != nil {
					t.Errorf("parseIPWithNormalization(%q) = %v, want nil", tt.host, got)
				}
				return
			}
			if got == nil || !got.Equal(net.ParseIP(tt.want)) {
				t.Errorf("parseIPWithNormalization(%q) = %v, want %s", tt.host, got, tt.want)
			}
		})
	}
}

func TestValidateURL_NumericHostBypass(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "octal 10.0.0.1", url: "http://01200000001/"},
		{name: "octal 10.99.0.2", url: "http://01230600002/"},
		{name: "octal loopback", url: "http://017700000001/"},
		{name: "hex loopback", url: "http://0x7f000001/"},
		{name: "loopback trailing dot", url: "http://127.0.0.1./"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateURL(tt.url); err == nil {
				t.Errorf("ValidateURL(%q) = nil, want error", tt.url)
			}
		})
	}
}

func TestValidateIP_SpecialPurposeRanges(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{name: "public v4", ip: "93.184.216.34", blocked: false},
		{name: "public v6", ip: "2606:4700:4700::1111", blocked: false},
		{name: "this network", ip: "0.1.2.3", blocked: true},
		{name: "cgnat", ip: "100.64.0.1", blocked: true},
		{name: "cgnat upper", ip: "100.127.255.254", blocked: true},
		{name: "just below cgnat", ip: "100.63.255.255", blocked: false},
		{name: "ietf protocol", ip: "192.0.0.8", blocked: true},
		{name: "test-net-1", ip: "192.0.2.1", blocked: true},
		{name: "benchmarking", ip: "198.18.0.1", blocked: true},
		{name: "test-net-2", ip: "198.51.100.1", blocked: true},
		{name: "test-net-3", ip: "203.0.113.1", blocked: true},
		{name: "multicast", ip: "224.0.0.1", blocked: true},
		{name: "reserved", ip: "240.0.0.1", blocked: true},
		{name: "broadcast", ip: "255.255.255.255", blocked: true},
		{name: "v4-mapped cgnat", ip: "::ffff:100.64.0.1", blocked: true},
		{name: "v4-compatible", ip: "::10.0.0.1", blocked: true},
		{name: "nat64 private", ip: "64:ff9b::a00:1", blocked: true},
		{name: "nat64 loopback", ip: "64:ff9b::7f00:1", blocked: true},
		{name: "nat64 public", ip: "64:ff9b::5db8:d822", blocked: false},
		{name: "nat64 local-use", ip: "64:ff9b:1::1", blocked: true},
		{name: "6to4 private", ip: "2002:0a00:0001::1", blocked: true},
		{name: "6to4 public", ip: "2002:5db8:d822::1", blocked: false},
		{name: "teredo", ip: "2001:0:4136:e378::1", blocked: true},
		{name: "documentation v6", ip: "2001:db8::1", blocked: true},
		{name: "site-local", ip: "fec0::1", blocked: true},
		{name: "multicast v6", ip: "ff02::1", blocked: true},
		{name: "discard", ip: "100::1", blocked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIP(net.ParseIP(tt.ip))
			if tt.blocked && err == nil {
				t.Errorf("validateIP(%s) = nil, want blocked", tt.ip)
			}
			if !tt.blocked && err != nil {
				t.Errorf("validateIP(%s) = %v, want allowed", tt.ip, err)
			}
		})
	}
}

// TestValidateURLWithPinnedIP_DNSRotation verifies a public host is not rejected
// because its current addresses differ from the one recorded before navigation
// (load-balanced hosts rotate; redirects change the host entirely), while a
// private destination is still rejected whatever was recorded.
func TestValidateURLWithPinnedIP_DNSRotation(t *testing.T) {
	stale := net.ParseIP("198.41.0.4") // a public address the host does not resolve to

	tests := []struct {
		name    string
		url     string
		pinned  net.IP
		wantErr bool
	}{
		{name: "public IP literal, different pinned address", url: "http://93.184.216.34/", pinned: stale, wantErr: false},
		{name: "public IP literal, no pin", url: "http://93.184.216.34/", pinned: nil, wantErr: false},
		{name: "private IP literal, pinned to itself", url: "http://10.0.0.1/", pinned: net.ParseIP("10.0.0.1"), wantErr: true},
		{name: "loopback, pinned to a public address", url: "http://127.0.0.1/", pinned: stale, wantErr: true},
		{name: "metadata address", url: "http://169.254.169.254/", pinned: stale, wantErr: true},
		{name: "octal private host", url: "http://01200000001/", pinned: stale, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLWithPinnedIP(tt.url, tt.pinned)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateURLWithPinnedIP(%q) = nil, want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateURLWithPinnedIP(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}
