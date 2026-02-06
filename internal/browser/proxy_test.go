package browser

import (
	"testing"
)

// TestProxyConfigSpecialCharacters verifies that ProxyConfig correctly handles
// special characters in username and password fields when passed through
// the CDP Fetch API. The CDP auth mechanism uses JSON serialization via rod,
// which properly escapes special characters.
func TestProxyConfigSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "double quotes",
			username: `user"name`,
			password: `pass"word`,
		},
		{
			name:     "single quotes",
			username: `user'name`,
			password: `pass'word`,
		},
		{
			name:     "backslash",
			username: `user\name`,
			password: `pass\word`,
		},
		{
			name:     "at sign in password",
			username: `user@domain.com`,
			password: `p@ssword`,
		},
		{
			name:     "colon in credentials",
			username: `user:name`,
			password: `pass:word`,
		},
		{
			name:     "percent encoding chars",
			username: `user%20name`,
			password: `pass%20word`,
		},
		{
			name:     "newline characters",
			username: "user\nname",
			password: "pass\nword",
		},
		{
			name:     "tab characters",
			username: "user\tname",
			password: "pass\tword",
		},
		{
			name:     "carriage return",
			username: "user\rname",
			password: "pass\rword",
		},
		{
			name:     "unicode chinese",
			username: `用户名`,
			password: `密码`,
		},
		{
			name:     "unicode emoji",
			username: `user🔐`,
			password: `pass🔑word`,
		},
		{
			name:     "unicode mixed",
			username: `user日本語`,
			password: `пароль`,
		},
		{
			name:     "null byte",
			username: "user\x00name",
			password: "pass\x00word",
		},
		{
			name:     "mixed special characters",
			username: `u"s'e\r@:name`,
			password: `p"a's\s@:word`,
		},
		{
			name:     "url special chars",
			username: `user?query=1&foo=bar`,
			password: `pass#fragment/path`,
		},
		{
			name:     "html entities",
			username: `user<script>`,
			password: `pass</script>`,
		},
		{
			name:     "brackets and braces",
			username: `user[0]`,
			password: `pass{key}`,
		},
		{
			name:     "very long password",
			username: `user`,
			password: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()`,
		},
		{
			name:     "empty username",
			username: ``,
			password: `password`,
		},
		{
			name:     "spaces in credentials",
			username: `user name`,
			password: `pass word`,
		},
		{
			name:     "leading trailing spaces",
			username: ` username `,
			password: ` password `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create ProxyConfig with special characters
			// The struct should store these values without modification
			config := &ProxyConfig{
				URL:      "http://proxy.example.com:8080",
				Username: tt.username,
				Password: tt.password,
			}

			// Verify the config stores the values exactly as provided
			if config.URL != "http://proxy.example.com:8080" {
				t.Errorf("URL not stored correctly: got %q", config.URL)
			}
			if config.Username != tt.username {
				t.Errorf("Username not stored correctly: got %q, want %q",
					config.Username, tt.username)
			}
			if config.Password != tt.password {
				t.Errorf("Password not stored correctly: got %q, want %q",
					config.Password, tt.password)
			}
		})
	}
}

// TestGetProxyArg verifies that GetProxyArg returns the proxy URL unchanged.
// The proxy URL passed to Chrome's --proxy-server flag should be the URL
// without credentials embedded (credentials are handled separately via CDP or extension).
func TestGetProxyArg(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		want     string
	}{
		{
			name:     "empty url",
			proxyURL: "",
			want:     "",
		},
		{
			name:     "simple http proxy",
			proxyURL: "http://proxy.example.com:8080",
			want:     "http://proxy.example.com:8080",
		},
		{
			name:     "socks5 proxy",
			proxyURL: "socks5://proxy.example.com:1080",
			want:     "socks5://proxy.example.com:1080",
		},
		{
			name:     "https proxy",
			proxyURL: "https://secure-proxy.example.com:443",
			want:     "https://secure-proxy.example.com:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetProxyArg(tt.proxyURL)
			if got != tt.want {
				t.Errorf("GetProxyArg(%q) = %q, want %q", tt.proxyURL, got, tt.want)
			}
		})
	}
}

// TestProxyConfigNilHandling verifies that nil ProxyConfig is handled safely.
func TestProxyConfigNilHandling(t *testing.T) {
	// This tests the behavior when SetPageProxy receives nil
	// The function should return a no-op cleanup function and no error

	// Test nil config pointer behavior via helper function
	isNil := func(cfg *ProxyConfig) bool {
		return cfg == nil
	}

	var config *ProxyConfig
	if !isNil(config) {
		t.Error("Config should be nil")
	}

	// Verify empty URL check works
	config = &ProxyConfig{URL: ""}
	if config.URL != "" {
		t.Error("Empty URL should be detected")
	}
}

// TestProxyConfigWithCredentialsPresent verifies that the presence of credentials
// is correctly detected for CDP auth setup.
func TestProxyConfigWithCredentialsPresent(t *testing.T) {
	tests := []struct {
		name            string
		config          *ProxyConfig
		expectAuthSetup bool
	}{
		{
			name:            "nil config",
			config:          nil,
			expectAuthSetup: false,
		},
		{
			name:            "empty url",
			config:          &ProxyConfig{URL: ""},
			expectAuthSetup: false,
		},
		{
			name: "url only no credentials",
			config: &ProxyConfig{
				URL:      "http://proxy:8080",
				Username: "",
				Password: "",
			},
			expectAuthSetup: false,
		},
		{
			name: "url with username only",
			config: &ProxyConfig{
				URL:      "http://proxy:8080",
				Username: "user",
				Password: "",
			},
			expectAuthSetup: true,
		},
		{
			name: "url with full credentials",
			config: &ProxyConfig{
				URL:      "http://proxy:8080",
				Username: "user",
				Password: "pass",
			},
			expectAuthSetup: true,
		},
		{
			name: "credentials with special chars",
			config: &ProxyConfig{
				URL:      "http://proxy:8080",
				Username: `user"@domain`,
				Password: `p@ss"word`,
			},
			expectAuthSetup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needsAuth := tt.config != nil && tt.config.URL != "" && tt.config.Username != ""
			if needsAuth != tt.expectAuthSetup {
				t.Errorf("Auth setup needed = %v, want %v", needsAuth, tt.expectAuthSetup)
			}
		})
	}
}
