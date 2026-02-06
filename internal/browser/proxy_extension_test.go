package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProxyExtensionSpecialCharacters verifies that the proxy extension correctly
// handles special characters in credentials by using json.Marshal for escaping.
func TestProxyExtensionSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     string
		username string
		password string
	}{
		{
			name:     "double quotes",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user"name`,
			password: `pass"word`,
		},
		{
			name:     "single quotes",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user'name`,
			password: `pass'word`,
		},
		{
			name:     "backslash",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user\name`,
			password: `pass\word`,
		},
		{
			name:     "at sign in credentials",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user@domain.com`,
			password: `p@ssword`,
		},
		{
			name:     "colon in credentials",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user:name`,
			password: `pass:word`,
		},
		{
			name:     "percent encoding chars",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user%20name`,
			password: `pass%20word`,
		},
		{
			name:     "newline characters",
			host:     "proxy.example.com",
			port:     "8080",
			username: "user\nname",
			password: "pass\nword",
		},
		{
			name:     "unicode chinese",
			host:     "proxy.example.com",
			port:     "8080",
			username: `用户名`,
			password: `密码`,
		},
		{
			name:     "unicode emoji",
			host:     "proxy.example.com",
			port:     "8080",
			username: `user🔐`,
			password: `pass🔑word`,
		},
		{
			name:     "js injection attempt",
			host:     "proxy.example.com",
			port:     "8080",
			username: `"; alert('xss'); //`,
			password: `pass`,
		},
		{
			name:     "js injection with closing brace",
			host:     "proxy.example.com",
			port:     "8080",
			username: `"}); malicious(); ({x:"`,
			password: `pass`,
		},
		{
			name:     "html script tag",
			host:     "proxy.example.com",
			port:     "8080",
			username: `<script>alert(1)</script>`,
			password: `pass`,
		},
		{
			name:     "mixed special characters",
			host:     "proxy.example.com",
			port:     "8080",
			username: `u"s'e\r@:name`,
			password: `p"a's\s@:word`,
		},
		{
			name:     "null byte",
			host:     "proxy.example.com",
			port:     "8080",
			username: "user\x00name",
			password: "pass\x00word",
		},
		{
			name:     "template literal attempt",
			host:     "proxy.example.com",
			port:     "8080",
			username: "${process.env.SECRET}",
			password: "`${require('child_process').execSync('id')}`",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := NewProxyExtension("http", tt.host, tt.port, tt.username, tt.password)
			if err != nil {
				t.Fatalf("Failed to create extension: %v", err)
			}
			defer ext.Cleanup()

			// Verify extension directory was created
			if ext.Dir() == "" {
				t.Fatal("Extension directory is empty")
			}

			// Read and verify background.js
			scriptPath := filepath.Join(ext.Dir(), "background.js")
			scriptContent, err := os.ReadFile(scriptPath)
			if err != nil {
				t.Fatalf("Failed to read background.js: %v", err)
			}

			script := string(scriptContent)

			// Verify the script contains properly JSON-escaped values
			// json.Marshal adds quotes around strings, so we check for the escaped form
			usernameJSON, _ := json.Marshal(tt.username)
			passwordJSON, _ := json.Marshal(tt.password)

			if !strings.Contains(script, string(usernameJSON)) {
				t.Errorf("Script does not contain properly escaped username.\nExpected substring: %s\nScript:\n%s",
					usernameJSON, script)
			}

			if !strings.Contains(script, string(passwordJSON)) {
				t.Errorf("Script does not contain properly escaped password.\nExpected substring: %s",
					passwordJSON)
			}

			// Verify manifest.json exists and is valid JSON
			manifestPath := filepath.Join(ext.Dir(), "manifest.json")
			manifestContent, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("Failed to read manifest.json: %v", err)
			}

			var manifest map[string]interface{}
			if err := json.Unmarshal(manifestContent, &manifest); err != nil {
				t.Errorf("manifest.json is not valid JSON: %v", err)
			}

			// Verify it's Manifest V3
			if version, ok := manifest["manifest_version"].(float64); !ok || version != 3 {
				t.Errorf("Expected manifest_version 3, got %v", manifest["manifest_version"])
			}
		})
	}
}

// TestProxyExtensionMV2SpecialCharacters verifies that the MV2 proxy extension
// also correctly handles special characters.
func TestProxyExtensionMV2SpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "js injection attempt",
			username: `"; return {authCredentials:{username:"hacked",password:"hacked"}}; //`,
			password: `pass`,
		},
		{
			name:     "double quotes",
			username: `user"with"quotes`,
			password: `pass"word`,
		},
		{
			name:     "unicode",
			username: `用户名`,
			password: `密码123`,
		},
		{
			name:     "backslash sequences",
			username: `user\n\r\t`,
			password: `pass\\word`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := NewProxyExtensionMV2("http", "proxy.example.com", "8080", tt.username, tt.password)
			if err != nil {
				t.Fatalf("Failed to create MV2 extension: %v", err)
			}
			defer ext.Cleanup()

			// Read background.js
			scriptPath := filepath.Join(ext.Dir(), "background.js")
			scriptContent, err := os.ReadFile(scriptPath)
			if err != nil {
				t.Fatalf("Failed to read background.js: %v", err)
			}

			script := string(scriptContent)

			// Verify proper JSON escaping
			usernameJSON, _ := json.Marshal(tt.username)
			passwordJSON, _ := json.Marshal(tt.password)

			if !strings.Contains(script, string(usernameJSON)) {
				t.Errorf("MV2 script does not contain properly escaped username")
			}

			if !strings.Contains(script, string(passwordJSON)) {
				t.Errorf("MV2 script does not contain properly escaped password")
			}

			// Verify manifest is MV2
			manifestPath := filepath.Join(ext.Dir(), "manifest.json")
			manifestContent, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("Failed to read manifest.json: %v", err)
			}

			var manifest map[string]interface{}
			if err := json.Unmarshal(manifestContent, &manifest); err != nil {
				t.Errorf("manifest.json is not valid JSON: %v", err)
			}

			if version, ok := manifest["manifest_version"].(float64); !ok || version != 2 {
				t.Errorf("Expected manifest_version 2, got %v", manifest["manifest_version"])
			}
		})
	}
}

// TestProxyExtensionCleanup verifies that extension directories are properly cleaned up.
func TestProxyExtensionCleanup(t *testing.T) {
	ext, err := NewProxyExtension("http", "proxy.example.com", "8080", "user", "pass")
	if err != nil {
		t.Fatalf("Failed to create extension: %v", err)
	}

	dir := ext.Dir()

	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("Extension directory does not exist before cleanup")
	}

	// Cleanup
	ext.Cleanup()

	// Verify directory is removed
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("Extension directory still exists after cleanup")
	}

	// Verify double cleanup doesn't panic
	ext.Cleanup()
}

// TestProxyExtensionMV2Cleanup verifies that MV2 extension directories are cleaned up.
func TestProxyExtensionMV2Cleanup(t *testing.T) {
	ext, err := NewProxyExtensionMV2("http", "proxy.example.com", "8080", "user", "pass")
	if err != nil {
		t.Fatalf("Failed to create MV2 extension: %v", err)
	}

	dir := ext.Dir()

	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("MV2 extension directory does not exist before cleanup")
	}

	ext.Cleanup()

	// Verify directory is removed
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("MV2 extension directory still exists after cleanup")
	}
}

// TestProxyExtensionFilePermissions verifies that extension files have secure permissions.
func TestProxyExtensionFilePermissions(t *testing.T) {
	ext, err := NewProxyExtension("http", "proxy.example.com", "8080", "secret_user", "secret_pass")
	if err != nil {
		t.Fatalf("Failed to create extension: %v", err)
	}
	defer ext.Cleanup()

	// Check directory permissions (should be 0700)
	dirInfo, err := os.Stat(ext.Dir())
	if err != nil {
		t.Fatalf("Failed to stat directory: %v", err)
	}
	dirPerm := dirInfo.Mode().Perm()
	if dirPerm != 0700 {
		t.Errorf("Directory permissions should be 0700, got %o", dirPerm)
	}

	// Check manifest.json permissions (should be 0600)
	manifestInfo, err := os.Stat(filepath.Join(ext.Dir(), "manifest.json"))
	if err != nil {
		t.Fatalf("Failed to stat manifest.json: %v", err)
	}
	manifestPerm := manifestInfo.Mode().Perm()
	if manifestPerm != 0600 {
		t.Errorf("manifest.json permissions should be 0600, got %o", manifestPerm)
	}

	// Check background.js permissions (should be 0600)
	scriptInfo, err := os.Stat(filepath.Join(ext.Dir(), "background.js"))
	if err != nil {
		t.Fatalf("Failed to stat background.js: %v", err)
	}
	scriptPerm := scriptInfo.Mode().Perm()
	if scriptPerm != 0600 {
		t.Errorf("background.js permissions should be 0600, got %o", scriptPerm)
	}
}

// TestProxyExtensionJavaScriptSyntax verifies that generated JavaScript is syntactically valid.
// This test uses a simple heuristic check - proper JSON escaping ensures syntax validity.
func TestProxyExtensionJavaScriptSyntax(t *testing.T) {
	// Test cases that could break JavaScript syntax if not properly escaped
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "unbalanced quotes",
			username: `"`,
			password: `'`,
		},
		{
			name:     "unbalanced braces",
			username: `{`,
			password: `}`,
		},
		{
			name:     "unbalanced brackets",
			username: `[`,
			password: `]`,
		},
		{
			name:     "unbalanced parens",
			username: `(`,
			password: `)`,
		},
		{
			name:     "comment sequence",
			username: `//`,
			password: `/* */`,
		},
		{
			name:     "multiline",
			username: "line1\nline2",
			password: "line1\r\nline2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := NewProxyExtension("http", "proxy.example.com", "8080", tt.username, tt.password)
			if err != nil {
				t.Fatalf("Failed to create extension: %v", err)
			}
			defer ext.Cleanup()

			// Read the script
			scriptPath := filepath.Join(ext.Dir(), "background.js")
			scriptContent, err := os.ReadFile(scriptPath)
			if err != nil {
				t.Fatalf("Failed to read background.js: %v", err)
			}

			script := string(scriptContent)

			// Basic syntax validation: ensure JSON-encoded strings are present
			// A proper JSON string will have all special characters escaped
			usernameJSON, _ := json.Marshal(tt.username)
			passwordJSON, _ := json.Marshal(tt.password)

			if !strings.Contains(script, string(usernameJSON)) {
				t.Errorf("Script missing properly escaped username")
			}

			if !strings.Contains(script, string(passwordJSON)) {
				t.Errorf("Script missing properly escaped password")
			}

			// Verify the script has balanced structure for key elements
			// Count occurrences of chrome.proxy and chrome.webRequest
			if !strings.Contains(script, "chrome.proxy.settings.set") {
				t.Error("Script missing chrome.proxy.settings.set call")
			}

			if !strings.Contains(script, "chrome.webRequest.onAuthRequired.addListener") {
				t.Error("Script missing chrome.webRequest.onAuthRequired.addListener call")
			}
		})
	}
}

// TestProxyExtensionScheme verifies that both http and https schemes work.
func TestProxyExtensionScheme(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
	}{
		{
			name:   "http scheme",
			scheme: "http",
		},
		{
			name:   "https scheme",
			scheme: "https",
		},
		{
			name:   "empty scheme defaults to http",
			scheme: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := NewProxyExtension(tt.scheme, "proxy.example.com", "8080", "user", "pass")
			if err != nil {
				t.Fatalf("Failed to create extension: %v", err)
			}
			defer ext.Cleanup()

			scriptPath := filepath.Join(ext.Dir(), "background.js")
			scriptContent, err := os.ReadFile(scriptPath)
			if err != nil {
				t.Fatalf("Failed to read background.js: %v", err)
			}

			script := string(scriptContent)

			// Expected scheme (empty defaults to http)
			expectedScheme := tt.scheme
			if expectedScheme == "" {
				expectedScheme = "http"
			}

			// Verify scheme is JSON-encoded in script
			schemeJSON, _ := json.Marshal(expectedScheme)
			if !strings.Contains(script, "scheme: "+string(schemeJSON)) {
				t.Errorf("Script does not contain expected scheme. Expected: %s, Script:\n%s", schemeJSON, script)
			}
		})
	}
}

// TestProxyExtensionInvalidScheme verifies that invalid schemes are rejected.
func TestProxyExtensionInvalidScheme(t *testing.T) {
	invalidSchemes := []string{"socks5", "socks4", "ftp", "invalid"}

	for _, scheme := range invalidSchemes {
		t.Run(scheme, func(t *testing.T) {
			_, err := NewProxyExtension(scheme, "proxy.example.com", "8080", "user", "pass")
			if err == nil {
				t.Errorf("Expected error for scheme %q, got nil", scheme)
			}
		})
	}
}

// TestProxyExtensionHostPort verifies that host and port are correctly embedded.
func TestProxyExtensionHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		port string
	}{
		{
			name: "standard",
			host: "proxy.example.com",
			port: "8080",
		},
		{
			name: "ip address",
			host: "192.168.1.100",
			port: "3128",
		},
		{
			name: "ipv6",
			host: "::1",
			port: "8080",
		},
		{
			name: "high port",
			host: "proxy.local",
			port: "65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := NewProxyExtension("http", tt.host, tt.port, "user", "pass")
			if err != nil {
				t.Fatalf("Failed to create extension: %v", err)
			}
			defer ext.Cleanup()

			scriptPath := filepath.Join(ext.Dir(), "background.js")
			scriptContent, err := os.ReadFile(scriptPath)
			if err != nil {
				t.Fatalf("Failed to read background.js: %v", err)
			}

			script := string(scriptContent)

			// Verify host is JSON-encoded in script
			hostJSON, _ := json.Marshal(tt.host)
			if !strings.Contains(script, string(hostJSON)) {
				t.Errorf("Script does not contain host: %s", hostJSON)
			}

			// Verify port is JSON-encoded in script
			portJSON, _ := json.Marshal(tt.port)
			if !strings.Contains(script, string(portJSON)) {
				t.Errorf("Script does not contain port: %s", portJSON)
			}
		})
	}
}
