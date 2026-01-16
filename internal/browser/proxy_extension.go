// Package browser provides browser management functionality.
package browser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ProxyExtension creates a Chrome extension for authenticated proxy support.
// This matches Python FlareSolverr's approach of using an extension for proxy auth
// because Chrome doesn't support authenticated proxies via command line.
type ProxyExtension struct {
	dir      string
	host     string
	port     string
	username string
	password string
}

// NewProxyExtension creates a new proxy extension for authenticated proxy support.
// Security: Creates files with 0600 permissions and directory with 0700 to protect credentials.
func NewProxyExtension(host, port, username, password string) (*ProxyExtension, error) {
	// Create temporary directory for extension
	dir, err := os.MkdirTemp("", "flaresolverr-proxy-ext-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for proxy extension: %w", err)
	}

	// Set restrictive directory permissions (owner only)
	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to set directory permissions: %w", err)
	}

	ext := &ProxyExtension{
		dir:      dir,
		host:     host,
		port:     port,
		username: username,
		password: password,
	}

	// Create extension files
	if err := ext.createManifest(); err != nil {
		ext.Cleanup()
		return nil, err
	}
	if err := ext.createBackgroundScript(); err != nil {
		ext.Cleanup()
		return nil, err
	}

	return ext, nil
}

// Dir returns the extension directory path.
func (e *ProxyExtension) Dir() string {
	return e.dir
}

// Cleanup removes the extension directory.
func (e *ProxyExtension) Cleanup() {
	if e.dir != "" {
		os.RemoveAll(e.dir)
	}
}

// createManifest creates the extension's manifest.json file.
func (e *ProxyExtension) createManifest() error {
	manifest := map[string]interface{}{
		"manifest_version": 3,
		"name":             "FlareSolverr Proxy Auth",
		"version":          "1.0",
		"permissions": []string{
			"proxy",
			"webRequest",
			"webRequestAuthProvider",
		},
		"host_permissions": []string{
			"<all_urls>",
		},
		"background": map[string]interface{}{
			"service_worker": "background.js",
		},
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	manifestPath := filepath.Join(e.dir, "manifest.json")
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// createBackgroundScript creates the extension's background.js file.
func (e *ProxyExtension) createBackgroundScript() error {
	// JavaScript that handles proxy configuration and authentication
	script := fmt.Sprintf(`
// Proxy configuration
const config = {
    mode: "fixed_servers",
    rules: {
        singleProxy: {
            scheme: "http",
            host: "%s",
            port: parseInt("%s")
        },
        bypassList: []
    }
};

// Set proxy configuration
chrome.proxy.settings.set({value: config, scope: "regular"}, function() {
    if (chrome.runtime.lastError) {
        console.error("Proxy config error:", chrome.runtime.lastError);
    }
});

// Handle proxy authentication
chrome.webRequest.onAuthRequired.addListener(
    function(details, callbackFn) {
        callbackFn({
            authCredentials: {
                username: "%s",
                password: "%s"
            }
        });
    },
    {urls: ["<all_urls>"]},
    ["asyncBlocking"]
);
`, e.host, e.port, e.username, e.password)

	scriptPath := filepath.Join(e.dir, "background.js")
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return fmt.Errorf("failed to write background script: %w", err)
	}

	return nil
}

// ProxyExtensionMV2 creates a Manifest V2 extension for older Chrome versions.
// Manifest V2 is deprecated but may be needed for some environments.
type ProxyExtensionMV2 struct {
	dir      string
	host     string
	port     string
	username string
	password string
}

// NewProxyExtensionMV2 creates a new Manifest V2 proxy extension.
// Security: Creates files with 0600 permissions and directory with 0700 to protect credentials.
func NewProxyExtensionMV2(host, port, username, password string) (*ProxyExtensionMV2, error) {
	dir, err := os.MkdirTemp("", "flaresolverr-proxy-ext-mv2-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for proxy extension: %w", err)
	}

	// Set restrictive directory permissions (owner only)
	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to set directory permissions: %w", err)
	}

	ext := &ProxyExtensionMV2{
		dir:      dir,
		host:     host,
		port:     port,
		username: username,
		password: password,
	}

	if err := ext.createManifest(); err != nil {
		ext.Cleanup()
		return nil, err
	}
	if err := ext.createBackgroundScript(); err != nil {
		ext.Cleanup()
		return nil, err
	}

	return ext, nil
}

// Dir returns the extension directory path.
func (e *ProxyExtensionMV2) Dir() string {
	return e.dir
}

// Cleanup removes the extension directory.
func (e *ProxyExtensionMV2) Cleanup() {
	if e.dir != "" {
		os.RemoveAll(e.dir)
	}
}

// createManifest creates the Manifest V2 manifest.json file.
func (e *ProxyExtensionMV2) createManifest() error {
	manifest := map[string]interface{}{
		"manifest_version": 2,
		"name":             "FlareSolverr Proxy Auth",
		"version":          "1.0",
		"permissions": []string{
			"proxy",
			"webRequest",
			"webRequestBlocking",
			"<all_urls>",
		},
		"background": map[string]interface{}{
			"scripts":    []string{"background.js"},
			"persistent": true,
		},
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	manifestPath := filepath.Join(e.dir, "manifest.json")
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// createBackgroundScript creates the Manifest V2 background.js file.
func (e *ProxyExtensionMV2) createBackgroundScript() error {
	// JavaScript that handles proxy configuration and authentication (MV2 style)
	script := fmt.Sprintf(`
// Proxy configuration
var config = {
    mode: "fixed_servers",
    rules: {
        singleProxy: {
            scheme: "http",
            host: "%s",
            port: parseInt("%s")
        },
        bypassList: []
    }
};

// Set proxy configuration
chrome.proxy.settings.set({value: config, scope: "regular"}, function() {});

// Handle proxy authentication (blocking style for MV2)
chrome.webRequest.onAuthRequired.addListener(
    function(details) {
        return {
            authCredentials: {
                username: "%s",
                password: "%s"
            }
        };
    },
    {urls: ["<all_urls>"]},
    ["blocking"]
);
`, e.host, e.port, e.username, e.password)

	scriptPath := filepath.Join(e.dir, "background.js")
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return fmt.Errorf("failed to write background script: %w", err)
	}

	return nil
}
