package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Clear any environment variables that might interfere
	envVars := []string{
		"HOST", "PORT", "HEADLESS", "BROWSER_PATH",
		"BROWSER_POOL_SIZE", "BROWSER_POOL_TIMEOUT", "MAX_MEMORY_MB",
		"SESSION_TTL", "SESSION_CLEANUP_INTERVAL", "MAX_SESSIONS",
		"DEFAULT_TIMEOUT", "MAX_TIMEOUT",
		"PROXY_URL", "PROXY_USERNAME", "PROXY_PASSWORD",
		"LOG_LEVEL", "LOG_HTML",
		"PROMETHEUS_ENABLED", "PROMETHEUS_PORT",
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}

	cfg := Load()

	// Server defaults
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Expected default host '0.0.0.0', got %q", cfg.Host)
	}
	if cfg.Port != 8191 {
		t.Errorf("Expected default port 8191, got %d", cfg.Port)
	}

	// Browser defaults
	if !cfg.Headless {
		t.Error("Expected Headless to be true by default")
	}
	if cfg.BrowserPath != "" {
		t.Errorf("Expected empty BrowserPath by default, got %q", cfg.BrowserPath)
	}

	// Pool defaults
	if cfg.BrowserPoolSize != 3 {
		t.Errorf("Expected default pool size 3, got %d", cfg.BrowserPoolSize)
	}
	if cfg.BrowserPoolTimeout != 30*time.Second {
		t.Errorf("Expected default pool timeout 30s, got %v", cfg.BrowserPoolTimeout)
	}
	if cfg.MaxMemoryMB != 2048 {
		t.Errorf("Expected default max memory 2048MB, got %d", cfg.MaxMemoryMB)
	}

	// Session defaults
	if cfg.SessionTTL != 30*time.Minute {
		t.Errorf("Expected default session TTL 30m, got %v", cfg.SessionTTL)
	}
	if cfg.MaxSessions != 100 {
		t.Errorf("Expected default max sessions 100, got %d", cfg.MaxSessions)
	}

	// Timeout defaults
	if cfg.DefaultTimeout != 60*time.Second {
		t.Errorf("Expected default timeout 60s, got %v", cfg.DefaultTimeout)
	}
	if cfg.MaxTimeout != 300*time.Second {
		t.Errorf("Expected max timeout 300s, got %v", cfg.MaxTimeout)
	}

	// Logging defaults
	if cfg.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got %q", cfg.LogLevel)
	}
	if cfg.LogHTML {
		t.Error("Expected LogHTML to be false by default")
	}

	// Metrics defaults
	if cfg.PrometheusEnabled {
		t.Error("Expected PrometheusEnabled to be false by default")
	}
	if cfg.PrometheusPort != 8192 {
		t.Errorf("Expected default Prometheus port 8192, got %d", cfg.PrometheusPort)
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("HOST", "127.0.0.1")
	os.Setenv("PORT", "9999")
	os.Setenv("HEADLESS", "false")
	os.Setenv("BROWSER_PATH", "/usr/bin/chromium")
	os.Setenv("BROWSER_POOL_SIZE", "5")
	os.Setenv("BROWSER_POOL_TIMEOUT", "1m")
	os.Setenv("MAX_MEMORY_MB", "4096")
	os.Setenv("SESSION_TTL", "1h")
	os.Setenv("MAX_SESSIONS", "50")
	os.Setenv("DEFAULT_TIMEOUT", "30s")
	os.Setenv("MAX_TIMEOUT", "10m")
	os.Setenv("PROXY_URL", "http://proxy:8080")
	os.Setenv("PROXY_USERNAME", "user")
	os.Setenv("PROXY_PASSWORD", "pass")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_HTML", "true")
	os.Setenv("PROMETHEUS_ENABLED", "true")
	os.Setenv("PROMETHEUS_PORT", "9090")

	defer func() {
		// Clean up
		envVars := []string{
			"HOST", "PORT", "HEADLESS", "BROWSER_PATH",
			"BROWSER_POOL_SIZE", "BROWSER_POOL_TIMEOUT", "MAX_MEMORY_MB",
			"SESSION_TTL", "MAX_SESSIONS",
			"DEFAULT_TIMEOUT", "MAX_TIMEOUT",
			"PROXY_URL", "PROXY_USERNAME", "PROXY_PASSWORD",
			"LOG_LEVEL", "LOG_HTML",
			"PROMETHEUS_ENABLED", "PROMETHEUS_PORT",
		}
		for _, env := range envVars {
			os.Unsetenv(env)
		}
	}()

	cfg := Load()

	// Verify overrides
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Host)
	}
	if cfg.Port != 9999 {
		t.Errorf("Expected port 9999, got %d", cfg.Port)
	}
	if cfg.Headless {
		t.Error("Expected Headless to be false")
	}
	if cfg.BrowserPath != "/usr/bin/chromium" {
		t.Errorf("Expected BrowserPath '/usr/bin/chromium', got %q", cfg.BrowserPath)
	}
	if cfg.BrowserPoolSize != 5 {
		t.Errorf("Expected pool size 5, got %d", cfg.BrowserPoolSize)
	}
	if cfg.BrowserPoolTimeout != 1*time.Minute {
		t.Errorf("Expected pool timeout 1m, got %v", cfg.BrowserPoolTimeout)
	}
	if cfg.MaxMemoryMB != 4096 {
		t.Errorf("Expected max memory 4096MB, got %d", cfg.MaxMemoryMB)
	}
	if cfg.SessionTTL != 1*time.Hour {
		t.Errorf("Expected session TTL 1h, got %v", cfg.SessionTTL)
	}
	if cfg.MaxSessions != 50 {
		t.Errorf("Expected max sessions 50, got %d", cfg.MaxSessions)
	}
	if cfg.DefaultTimeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", cfg.DefaultTimeout)
	}
	if cfg.MaxTimeout != 10*time.Minute {
		t.Errorf("Expected max timeout 10m, got %v", cfg.MaxTimeout)
	}
	if cfg.ProxyURL != "http://proxy:8080" {
		t.Errorf("Expected proxy URL 'http://proxy:8080', got %q", cfg.ProxyURL)
	}
	if cfg.ProxyUsername != "user" {
		t.Errorf("Expected proxy username 'user', got %q", cfg.ProxyUsername)
	}
	if cfg.ProxyPassword != "pass" {
		t.Errorf("Expected proxy password 'pass', got %q", cfg.ProxyPassword)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("Expected log level 'debug', got %q", cfg.LogLevel)
	}
	if !cfg.LogHTML {
		t.Error("Expected LogHTML to be true")
	}
	if !cfg.PrometheusEnabled {
		t.Error("Expected PrometheusEnabled to be true")
	}
	if cfg.PrometheusPort != 9090 {
		t.Errorf("Expected Prometheus port 9090, got %d", cfg.PrometheusPort)
	}
}

func TestHasDefaultProxy(t *testing.T) {
	cfg := &Config{}
	if cfg.HasDefaultProxy() {
		t.Error("Expected HasDefaultProxy to return false when ProxyURL is empty")
	}

	cfg.ProxyURL = "http://proxy:8080"
	if !cfg.HasDefaultProxy() {
		t.Error("Expected HasDefaultProxy to return true when ProxyURL is set")
	}
}

func TestInvalidEnvValues(t *testing.T) {
	// Set invalid values
	os.Setenv("PORT", "not_a_number")
	os.Setenv("HEADLESS", "not_a_bool")
	os.Setenv("BROWSER_POOL_TIMEOUT", "not_a_duration")

	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("HEADLESS")
		os.Unsetenv("BROWSER_POOL_TIMEOUT")
	}()

	cfg := Load()

	// Should fall back to defaults for invalid values
	if cfg.Port != 8191 {
		t.Errorf("Expected default port 8191 for invalid value, got %d", cfg.Port)
	}
	if !cfg.Headless {
		t.Error("Expected default Headless (true) for invalid value")
	}
	if cfg.BrowserPoolTimeout != 30*time.Second {
		t.Errorf("Expected default pool timeout for invalid value, got %v", cfg.BrowserPoolTimeout)
	}
}
