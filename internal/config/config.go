// Package config provides application configuration management.
package config

import (
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds all application configuration.
// Configuration is loaded from environment variables at startup.
type Config struct {
	// Server settings
	Host string
	Port int

	// Browser settings
	Headless    bool
	BrowserPath string

	// Pool settings - CRITICAL for memory efficiency
	BrowserPoolSize    int
	BrowserPoolTimeout time.Duration
	MaxMemoryMB        int

	// Session settings
	SessionTTL             time.Duration
	SessionCleanupInterval time.Duration
	MaxSessions            int

	// Timeouts
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration

	// Proxy defaults
	ProxyURL      string
	ProxyUsername string
	ProxyPassword string

	// Logging
	LogLevel string
	LogHTML  bool

	// Metrics
	PrometheusEnabled bool
	PrometheusPort    int

	// Profiling
	PProfEnabled  bool
	PProfPort     int
	PProfBindAddr string // Bind address for pprof server (default: localhost only)

	// Security
	RateLimitEnabled bool
	RateLimitRPM     int  // Requests per minute per IP
	TrustProxy       bool // Trust X-Forwarded-For headers (only enable behind a reverse proxy)
	IgnoreCertErrors bool // Ignore TLS certificate errors (required for some proxies)
}

// Load loads configuration from environment variables.
// Returns a Config with values from environment or sensible defaults.
func Load() *Config {
	return &Config{
		// Server
		Host: getEnvString("HOST", "0.0.0.0"),
		Port: getEnvInt("PORT", 8191),

		// Browser
		Headless:    getEnvBool("HEADLESS", true),
		BrowserPath: getEnvString("BROWSER_PATH", ""),

		// Pool - These defaults are tuned for memory efficiency
		BrowserPoolSize:    getEnvInt("BROWSER_POOL_SIZE", 3),
		BrowserPoolTimeout: getEnvDuration("BROWSER_POOL_TIMEOUT", 30*time.Second),
		MaxMemoryMB:        getEnvInt("MAX_MEMORY_MB", 2048),

		// Sessions
		SessionTTL:             getEnvDuration("SESSION_TTL", 30*time.Minute),
		SessionCleanupInterval: getEnvDuration("SESSION_CLEANUP_INTERVAL", 1*time.Minute),
		MaxSessions:            getEnvInt("MAX_SESSIONS", 100),

		// Timeouts
		DefaultTimeout: getEnvDuration("DEFAULT_TIMEOUT", 60*time.Second),
		MaxTimeout:     getEnvDuration("MAX_TIMEOUT", 300*time.Second),

		// Proxy
		ProxyURL:      getEnvString("PROXY_URL", ""),
		ProxyUsername: getEnvString("PROXY_USERNAME", ""),
		ProxyPassword: getEnvString("PROXY_PASSWORD", ""),

		// Logging
		LogLevel: getEnvString("LOG_LEVEL", "info"),
		LogHTML:  getEnvBool("LOG_HTML", false),

		// Metrics
		PrometheusEnabled: getEnvBool("PROMETHEUS_ENABLED", false),
		PrometheusPort:    getEnvInt("PROMETHEUS_PORT", 8192),

		// Profiling - disabled by default for security
		PProfEnabled:  getEnvBool("PPROF_ENABLED", false),
		PProfPort:     getEnvInt("PPROF_PORT", 6060),
		PProfBindAddr: getEnvString("PPROF_BIND_ADDR", "127.0.0.1"), // Localhost only by default

		// Security
		RateLimitEnabled: getEnvBool("RATE_LIMIT_ENABLED", true),
		RateLimitRPM:     getEnvInt("RATE_LIMIT_RPM", 60), // 60 requests per minute per IP
		TrustProxy:       getEnvBool("TRUST_PROXY", false),
		IgnoreCertErrors: getEnvBool("IGNORE_CERT_ERRORS", false),
	}
}

// HasDefaultProxy returns true if a default proxy is configured.
func (c *Config) HasDefaultProxy() bool {
	return c.ProxyURL != ""
}

// Validate checks configuration values and logs warnings for invalid values.
// Invalid values are corrected to sensible defaults. (Bug 12: config bounds validation)
func (c *Config) Validate() {
	// Port validation
	if c.Port < 1 || c.Port > 65535 {
		log.Warn().Int("port", c.Port).Msg("Invalid port, using default 8191")
		c.Port = 8191
	}

	// Pool size validation
	if c.BrowserPoolSize < 1 {
		log.Warn().Int("size", c.BrowserPoolSize).Msg("Invalid pool size, using default 3")
		c.BrowserPoolSize = 3
	}
	if c.BrowserPoolSize > 20 {
		log.Warn().Int("size", c.BrowserPoolSize).Msg("Large pool size may cause high memory usage")
	}

	// Memory validation
	if c.MaxMemoryMB < 256 {
		log.Warn().Int("mb", c.MaxMemoryMB).Msg("Memory limit too low, using default 2048")
		c.MaxMemoryMB = 2048
	}

	// Timeout validation
	if c.DefaultTimeout < time.Second {
		log.Warn().Dur("timeout", c.DefaultTimeout).Msg("Default timeout too short, using 60s")
		c.DefaultTimeout = 60 * time.Second
	}
	if c.MaxTimeout < c.DefaultTimeout {
		log.Warn().
			Dur("max", c.MaxTimeout).
			Dur("default", c.DefaultTimeout).
			Msg("Max timeout less than default, adjusting")
		c.MaxTimeout = c.DefaultTimeout
	}

	// Session validation
	if c.MaxSessions < 1 {
		log.Warn().Int("max", c.MaxSessions).Msg("Invalid max sessions, using 100")
		c.MaxSessions = 100
	}

	// Rate limit validation
	if c.RateLimitEnabled && c.RateLimitRPM < 1 {
		log.Warn().Int("rpm", c.RateLimitRPM).Msg("Invalid rate limit, using 60 RPM")
		c.RateLimitRPM = 60
	}

	// Prometheus port validation
	if c.PrometheusEnabled && (c.PrometheusPort < 1 || c.PrometheusPort > 65535) {
		log.Warn().Int("port", c.PrometheusPort).Msg("Invalid Prometheus port, using 8192")
		c.PrometheusPort = 8192
	}

	// PProf security warning
	if c.PProfEnabled && c.PProfBindAddr != "127.0.0.1" && c.PProfBindAddr != "localhost" {
		log.Warn().
			Str("addr", c.PProfBindAddr).
			Msg("WARNING: pprof exposed on non-localhost address - this is a security risk")
	}
}

// Helper functions for environment variable parsing

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		intValue, err := strconv.Atoi(value)
		if err == nil {
			return intValue
		}
		// Bug 8: Log warning on parse failure instead of silent fallback
		log.Warn().
			Str("key", key).
			Str("value", value).
			Err(err).
			Int("default", defaultValue).
			Msg("Invalid integer in environment variable, using default")
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		boolValue, err := strconv.ParseBool(value)
		if err == nil {
			return boolValue
		}
		// Bug 8: Log warning on parse failure instead of silent fallback
		log.Warn().
			Str("key", key).
			Str("value", value).
			Err(err).
			Bool("default", defaultValue).
			Msg("Invalid boolean in environment variable, using default")
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		duration, err := time.ParseDuration(value)
		if err == nil {
			return duration
		}
		// Bug 8: Log warning on parse failure instead of silent fallback
		log.Warn().
			Str("key", key).
			Str("value", value).
			Err(err).
			Dur("default", defaultValue).
			Msg("Invalid duration in environment variable, using default")
	}
	return defaultValue
}
