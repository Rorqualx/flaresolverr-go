// Package config provides application configuration management.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Configuration upper bounds to prevent resource exhaustion.
const (
	maxBrowserPoolSize = 20
	maxMaxSessions     = 10000
	maxMaxMemoryMB     = 16384
	maxTimeout         = 10 * time.Minute
	maxRateLimitRPM    = 10000 // Maximum requests per minute per IP
	minAPIKeyLength    = 16    // Minimum API key length for security
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
	// Fix #32: Note - Proxy credentials are stored in plaintext in memory
	// for compatibility with proxy libraries. Consider using environment
	// variables that are cleared after reading if security is critical.
	ProxyURL      string
	ProxyUsername string
	ProxyPassword string

	// Logging
	LogLevel string
	LogHTML  bool

	// Profiling
	PProfEnabled  bool
	PProfPort     int
	PProfBindAddr string // Bind address for pprof server (default: localhost only)

	// Security
	RateLimitEnabled   bool
	RateLimitRPM       int      // Requests per minute per IP
	TrustProxy         bool     // Trust X-Forwarded-For headers (only enable behind a reverse proxy)
	IgnoreCertErrors   bool     // Ignore TLS certificate errors (required for some proxies)
	CORSAllowedOrigins []string // Allowed CORS origins (empty = allow all with warning)
	AllowLocalProxies  bool     // Allow localhost/private IP proxies (default: true for backward compatibility)

	// API Key Authentication
	APIKeyEnabled bool   // Enable API key authentication
	APIKey        string // Required API key for requests (only used if APIKeyEnabled is true)

	// CAPTCHA Solver settings
	CaptchaNativeAttempts  int           // Native solve attempts before external fallback (default: 3)
	CaptchaFallbackEnabled bool          // Enable external CAPTCHA solver fallback
	Captcha2CaptchaAPIKey  string        // 2Captcha API key (TWOCAPTCHA_API_KEY)
	CaptchaCapSolverAPIKey string        // CapSolver API key (CAPSOLVER_API_KEY)
	CaptchaPrimaryProvider string        // Primary provider: "2captcha" or "capsolver" (default: "2captcha")
	CaptchaSolverTimeout   time.Duration // Timeout for external solver API (default: 120s)

	// Selectors settings
	SelectorsPath      string // Path to external selectors.yaml override file
	SelectorsHotReload bool   // Enable file watching for hot-reload of selectors
}

// Load loads configuration from environment variables.
// Returns a Config with values from environment or sensible defaults.
func Load() *Config {
	return &Config{
		// Server - default to localhost for security (prevents accidental exposure)
		// Set HOST=0.0.0.0 explicitly to bind to all interfaces
		Host: getEnvString("HOST", "127.0.0.1"),
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

		// Profiling - disabled by default for security
		PProfEnabled:  getEnvBool("PPROF_ENABLED", false),
		PProfPort:     getEnvInt("PPROF_PORT", 6060),
		PProfBindAddr: getEnvString("PPROF_BIND_ADDR", "127.0.0.1"), // Localhost only by default

		// Security
		RateLimitEnabled:   getEnvBool("RATE_LIMIT_ENABLED", true),
		RateLimitRPM:       getEnvInt("RATE_LIMIT_RPM", 60), // 60 requests per minute per IP
		TrustProxy:         getEnvBool("TRUST_PROXY", false),
		IgnoreCertErrors:   getEnvBool("IGNORE_CERT_ERRORS", false),
		CORSAllowedOrigins: getEnvStringSlice("CORS_ALLOWED_ORIGINS", nil),
		AllowLocalProxies:  getEnvBool("ALLOW_LOCAL_PROXIES", false), // Default false for security

		// API Key Authentication
		APIKeyEnabled: getEnvBool("API_KEY_ENABLED", false),
		APIKey:        getEnvString("API_KEY", ""),

		// CAPTCHA Solver settings
		CaptchaNativeAttempts:  getEnvInt("CAPTCHA_NATIVE_ATTEMPTS", 3),
		CaptchaFallbackEnabled: getEnvBool("CAPTCHA_FALLBACK_ENABLED", false),
		Captcha2CaptchaAPIKey:  getEnvString("TWOCAPTCHA_API_KEY", ""),
		CaptchaCapSolverAPIKey: getEnvString("CAPSOLVER_API_KEY", ""),
		CaptchaPrimaryProvider: getEnvString("CAPTCHA_PRIMARY_PROVIDER", "2captcha"),
		CaptchaSolverTimeout:   getEnvDuration("CAPTCHA_SOLVER_TIMEOUT", 120*time.Second),

		// Selectors settings
		SelectorsPath:      getEnvString("SELECTORS_PATH", ""),
		SelectorsHotReload: getEnvBool("SELECTORS_HOT_RELOAD", false),
	}
}

// HasDefaultProxy returns true if a default proxy is configured.
func (c *Config) HasDefaultProxy() bool {
	return c.ProxyURL != ""
}

// Validate checks configuration values and logs warnings for invalid values.
// Invalid values are corrected to sensible defaults. (Bug 12: config bounds validation)
func (c *Config) Validate() {
	// Port validation - allow 0 for system-assigned ports
	if c.Port < 0 || c.Port > 65535 {
		log.Warn().Int("port", c.Port).Msg("Invalid port, using default 8191")
		c.Port = 8191
	}

	// BrowserPath validation - prevent path traversal attacks
	if c.BrowserPath != "" {
		// Check for path traversal sequences
		if strings.Contains(c.BrowserPath, "..") {
			log.Error().
				Str("path", c.BrowserPath).
				Msg("BrowserPath contains path traversal sequence (..), ignoring")
			c.BrowserPath = ""
		} else if !strings.HasPrefix(c.BrowserPath, "/") && !strings.HasPrefix(c.BrowserPath, "C:") && !strings.HasPrefix(c.BrowserPath, "c:") {
			// Not an absolute path (Unix or Windows)
			log.Warn().
				Str("path", c.BrowserPath).
				Msg("BrowserPath should be an absolute path")
		}
	}

	// Pool size validation with upper bound
	if c.BrowserPoolSize < 1 {
		log.Warn().Int("size", c.BrowserPoolSize).Msg("Invalid pool size, using default 3")
		c.BrowserPoolSize = 3
	} else if c.BrowserPoolSize > maxBrowserPoolSize {
		log.Warn().
			Int("size", c.BrowserPoolSize).
			Int("max", maxBrowserPoolSize).
			Msg("Pool size too large, capping to maximum")
		c.BrowserPoolSize = maxBrowserPoolSize
	}

	// Memory validation with upper bound
	if c.MaxMemoryMB < 256 {
		log.Warn().Int("mb", c.MaxMemoryMB).Msg("Memory limit too low, using default 2048")
		c.MaxMemoryMB = 2048
	} else if c.MaxMemoryMB > maxMaxMemoryMB {
		log.Warn().
			Int("mb", c.MaxMemoryMB).
			Int("max", maxMaxMemoryMB).
			Msg("Memory limit too high, capping to maximum")
		c.MaxMemoryMB = maxMaxMemoryMB
	}

	// Timeout validation with upper bound
	// Fix 3.21: Validate MaxTimeout first, then DefaultTimeout, to ensure proper ordering
	if c.MaxTimeout < time.Second {
		log.Warn().Dur("timeout", c.MaxTimeout).Msg("Max timeout too short, using 300s")
		c.MaxTimeout = 300 * time.Second
	}
	if c.MaxTimeout > maxTimeout {
		log.Warn().
			Dur("timeout", c.MaxTimeout).
			Dur("max", maxTimeout).
			Msg("Max timeout too high, capping to maximum")
		c.MaxTimeout = maxTimeout
	}
	if c.DefaultTimeout < time.Second {
		log.Warn().Dur("timeout", c.DefaultTimeout).Msg("Default timeout too short, using 60s")
		c.DefaultTimeout = 60 * time.Second
	}
	if c.DefaultTimeout > c.MaxTimeout {
		log.Warn().
			Dur("default", c.DefaultTimeout).
			Dur("max", c.MaxTimeout).
			Msg("Default timeout exceeds max timeout, adjusting to max")
		c.DefaultTimeout = c.MaxTimeout
	}

	// Session validation with upper bound
	if c.MaxSessions < 1 {
		log.Warn().Int("max", c.MaxSessions).Msg("Invalid max sessions, using 100")
		c.MaxSessions = 100
	} else if c.MaxSessions > maxMaxSessions {
		log.Warn().
			Int("sessions", c.MaxSessions).
			Int("max", maxMaxSessions).
			Msg("Max sessions too high, capping to maximum")
		c.MaxSessions = maxMaxSessions
	}

	// SessionTTL validation (minimum 1 minute, maximum 24 hours)
	const minSessionTTL = 1 * time.Minute
	const maxSessionTTL = 24 * time.Hour
	if c.SessionTTL < minSessionTTL {
		log.Warn().
			Dur("ttl", c.SessionTTL).
			Dur("min", minSessionTTL).
			Msg("Session TTL too short, using minimum")
		c.SessionTTL = minSessionTTL
	} else if c.SessionTTL > maxSessionTTL {
		log.Warn().
			Dur("ttl", c.SessionTTL).
			Dur("max", maxSessionTTL).
			Msg("Session TTL too long, using maximum")
		c.SessionTTL = maxSessionTTL
	}

	// SessionCleanupInterval validation (minimum 10 seconds, maximum 1 hour)
	const minCleanupInterval = 10 * time.Second
	const maxCleanupInterval = 1 * time.Hour
	if c.SessionCleanupInterval < minCleanupInterval {
		log.Warn().
			Dur("interval", c.SessionCleanupInterval).
			Dur("min", minCleanupInterval).
			Msg("Session cleanup interval too short, using minimum")
		c.SessionCleanupInterval = minCleanupInterval
	} else if c.SessionCleanupInterval > maxCleanupInterval {
		log.Warn().
			Dur("interval", c.SessionCleanupInterval).
			Dur("max", maxCleanupInterval).
			Msg("Session cleanup interval too long, using maximum")
		c.SessionCleanupInterval = maxCleanupInterval
	}

	// Fix #34: Cross-validate session cleanup interval vs TTL
	if c.SessionCleanupInterval >= c.SessionTTL {
		log.Warn().
			Dur("cleanup_interval", c.SessionCleanupInterval).
			Dur("ttl", c.SessionTTL).
			Msg("SESSION_CLEANUP_INTERVAL should be less than SESSION_TTL for timely cleanup")
	}

	// BrowserPoolTimeout validation (minimum 1 second, maximum 5 minutes)
	const minPoolTimeout = 1 * time.Second
	const maxPoolTimeout = 5 * time.Minute
	if c.BrowserPoolTimeout < minPoolTimeout {
		log.Warn().
			Dur("timeout", c.BrowserPoolTimeout).
			Dur("min", minPoolTimeout).
			Msg("Browser pool timeout too short, using minimum")
		c.BrowserPoolTimeout = minPoolTimeout
	} else if c.BrowserPoolTimeout > maxPoolTimeout {
		log.Warn().
			Dur("timeout", c.BrowserPoolTimeout).
			Dur("max", maxPoolTimeout).
			Msg("Browser pool timeout too long, using maximum")
		c.BrowserPoolTimeout = maxPoolTimeout
	}

	// Rate limit validation with upper bound
	if c.RateLimitEnabled {
		if c.RateLimitRPM < 1 {
			log.Warn().Int("rpm", c.RateLimitRPM).Msg("Invalid rate limit, using 60 RPM")
			c.RateLimitRPM = 60
		} else if c.RateLimitRPM > maxRateLimitRPM {
			log.Warn().
				Int("rpm", c.RateLimitRPM).
				Int("max", maxRateLimitRPM).
				Msg("Rate limit too high, capping to maximum")
			c.RateLimitRPM = maxRateLimitRPM
		}
	}

	// Log level validation
	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		log.Warn().Str("level", c.LogLevel).Msg("Invalid log level, using 'info'")
		c.LogLevel = "info"
	}

	// PProf security warning
	if c.PProfEnabled && c.PProfBindAddr != "127.0.0.1" && c.PProfBindAddr != "localhost" {
		log.Warn().
			Str("addr", c.PProfBindAddr).
			Msg("WARNING: pprof exposed on non-localhost address - this is a security risk")
	}

	// CORS security warning
	if len(c.CORSAllowedOrigins) == 0 {
		log.Warn().Msg("CORS_ALLOWED_ORIGINS not set - allowing all origins (potential CSRF risk)")
	}

	// Certificate validation warning
	if c.IgnoreCertErrors {
		if c.ProxyURL == "" {
			log.Warn().Msg("WARNING: IGNORE_CERT_ERRORS enabled without a proxy - this exposes you to MITM attacks")
		} else {
			log.Info().Msg("IGNORE_CERT_ERRORS enabled for proxy compatibility")
		}
	}

	// Fix #17: Proxy URL and credential validation
	if c.ProxyURL != "" {
		// Basic URL format validation
		if !strings.Contains(c.ProxyURL, "://") {
			log.Error().
				Str("proxy_url", c.ProxyURL).
				Msg("ProxyURL missing scheme (should be http://, https://, socks4://, or socks5://)")
		} else {
			scheme := strings.ToLower(strings.Split(c.ProxyURL, "://")[0])
			validSchemes := map[string]bool{"http": true, "https": true, "socks4": true, "socks5": true}
			if !validSchemes[scheme] {
				log.Error().
					Str("proxy_url", c.ProxyURL).
					Str("scheme", scheme).
					Msg("ProxyURL has invalid scheme (must be http, https, socks4, or socks5)")
			}

			// Fix #33: Check for embedded credentials in proxy URL
			// Credentials should be passed via PROXY_USERNAME/PROXY_PASSWORD for security
			if strings.Contains(c.ProxyURL, "@") {
				log.Warn().Msg("ProxyURL contains embedded credentials (@) - use PROXY_USERNAME and PROXY_PASSWORD environment variables instead for better security")
			}
		}
	}

	// Warn if username is set without password or vice versa
	if c.ProxyUsername != "" && c.ProxyPassword == "" {
		log.Warn().Msg("PROXY_USERNAME set but PROXY_PASSWORD is empty - authentication may fail")
	}
	if c.ProxyPassword != "" && c.ProxyUsername == "" {
		log.Warn().Msg("PROXY_PASSWORD set but PROXY_USERNAME is empty - authentication may fail")
	}
	// Warn if credentials are set but no proxy URL is configured
	if (c.ProxyUsername != "" || c.ProxyPassword != "") && c.ProxyURL == "" {
		log.Warn().Msg("Proxy credentials set but PROXY_URL is empty - credentials will not be used")
	}
	// Security: Warn if proxy credentials are used over HTTP (vulnerable to interception)
	if (c.ProxyUsername != "" || c.ProxyPassword != "") && c.ProxyURL != "" {
		if strings.HasPrefix(strings.ToLower(c.ProxyURL), "http://") {
			log.Warn().Msg("WARNING: Proxy credentials over HTTP - credentials may be intercepted. Consider using HTTPS proxy")
		}
	}

	// Port conflict validation with fixed loop logic
	usedPorts := make(map[int]string)
	if c.Port > 0 {
		usedPorts[c.Port] = "PORT"
	}
	if c.PProfEnabled {
		if existingName, exists := usedPorts[c.PProfPort]; exists {
			log.Error().
				Int("port", c.PProfPort).
				Str("conflicts_with", existingName).
				Msg("PPROF_PORT conflicts with another port, adjusting")
			// Find next available port starting from 6060
			c.PProfPort = 6060
			for usedPorts[c.PProfPort] != "" {
				c.PProfPort++
				if c.PProfPort > 65535 {
					log.Warn().Msg("Could not find available pprof port, disabling")
					c.PProfEnabled = false
					break
				}
			}
		}
	}

	// CAPTCHA solver validation
	c.validateCaptchaConfig()

	// Selectors path validation
	if c.SelectorsPath != "" {
		// Check for path traversal sequences
		if strings.Contains(c.SelectorsPath, "..") {
			log.Error().
				Str("path", c.SelectorsPath).
				Msg("SelectorsPath contains path traversal sequence (..), ignoring")
			c.SelectorsPath = ""
		} else if !strings.HasPrefix(c.SelectorsPath, "/") && !strings.HasPrefix(c.SelectorsPath, "C:") && !strings.HasPrefix(c.SelectorsPath, "c:") {
			log.Warn().
				Str("path", c.SelectorsPath).
				Msg("SelectorsPath should be an absolute path")
		}
		// Warn if hot-reload is enabled but path doesn't exist
		if c.SelectorsHotReload && c.SelectorsPath != "" {
			if _, err := os.Stat(c.SelectorsPath); os.IsNotExist(err) {
				log.Warn().
					Str("path", c.SelectorsPath).
					Msg("SelectorsPath does not exist - hot-reload will watch for file creation")
			}
		}
	}

	// Warn if hot-reload is enabled but no path is set
	if c.SelectorsHotReload && c.SelectorsPath == "" {
		log.Warn().Msg("SELECTORS_HOT_RELOAD enabled but SELECTORS_PATH not set - hot-reload disabled")
		c.SelectorsHotReload = false
	}

	// API key validation with minimum length enforcement
	if c.APIKeyEnabled {
		const maxAPIKeyLength = 256
		switch {
		case c.APIKey == "":
			log.Error().Msg("API_KEY_ENABLED is true but API_KEY is empty - authentication will always fail")
		case len(c.APIKey) < minAPIKeyLength:
			log.Error().
				Int("length", len(c.APIKey)).
				Int("min_required", minAPIKeyLength).
				Msg("API_KEY is too short for secure authentication - consider using a longer key")
		default:
			// Fix #45: Validate API key format (alphanumeric with - or _)
			if len(c.APIKey) > maxAPIKeyLength {
				log.Error().
					Int("length", len(c.APIKey)).
					Int("max", maxAPIKeyLength).
					Msg("API_KEY is too long")
			}
			for i, r := range c.APIKey {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
					(r >= '0' && r <= '9') || r == '-' || r == '_') {
					log.Warn().
						Int("position", i).
						Msg("API_KEY contains non-alphanumeric characters (only a-z, A-Z, 0-9, -, _ are recommended)")
					break
				}
			}
		}
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
		// Use ParseInt with explicit bounds to catch overflow
		intValue, err := strconv.ParseInt(value, 10, 32)
		if err == nil {
			// Additional bounds check for sanity
			if intValue < -2147483648 || intValue > 2147483647 {
				log.Warn().
					Str("key", key).
					Str("value", value).
					Int("default", defaultValue).
					Msg("Integer value out of range in environment variable, using default")
				return defaultValue
			}
			return int(intValue)
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
			// Reject negative or zero durations
			if duration > 0 {
				return duration
			}
			log.Warn().
				Str("key", key).
				Str("value", value).
				Dur("default", defaultValue).
				Msg("Duration must be positive, using default")
			return defaultValue
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

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Parse comma-separated values, trimming whitespace
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

// validateCaptchaConfig validates CAPTCHA solver configuration.
func (c *Config) validateCaptchaConfig() {
	// Validate native attempts (min 1, max 10)
	if c.CaptchaNativeAttempts < 1 {
		log.Warn().
			Int("attempts", c.CaptchaNativeAttempts).
			Msg("CAPTCHA_NATIVE_ATTEMPTS too low, using 1")
		c.CaptchaNativeAttempts = 1
	} else if c.CaptchaNativeAttempts > 10 {
		log.Warn().
			Int("attempts", c.CaptchaNativeAttempts).
			Msg("CAPTCHA_NATIVE_ATTEMPTS too high, capping at 10")
		c.CaptchaNativeAttempts = 10
	}

	// Validate solver timeout (min 30s, max 300s)
	const minSolverTimeout = 30 * time.Second
	const maxSolverTimeout = 300 * time.Second
	if c.CaptchaSolverTimeout < minSolverTimeout {
		log.Warn().
			Dur("timeout", c.CaptchaSolverTimeout).
			Dur("min", minSolverTimeout).
			Msg("CAPTCHA_SOLVER_TIMEOUT too short, using minimum")
		c.CaptchaSolverTimeout = minSolverTimeout
	} else if c.CaptchaSolverTimeout > maxSolverTimeout {
		log.Warn().
			Dur("timeout", c.CaptchaSolverTimeout).
			Dur("max", maxSolverTimeout).
			Msg("CAPTCHA_SOLVER_TIMEOUT too long, using maximum")
		c.CaptchaSolverTimeout = maxSolverTimeout
	}

	// Validate primary provider
	validProviders := map[string]bool{"2captcha": true, "capsolver": true}
	if c.CaptchaPrimaryProvider != "" && !validProviders[strings.ToLower(c.CaptchaPrimaryProvider)] {
		log.Warn().
			Str("provider", c.CaptchaPrimaryProvider).
			Msg("Invalid CAPTCHA_PRIMARY_PROVIDER, using '2captcha'")
		c.CaptchaPrimaryProvider = "2captcha"
	}
	c.CaptchaPrimaryProvider = strings.ToLower(c.CaptchaPrimaryProvider)

	// Warn if fallback enabled but no API keys configured
	if c.CaptchaFallbackEnabled {
		if c.Captcha2CaptchaAPIKey == "" && c.CaptchaCapSolverAPIKey == "" {
			log.Warn().Msg("CAPTCHA_FALLBACK_ENABLED is true but no API keys configured (TWOCAPTCHA_API_KEY or CAPSOLVER_API_KEY)")
		} else {
			// Log which providers are configured
			var configured []string
			if c.Captcha2CaptchaAPIKey != "" {
				configured = append(configured, "2captcha")
			}
			if c.CaptchaCapSolverAPIKey != "" {
				configured = append(configured, "capsolver")
			}
			log.Info().
				Strs("providers", configured).
				Str("primary", c.CaptchaPrimaryProvider).
				Int("native_attempts", c.CaptchaNativeAttempts).
				Msg("External CAPTCHA solver fallback enabled")
		}
	}
}

// HasCaptchaFallback returns true if external CAPTCHA fallback is configured.
func (c *Config) HasCaptchaFallback() bool {
	return c.CaptchaFallbackEnabled && (c.Captcha2CaptchaAPIKey != "" || c.CaptchaCapSolverAPIKey != "")
}
