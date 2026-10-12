// Package config provides application configuration management.
package config

import (
	"fmt"
	"net/netip"

	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Configuration upper bounds to prevent resource exhaustion.
const (
	maxBrowserPoolSize = 20
	maxMaxSessions     = 10000

	// defaultMaxSessions bounds concurrent sessions. Each one holds a page in
	// its own browser context, measured at roughly 150MB resident on a
	// script-heavy site, so the old default of 100 could need ~15GB.
	defaultMaxSessions      = 20
	sessionMemoryEstimateMB = 150
	maxMaxMemoryMB          = 16384
	maxTimeout              = 10 * time.Minute
	maxRateLimitRPM         = 10000 // Maximum requests per minute per IP
	minAPIKeyLength         = 16    // Minimum API key length for security

	// Paid external captcha solves one request may buy with the server's keys.
	defaultCaptchaMaxExternalSolves = 1
	maxCaptchaMaxExternalSolves     = 3
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
	// BrowserSandbox keeps Chromium's own sandbox on (omits --no-sandbox).
	// Off by default: the sandbox needs user namespaces or a seccomp profile
	// that the default Docker runtime does not grant.
	BrowserSandbox bool

	// Pool settings - CRITICAL for memory efficiency
	BrowserPoolSize    int
	BrowserPoolTimeout time.Duration
	MaxMemoryMB        int

	// Session settings
	SessionTTL             time.Duration
	SessionCleanupInterval time.Duration
	MaxSessions            int

	// Clearance cache (Layer-2 of the clean-egress path)
	ClearanceCacheEnabled bool          // Reuse minted cf_clearance across requests (CLEARANCE_CACHE_ENABLED)
	ClearanceTTL          time.Duration // Max lifetime of a cached cf_clearance (CLEARANCE_TTL)

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
	ProxyList     string // Pool of egress proxies, comma/newline-separated (PROXY_LIST)
	ProxyStrategy string // Egress selection: sticky-domain|round-robin|per-request (PROXY_STRATEGY)

	// Browser locale/timezone
	BrowserTimezone string // TZ env var — sets browser timezone (e.g., "America/New_York")
	BrowserLang     string // LANG env var — sets browser accept-language (e.g., "en_GB")
	TestURL         string // TEST_URL — URL to verify browser works on startup (default: https://www.google.com)
	DisableMedia    bool   // DISABLE_MEDIA — global default for blocking images/CSS/fonts

	// Logging
	LogLevel string
	LogHTML  bool
	LogFile  string // LOG_FILE — path to log file (in addition to stdout)

	// Profiling
	PProfEnabled  bool
	PProfPort     int
	PProfBindAddr string // Bind address for pprof server (default: localhost only)

	// Security
	RateLimitEnabled   bool
	RateLimitRPM       int      // Requests per minute per IP
	TrustProxy         bool     // Trust X-Forwarded-For headers (only enable behind a reverse proxy)
	IgnoreCertErrors   bool     // Ignore TLS certificate errors (required for some proxies)
	CORSAllowedOrigins []string // Origins allowed to call the API from a browser (empty = none; any other Origin is rejected)
	AllowLocalProxies  bool     // Allow localhost/private IP proxies in requests (default: false)

	// TrustedProxies lists the reverse proxies (CIDRs) whose X-Forwarded-For is
	// believed when TrustProxy is on (TRUSTED_PROXIES). Empty keeps the legacy
	// behavior of believing the header from any peer.
	TrustedProxies []netip.Prefix

	// AllowedHosts lists extra hostnames accepted in the Host header
	// (ALLOWED_HOSTS). IP literals, localhost, this machine's hostname and
	// single-label names are always accepted; "*" disables the check.
	AllowedHosts []string

	// StrictContentType requires Content-Type: application/json on API requests
	// (STRICT_CONTENT_TYPE, default true).
	StrictContentType bool

	// DNSRebindingProtection pins the response URL to the IP resolved at request
	// time. Disable (DNS_REBINDING_PROTECTION=false) for sites that legitimately
	// serve identical content across multiple TLDs/CDN IPs. SSRF protection
	// (blocking private/internal/metadata IPs) stays active either way.
	DNSRebindingProtection bool

	// EgressGuard routes every browser and browser context through an
	// in-process proxy that validates each connection's destination
	// (EGRESS_GUARD, default false). It closes the gaps URL validation cannot:
	// redirects, subresources, WebSockets and DNS rebinding to private
	// addresses.
	EgressGuard bool

	// API Key Authentication
	APIKeyEnabled bool   // Enable API key authentication
	APIKey        string // Required API key for requests (only used if APIKeyEnabled is true)

	// CAPTCHA Solver settings
	CaptchaNativeAttempts    int           // Native solve attempts before external fallback (default: 3)
	CaptchaFallbackEnabled   bool          // Enable external CAPTCHA solver fallback
	Captcha2CaptchaAPIKey    string        // 2Captcha API key (TWOCAPTCHA_API_KEY)
	CaptchaCapSolverAPIKey   string        // CapSolver API key (CAPSOLVER_API_KEY)
	CaptchaAntiCaptchaAPIKey string        // anti-captcha.com API key (ANTICAPTCHA_API_KEY)
	Captcha9kwAPIKey         string        // 9kw.eu API key (NINEKW_API_KEY) — hCaptcha/reCAPTCHA only, no Turnstile
	CaptchaPrimaryProvider   string        // Primary provider: "2captcha", "capsolver", "anticaptcha", or "9kw" (default: "2captcha")
	CaptchaSolverTimeout     time.Duration // Timeout for external solver API (default: 120s)
	CaptchaMaxExternalSolves int           // Paid solves one request may buy with the server's keys (default: 1, max: 3, 0 buys nothing)

	// Provider base URL overrides, for testing and self-hosted gateways.
	// Empty selects the provider's public API.
	Captcha2CaptchaBaseURL    string // TWOCAPTCHA_BASE_URL
	CaptchaCapSolverBaseURL   string // CAPSOLVER_BASE_URL
	CaptchaAntiCaptchaBaseURL string // ANTICAPTCHA_BASE_URL
	Captcha9kwBaseURL         string // NINEKW_BASE_URL

	// Selectors settings
	SelectorsPath          string        // Path to external selectors.yaml override file
	SelectorsHotReload     bool          // Enable file watching for hot-reload of selectors
	SelectorsRemoteURL     string        // HTTP(S) URL to fetch selectors from
	SelectorsRemoteRefresh time.Duration // Refresh interval for remote selectors (default: 1h)

	// Dashboard
	DashboardEnabled bool // TUI dashboard enabled by default; disable with DASHBOARD_ENABLED=false
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
		Headless:       getEnvBool("HEADLESS", true),
		BrowserPath:    getEnvString("BROWSER_PATH", ""),
		BrowserSandbox: getEnvBool("BROWSER_SANDBOX", false),

		// Pool - These defaults are tuned for memory efficiency
		BrowserPoolSize:    getEnvInt("BROWSER_POOL_SIZE", 3),
		BrowserPoolTimeout: getEnvDuration("BROWSER_POOL_TIMEOUT", 30*time.Second),
		MaxMemoryMB:        getEnvInt("MAX_MEMORY_MB", 2048),

		// Sessions
		SessionTTL:             getEnvDuration("SESSION_TTL", 30*time.Minute),
		SessionCleanupInterval: getEnvDuration("SESSION_CLEANUP_INTERVAL", 1*time.Minute),
		MaxSessions:            getEnvInt("MAX_SESSIONS", defaultMaxSessions),

		ClearanceCacheEnabled: getEnvBool("CLEARANCE_CACHE_ENABLED", true),
		ClearanceTTL:          getEnvDuration("CLEARANCE_TTL", 25*time.Minute),

		// Timeouts
		DefaultTimeout: getEnvDuration("DEFAULT_TIMEOUT", 60*time.Second),
		MaxTimeout:     getEnvDuration("MAX_TIMEOUT", 300*time.Second),

		// Proxy
		ProxyURL:      getEnvString("PROXY_URL", ""),
		ProxyUsername: getEnvString("PROXY_USERNAME", ""),
		ProxyPassword: getEnvString("PROXY_PASSWORD", ""),
		ProxyList:     getEnvString("PROXY_LIST", ""),
		ProxyStrategy: getEnvString("PROXY_STRATEGY", "sticky-domain"),

		// Browser locale/timezone
		BrowserTimezone: getEnvTimezone("TZ", ""),
		BrowserLang:     getEnvString("LANG", ""),
		TestURL:         getEnvString("TEST_URL", "https://www.google.com"),
		DisableMedia:    getEnvBool("DISABLE_MEDIA", false),

		// Logging
		LogLevel: getEnvString("LOG_LEVEL", "info"),
		LogHTML:  getEnvBool("LOG_HTML", false),
		LogFile:  getEnvString("LOG_FILE", ""),

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
		TrustedProxies:     getEnvPrefixes("TRUSTED_PROXIES"),
		AllowedHosts:       getEnvStringSlice("ALLOWED_HOSTS", nil),
		StrictContentType:  getEnvBool("STRICT_CONTENT_TYPE", true),

		DNSRebindingProtection: getEnvBool("DNS_REBINDING_PROTECTION", true), // Default true for security
		EgressGuard:            getEnvBool("EGRESS_GUARD", false),

		// API Key Authentication
		APIKeyEnabled: getEnvBool("API_KEY_ENABLED", false),
		APIKey:        getEnvString("API_KEY", ""),

		// CAPTCHA Solver settings
		CaptchaNativeAttempts:    getEnvInt("CAPTCHA_NATIVE_ATTEMPTS", 3),
		CaptchaFallbackEnabled:   getEnvBool("CAPTCHA_FALLBACK_ENABLED", false),
		Captcha2CaptchaAPIKey:    getEnvString("TWOCAPTCHA_API_KEY", ""),
		CaptchaCapSolverAPIKey:   getEnvString("CAPSOLVER_API_KEY", ""),
		CaptchaAntiCaptchaAPIKey: getEnvString("ANTICAPTCHA_API_KEY", ""),
		Captcha9kwAPIKey:         getEnvString("NINEKW_API_KEY", ""),
		CaptchaPrimaryProvider:   getEnvString("CAPTCHA_PRIMARY_PROVIDER", "2captcha"),
		CaptchaSolverTimeout:     getEnvDuration("CAPTCHA_SOLVER_TIMEOUT", 120*time.Second),
		CaptchaMaxExternalSolves: getEnvInt("CAPTCHA_MAX_EXTERNAL_SOLVES", defaultCaptchaMaxExternalSolves),

		Captcha2CaptchaBaseURL:    getEnvString("TWOCAPTCHA_BASE_URL", ""),
		CaptchaCapSolverBaseURL:   getEnvString("CAPSOLVER_BASE_URL", ""),
		CaptchaAntiCaptchaBaseURL: getEnvString("ANTICAPTCHA_BASE_URL", ""),
		Captcha9kwBaseURL:         getEnvString("NINEKW_BASE_URL", ""),

		// Selectors settings
		SelectorsPath:          getEnvString("SELECTORS_PATH", ""),
		SelectorsHotReload:     getEnvBool("SELECTORS_HOT_RELOAD", false),
		SelectorsRemoteURL:     getEnvString("SELECTORS_REMOTE_URL", ""),
		SelectorsRemoteRefresh: getEnvDuration("SELECTORS_REMOTE_REFRESH", 1*time.Hour),

		// Dashboard
		DashboardEnabled: getEnvBool("DASHBOARD_ENABLED", true),
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
	// Uses proper path normalization instead of simple string matching
	if c.BrowserPath != "" {
		cleanPath := filepath.Clean(c.BrowserPath)
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			log.Error().
				Err(err).
				Str("path", c.BrowserPath).
				Msg("BrowserPath could not be resolved, ignoring")
			c.BrowserPath = ""
		} else {
			// Warn if path was normalized (contained relative elements like ..)
			if cleanPath != c.BrowserPath {
				log.Warn().
					Str("original", c.BrowserPath).
					Str("cleaned", absPath).
					Msg("BrowserPath normalized (contained relative elements)")
			}
			c.BrowserPath = absPath
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
		log.Warn().Int("max", c.MaxSessions).Int("default", defaultMaxSessions).Msg("Invalid max sessions, using default")
		c.MaxSessions = defaultMaxSessions
	} else if c.MaxSessions > maxMaxSessions {
		log.Warn().
			Int("sessions", c.MaxSessions).
			Int("max", maxMaxSessions).
			Msg("Max sessions too high, capping to maximum")
		c.MaxSessions = maxMaxSessions
	}

	// Each session keeps a page open in its own browser context. Warn when the
	// configured limit could not fit in the memory budget.
	if estimate := c.MaxSessions * sessionMemoryEstimateMB; estimate > c.MaxMemoryMB {
		log.Warn().
			Int("max_sessions", c.MaxSessions).
			Int("estimated_mb", estimate).
			Int("max_memory_mb", c.MaxMemoryMB).
			Msg("MAX_SESSIONS may exceed the memory budget (about 150MB per open session)")
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
	// Normalise so LOG_LEVEL=DEBUG means debug everywhere the value is read
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	if c.LogLevel == "warning" {
		c.LogLevel = "warn"
	}
	if !validLogLevels[c.LogLevel] {
		log.Warn().Str("level", c.LogLevel).Msg("Invalid log level, using 'info'")
		c.LogLevel = "info"
	}

	// PProf security warning
	if c.PProfEnabled && c.PProfBindAddr != "127.0.0.1" && c.PProfBindAddr != "localhost" {
		log.Warn().
			Str("addr", c.PProfBindAddr).
			Msg("WARNING: pprof exposed on non-localhost address - this is a security risk")
	}

	// Forwarded-header trust warning
	if c.TrustProxy && len(c.TrustedProxies) == 0 {
		log.Warn().Msg("TRUST_PROXY is on without TRUSTED_PROXIES - X-Forwarded-For is believed from any client, so rate limiting can be bypassed by sending the header; set TRUSTED_PROXIES to your reverse proxy's address")
	}
	if len(c.CORSAllowedOrigins) == 0 {
		log.Debug().Msg("CORS_ALLOWED_ORIGINS not set - requests from web pages (any Origin header) are rejected")
	}

	// Certificate validation warning
	if c.IgnoreCertErrors {
		if c.ProxyURL == "" {
			log.Warn().Msg("WARNING: IGNORE_CERT_ERRORS enabled without a proxy - this exposes you to MITM attacks")
		} else {
			log.Info().Msg("IGNORE_CERT_ERRORS enabled for proxy compatibility")
		}
	}

	// DNS rebinding protection warning
	if !c.DNSRebindingProtection {
		log.Warn().Msg("DNS_REBINDING_PROTECTION disabled - response URL IP pinning is off (SSRF protection against private/internal IPs remains active)")
	}

	if c.EgressGuard {
		log.Info().Msg("EGRESS_GUARD enabled - every browser connection is validated by the in-process egress guard (HTTP/3 is not used through it)")
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

	// Selectors path validation - prevent path traversal attacks
	// Uses proper path normalization instead of simple string matching
	if c.SelectorsPath != "" {
		cleanPath := filepath.Clean(c.SelectorsPath)
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			log.Error().
				Err(err).
				Str("path", c.SelectorsPath).
				Msg("SelectorsPath could not be resolved, ignoring")
			c.SelectorsPath = ""
		} else {
			// Warn if path was normalized (contained relative elements like ..)
			if cleanPath != c.SelectorsPath {
				log.Warn().
					Str("original", c.SelectorsPath).
					Str("cleaned", absPath).
					Msg("SelectorsPath normalized (contained relative elements)")
			}
			c.SelectorsPath = absPath
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

	// Remote selectors URL validation
	if c.SelectorsRemoteURL != "" {
		// Validate URL scheme. The selectors manager enforces https (plain http
		// only for a loopback host); this catches anything that is not a URL.
		if !strings.HasPrefix(c.SelectorsRemoteURL, "http://") && !strings.HasPrefix(c.SelectorsRemoteURL, "https://") {
			log.Error().
				Str("url", c.SelectorsRemoteURL).
				Msg("SELECTORS_REMOTE_URL must be an https:// URL, ignoring")
			c.SelectorsRemoteURL = ""
		} else if strings.HasPrefix(c.SelectorsRemoteURL, "http://") {
			log.Warn().
				Str("url", c.SelectorsRemoteURL).
				Msg("SELECTORS_REMOTE_URL uses plain http - it will be refused unless the host is loopback; use https")
		}

		// Warn if both file and remote are configured
		if c.SelectorsPath != "" {
			log.Warn().
				Str("file_path", c.SelectorsPath).
				Str("remote_url", c.SelectorsRemoteURL).
				Msg("Both SELECTORS_PATH and SELECTORS_REMOTE_URL are set - file takes priority, remote will supplement")
		}
	}

	// Remote selectors refresh interval validation (min 5m, max 24h)
	if c.SelectorsRemoteURL != "" {
		const minRemoteRefresh = 5 * time.Minute
		const maxRemoteRefresh = 24 * time.Hour
		if c.SelectorsRemoteRefresh < minRemoteRefresh {
			log.Warn().
				Dur("interval", c.SelectorsRemoteRefresh).
				Dur("min", minRemoteRefresh).
				Msg("SELECTORS_REMOTE_REFRESH too short, using minimum")
			c.SelectorsRemoteRefresh = minRemoteRefresh
		} else if c.SelectorsRemoteRefresh > maxRemoteRefresh {
			log.Warn().
				Dur("interval", c.SelectorsRemoteRefresh).
				Dur("max", maxRemoteRefresh).
				Msg("SELECTORS_REMOTE_REFRESH too long, using maximum")
			c.SelectorsRemoteRefresh = maxRemoteRefresh
		}
	}

	// API key validation with minimum length enforcement
	if c.APIKeyEnabled {
		const maxAPIKeyLength = 256
		switch {
		case c.APIKey == "":
			log.Error().Msg("API_KEY_ENABLED is true but API_KEY is empty - all API requests will be rejected")
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

func getEnvTimezone(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	if _, err := time.LoadLocation(value); err != nil {
		log.Warn().
			Str("key", key).
			Str("value", value).
			Err(err).
			Str("default", defaultValue).
			Msg("Invalid IANA timezone in environment variable, using default")
		return defaultValue
	}
	return value
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

// getEnvPrefixes reads a comma-separated list of CIDRs (or bare IP addresses,
// taken as a single-address prefix) from the environment. Invalid entries are
// logged and skipped.
func getEnvPrefixes(key string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range getEnvStringSlice(key, nil) {
		prefix, err := parsePrefix(entry)
		if err != nil {
			log.Warn().Str("key", key).Str("value", entry).Msg("Invalid CIDR in environment variable, ignoring")
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// parsePrefix parses a CIDR, or a bare IP address as a one-address prefix.
// IPv4-mapped IPv6 input is normalised to IPv4.
func parsePrefix(entry string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		if addr := prefix.Addr(); addr.Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("prefix %q is too wide for an IPv4-mapped address", entry)
			}
			return netip.PrefixFrom(addr.Unmap(), bits).Masked(), nil
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR or IP address", entry)
	}
	addr = addr.Unmap().WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), nil
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
	validProviders := map[string]bool{"2captcha": true, "capsolver": true, "anticaptcha": true, "9kw": true}
	if c.CaptchaPrimaryProvider != "" && !validProviders[strings.ToLower(c.CaptchaPrimaryProvider)] {
		log.Warn().
			Str("provider", c.CaptchaPrimaryProvider).
			Msg("Invalid CAPTCHA_PRIMARY_PROVIDER, using '2captcha'")
		c.CaptchaPrimaryProvider = "2captcha"
	}
	c.CaptchaPrimaryProvider = strings.ToLower(c.CaptchaPrimaryProvider)

	// Validate the per-request budget of paid solves (0 buys nothing).
	if c.CaptchaMaxExternalSolves < 0 {
		log.Warn().
			Int("max_solves", c.CaptchaMaxExternalSolves).
			Msg("CAPTCHA_MAX_EXTERNAL_SOLVES cannot be negative, using 0 (no external solves)")
		c.CaptchaMaxExternalSolves = 0
	} else if c.CaptchaMaxExternalSolves > maxCaptchaMaxExternalSolves {
		log.Warn().
			Int("max_solves", c.CaptchaMaxExternalSolves).
			Int("max", maxCaptchaMaxExternalSolves).
			Msg("CAPTCHA_MAX_EXTERNAL_SOLVES too high, capping")
		c.CaptchaMaxExternalSolves = maxCaptchaMaxExternalSolves
	}

	// Validate provider base URL overrides. A malformed override must not fall
	// back silently to the provider's public (paid) API with the server's keys,
	// so it turns the server-side fallback off.
	for _, override := range []struct {
		env   string
		value *string
	}{
		{"TWOCAPTCHA_BASE_URL", &c.Captcha2CaptchaBaseURL},
		{"CAPSOLVER_BASE_URL", &c.CaptchaCapSolverBaseURL},
		{"ANTICAPTCHA_BASE_URL", &c.CaptchaAntiCaptchaBaseURL},
		{"NINEKW_BASE_URL", &c.Captcha9kwBaseURL},
	} {
		if *override.value == "" {
			continue
		}
		cleaned, err := validateProviderBaseURL(*override.value)
		if err != nil {
			log.Error().
				Err(err).
				Str("setting", override.env).
				Msg("Invalid captcha provider base URL; ignoring it and disabling the external CAPTCHA fallback")
			*override.value = ""
			c.CaptchaFallbackEnabled = false
			continue
		}
		*override.value = cleaned
		log.Warn().
			Str("setting", override.env).
			Str("base_url", cleaned).
			Msg("Captcha provider base URL overridden; API keys for this provider are sent to this address")
	}

	// Warn if fallback enabled but no API keys configured
	if c.CaptchaFallbackEnabled {
		if c.Captcha2CaptchaAPIKey == "" && c.CaptchaCapSolverAPIKey == "" && c.CaptchaAntiCaptchaAPIKey == "" && c.Captcha9kwAPIKey == "" {
			log.Warn().Msg("CAPTCHA_FALLBACK_ENABLED is true but no API keys configured (TWOCAPTCHA_API_KEY, CAPSOLVER_API_KEY, ANTICAPTCHA_API_KEY, or NINEKW_API_KEY)")
		} else {
			// Log which providers are configured
			var configured []string
			if c.Captcha2CaptchaAPIKey != "" {
				configured = append(configured, "2captcha")
			}
			if c.CaptchaCapSolverAPIKey != "" {
				configured = append(configured, "capsolver")
			}
			if c.CaptchaAntiCaptchaAPIKey != "" {
				configured = append(configured, "anticaptcha")
			}
			if c.Captcha9kwAPIKey != "" {
				configured = append(configured, "9kw")
			}
			log.Info().
				Strs("providers", configured).
				Str("primary", c.CaptchaPrimaryProvider).
				Int("native_attempts", c.CaptchaNativeAttempts).
				Int("max_external_solves_per_request", c.CaptchaMaxExternalSolves).
				Msg("External CAPTCHA solver fallback enabled")
			if c.CaptchaMaxExternalSolves == 0 {
				log.Warn().Msg("CAPTCHA_MAX_EXTERNAL_SOLVES is 0: the fallback is enabled but will never buy a solve")
			}
		}
	}
}

// validateProviderBaseURL checks a captcha provider base URL override and
// returns it without a trailing slash.
func validateProviderBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return "", errors.New("host is missing")
	}
	if u.User != nil {
		return "", errors.New("must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must not contain a query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// HasCaptchaFallback returns true if external CAPTCHA fallback is configured.
func (c *Config) HasCaptchaFallback() bool {
	return c.CaptchaFallbackEnabled && (c.Captcha2CaptchaAPIKey != "" || c.CaptchaCapSolverAPIKey != "" || c.CaptchaAntiCaptchaAPIKey != "" || c.Captcha9kwAPIKey != "")
}
