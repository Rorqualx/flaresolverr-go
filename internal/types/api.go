package types

import (
	"fmt"
	"net/url"
	"strings"
)

// Request validation limits.
const (
	MaxCmdLength           = 64
	MaxURLLength           = 8192
	MaxSessionIDLength     = 128
	MaxTimeoutMs           = 600000 // 10 minutes in milliseconds
	MaxCookies             = 100
	MaxCookieNameLength    = 256
	MaxCookieValueLength   = 4096
	MaxCookieDomainLength  = 256
	MaxCookiePathLength    = 2048
	MaxPostDataLength      = 256 * 1024 // 256KB
	MaxHeaders             = 50
	MaxHeaderNameLength    = 256
	MaxHeaderValueLength   = 8192
	MaxProxyUsernameLength = 256
	MaxProxyPasswordLength = 256
	MaxWaitSeconds         = 60
	MaxTabsTillVerify      = 50
	MaxSessionTTLMinutes   = 1440 // 24 hours
	MaxCookieExtractDelay  = 30   // 30 seconds
)

// Request represents an incoming API request.
// This matches the FlareSolverr API specification.
type Request struct {
	Cmd                string             `json:"cmd"`
	URL                string             `json:"url,omitempty"`
	Session            string             `json:"session,omitempty"`
	SessionTTL         int                `json:"session_ttl_minutes,omitempty"` // Per-session TTL override in minutes (0 = use server default)
	MaxTimeout         int                `json:"maxTimeout,omitempty"`
	Cookies            []RequestCookie    `json:"cookies,omitempty"`
	ReturnOnlyCookies  bool               `json:"returnOnlyCookies,omitempty"`
	Proxy              *Proxy             `json:"proxy,omitempty"`
	PostData           string             `json:"postData,omitempty"`
	ContentType        string             `json:"contentType,omitempty"`        // Content type for POST: "application/json" or "application/x-www-form-urlencoded" (default)
	Headers            map[string]string  `json:"headers,omitempty"`            // Custom HTTP headers to send with the request
	ReturnScreenshot   bool               `json:"returnScreenshot,omitempty"`   // Capture screenshot and return as base64
	DisableMedia       bool               `json:"disableMedia,omitempty"`       // Disable loading of media (images, CSS, fonts)
	WaitInSeconds      int                `json:"waitInSeconds,omitempty"`      // Wait N seconds before returning the response
	TabsTillVerify     int                `json:"tabsTillVerify,omitempty"`     // Number of Tab presses to reach Turnstile checkbox (default: 10)
	Download           bool               `json:"download,omitempty"`           // Download URL as binary and return base64 in response
	FollowRedirects    *bool              `json:"followRedirects,omitempty"`    // Follow HTTP redirects (default: true)
	CaptchaSolver      string             `json:"captchaSolver,omitempty"`      // Per-request captcha provider: "2captcha", "capsolver", or "none"
	CaptchaApiKey      string             `json:"captchaApiKey,omitempty"`      //nolint:revive,stylecheck // JSON API compatibility
	UserAgent          string             `json:"userAgent,omitempty"`          // Override User-Agent for this request
	ReturnRawHtml      bool               `json:"returnRawHtml,omitempty"`      //nolint:revive,stylecheck // JSON API compatibility
	ExecuteJs          string             `json:"executeJs,omitempty"`          // Custom JavaScript to execute after solve
	KeepaliveTTL       int                `json:"keepaliveTtl,omitempty"`       // New TTL in minutes for sessions.keepalive (0 = just touch)
	CookieExtractDelay int                `json:"cookieExtractDelay,omitempty"` // Seconds to wait before extracting cookies (0-30)
	BrowserFlags       *BrowserFlags      `json:"browserFlags,omitempty"`       // Per-session Chrome flag overrides (sessions.create only)
	Fingerprint        *FingerprintConfig `json:"fingerprint,omitempty"`        // Per-request browser fingerprint customization
}

// Validate validates the request and returns an error if invalid.
// Fix HIGH: Add comprehensive input validation to prevent resource exhaustion and injection.
func (r *Request) Validate() error {
	// Validate cmd field
	if r.Cmd == "" {
		return fmt.Errorf("cmd is required")
	}
	if len(r.Cmd) > MaxCmdLength {
		return fmt.Errorf("cmd exceeds maximum length of %d", MaxCmdLength)
	}

	// Validate cmd is a known command
	switch r.Cmd {
	case CmdRequestGet, CmdRequestPost, CmdSessionsCreate, CmdSessionsList, CmdSessionsDestroy, CmdSessionsKeepalive:
		// Valid command
	default:
		// Use %q format for security (prevents log injection) - matches test expectations
		return fmt.Errorf("unknown command: %q", r.Cmd)
	}

	// Validate URL if present
	if r.URL != "" {
		if len(r.URL) > MaxURLLength {
			return fmt.Errorf("url exceeds maximum length of %d", MaxURLLength)
		}
		// Check URL scheme
		u, err := url.Parse(r.URL)
		if err != nil {
			return fmt.Errorf("invalid url: %w", err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("url scheme must be http or https, got: %s", scheme)
		}
	}

	// Validate session ID if present
	if r.Session != "" && len(r.Session) > MaxSessionIDLength {
		return fmt.Errorf("session exceeds maximum length of %d", MaxSessionIDLength)
	}

	// Validate maxTimeout bounds
	if r.MaxTimeout < 0 {
		return fmt.Errorf("maxTimeout cannot be negative")
	}
	if r.MaxTimeout > MaxTimeoutMs {
		return fmt.Errorf("maxTimeout exceeds maximum of %d ms", MaxTimeoutMs)
	}

	// Validate cookies
	if len(r.Cookies) > MaxCookies {
		return fmt.Errorf("too many cookies (maximum %d)", MaxCookies)
	}
	for i, cookie := range r.Cookies {
		if cookie.Name == "" {
			return fmt.Errorf("cookie[%d]: name is required", i)
		}
		if len(cookie.Name) > MaxCookieNameLength {
			return fmt.Errorf("cookie[%d]: name exceeds maximum length of %d", i, MaxCookieNameLength)
		}
		if len(cookie.Value) > MaxCookieValueLength {
			return fmt.Errorf("cookie[%d]: value exceeds maximum length of %d", i, MaxCookieValueLength)
		}
		if len(cookie.Domain) > MaxCookieDomainLength {
			return fmt.Errorf("cookie[%d]: domain exceeds maximum length of %d", i, MaxCookieDomainLength)
		}
		if len(cookie.Path) > MaxCookiePathLength {
			return fmt.Errorf("cookie[%d]: path exceeds maximum length of %d", i, MaxCookiePathLength)
		}
		if strings.Contains(cookie.Path, "..") {
			return fmt.Errorf("cookie[%d]: path cannot contain '..'", i)
		}
	}

	// Validate proxy if present
	if r.Proxy != nil {
		if err := r.Proxy.Validate(); err != nil {
			return fmt.Errorf("proxy: %w", err)
		}
	}

	// Validate postData
	if len(r.PostData) > MaxPostDataLength {
		return fmt.Errorf("postData exceeds maximum length of %d", MaxPostDataLength)
	}

	// Validate contentType
	if r.ContentType != "" {
		switch r.ContentType {
		case ContentTypeFormURLEncoded, ContentTypeJSON:
			// Valid
		default:
			return fmt.Errorf("contentType must be '%s' or '%s'", ContentTypeFormURLEncoded, ContentTypeJSON)
		}
	}

	// Validate headers
	if len(r.Headers) > MaxHeaders {
		return fmt.Errorf("too many headers (maximum %d)", MaxHeaders)
	}
	for name, value := range r.Headers {
		if len(name) > MaxHeaderNameLength {
			return fmt.Errorf("header name exceeds maximum length of %d", MaxHeaderNameLength)
		}
		if len(value) > MaxHeaderValueLength {
			return fmt.Errorf("header value exceeds maximum length of %d", MaxHeaderValueLength)
		}
	}

	// Validate waitInSeconds bounds
	if r.WaitInSeconds < 0 {
		return fmt.Errorf("waitInSeconds cannot be negative")
	}
	if r.WaitInSeconds > MaxWaitSeconds {
		return fmt.Errorf("waitInSeconds exceeds maximum of %d", MaxWaitSeconds)
	}

	// Validate tabsTillVerify bounds
	if r.TabsTillVerify < 0 {
		return fmt.Errorf("tabsTillVerify cannot be negative")
	}
	if r.TabsTillVerify > MaxTabsTillVerify {
		return fmt.Errorf("tabsTillVerify exceeds maximum of %d", MaxTabsTillVerify)
	}

	// Validate captchaSolver if present
	if r.CaptchaSolver != "" {
		if !isValidCaptchaSolver(r.CaptchaSolver) {
			return fmt.Errorf("captchaSolver %q is not a registered provider", r.CaptchaSolver)
		}
	}

	// Validate session_ttl_minutes bounds
	if r.SessionTTL < 0 {
		return fmt.Errorf("session_ttl_minutes cannot be negative")
	}
	if r.SessionTTL > MaxSessionTTLMinutes {
		return fmt.Errorf("session_ttl_minutes exceeds maximum of %d", MaxSessionTTLMinutes)
	}

	// Validate keepaliveTtl bounds (same limits as session TTL)
	if r.KeepaliveTTL < 0 {
		return fmt.Errorf("keepaliveTtl cannot be negative")
	}
	if r.KeepaliveTTL > MaxSessionTTLMinutes {
		return fmt.Errorf("keepaliveTtl exceeds maximum of %d minutes", MaxSessionTTLMinutes)
	}

	// Validate browserFlags if present
	if r.BrowserFlags != nil {
		if err := r.BrowserFlags.Validate(); err != nil {
			return fmt.Errorf("browserFlags: %w", err)
		}
	}

	// Validate cookieExtractDelay bounds
	if r.CookieExtractDelay < 0 {
		return fmt.Errorf("cookieExtractDelay cannot be negative")
	}
	if r.CookieExtractDelay > MaxCookieExtractDelay {
		return fmt.Errorf("cookieExtractDelay exceeds maximum of %d seconds", MaxCookieExtractDelay)
	}

	return nil
}

// RequestCookie represents a cookie to be set before navigation.
type RequestCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
}

// Proxy contains proxy configuration for a request.
type Proxy struct {
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Validate validates the proxy configuration.
func (p *Proxy) Validate() error {
	if p.URL == "" {
		return nil // Empty proxy is valid (means no proxy)
	}

	// Validate proxy URL format
	u, err := url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	// Validate scheme
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks4", "socks5":
		// Valid proxy schemes
	default:
		return fmt.Errorf("unsupported scheme: %s (must be http, https, socks4, or socks5)", scheme)
	}

	// Validate host is present
	if u.Host == "" {
		return fmt.Errorf("host is required")
	}

	// Validate credential lengths
	if len(p.Username) > MaxProxyUsernameLength {
		return fmt.Errorf("username exceeds maximum length of %d", MaxProxyUsernameLength)
	}
	if len(p.Password) > MaxProxyPasswordLength {
		return fmt.Errorf("password exceeds maximum length of %d", MaxProxyPasswordLength)
	}

	return nil
}

// Response represents an API response.
// This matches the FlareSolverr API specification.
type Response struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	StartTime int64     `json:"startTimestamp"`
	EndTime   int64     `json:"endTimestamp"`
	Version   string    `json:"version"`
	Solution  *Solution `json:"solution,omitempty"`
	Sessions  []string  `json:"sessions,omitempty"`
}

// Solution contains the result of a successful solve.
type Solution struct {
	URL            string            `json:"url"`
	Status         int               `json:"status"`
	Headers        map[string]string `json:"headers,omitempty"`
	Response       string            `json:"response"`
	Cookies        []Cookie          `json:"cookies"`
	UserAgent      string            `json:"userAgent"`
	BrowserVersion string            `json:"browserVersion,omitempty"`  // Chrome major version (e.g., "124") for tls-client profile matching
	Screenshot     string            `json:"screenshot,omitempty"`      // Base64 encoded PNG screenshot
	TurnstileToken string            `json:"turnstile_token,omitempty"` // cf-turnstile-response token if present

	// Extended extraction for debugging (omitted when empty)
	LocalStorage    map[string]string `json:"localStorage,omitempty"`    // All localStorage key-value pairs
	SessionStorage  map[string]string `json:"sessionStorage,omitempty"`  // All sessionStorage key-value pairs
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"` // Extracted response metadata

	// Custom JS result
	ExecuteJsResult *string `json:"executeJsResult,omitempty"` // Result of executeJs if provided

	// Response metadata (omitted when not applicable)
	ResponseEncoding  string  `json:"responseEncoding,omitempty"`  // "base64" when download=true, empty for HTML
	ResponseTruncated *bool   `json:"responseTruncated,omitempty"` // true if HTML response was truncated due to size limit
	CookieError       *string `json:"cookieError,omitempty"`       // error message if cookies could not be retrieved

	// Rate limit detection fields (omitted when not applicable)
	RateLimited      *bool   `json:"rateLimited,omitempty"`      // true if rate limiting detected
	SuggestedDelayMs *int    `json:"suggestedDelayMs,omitempty"` // recommended delay before retry in ms
	ErrorCode        *string `json:"errorCode,omitempty"`        // specific error identifier (e.g., CF_1015)
	ErrorCategory    *string `json:"errorCategory,omitempty"`    // broad category: rate_limit, access_denied, captcha, geo_blocked
}

// Cookie represents a browser cookie.
type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires,omitempty"`
	Size     int     `json:"size,omitempty"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	Session  bool    `json:"session,omitempty"`
	SameSite string  `json:"sameSite,omitempty"`
}

// Commands supported by the API.
const (
	CmdRequestGet        = "request.get"
	CmdRequestPost       = "request.post"
	CmdSessionsCreate    = "sessions.create"
	CmdSessionsList      = "sessions.list"
	CmdSessionsDestroy   = "sessions.destroy"
	CmdSessionsKeepalive = "sessions.keepalive"
)

// Status values for API responses.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// Content type constants for POST requests.
const (
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"
	ContentTypeJSON           = "application/json"
)

// BrowserFlags contains per-session Chrome flag overrides.
// Only a curated subset of flags is supported for security.
type BrowserFlags struct {
	WindowSize string   `json:"windowSize,omitempty"` // e.g. "1280,720"
	Language   string   `json:"language,omitempty"`   // e.g. "fr-FR"
	Timezone   string   `json:"timezone,omitempty"`   // e.g. "Europe/Paris"
	Headless   *bool    `json:"headless,omitempty"`   // Override global headless setting
	DisableGPU *bool    `json:"disableGpu,omitempty"` // Force software rendering
	ExtraArgs  []string `json:"extraArgs,omitempty"`  // Validated against allowed whitelist
}

// Validate validates the browser flags.
func (f *BrowserFlags) Validate() error {
	if f.WindowSize != "" {
		parts := strings.SplitN(f.WindowSize, ",", 2)
		if len(parts) != 2 {
			return fmt.Errorf("windowSize must be 'width,height' (e.g. '1280,720')")
		}
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				return fmt.Errorf("windowSize dimensions cannot be empty")
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					return fmt.Errorf("windowSize dimensions must be numeric")
				}
			}
		}
	}

	if f.Language != "" && len(f.Language) > 20 {
		return fmt.Errorf("language exceeds maximum length of 20")
	}

	if f.Timezone != "" && len(f.Timezone) > 50 {
		return fmt.Errorf("timezone exceeds maximum length of 50")
	}

	if len(f.ExtraArgs) > 10 {
		return fmt.Errorf("extraArgs exceeds maximum of 10 arguments")
	}

	for _, arg := range f.ExtraArgs {
		if !strings.HasPrefix(arg, "--") {
			return fmt.Errorf("extraArgs must start with '--': %s", arg)
		}
		if len(arg) > 256 {
			return fmt.Errorf("extraArg exceeds maximum length of 256: %s", arg[:50])
		}
	}

	return nil
}

// FingerprintConfig specifies per-session browser fingerprint customization.
type FingerprintConfig struct {
	Profile        string         `json:"profile,omitempty"`        // Builtin profile name: "default", "desktop-chrome-windows", "desktop-chrome-mac", "minimal"
	Overrides      map[string]any `json:"overrides,omitempty"`      // Dimension overrides (timezone, locale, screenWidth, etc.)
	DisablePatches []string       `json:"disablePatches,omitempty"` // Stealth patches to skip
}

// CaptchaSolverValidator is set by the captcha package to validate provider names
// dynamically against the registry. Falls back to a hardcoded list if not set.
var CaptchaSolverValidator func(name string) bool

// isValidCaptchaSolver checks if a captcha solver name is valid.
func isValidCaptchaSolver(name string) bool {
	if name == "none" {
		return true
	}
	if CaptchaSolverValidator != nil {
		return CaptchaSolverValidator(name)
	}
	// Fallback: hardcoded list for when registry isn't initialized
	switch name {
	case "2captcha", "capsolver", "anticaptcha":
		return true
	}
	return false
}
