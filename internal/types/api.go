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
)

// Request represents an incoming API request.
// This matches the FlareSolverr API specification.
type Request struct {
	Cmd               string            `json:"cmd"`
	URL               string            `json:"url,omitempty"`
	Session           string            `json:"session,omitempty"`
	SessionTTL        int               `json:"session_ttl_minutes,omitempty"` // Reserved for future use - currently ignored
	MaxTimeout        int               `json:"maxTimeout,omitempty"`
	Cookies           []RequestCookie   `json:"cookies,omitempty"`
	ReturnOnlyCookies bool              `json:"returnOnlyCookies,omitempty"`
	Proxy             *Proxy            `json:"proxy,omitempty"`
	PostData          string            `json:"postData,omitempty"`
	ContentType       string            `json:"contentType,omitempty"`      // Content type for POST: "application/json" or "application/x-www-form-urlencoded" (default)
	Headers           map[string]string `json:"headers,omitempty"`          // Custom HTTP headers to send with the request
	ReturnScreenshot  bool              `json:"returnScreenshot,omitempty"` // Capture screenshot and return as base64
	DisableMedia      bool              `json:"disableMedia,omitempty"`     // Disable loading of media (images, CSS, fonts)
	WaitInSeconds     int               `json:"waitInSeconds,omitempty"`    // Wait N seconds before returning the response
	TabsTillVerify    int               `json:"tabsTillVerify,omitempty"`   // Number of Tab presses to reach Turnstile checkbox (default: 10)
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
	case CmdRequestGet, CmdRequestPost, CmdSessionsCreate, CmdSessionsList, CmdSessionsDestroy:
		// Valid command
	default:
		// Use %q format for security (prevents log injection) - matches test expectations
		return fmt.Errorf("Unknown command: %q", r.Cmd)
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

	// Response metadata (omitted when not applicable)
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
	CmdRequestGet      = "request.get"
	CmdRequestPost     = "request.post"
	CmdSessionsCreate  = "sessions.create"
	CmdSessionsList    = "sessions.list"
	CmdSessionsDestroy = "sessions.destroy"
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
