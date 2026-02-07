// Package handlers provides HTTP request handlers for the FlareSolverr API.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/ratelimit"
	"github.com/Rorqualx/flaresolverr-go/internal/security"
	"github.com/Rorqualx/flaresolverr-go/internal/selectors"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
	"github.com/Rorqualx/flaresolverr-go/pkg/version"
)

// sensitiveParams contains query parameter names that may contain secrets
// and should be redacted in logs.
var sensitiveParams = []string{
	"key", "token", "api_key", "apikey", "password", "secret", "auth",
	"access_token", "refresh_token", "bearer", "credential", "private_key",
}

// sanitizeURLForLogging removes sensitive query parameters from URLs before logging.
// This prevents accidental exposure of API keys, tokens, and other secrets in logs.
func sanitizeURLForLogging(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}

	// If no query parameters, return as-is
	if parsed.RawQuery == "" {
		return rawURL
	}

	// Check and redact sensitive parameters
	query := parsed.Query()
	redacted := false
	for _, param := range sensitiveParams {
		// Check case-insensitively
		for key := range query {
			if strings.EqualFold(key, param) {
				query.Set(key, "[REDACTED]")
				redacted = true
			}
		}
	}

	if !redacted {
		return rawURL
	}

	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// specialCharsForLogging contains characters that commonly cause issues in proxy credentials.
// This is used for debug logging to help troubleshoot authentication problems.
var specialCharsForLogging = []rune{'"', '\'', '\\', '@', ':', '%', '\n', '\r', '\t'}

// logProxyCredentialInfo logs debug information about proxy credentials without exposing
// the actual values. This helps troubleshoot issues with special characters in credentials.
func logProxyCredentialInfo(username, password string) {
	// Check if username contains special characters
	usernameHasSpecial := false
	for _, c := range username {
		for _, special := range specialCharsForLogging {
			if c == special {
				usernameHasSpecial = true
				break
			}
		}
		if usernameHasSpecial {
			break
		}
	}

	// Check if password contains special characters
	passwordHasSpecial := false
	for _, c := range password {
		for _, special := range specialCharsForLogging {
			if c == special {
				passwordHasSpecial = true
				break
			}
		}
		if passwordHasSpecial {
			break
		}
	}

	// Only log if special characters are present (to reduce noise)
	if usernameHasSpecial || passwordHasSpecial {
		log.Debug().
			Bool("username_has_special_chars", usernameHasSpecial).
			Bool("password_has_special_chars", passwordHasSpecial).
			Int("username_length", len(username)).
			Int("password_length", len(password)).
			Msg("Proxy credentials contain special characters (handled via CDP/extension)")
	}
}

// extractChromeVersion extracts the major Chrome version from a User-Agent string.
// Returns the major version number (e.g., "124" from "Chrome/124.0.0.0") or empty string if not found.
// This is useful for matching tls-client profiles which are named by Chrome version.
func extractChromeVersion(userAgent string) string {
	idx := strings.Index(userAgent, "Chrome/")
	if idx == -1 {
		return ""
	}
	versionStart := idx + 7 // skip past "Chrome/"
	versionEnd := versionStart
	for versionEnd < len(userAgent) && userAgent[versionEnd] != '.' && userAgent[versionEnd] != ' ' {
		versionEnd++
	}
	if versionEnd > versionStart {
		return userAgent[versionStart:versionEnd]
	}
	return ""
}

// Handler handles all FlareSolverr API requests.
type Handler struct {
	pool             *browser.Pool
	sessions         *session.Manager
	solver           *solver.Solver
	config           *config.Config
	userAgent        string
	domainStats      *stats.Manager
	selectorsManager *selectors.Manager
}

// Fix #11: closeBody closes an io.ReadCloser and logs any error at debug level.
// This helper prevents silent errors when closing request bodies.
func closeBody(body io.ReadCloser) {
	if err := body.Close(); err != nil {
		log.Debug().Err(err).Msg("Error closing request body")
	}
}

// New creates a new Handler.
func New(pool *browser.Pool, sessions *session.Manager, cfg *config.Config) *Handler {
	return NewWithSelectors(pool, sessions, cfg, nil)
}

// NewWithSelectors creates a new Handler with an optional SelectorsManager.
// If selectorsManager is nil, a default manager using embedded selectors is created.
func NewWithSelectors(pool *browser.Pool, sessions *session.Manager, cfg *config.Config, selectorsManager *selectors.Manager) *Handler {
	// Get the real user agent from the browser
	// This is critical: using a mismatched UA (e.g., claiming Chrome 142 when the browser is 124)
	// is detected by Cloudflare. Python FlareSolverr gets the UA from the browser itself.
	userAgent := getActualUserAgent(pool)

	log.Info().Str("user_agent", userAgent).Msg("Using browser's actual user agent")

	// Create default selectors manager if not provided
	if selectorsManager == nil {
		selectorsManager = selectors.GetManager()
	}

	// Create stats manager for domain tracking
	domainStats := stats.NewManager()

	// Create solver with selectors manager
	solverInstance := solver.NewWithSelectors(pool, userAgent, selectorsManager)

	// Wire up stats manager to solver for Turnstile method tracking
	// This enables per-domain learning of which solving methods work best
	solverInstance.SetStatsManager(domainStats)

	return &Handler{
		pool:             pool,
		sessions:         sessions,
		solver:           solverInstance,
		config:           cfg,
		userAgent:        userAgent,
		domainStats:      domainStats,
		selectorsManager: selectorsManager,
	}
}

// getActualUserAgent retrieves the real user agent from the browser via CDP.
// This ensures the User-Agent and Client Hints match the actual browser version,
// preventing detection by Cloudflare which checks for version mismatches.
func getActualUserAgent(pool *browser.Pool) string {
	// Fallback user agent in case we can't get the real one
	fallbackUA := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

	// Acquire a browser to get the real user agent
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	b, err := pool.Acquire(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Could not acquire browser to get user agent, using fallback")
		return fallbackUA
	}
	defer pool.Release(b)

	// Use CDP's Browser.getVersion() to get the real user agent
	// This is more reliable than navigator.userAgent on about:blank
	result, err := proto.BrowserGetVersion{}.Call(b)
	if err != nil {
		log.Warn().Err(err).Msg("Could not get browser version via CDP, using fallback")
		return fallbackUA
	}

	ua := result.UserAgent

	// Strip "HeadlessChrome" if present (like Python FlareSolverr does)
	ua = strings.Replace(ua, "HeadlessChrome", "Chrome", 1)

	// IMPORTANT: Use the browser's actual user agent to avoid version mismatch detection.
	// Cloudflare detects when User-Agent claims a different version than the browser's
	// actual capabilities (detected via JavaScript APIs, Client Hints, etc.)
	//
	// Previously this code forced Chrome 142, but if the actual browser is Chrome 124,
	// this mismatch is detected and triggers Turnstile challenges.
	log.Debug().Str("browser_ua", ua).Msg("Using browser's actual user agent")

	return ua
}

// DomainStats returns the domain statistics manager.
func (h *Handler) DomainStats() *stats.Manager {
	return h.domainStats
}

// ServeHTTP handles incoming requests (implements http.Handler).
// This delegates to the Router for path-based routing.
// Note: CORS headers are handled by middleware.CORS(), not here.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Set response content type (CORS is handled by middleware)
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight - delegate to middleware
	// Note: CORS middleware handles OPTIONS, but we still need to return
	// early here if an OPTIONS request reaches the handler
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Handle health check
	if r.URL.Path == "/health" {
		h.handleHealth(w, startTime)
		return
	}

	// Only POST is allowed for the main endpoint
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", startTime)
		return
	}

	// Limit request body size to prevent memory exhaustion (1MB max)
	const maxBodySize = 1 << 20 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer closeBody(r.Body) // Fix #11: Use helper to log close errors

	// Parse request using pooled buffer to reduce GC pressure
	buf := getBuffer()
	defer putBuffer(buf)

	if _, err := io.Copy(buf, r.Body); err != nil {
		log.Warn().Err(err).Msg("Failed to read request body")
		h.writeError(w, "Failed to read request", startTime)
		return
	}

	var req types.Request
	if err := json.Unmarshal(buf.Bytes(), &req); err != nil {
		log.Warn().Err(err).Msg("Failed to decode request")
		h.writeError(w, "Invalid JSON request", startTime)
		return
	}

	// Fix HIGH: Call centralized validation instead of duplicating checks
	// This validates cmd, url, session, cookies, proxy, headers, etc.
	if err := req.Validate(); err != nil {
		log.Warn().Err(err).Msg("Request validation failed")
		h.writeError(w, err.Error(), startTime)
		return
	}

	log.Info().
		Str("cmd", req.Cmd).
		Str("url", sanitizeURLForLogging(req.URL)).
		Str("session", req.Session).
		Msg("Request received")

	// Route to appropriate command handler
	h.routeCommand(w, r, &req, startTime)
}

// HandleHealth handles the /health and /v1 endpoints.
func (h *Handler) HandleHealth(w http.ResponseWriter, _ *http.Request) {
	h.handleHealth(w, time.Now())
}

// HandleAPI handles the main API endpoint.
func (h *Handler) HandleAPI(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Limit request body size to prevent memory exhaustion (1MB max)
	const maxBodySize = 1 << 20 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer closeBody(r.Body) // Fix #11: Use helper to log close errors

	// Parse request using pooled buffer to reduce GC pressure
	buf := getBuffer()
	defer putBuffer(buf)

	if _, err := io.Copy(buf, r.Body); err != nil {
		log.Warn().Err(err).Msg("Failed to read request body")
		h.writeError(w, "Failed to read request", startTime)
		return
	}

	var req types.Request
	if err := json.Unmarshal(buf.Bytes(), &req); err != nil {
		log.Warn().Err(err).Msg("Failed to decode request")
		h.writeError(w, "Invalid JSON request", startTime)
		return
	}

	// Fix HIGH: Call centralized validation instead of duplicating checks
	// This validates cmd, url, session, cookies, proxy, headers, etc.
	if err := req.Validate(); err != nil {
		log.Warn().Err(err).Msg("Request validation failed")
		h.writeError(w, err.Error(), startTime)
		return
	}

	log.Info().
		Str("cmd", req.Cmd).
		Str("url", sanitizeURLForLogging(req.URL)).
		Str("session", req.Session).
		Msg("Request received")

	h.routeCommand(w, r, &req, startTime)
}

// HandleMethodNotAllowed handles requests with unsupported HTTP methods.
func (h *Handler) HandleMethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	h.writeErrorWithStatus(w, http.StatusMethodNotAllowed, "Method not allowed", time.Now())
}

// HandleNotFound handles requests to unknown paths.
func (h *Handler) HandleNotFound(w http.ResponseWriter, _ *http.Request) {
	h.writeErrorWithStatus(w, http.StatusNotFound, "Not found", time.Now())
}

// PoolStats holds pool statistics for the health endpoint.
type PoolStats struct {
	Size      int   `json:"size"`
	Available int   `json:"available"`
	Acquired  int64 `json:"acquired"`
	Released  int64 `json:"released"`
	Recycled  int64 `json:"recycled"`
	Errors    int64 `json:"errors"`
}

// SelectorsStats contains statistics about selector hot-reloading.
type SelectorsStats struct {
	LastReloadTime string `json:"lastReloadTime,omitempty"`
	ReloadCount    int64  `json:"reloadCount"`
	LastError      string `json:"lastError,omitempty"`
}

// HealthResponse is the response format for the /health endpoint.
type HealthResponse struct {
	Status         string                           `json:"status"`
	Message        string                           `json:"message,omitempty"`
	StartTime      int64                            `json:"startTimestamp,omitempty"`
	EndTime        int64                            `json:"endTimestamp,omitempty"`
	Version        string                           `json:"version,omitempty"`
	Pool           *PoolStats                       `json:"pool,omitempty"`
	DomainStats    map[string]stats.DomainStatsJSON `json:"domainStats,omitempty"`
	Defaults       *DelayDefaults                   `json:"defaults,omitempty"`
	SelectorsStats *SelectorsStats                  `json:"selectorsStats,omitempty"`
}

// DelayDefaults contains default delay configuration.
type DelayDefaults struct {
	MinDelayMs int `json:"minDelayMs"`
	MaxDelayMs int `json:"maxDelayMs"`
}

// handleHealth returns service health information.
func (h *Handler) handleHealth(w http.ResponseWriter, startTime time.Time) {
	resp := HealthResponse{
		Status:    types.StatusOK,
		Message:   "FlareSolverr is ready",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
	}

	// Include pool stats if pool is available
	if h.pool != nil {
		poolStats := h.pool.Stats()
		resp.Pool = &PoolStats{
			Size:      h.pool.Size(),
			Available: h.pool.Available(),
			Acquired:  poolStats.Acquired,
			Released:  poolStats.Released,
			Recycled:  poolStats.Recycled,
			Errors:    poolStats.Errors,
		}
	}

	// Include domain stats if any domains have been tracked
	if h.domainStats != nil && h.domainStats.DomainCount() > 0 {
		resp.DomainStats = h.domainStats.AllStats()
		resp.Defaults = &DelayDefaults{
			MinDelayMs: h.domainStats.DefaultMinDelayMs,
			MaxDelayMs: h.domainStats.DefaultMaxDelayMs,
		}
	}

	// Include selectors stats if hot-reload has been used
	if h.selectorsManager != nil {
		selectorStats := h.selectorsManager.Stats()
		if selectorStats.ReloadCount > 0 || selectorStats.LastError != nil {
			selStats := &SelectorsStats{
				ReloadCount: selectorStats.ReloadCount,
			}
			if !selectorStats.LastReloadTime.IsZero() {
				selStats.LastReloadTime = selectorStats.LastReloadTime.Format(time.RFC3339)
			}
			if selectorStats.LastErrorStr != "" {
				selStats.LastError = selectorStats.LastErrorStr
			}
			resp.SelectorsStats = selStats
		}
	}

	h.writeJSONResponse(w, http.StatusOK, resp)
}

// handleRequest handles both GET and POST requests with challenge solving.
func (h *Handler) handleRequest(w http.ResponseWriter, ctx context.Context, req *types.Request, isPost bool, startTime time.Time) {
	if req.URL == "" {
		h.writeError(w, "url is required", startTime)
		return
	}

	// Validate URL for SSRF protection with DNS resolution and pinning
	// DNS Pinning: The resolved IP is captured here and passed to the solver.
	// After browser navigation, the response URL's IP is compared against this
	// expected IP to detect DNS rebinding attacks where:
	// 1. Attacker's domain initially resolves to a safe IP (passes validation)
	// 2. Before browser navigates, attacker changes DNS to point to internal IP
	// 3. Browser ends up accessing internal resources
	// The post-navigation validation catches this by re-resolving and comparing.
	// Use request context to respect client-side timeouts for DNS resolution.
	validatedURL, resolvedIP, err := security.ValidateAndResolveURLWithContext(ctx, req.URL)
	if err != nil {
		log.Warn().Err(err).Str("url", sanitizeURLForLogging(req.URL)).Msg("URL validation failed")
		h.writeError(w, fmt.Sprintf("Invalid URL: %v", err), startTime)
		return
	}
	// Log resolved IP for DNS pinning
	if resolvedIP != nil {
		log.Debug().
			Str("url", sanitizeURLForLogging(validatedURL)).
			Str("resolved_ip", resolvedIP.String()).
			Msg("URL validated with DNS resolution (IP pinned for rebinding protection)")
	}

	// Validate proxy URL if provided
	var proxyURL string
	if req.Proxy != nil && req.Proxy.URL != "" {
		proxyURL = req.Proxy.URL
	} else if h.config.HasDefaultProxy() {
		proxyURL = h.config.ProxyURL
	}
	if proxyURL != "" {
		if err := security.ValidateProxyURL(proxyURL, h.config.AllowLocalProxies); err != nil {
			log.Warn().Err(err).Msg("Proxy URL validation failed")
			h.writeError(w, fmt.Sprintf("Invalid proxy URL: %v", err), startTime)
			return
		}
	}

	// Validate proxy credentials size
	const (
		maxProxyUsernameLength = 256
		maxProxyPasswordLength = 256
	)
	if req.Proxy != nil {
		if len(req.Proxy.Username) > maxProxyUsernameLength {
			log.Warn().Int("len", len(req.Proxy.Username)).Msg("Proxy username too long")
			h.writeError(w, "Proxy username exceeds maximum length of 256 characters", startTime)
			return
		}
		if len(req.Proxy.Password) > maxProxyPasswordLength {
			log.Warn().Msg("Proxy password too long") // Don't log password length
			h.writeError(w, "Proxy password exceeds maximum length of 256 characters", startTime)
			return
		}

		// Debug log when credentials contain special characters that commonly cause issues
		// This helps with troubleshooting without exposing the actual credentials
		if req.Proxy.Username != "" || req.Proxy.Password != "" {
			logProxyCredentialInfo(req.Proxy.Username, req.Proxy.Password)
		}
	}

	// Validate cookies to prevent resource exhaustion
	const (
		maxCookieCount        = 100
		maxCookieNameLength   = 256
		maxCookieValueLength  = 4096
		maxCookieDomainLength = 256
		maxCookiePathLength   = 2048
	)
	if len(req.Cookies) > maxCookieCount {
		log.Warn().Int("count", len(req.Cookies)).Msg("Too many cookies in request")
		h.writeError(w, "Too many cookies (maximum 100)", startTime)
		return
	}
	for _, cookie := range req.Cookies {
		// Fix #40: Validate cookie name is not empty
		if len(cookie.Name) == 0 {
			log.Warn().Msg("Empty cookie name")
			h.writeError(w, "Cookie name cannot be empty", startTime)
			return
		}
		if len(cookie.Name) > maxCookieNameLength {
			truncName := cookie.Name
			if len(truncName) > 50 {
				truncName = truncName[:50]
			}
			log.Warn().Str("name", truncName).Msg("Cookie name too long")
			h.writeError(w, "Cookie name exceeds maximum length of 256 characters", startTime)
			return
		}
		if len(cookie.Value) > maxCookieValueLength {
			log.Warn().Str("name", cookie.Name).Msg("Cookie value too long")
			h.writeError(w, "Cookie value exceeds maximum length of 4096 characters", startTime)
			return
		}
		if len(cookie.Domain) > maxCookieDomainLength {
			log.Warn().Str("name", cookie.Name).Int("len", len(cookie.Domain)).Msg("Cookie domain too long")
			h.writeError(w, "Cookie domain exceeds maximum length of 256 characters", startTime)
			return
		}
		if len(cookie.Path) > maxCookiePathLength {
			log.Warn().Str("name", cookie.Name).Int("len", len(cookie.Path)).Msg("Cookie path too long")
			h.writeError(w, "Cookie path exceeds maximum length of 2048 characters", startTime)
			return
		}
		// Fix #41: Validate cookie path doesn't contain traversal sequences
		if strings.Contains(cookie.Path, "..") {
			log.Warn().Str("name", cookie.Name).Str("path", cookie.Path).Msg("Cookie path contains traversal sequence")
			h.writeError(w, "Cookie path cannot contain '..'", startTime)
			return
		}
	}

	// Validate POST requirements
	if isPost && req.PostData == "" {
		h.writeError(w, "postData is required for POST requests", startTime)
		return
	}

	// Validate postData size to prevent memory exhaustion
	const maxPostDataSize = 256 * 1024 // 256KB
	if len(req.PostData) > maxPostDataSize {
		log.Warn().
			Int("size", len(req.PostData)).
			Int("max_size", maxPostDataSize).
			Msg("postData exceeds maximum size")
		h.writeError(w, "postData exceeds maximum size of 256KB", startTime)
		return
	}

	// Validate contentType (only for POST requests)
	contentType := req.ContentType
	if isPost && contentType != "" {
		switch contentType {
		case types.ContentTypeFormURLEncoded, types.ContentTypeJSON:
			// Valid content types
		default:
			log.Warn().Str("contentType", contentType).Msg("Invalid content type")
			h.writeError(w, "contentType must be 'application/json' or 'application/x-www-form-urlencoded'", startTime)
			return
		}

		// Validate JSON syntax if contentType is application/json
		if contentType == types.ContentTypeJSON {
			if !json.Valid([]byte(req.PostData)) {
				log.Warn().Msg("Invalid JSON in postData")
				h.writeError(w, "postData must be valid JSON when contentType is 'application/json'", startTime)
				return
			}
		}

		// Validate form-urlencoded syntax if contentType is application/x-www-form-urlencoded
		if contentType == types.ContentTypeFormURLEncoded && req.PostData != "" {
			if _, err := url.ParseQuery(req.PostData); err != nil {
				log.Warn().Err(err).Msg("Invalid form-urlencoded postData")
				h.writeError(w, "postData must be valid form-urlencoded format", startTime)
				return
			}
		}
	}

	// Validate custom headers
	if len(req.Headers) > 0 {
		if err := security.ValidateHeaders(req.Headers); err != nil {
			log.Warn().Err(err).Msg("Header validation failed")
			h.writeError(w, fmt.Sprintf("Invalid headers: %v", err), startTime)
			return
		}
	}

	// Validate and determine timeout with overflow protection
	if req.MaxTimeout < 0 {
		h.writeError(w, "maxTimeout cannot be negative", startTime)
		return
	}
	timeout := h.config.DefaultTimeout
	if req.MaxTimeout > 0 {
		// Fix 1.8: Cap maxTimeout to prevent integer overflow when converting to Duration
		// Maximum safe value: 10 minutes (600,000 ms) - prevents overflow and abuse
		const maxTimeoutMs = 10 * 60 * 1000 // 10 minutes in milliseconds
		maxTimeoutValue := req.MaxTimeout
		if maxTimeoutValue > maxTimeoutMs {
			maxTimeoutValue = maxTimeoutMs
		}
		timeout = time.Duration(maxTimeoutValue) * time.Millisecond
		if timeout > h.config.MaxTimeout {
			timeout = h.config.MaxTimeout
		}
	}

	// Validate and cap WaitInSeconds to prevent abuse
	// Maximum wait is 60 seconds or remaining timeout, whichever is smaller
	const maxWaitSeconds = 60
	waitInSeconds := req.WaitInSeconds
	if waitInSeconds < 0 {
		waitInSeconds = 0
	} else if waitInSeconds > maxWaitSeconds {
		log.Warn().
			Int("requested", req.WaitInSeconds).
			Int("capped_to", maxWaitSeconds).
			Msg("WaitInSeconds exceeds maximum, capping")
		waitInSeconds = maxWaitSeconds
	}

	// Validate and cap TabsTillVerify to prevent abuse
	const maxTabsTillVerify = 50
	tabsTillVerify := req.TabsTillVerify
	if tabsTillVerify < 0 {
		tabsTillVerify = 0
	} else if tabsTillVerify > maxTabsTillVerify {
		log.Warn().
			Int("requested", req.TabsTillVerify).
			Int("capped_to", maxTabsTillVerify).
			Msg("TabsTillVerify exceeds maximum, capping")
		tabsTillVerify = maxTabsTillVerify
	}

	// Build solve options with DNS pinning
	opts := &solver.SolveOptions{
		URL:            req.URL,
		Timeout:        timeout,
		Cookies:        req.Cookies,
		Proxy:          req.Proxy,
		PostData:       req.PostData,
		ContentType:    contentType, // Content type for POST (json or form-urlencoded)
		Headers:        req.Headers, // Custom HTTP headers
		IsPost:         isPost,
		Screenshot:     req.ReturnScreenshot,
		DisableMedia:   req.DisableMedia,
		WaitInSeconds:  waitInSeconds,
		ExpectedIP:     resolvedIP,     // DNS pinning: verify response URL resolves to same IP
		TabsTillVerify: tabsTillVerify, // Number of Tab presses for Turnstile keyboard navigation
	}

	var result *solver.Result
	var solveErr error

	// Use session if provided
	if req.Session != "" {
		sess, sessErr := h.sessions.Get(req.Session)
		if sessErr != nil {
			log.Warn().Err(sessErr).Str("session", req.Session).Msg("Session lookup failed")
			h.writeError(w, "Session not found or expired", startTime)
			return
		}

		// Acquire operation lock to prevent concurrent operations on the same session
		// This prevents page state corruption from concurrent navigation/actions
		sess.LockOperation()
		defer sess.UnlockOperation()

		// Use AcquirePageWithRelease for reference counting to prevent
		// race condition where page is closed during solve operation.
		// The release function uses sync.Once to ensure exactly one release.
		page, releasePage := sess.AcquirePageWithRelease()
		if page == nil {
			log.Error().Str("session", req.Session).Msg("Session page is nil or session is closing")
			h.writeError(w, "Session page is no longer available", startTime)
			return
		}
		defer releasePage()
		result, solveErr = h.solver.SolveWithPage(ctx, page, opts)
	} else {
		result, solveErr = h.solver.Solve(ctx, opts)
	}

	if solveErr != nil {
		log.Error().Err(solveErr).Str("url", sanitizeURLForLogging(req.URL)).Msg("Solve failed")

		// Check if this is a ChallengeError (access_denied, timeout, etc.)
		// and include rate limit hints in the response
		var challengeErr *types.ChallengeError
		if errors.As(solveErr, &challengeErr) && challengeErr.Type == "access_denied" {
			h.writeAccessDeniedError(w, req.URL, challengeErr.Message, startTime)
			return
		}

		h.writeError(w, solveErr.Error(), startTime)
		return
	}

	h.writeSuccess(w, result, req.ReturnOnlyCookies, startTime)
}

// handleSessionCreate creates a new session.
func (h *Handler) handleSessionCreate(w http.ResponseWriter, ctx context.Context, req *types.Request, startTime time.Time) {
	// Warn if unsupported field is provided
	if req.SessionTTL != 0 {
		log.Warn().
			Int("session_ttl", req.SessionTTL).
			Msg("session_ttl_minutes field is not currently supported, using server default")
	}

	sessionID := req.Session

	// Validate session ID
	if validationErr := security.ValidateSessionID(sessionID); validationErr != "" {
		h.writeError(w, validationErr, startTime)
		return
	}

	// Acquire browser for session
	browserInstance, err := h.pool.Acquire(ctx)
	if err != nil {
		h.writeError(w, fmt.Sprintf("Failed to acquire browser: %v", err), startTime)
		return
	}

	// Create session (note: this transfers browser ownership to session)
	// On error, Create() already releases the browser back to pool, so don't release here
	sess, err := h.sessions.Create(sessionID, browserInstance)
	if err != nil {
		// Note: Do NOT release browser here - session.Create() handles it on all error paths
		h.writeError(w, fmt.Sprintf("Failed to create session: %v", err), startTime)
		return
	}

	log.Info().
		Str("session_id", sess.ID).
		Msg("Session created")

	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "Session created successfully",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
		Sessions:  []string{sessionID},
	}
	h.writeJSONResponse(w, http.StatusOK, resp)
}

// handleSessionList lists all active sessions.
func (h *Handler) handleSessionList(w http.ResponseWriter, startTime time.Time) {
	sessions := h.sessions.List()

	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "Session list retrieved",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
		Sessions:  sessions,
	}
	h.writeJSONResponse(w, http.StatusOK, resp)
}

// handleSessionDestroy destroys a session.
func (h *Handler) handleSessionDestroy(w http.ResponseWriter, req *types.Request, startTime time.Time) {
	if req.Session == "" {
		h.writeError(w, "session is required", startTime)
		return
	}

	// Fix #42: Validate session ID format before attempting destroy
	if errMsg := security.ValidateSessionID(req.Session); errMsg != "" {
		h.writeError(w, errMsg, startTime)
		return
	}

	if err := h.sessions.Destroy(req.Session); err != nil {
		if errors.Is(err, types.ErrSessionInUse) {
			h.writeError(w, "Session is currently in use, try again later", startTime)
			return
		}
		h.writeError(w, "Session not found or already destroyed", startTime)
		return
	}

	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "Session destroyed successfully",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
	}
	h.writeJSONResponse(w, http.StatusOK, resp)
}

// writeSuccess writes a successful response.
func (h *Handler) writeSuccess(w http.ResponseWriter, result *solver.Result, cookiesOnly bool, startTime time.Time) {
	cookies := make([]types.Cookie, 0, len(result.Cookies))
	for _, c := range result.Cookies {
		cookie := types.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  float64(c.Expires),
			Size:     c.Size,
			HTTPOnly: c.HTTPOnly,
			Secure:   c.Secure,
			Session:  c.Session,
			SameSite: string(c.SameSite),
		}
		cookies = append(cookies, cookie)
	}

	response := ""
	if !cookiesOnly {
		response = result.HTML
	}

	solution := &types.Solution{
		URL:             result.URL,
		Status:          result.StatusCode,
		Response:        response,
		Cookies:         cookies,
		UserAgent:       result.UserAgent,
		BrowserVersion:  extractChromeVersion(result.UserAgent),
		Screenshot:      result.Screenshot,
		TurnstileToken:  result.TurnstileToken,
		LocalStorage:    result.LocalStorage,
		SessionStorage:  result.SessionStorage,
		ResponseHeaders: result.ResponseHeaders,
	}

	// Add response metadata if applicable
	if result.HTMLTruncated {
		truncated := true
		solution.ResponseTruncated = &truncated
	}
	if result.CookieError != "" {
		solution.CookieError = &result.CookieError
	}

	// Detect rate limiting in the response
	rateLimitInfo := ratelimit.Detect(result.StatusCode, result.HTML)
	if rateLimitInfo.Detected {
		rateLimited := true
		solution.RateLimited = &rateLimited
		solution.SuggestedDelayMs = &rateLimitInfo.SuggestedDelay
		solution.ErrorCode = &rateLimitInfo.ErrorCode
		category := string(rateLimitInfo.Category)
		solution.ErrorCategory = &category

		log.Info().
			Str("error_code", rateLimitInfo.ErrorCode).
			Str("category", category).
			Int("suggested_delay_ms", rateLimitInfo.SuggestedDelay).
			Msg("Rate limiting detected in response")
	}

	// Extract domain and record stats
	domain := stats.ExtractDomain(result.URL)
	if domain != "" && h.domainStats != nil {
		latencyMs := time.Since(startTime).Milliseconds()
		success := result.StatusCode >= 200 && result.StatusCode < 400 && !rateLimitInfo.Detected
		h.domainStats.RecordRequest(domain, latencyMs, success, rateLimitInfo.Detected)

		// Add domain stats headers
		h.addDomainHeaders(w, domain)
	}

	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "Challenge solved successfully",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
		Solution:  solution,
	}
	h.writeJSONResponse(w, http.StatusOK, resp)
}

// addDomainHeaders adds X-Domain-* headers to the response.
func (h *Handler) addDomainHeaders(w http.ResponseWriter, domain string) {
	if h.domainStats == nil {
		return
	}

	suggestedDelay := h.domainStats.SuggestedDelay(domain)
	w.Header().Set("X-Domain-Suggested-Delay", strconv.Itoa(suggestedDelay))

	errorRate := h.domainStats.ErrorRate(domain)
	w.Header().Set("X-Domain-Error-Rate", strconv.FormatFloat(errorRate, 'f', 2, 64))

	requestCount := h.domainStats.RequestCount(domain)
	w.Header().Set("X-Domain-Request-Count", strconv.FormatInt(requestCount, 10))
}

// writeAccessDeniedError writes an error response with rate limit hints.
// This provides clients with actionable information about why the request failed
// and how long to wait before retrying.
func (h *Handler) writeAccessDeniedError(w http.ResponseWriter, requestURL string, message string, startTime time.Time) {
	// Extract domain and record stats
	domain := stats.ExtractDomain(requestURL)
	if domain != "" && h.domainStats != nil {
		latencyMs := time.Since(startTime).Milliseconds()
		h.domainStats.RecordRequest(domain, latencyMs, false, true) // Mark as rate limited
		h.addDomainHeaders(w, domain)
	}

	// Build response with rate limit hints
	rateLimited := true
	suggestedDelay := 5000 // Default 5 second delay for access denied
	errorCode := "ACCESS_DENIED"
	errorCategory := string(ratelimit.CategoryAccessDenied)

	// Adjust suggested delay based on domain history
	if domain != "" && h.domainStats != nil {
		suggestedDelay = h.domainStats.SuggestedDelay(domain)
	}

	resp := types.Response{
		Status:    types.StatusError,
		Message:   message,
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
		Solution: &types.Solution{
			URL:              requestURL,
			Status:           403,
			RateLimited:      &rateLimited,
			SuggestedDelayMs: &suggestedDelay,
			ErrorCode:        &errorCode,
			ErrorCategory:    &errorCategory,
		},
	}

	log.Info().
		Str("error_code", errorCode).
		Str("category", errorCategory).
		Int("suggested_delay_ms", suggestedDelay).
		Str("domain", domain).
		Msg("Access denied - rate limit hints included in response")

	h.writeJSONResponse(w, http.StatusOK, resp)
}

// sanitizeErrorMessage removes internal details from error messages
// to prevent information disclosure to clients.
func sanitizeErrorMessage(message string) string {
	// List of internal error prefixes/patterns to sanitize
	sensitivePatterns := []string{
		"failed to acquire browser:",
		"failed to spawn browser:",
		"browser pool exhausted:",
		"context deadline exceeded",
		"context canceled",
		"i/o timeout",
		"connection refused",
		"no such host",
		"network is unreachable",
	}

	messageLower := strings.ToLower(message)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(messageLower, pattern) {
			// Return generic message for internal errors
			if strings.Contains(messageLower, "browser") || strings.Contains(messageLower, "pool") {
				return "Service temporarily unavailable"
			}
			if strings.Contains(messageLower, "timeout") || strings.Contains(messageLower, "context") {
				return "Request timed out"
			}
			if strings.Contains(messageLower, "connection") || strings.Contains(messageLower, "network") || strings.Contains(messageLower, "host") {
				return "Unable to connect to target"
			}
		}
	}
	return message
}

// writeError writes an error response with appropriate HTTP status code.
// Note: For backward compatibility with existing clients, we still return HTTP 200
// with the error in the JSON body. This matches the original FlareSolverr behavior.
// Use writeErrorWithStatus for cases where HTTP status codes are preferred.
// Fix: Sanitizes error messages to prevent internal detail disclosure.
func (h *Handler) writeError(w http.ResponseWriter, message string, startTime time.Time) {
	h.writeErrorWithStatus(w, http.StatusOK, sanitizeErrorMessage(message), startTime)
}

// writeErrorWithStatus writes an error response with a specific HTTP status code.
func (h *Handler) writeErrorWithStatus(w http.ResponseWriter, statusCode int, message string, startTime time.Time) {
	resp := types.Response{
		Status:    types.StatusError,
		Message:   message,
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
	}
	h.writeJSONResponse(w, statusCode, resp)
}

// writeJSONResponse buffers JSON before writing to ensure encoding errors are caught
// before headers are sent. Bug 6: Prevents partial responses on encoding failure.
func (h *Handler) writeJSONResponse(w http.ResponseWriter, statusCode int, resp interface{}) {
	buf := getResponseBuffer()
	defer putResponseBuffer(buf)

	if err := json.NewEncoder(buf).Encode(resp); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(`{"status":"error","message":"internal encoding error"}`)); err != nil {
			log.Error().Err(err).Msg("Failed to write fallback error response")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}
