// Package handlers provides HTTP request handlers for the FlareSolverr API.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/ratelimit"
	"github.com/Rorqualx/flaresolverr-go/internal/security"
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

// Handler handles all FlareSolverr API requests.
type Handler struct {
	pool        *browser.Pool
	sessions    *session.Manager
	solver      *solver.Solver
	config      *config.Config
	userAgent   string
	domainStats *stats.Manager
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
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	return &Handler{
		pool:        pool,
		sessions:    sessions,
		solver:      solver.New(pool, userAgent),
		config:      cfg,
		userAgent:   userAgent,
		domainStats: stats.NewManager(),
	}
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

	// Validate cmd field length to prevent memory abuse
	const maxCmdLength = 64
	if len(req.Cmd) > maxCmdLength {
		log.Warn().Int("len", len(req.Cmd)).Msg("Command too long")
		h.writeError(w, "Invalid command", startTime)
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

	// Validate cmd field length to prevent memory abuse
	const maxCmdLength = 64
	if len(req.Cmd) > maxCmdLength {
		log.Warn().Int("len", len(req.Cmd)).Msg("Command too long")
		h.writeError(w, "Invalid command", startTime)
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

// HealthResponse is the response format for the /health endpoint.
type HealthResponse struct {
	Status      string                           `json:"status"`
	Message     string                           `json:"message,omitempty"`
	StartTime   int64                            `json:"startTimestamp,omitempty"`
	EndTime     int64                            `json:"endTimestamp,omitempty"`
	Version     string                           `json:"version,omitempty"`
	Pool        *PoolStats                       `json:"pool,omitempty"`
	DomainStats map[string]stats.DomainStatsJSON `json:"domainStats,omitempty"`
	Defaults    *DelayDefaults                   `json:"defaults,omitempty"`
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

	h.writeJSONResponse(w, http.StatusOK, resp)
}

// handleRequest handles both GET and POST requests with challenge solving.
func (h *Handler) handleRequest(w http.ResponseWriter, ctx context.Context, req *types.Request, isPost bool, startTime time.Time) {
	if req.URL == "" {
		h.writeError(w, "url is required", startTime)
		return
	}

	// Validate URL for SSRF protection with DNS resolution for audit trail
	// Fix #8: Note on DNS pinning limitation:
	// The resolvedIP is logged for audit purposes to help detect DNS rebinding attacks,
	// but it is NOT used to enforce DNS pinning. True DNS rebinding protection would require
	// a custom DNS resolver that pins the IP for the entire request lifecycle, which is
	// not implemented here. The browser may re-resolve DNS and get a different IP.
	// The response URL is re-validated after navigation as a secondary defense.
	validatedURL, resolvedIP, err := security.ValidateAndResolveURL(req.URL)
	if err != nil {
		log.Warn().Err(err).Str("url", sanitizeURLForLogging(req.URL)).Msg("URL validation failed")
		h.writeError(w, "Invalid URL: "+err.Error(), startTime)
		return
	}
	// Log resolved IP for audit trail (helps detect DNS rebinding attempts)
	if resolvedIP != nil {
		log.Debug().
			Str("url", sanitizeURLForLogging(validatedURL)).
			Str("resolved_ip", resolvedIP.String()).
			Msg("URL validated with DNS resolution")
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
			h.writeError(w, "Invalid proxy URL: "+err.Error(), startTime)
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

	// Validate and determine timeout
	if req.MaxTimeout < 0 {
		h.writeError(w, "maxTimeout cannot be negative", startTime)
		return
	}
	timeout := h.config.DefaultTimeout
	if req.MaxTimeout > 0 {
		timeout = time.Duration(req.MaxTimeout) * time.Millisecond
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

	// Build solve options
	opts := &solver.SolveOptions{
		URL:           req.URL,
		Timeout:       timeout,
		Cookies:       req.Cookies,
		Proxy:         req.Proxy,
		PostData:      req.PostData,
		IsPost:        isPost,
		Screenshot:    req.ReturnScreenshot,
		DisableMedia:  req.DisableMedia,
		WaitInSeconds: waitInSeconds,
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
		// Fix #6: Check if session page is nil (may have been closed or corrupted)
		if sess.Page == nil {
			log.Error().Str("session", req.Session).Msg("Session page is nil")
			h.writeError(w, "Session page is no longer available", startTime)
			return
		}
		result, solveErr = h.solver.SolveWithPage(ctx, sess.Page, opts)
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
		h.writeError(w, "Failed to acquire browser: "+err.Error(), startTime)
		return
	}

	// Create session (note: this transfers browser ownership to session)
	sess, err := h.sessions.Create(sessionID, browserInstance)
	if err != nil {
		h.pool.Release(browserInstance)
		h.writeError(w, "Failed to create session: "+err.Error(), startTime)
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

	if err := h.sessions.Destroy(req.Session); err != nil {
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
		URL:            result.URL,
		Status:         result.StatusCode,
		Response:       response,
		Cookies:        cookies,
		UserAgent:      result.UserAgent,
		Screenshot:     result.Screenshot,
		TurnstileToken: result.TurnstileToken,
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

// writeError writes an error response with appropriate HTTP status code.
// Note: For backward compatibility with existing clients, we still return HTTP 200
// with the error in the JSON body. This matches the original FlareSolverr behavior.
// Use writeErrorWithStatus for cases where HTTP status codes are preferred.
func (h *Handler) writeError(w http.ResponseWriter, message string, startTime time.Time) {
	h.writeErrorWithStatus(w, http.StatusOK, message, startTime)
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
		_, _ = w.Write([]byte(`{"status":"error","message":"internal encoding error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
	}
	_, _ = w.Write(buf.Bytes())
}
