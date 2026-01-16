// Package handlers provides HTTP request handlers for the FlareSolverr API.
package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/security"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
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
	pool      *browser.Pool
	sessions  *session.Manager
	solver    *solver.Solver
	config    *config.Config
	userAgent string
}

// New creates a new Handler.
func New(pool *browser.Pool, sessions *session.Manager, cfg *config.Config) *Handler {
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	return &Handler{
		pool:      pool,
		sessions:  sessions,
		solver:    solver.New(pool, userAgent),
		config:    cfg,
		userAgent: userAgent,
	}
}

// ServeHTTP handles incoming requests (implements http.Handler).
// This delegates to the Router for path-based routing.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight
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
	defer r.Body.Close() // Bug 10: Explicitly close request body

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

	log.Info().
		Str("cmd", req.Cmd).
		Str("url", sanitizeURLForLogging(req.URL)).
		Str("session", req.Session).
		Msg("Request received")

	// Route to appropriate command handler
	h.routeCommand(w, r, &req, startTime)
}

// HandleHealth handles the /health and /v1 endpoints.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	h.handleHealth(w, time.Now())
}

// HandleAPI handles the main API endpoint.
func (h *Handler) HandleAPI(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Limit request body size to prevent memory exhaustion (1MB max)
	const maxBodySize = 1 << 20 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer r.Body.Close() // Bug 10: Explicitly close request body

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

	log.Info().
		Str("cmd", req.Cmd).
		Str("url", sanitizeURLForLogging(req.URL)).
		Str("session", req.Session).
		Msg("Request received")

	h.routeCommand(w, r, &req, startTime)
}

// HandleMethodNotAllowed handles requests with unsupported HTTP methods.
func (h *Handler) HandleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	h.writeErrorWithStatus(w, http.StatusMethodNotAllowed, "Method not allowed", time.Now())
}

// HandleNotFound handles requests to unknown paths.
func (h *Handler) HandleNotFound(w http.ResponseWriter, r *http.Request) {
	h.writeErrorWithStatus(w, http.StatusNotFound, "Not found", time.Now())
}

// handleHealth returns service health information.
func (h *Handler) handleHealth(w http.ResponseWriter, startTime time.Time) {
	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "FlareSolverr is ready",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
	}
	h.writeJSONResponse(w, http.StatusOK, resp)
}

// handleRequest handles both GET and POST requests with challenge solving.
func (h *Handler) handleRequest(w http.ResponseWriter, ctx context.Context, req *types.Request, isPost bool, startTime time.Time) {
	if req.URL == "" {
		h.writeError(w, "url is required", startTime)
		return
	}

	// Validate URL for SSRF protection
	if err := security.ValidateURL(req.URL); err != nil {
		log.Warn().Err(err).Str("url", sanitizeURLForLogging(req.URL)).Msg("URL validation failed")
		h.writeError(w, "Invalid URL: "+err.Error(), startTime)
		return
	}

	// Validate POST requirements
	if isPost && req.PostData == "" {
		h.writeError(w, "postData is required for POST requests", startTime)
		return
	}

	// Determine timeout
	timeout := h.config.DefaultTimeout
	if req.MaxTimeout > 0 {
		timeout = time.Duration(req.MaxTimeout) * time.Millisecond
		if timeout > h.config.MaxTimeout {
			timeout = h.config.MaxTimeout
		}
	}

	// Build solve options
	opts := &solver.SolveOptions{
		URL:        req.URL,
		Timeout:    timeout,
		Cookies:    req.Cookies,
		Proxy:      req.Proxy,
		PostData:   req.PostData,
		IsPost:     isPost,
		Screenshot: req.ReturnScreenshot,
	}

	var result *solver.Result
	var err error

	// Use session if provided
	if req.Session != "" {
		sess, sessErr := h.sessions.Get(req.Session)
		if sessErr != nil {
			log.Warn().Err(sessErr).Str("session", req.Session).Msg("Session lookup failed")
			h.writeError(w, "Session not found: "+req.Session, startTime)
			return
		}
		result, err = h.solver.SolveWithPage(ctx, sess.Page, opts)
	} else {
		result, err = h.solver.Solve(ctx, opts)
	}

	if err != nil {
		log.Error().Err(err).Str("url", sanitizeURLForLogging(req.URL)).Msg("Solve failed")
		h.writeError(w, err.Error(), startTime)
		return
	}

	h.writeSuccess(w, result, req.ReturnOnlyCookies, startTime)
}

// handleSessionCreate creates a new session.
func (h *Handler) handleSessionCreate(w http.ResponseWriter, ctx context.Context, req *types.Request, startTime time.Time) {
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
		h.writeError(w, "Failed to destroy session: "+err.Error(), startTime)
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

	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "Challenge solved successfully",
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
		Solution: &types.Solution{
			URL:            result.URL,
			Status:         result.StatusCode,
			Response:       response,
			Cookies:        cookies,
			UserAgent:      result.UserAgent,
			Screenshot:     result.Screenshot,
			TurnstileToken: result.TurnstileToken,
		},
	}
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
