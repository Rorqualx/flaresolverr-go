package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/middleware"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// mockHandler creates a handler without a real browser pool for testing
func mockHandler() *Handler {
	cfg := &config.Config{
		DefaultTimeout:         60 * time.Second,
		MaxTimeout:             300 * time.Second,
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            100,
	}

	return &Handler{
		pool:      nil, // No real pool for unit tests
		sessions:  session.NewManager(cfg, nil),
		solver:    nil, // No real solver for unit tests
		config:    cfg,
		userAgent: "TestAgent/1.0",
	}
}

func TestHealthEndpoint(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp types.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Status != types.StatusOK {
		t.Errorf("Expected status 'ok', got %q", resp.Status)
	}

	if resp.Message != "FlareSolverr is ready" {
		t.Errorf("Unexpected message: %q", resp.Message)
	}

	if resp.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestV1Endpoint(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	// /v1 is the main API endpoint (POST only) - matching original FlareSolverr
	// Test that POST /v1 works as the API endpoint
	body := types.Request{Cmd: types.CmdSessionsList}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/v1", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusOK {
		t.Errorf("Expected status 'ok', got %q", resp.Status)
	}
}

func TestV1EndpointRejectsGet(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	// GET /v1 should return "Method not allowed" since /v1 is POST-only API endpoint
	req := httptest.NewRequest("GET", "/v1", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status for GET /v1, got %q", resp.Status)
	}

	if resp.Message != "Method not allowed" {
		t.Errorf("Expected 'Method not allowed', got %q", resp.Message)
	}
}

func TestOptionsMethod(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	// CORS is handled by middleware, so wrap handler with CORS middleware
	// Empty config means allow all origins (backward compatible)
	corsHandler := middleware.CORS(middleware.CORSConfig{})(h)

	req := httptest.NewRequest("OPTIONS", "/v1", nil)
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", w.Code)
	}

	// Check CORS headers (set by middleware)
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Missing CORS Allow-Origin header")
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Missing CORS Allow-Methods header")
	}
}

func TestInvalidJSON(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	req := httptest.NewRequest("POST", "/api", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}

	if resp.Message != "Invalid JSON request" {
		t.Errorf("Unexpected error message: %q", resp.Message)
	}
}

func TestUnknownCommand(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{Cmd: "unknown.command"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}

	if resp.Message != "Unknown command: unknown.command" {
		t.Errorf("Unexpected error message: %q", resp.Message)
	}
}

func TestSessionsList(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{Cmd: types.CmdSessionsList}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusOK {
		t.Errorf("Expected ok status, got %q", resp.Status)
	}

	// Sessions can be nil or empty slice when no sessions exist
	if len(resp.Sessions) != 0 {
		t.Errorf("Expected empty sessions list, got %d", len(resp.Sessions))
	}
}

func TestSessionCreateMissingID(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{Cmd: types.CmdSessionsCreate}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}

	if resp.Message != "session ID is required" {
		t.Errorf("Unexpected error message: %q", resp.Message)
	}
}

func TestSessionDestroyMissingID(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{Cmd: types.CmdSessionsDestroy}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}
}

func TestSessionDestroyNotFound(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{
		Cmd:     types.CmdSessionsDestroy,
		Session: "nonexistent",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}
}

func TestRequestGetMissingURL(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{Cmd: types.CmdRequestGet}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}

	if resp.Message != "url is required" {
		t.Errorf("Unexpected error message: %q", resp.Message)
	}
}

func TestRequestPostMissingPostData(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	body := types.Request{
		Cmd: types.CmdRequestPost,
		URL: "https://example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", resp.Status)
	}

	if resp.Message != "postData is required for POST requests" {
		t.Errorf("Unexpected error message: %q", resp.Message)
	}
}

func TestContentTypeHeader(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %q", contentType)
	}
}

func TestResponseTimestamps(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp types.Response
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.StartTime == 0 {
		t.Error("StartTime should not be zero")
	}

	if resp.EndTime == 0 {
		t.Error("EndTime should not be zero")
	}

	if resp.EndTime < resp.StartTime {
		t.Error("EndTime should be >= StartTime")
	}
}
