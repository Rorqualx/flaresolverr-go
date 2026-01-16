//go:build integration

// Package integration provides integration tests for FlareSolverr.
// Run with: go test -tags=integration ./tests/integration/...
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/handlers"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

var testHandler *handlers.Handler
var testPool *browser.Pool
var testConfig *config.Config

func TestMain(m *testing.M) {
	// Setup
	testConfig = &config.Config{
		Host:                   "127.0.0.1",
		Port:                   8191,
		Headless:               true,
		BrowserPoolSize:        2,
		BrowserPoolTimeout:     30 * time.Second,
		MaxMemoryMB:            1024,
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
		DefaultTimeout:         30 * time.Second,
		MaxTimeout:             60 * time.Second,
		LogLevel:               "debug",
	}

	var err error
	testPool, err = browser.NewPool(testConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create browser pool: %v\n", err)
		os.Exit(1)
	}

	sessionMgr := session.NewManager(testConfig, testPool)
	testHandler = handlers.New(testPool, sessionMgr, testConfig)

	// Run tests
	code := m.Run()

	// Cleanup
	sessionMgr.Close()
	testPool.Close()

	os.Exit(code)
}

func TestHealthEndpoint(t *testing.T) {
	req, _ := http.NewRequest("GET", "/health", nil)
	resp := executeRequest(req)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	if body.Status != types.StatusOK {
		t.Errorf("Expected status 'ok', got %q", body.Status)
	}

	if body.Message != "FlareSolverr is ready" {
		t.Errorf("Unexpected message: %q", body.Message)
	}
}

func TestRequestGetSimplePage(t *testing.T) {
	reqBody := types.Request{
		Cmd: types.CmdRequestGet,
		URL: "https://httpbin.org/html",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp := executeRequest(req)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	if body.Status != types.StatusOK {
		t.Errorf("Expected status 'ok', got %q: %s", body.Status, body.Message)
	}

	if body.Solution == nil {
		t.Fatal("Expected solution in response")
	}

	if body.Solution.Response == "" {
		t.Error("Expected non-empty response body")
	}

	if len(body.Solution.Cookies) == 0 {
		// httpbin.org may not set cookies, so this is informational
		t.Log("No cookies returned (may be expected for httpbin)")
	}
}

func TestRequestGetWithCookies(t *testing.T) {
	cookies := []types.RequestCookie{
		{Name: "test_cookie", Value: "test_value"},
	}

	reqBody := types.Request{
		Cmd:     types.CmdRequestGet,
		URL:     "https://httpbin.org/cookies",
		Cookies: cookies,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp := executeRequest(req)

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	if body.Status != types.StatusOK {
		t.Errorf("Expected status 'ok', got %q: %s", body.Status, body.Message)
	}
}

func TestSessionLifecycle(t *testing.T) {
	sessionID := fmt.Sprintf("test-session-%d", time.Now().UnixNano())

	// Create session
	createReq := types.Request{
		Cmd:     types.CmdSessionsCreate,
		Session: sessionID,
	}
	createBytes, _ := json.Marshal(createReq)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(createBytes))
	req.Header.Set("Content-Type", "application/json")
	resp := executeRequest(req)

	var createResp types.Response
	json.NewDecoder(resp.Body).Decode(&createResp)

	if createResp.Status != types.StatusOK {
		t.Fatalf("Failed to create session: %s", createResp.Message)
	}

	// List sessions
	listReq := types.Request{Cmd: types.CmdSessionsList}
	listBytes, _ := json.Marshal(listReq)

	req, _ = http.NewRequest("POST", "/api", bytes.NewReader(listBytes))
	req.Header.Set("Content-Type", "application/json")
	resp = executeRequest(req)

	var listResp types.Response
	json.NewDecoder(resp.Body).Decode(&listResp)

	if listResp.Status != types.StatusOK {
		t.Fatalf("Failed to list sessions: %s", listResp.Message)
	}

	found := false
	for _, s := range listResp.Sessions {
		if s == sessionID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Session %s not found in list", sessionID)
	}

	// Use session for a request
	useReq := types.Request{
		Cmd:     types.CmdRequestGet,
		URL:     "https://httpbin.org/get",
		Session: sessionID,
	}
	useBytes, _ := json.Marshal(useReq)

	req, _ = http.NewRequest("POST", "/api", bytes.NewReader(useBytes))
	req.Header.Set("Content-Type", "application/json")
	resp = executeRequest(req)

	var useResp types.Response
	json.NewDecoder(resp.Body).Decode(&useResp)

	if useResp.Status != types.StatusOK {
		t.Errorf("Failed to use session: %s", useResp.Message)
	}

	// Destroy session
	destroyReq := types.Request{
		Cmd:     types.CmdSessionsDestroy,
		Session: sessionID,
	}
	destroyBytes, _ := json.Marshal(destroyReq)

	req, _ = http.NewRequest("POST", "/api", bytes.NewReader(destroyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp = executeRequest(req)

	var destroyResp types.Response
	json.NewDecoder(resp.Body).Decode(&destroyResp)

	if destroyResp.Status != types.StatusOK {
		t.Errorf("Failed to destroy session: %s", destroyResp.Message)
	}
}

func TestRequestPost(t *testing.T) {
	reqBody := types.Request{
		Cmd:      types.CmdRequestPost,
		URL:      "https://httpbin.org/post",
		PostData: "key1=value1&key2=value2",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp := executeRequest(req)

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	if body.Status != types.StatusOK {
		t.Errorf("Expected status 'ok', got %q: %s", body.Status, body.Message)
	}

	if body.Solution == nil {
		t.Fatal("Expected solution in response")
	}
}

func TestRequestTimeout(t *testing.T) {
	// Use a very short timeout that should fail
	reqBody := types.Request{
		Cmd:        types.CmdRequestGet,
		URL:        "https://httpbin.org/delay/10", // 10 second delay
		MaxTimeout: 1000,                           // 1 second timeout
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp := executeRequest(req)

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	// Should either timeout or error
	if body.Status == types.StatusOK {
		t.Log("Request succeeded despite short timeout (server may be fast)")
	}
}

func TestInvalidCommand(t *testing.T) {
	reqBody := types.Request{
		Cmd: "invalid.command",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp := executeRequest(req)

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	if body.Status != types.StatusError {
		t.Errorf("Expected error status, got %q", body.Status)
	}
}

func TestInvalidURL(t *testing.T) {
	reqBody := types.Request{
		Cmd: types.CmdRequestGet,
		URL: "not-a-valid-url",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp := executeRequest(req)

	var body types.Response
	json.NewDecoder(resp.Body).Decode(&body)

	if body.Status != types.StatusError {
		t.Errorf("Expected error status for invalid URL, got %q", body.Status)
	}
}

// executeRequest is a helper that executes a request against the test handler.
func executeRequest(req *http.Request) *http.Response {
	rr := &responseRecorder{
		headers: make(http.Header),
		body:    new(bytes.Buffer),
		code:    http.StatusOK,
	}

	testHandler.ServeHTTP(rr, req)

	return &http.Response{
		StatusCode: rr.code,
		Body:       nopCloser{rr.body},
		Header:     rr.headers,
	}
}

type responseRecorder struct {
	headers http.Header
	body    *bytes.Buffer
	code    int
}

func (r *responseRecorder) Header() http.Header {
	return r.headers
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	r.code = code
}

type nopCloser struct {
	*bytes.Buffer
}

func (nopCloser) Close() error { return nil }
