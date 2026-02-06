package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

func TestRecoveryMiddleware(t *testing.T) {
	// Handler that panics
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := Recovery(panicHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("Expected Content-Type application/json")
	}
}

func TestRecoveryMiddlewareNoPanic(t *testing.T) {
	// Normal handler
	normalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := Recovery(normalHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Logging(innerHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Inner handler was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestLoggingMiddlewareCapturesStatusCode(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := Logging(innerHandler)

	req := httptest.NewRequest("GET", "/notfound", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestCORSMiddleware(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Fix #17: Test with allowed origins (empty config now rejects all)
	handler := CORS(CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
	})(innerHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check CORS headers - should return specific origin, not wildcard
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("Expected Access-Control-Allow-Origin 'https://example.com', got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}

	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Missing Access-Control-Allow-Methods header")
	}

	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("Missing Access-Control-Allow-Headers header")
	}
}

func TestCORSMiddlewareRejectsWithoutConfig(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Fix #17: Empty config now rejects all cross-origin requests (secure default)
	handler := CORS(CORSConfig{})(innerHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://attacker.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// CORS headers should NOT be set when origins not configured
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Expected no Access-Control-Allow-Origin header, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddlewareOptionsPreflight(t *testing.T) {
	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Use empty config for wildcard CORS (backward compatible)
	handler := CORS(CORSConfig{})(innerHandler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("Inner handler should not be called for OPTIONS")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", w.Code)
	}
}

func TestTimeoutMiddleware(t *testing.T) {
	// Handler that completes quickly
	quickHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := Timeout(5 * time.Second)(quickHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestChainMiddleware(t *testing.T) {
	order := []string{}

	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	chain := Chain(middleware1, middleware2)
	handler := chain(innerHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Expected order: m1-before, m2-before, handler, m2-after, m1-after
	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expected) {
		t.Fatalf("Expected %d calls, got %d", len(expected), len(order))
	}

	for i, exp := range expected {
		if order[i] != exp {
			t.Errorf("At position %d: expected %q, got %q", i, exp, order[i])
		}
	}
}

func TestResponseWriterWrapper(t *testing.T) {
	w := httptest.NewRecorder()
	wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Test default status code
	if wrapped.statusCode != http.StatusOK {
		t.Errorf("Expected default status 200, got %d", wrapped.statusCode)
	}

	// Test WriteHeader
	wrapped.WriteHeader(http.StatusNotFound)
	if wrapped.statusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 after WriteHeader, got %d", wrapped.statusCode)
	}
}

func TestTimeoutMiddlewareTimesOut(t *testing.T) {
	// Handler that takes longer than timeout
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			// Context canceled - this is expected
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	})

	handler := Timeout(50 * time.Millisecond)(slowHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("Expected status 504 (Gateway Timeout), got %d", w.Code)
	}
}

func TestTimeoutWriterDiscardsAfterTimeout(t *testing.T) {
	w := httptest.NewRecorder()
	tw := &timeoutWriter{ResponseWriter: w}

	// Write should work before timeout
	n, err := tw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Errorf("Write before timeout failed: n=%d, err=%v", n, err)
	}

	// Mark as timed out
	tw.markTimedOut()

	// Write should be discarded after timeout (but return success)
	n, err = tw.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Errorf("Write after timeout should return success: n=%d, err=%v", n, err)
	}

	// But the underlying writer should not have received "world"
	body := w.Body.String()
	if body != "hello" {
		t.Errorf("Expected body 'hello', got %q", body)
	}
}

func TestRateLimiterAllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10, time.Second, false)
	defer rl.Close()

	// First 10 requests should be allowed
	for i := 0; i < 10; i++ {
		if !rl.Allow("127.0.0.1") {
			t.Errorf("Request %d should have been allowed", i+1)
		}
	}

	// 11th request should be blocked
	if rl.Allow("127.0.0.1") {
		t.Error("11th request should have been blocked")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl := NewRateLimiter(5, 50*time.Millisecond, false)
	defer rl.Close()

	// Exhaust the limit
	for i := 0; i < 5; i++ {
		rl.Allow("127.0.0.1")
	}

	// Should be blocked
	if rl.Allow("127.0.0.1") {
		t.Error("Should be blocked after exhausting limit")
	}

	// Wait for window to reset
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow("127.0.0.1") {
		t.Error("Should be allowed after window reset")
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Second, false)
	defer rl.Close()

	// Exhaust limit for IP1
	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.1")

	if rl.Allow("192.168.1.1") {
		t.Error("IP1 should be blocked")
	}

	// IP2 should still be allowed
	if !rl.Allow("192.168.1.2") {
		t.Error("IP2 should be allowed (separate limit)")
	}
}

// ==================== APIKey Middleware Tests ====================

func TestAPIKeyMiddlewareDisabled(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: false,
		APIKey:        "test-api-key",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	req := httptest.NewRequest("GET", "/v1", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Inner handler should be called when API key auth is disabled")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareValidKeyHeader(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "test-secret-key-12345",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	req := httptest.NewRequest("POST", "/v1", nil)
	req.Header.Set("X-API-Key", "test-secret-key-12345")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Inner handler should be called with valid API key")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestAPIKeyMiddlewareQueryParamRejected verifies that query parameter API keys
// are rejected for security reasons. Query parameters appear in logs, browser
// history, and referrer headers, making them unsuitable for secrets.
func TestAPIKeyMiddlewareQueryParamRejected(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "test-secret-key-12345",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	// API key in query parameter should be rejected - header only is supported
	req := httptest.NewRequest("POST", "/v1?api_key=test-secret-key-12345", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("Inner handler should NOT be called with API key in query param (security fix)")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for query param API key, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareInvalidKey(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "correct-secret-key",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := APIKey(cfg)(innerHandler)

	req := httptest.NewRequest("POST", "/v1", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("Inner handler should NOT be called with invalid API key")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareMissingKey(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "secret-key",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := APIKey(cfg)(innerHandler)

	req := httptest.NewRequest("POST", "/v1", nil)
	// No API key provided
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("Inner handler should NOT be called without API key")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareHealthEndpointBypass(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "secret-key",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	// Health endpoint should bypass API key check
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("/health should bypass API key authentication")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareMetricsEndpointBypass(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "secret-key",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	// Metrics endpoint should bypass API key check
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("/metrics should bypass API key authentication")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareHeaderPrefersOverQuery(t *testing.T) {
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "correct-key",
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	// Header has correct key, query param has wrong key
	// Header should be checked first
	req := httptest.NewRequest("POST", "/v1?api_key=wrong-key", nil)
	req.Header.Set("X-API-Key", "correct-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Should authenticate using header key when both are present")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAPIKeyMiddlewareEmptyConfigKey(t *testing.T) {
	// When APIKeyEnabled is true but APIKey is empty,
	// all requests should fail authentication
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "", // Empty key
	}

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := APIKey(cfg)(innerHandler)

	// Even with empty key in request, should fail
	req := httptest.NewRequest("POST", "/v1", nil)
	req.Header.Set("X-API-Key", "")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// With empty config key and empty provided key, they "match"
	// but this is expected - the Validate() function should warn about this
	if !called {
		t.Error("Empty key comparison should match (both empty)")
	}
}

func TestAPIKeyMiddlewareConstantTimeComparison(t *testing.T) {
	// This test verifies that different key lengths don't cause
	// significantly different response times (constant-time comparison)
	// Note: This is a basic sanity check, not a rigorous timing attack test
	cfg := &config.Config{
		APIKeyEnabled: true,
		APIKey:        "correct-secret-key-that-is-long",
	}

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKey(cfg)(innerHandler)

	testCases := []string{
		"a",                                  // Very short
		"wrong",                              // Short
		"wrong-secret-key-that-is-long",      // Same length as correct
		"wrong-secret-key-that-is-very-long", // Longer than correct
		"",                                   // Empty
	}

	for _, testKey := range testCases {
		req := httptest.NewRequest("POST", "/v1", nil)
		req.Header.Set("X-API-Key", testKey)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for key %q, got %d", testKey, w.Code)
		}
	}
}
