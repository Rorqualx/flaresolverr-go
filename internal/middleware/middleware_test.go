package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

	// Use empty config for wildcard CORS (backward compatible)
	handler := CORS(CORSConfig{})(innerHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Missing Access-Control-Allow-Origin header")
	}

	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Missing Access-Control-Allow-Methods header")
	}

	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("Missing Access-Control-Allow-Headers header")
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
