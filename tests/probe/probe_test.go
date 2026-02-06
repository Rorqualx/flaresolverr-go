// Package probe provides comprehensive test utilities and common fixtures
// for validating all sections of the FlareSolverr application.
package probe

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// skipCI skips browser tests in CI/short mode.
// Browser tests require a real Chrome/Chromium installation.
func skipCI(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping browser test in short mode (-short flag)")
	}
}

// assertEventually retries an assertion until it passes or times out.
// This is useful for testing asynchronous operations.
func assertEventually(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("assertion failed after %v: %s", timeout, msg)
		}
		<-ticker.C
	}
}

// startTestServer starts a local HTTP server for isolated testing.
// It provides several endpoints useful for testing the solver.
func startTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Simple HTML page
	mux.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Test Page</title></head><body>Test Content</body></html>"))
	})

	// Set cookies endpoint
	mux.HandleFunc("/cookies/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "test_cookie",
			Value: "test_value",
			Path:  "/",
		})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Cookie Set</body></html>"))
	})

	// POST echo endpoint
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"method":      r.Method,
			"data":        string(body),
			"contentType": r.Header.Get("Content-Type"),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Slow endpoint for timeout testing
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		case <-r.Context().Done():
			// Request was canceled
			return
		}
	})

	// Large response endpoint
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>"))
		// Write ~15MB of content
		for i := 0; i < 15*1024*1024; i++ {
			_, _ = w.Write([]byte("X"))
		}
		_, _ = w.Write([]byte("</body></html>"))
	})

	// Status code endpoints
	mux.HandleFunc("/status/200", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	mux.HandleFunc("/status/403", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
	})

	mux.HandleFunc("/status/429", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("Too Many Requests"))
	})

	// Redirect endpoint
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/html", http.StatusFound)
	})

	// Echo headers endpoint
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		headers := make(map[string]string)
		for key := range r.Header {
			headers[key] = r.Header.Get(key)
		}
		_ = json.NewEncoder(w).Encode(headers)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}
