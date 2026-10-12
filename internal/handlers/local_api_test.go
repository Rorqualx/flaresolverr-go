package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/solver"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
)

// strictHandler is mockHandler with the production default for content types.
func strictHandler() *Handler {
	h := mockHandler()
	h.config.StrictContentType = true
	return h
}

func TestContentTypeEnforcement(t *testing.T) {
	const body = `{"cmd":"sessions.list"}`

	tests := []struct {
		name        string
		contentType string
		setHeader   bool
		wantStatus  int
	}{
		{name: "application/json", contentType: "application/json", setHeader: true, wantStatus: http.StatusOK},
		{name: "with charset", contentType: "application/json; charset=utf-8", setHeader: true, wantStatus: http.StatusOK},
		{name: "mixed case with spacing", contentType: "Application/JSON ;charset=UTF-8", setHeader: true, wantStatus: http.StatusOK},
		{name: "missing header", setHeader: false, wantStatus: http.StatusUnsupportedMediaType},
		{name: "empty header", contentType: "", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "text/plain (no-preflight CSRF)", contentType: "text/plain", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "form (curl -d default)", contentType: "application/x-www-form-urlencoded", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "multipart", contentType: "multipart/form-data; boundary=x", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "json lookalike", contentType: "application/jsonp", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "json suffix type", contentType: "application/ld+json", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "text/json", contentType: "text/json", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
		{name: "malformed", contentType: "application/json; charset", setHeader: true, wantStatus: http.StatusUnsupportedMediaType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := strictHandler()
			defer h.sessions.Close()

			req := httptest.NewRequest(http.MethodPost, "/v1", bytes.NewBufferString(body))
			if tt.setHeader {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantStatus == http.StatusUnsupportedMediaType && !strings.Contains(w.Body.String(), "STRICT_CONTENT_TYPE") {
				t.Errorf("415 response does not mention the escape hatch: %s", w.Body.String())
			}
		})
	}
}

func TestContentTypeEnforcement_EscapeHatch(t *testing.T) {
	h := mockHandler() // StrictContentType false, as with STRICT_CONTENT_TYPE=false
	defer h.sessions.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1", bytes.NewBufferString(`{"cmd":"sessions.list"}`))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when strict content type is off", w.Code)
	}
}

// TestContentTypeNotRequiredForGets verifies the check applies to the API
// endpoint only: health checks send no body and no content type.
func TestContentTypeNotRequiredForGets(t *testing.T) {
	for _, path := range []string{"/health", "/stats", "/docs"} {
		t.Run(path, func(t *testing.T) {
			h := strictHandler()
			defer h.sessions.Close()

			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusOK {
				t.Errorf("GET %s status = %d, want 200", path, w.Code)
			}
		})
	}
}

// TestHealthOmitsUsageDetails verifies the unauthenticated /health endpoint
// does not reveal which sites the server has been used for, and that the
// details are still available on /stats.
func TestHealthOmitsUsageDetails(t *testing.T) {
	h := strictHandler()
	defer h.sessions.Close()
	h.domainStats = stats.NewManager()
	h.domainStats.RecordRequest("private-tracker.example", 1234, true, false)

	get := func(path string) map[string]json.RawMessage {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, w.Code)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
			t.Fatalf("GET %s: invalid JSON: %v", path, err)
		}
		if strings.Contains(w.Body.String(), "private-tracker.example") != (path == "/stats") {
			t.Errorf("GET %s: domain name presence is wrong: %s", path, w.Body.String())
		}
		return fields
	}

	health := get("/health")
	for _, field := range []string{"domainStats", "defaults", "selectorsStats"} {
		if _, present := health[field]; present {
			t.Errorf("/health exposes %q", field)
		}
	}
	for _, field := range []string{"status", "message", "version", "userAgent"} {
		if _, present := health[field]; !present {
			t.Errorf("/health is missing %q", field)
		}
	}

	statsFields := get("/stats")
	for _, field := range []string{"status", "version", "domainStats", "defaults"} {
		if _, present := statsFields[field]; !present {
			t.Errorf("/stats is missing %q", field)
		}
	}
}

func TestSanitizeURLForLogging(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		want        string
		mustNotHave []string
	}{
		{name: "empty", in: "", want: ""},
		{name: "plain URL unchanged", in: "https://example.com/path", want: "https://example.com/path"},
		{name: "harmless query unchanged", in: "https://example.com/p?q=1&page=2", want: "https://example.com/p?q=1&page=2"},
		{name: "userinfo stripped", in: "https://user:hunter2@example.com/path", want: "https://example.com/path", mustNotHave: []string{"user", "hunter2", "@"}},
		{name: "username only stripped", in: "https://user@example.com/", want: "https://example.com/", mustNotHave: []string{"user@"}},
		{name: "userinfo stripped with harmless query", in: "http://u:p@example.com/a?x=1", want: "http://example.com/a?x=1", mustNotHave: []string{"u:p"}},
		{name: "userinfo and secret query", in: "http://u:p@example.com/a?token=abc", mustNotHave: []string{"u:p", "abc"}},
		{name: "secret query redacted", in: "https://example.com/a?api_key=abc123", mustNotHave: []string{"abc123"}},
		{name: "unparsable", in: "http://[::1", want: "[invalid-url]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeURLForLogging(tt.in)
			if tt.want != "" && got != tt.want {
				t.Errorf("sanitizeURLForLogging(%q) = %q, want %q", tt.in, got, tt.want)
			}
			for _, secret := range tt.mustNotHave {
				if strings.Contains(got, secret) {
					t.Errorf("sanitizeURLForLogging(%q) = %q, still contains %q", tt.in, got, secret)
				}
			}
		})
	}
}

// TestRequestDeadlineFitsServerWriteTimeout pins the relationship main.go
// relies on: the handler must give up before the server's write timeout
// (MaxTimeout + bypass + pool wait + 10s), or the response is never delivered.
func TestRequestDeadlineFitsServerWriteTimeout(t *testing.T) {
	h := mockHandler()
	defer h.sessions.Close()
	h.config.BrowserPoolTimeout = 30 * time.Second

	for _, timeout := range []time.Duration{time.Second, h.config.DefaultTimeout, h.config.MaxTimeout} {
		got := h.requestDeadline(timeout)
		writeTimeout := h.config.MaxTimeout + solver.ReconnectBypassBudget + h.config.BrowserPoolTimeout + 10*time.Second

		if got <= timeout+solver.ReconnectBypassBudget {
			t.Errorf("requestDeadline(%v) = %v, leaves no room for the solve plus the bypass", timeout, got)
		}
		if got >= writeTimeout {
			t.Errorf("requestDeadline(%v) = %v, not below the server write timeout %v", timeout, got, writeTimeout)
		}
	}
}
