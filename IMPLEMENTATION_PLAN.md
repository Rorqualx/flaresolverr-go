# FlareSolverr Go - Remaining Implementation Plan

## Overview
This document outlines the implementation plan for features not yet completed in the Go rewrite.

---

## 1. POST Request with Form Data

### Current State
- `handleRequestPost` just calls `handleRequestGet`
- No actual form data submission

### Implementation

**File:** `internal/solver/solver.go`

```go
// Add new method to Solver
func (s *Solver) SolvePost(ctx context.Context, url string, postData string, timeout time.Duration) (*Result, error)
```

**Steps:**
1. Add `SolvePost` method to solver that:
   - Acquires browser from pool
   - Creates page with stealth patches
   - Uses CDP to intercept the navigation and convert to POST
   - Alternatively: inject a form and submit it programmatically

2. Update `internal/handlers/handlers.go`:
```go
func (h *Handler) handleRequestPost(w http.ResponseWriter, ctx context.Context, req *types.Request, startTime time.Time) {
    if req.URL == "" {
        h.writeError(w, "url is required", startTime)
        return
    }
    if req.PostData == "" {
        h.writeError(w, "postData is required for POST requests", startTime)
        return
    }
    // Call solver.SolvePost instead of Solve
}
```

3. POST submission via JavaScript injection:
```go
const postScript = `
(function(url, data) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = url;

    // Parse postData (assume URL-encoded)
    const params = new URLSearchParams(data);
    for (const [key, value] of params) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = value;
        form.appendChild(input);
    }

    document.body.appendChild(form);
    form.submit();
})(%q, %q);
`
```

---

## 2. Proxy Support

### Current State
- Config has `ProxyURL`, `ProxyUsername`, `ProxyPassword`
- Request has `Proxy` field
- Not wired into browser launcher

### Implementation

**File:** `internal/browser/pool.go`

**Steps:**
1. Modify `createLauncher()` to accept proxy config:
```go
func (p *Pool) createLauncher(proxy *ProxyConfig) *launcher.Launcher {
    l := launcher.New()
    // ... existing flags ...

    if proxy != nil && proxy.URL != "" {
        l = l.Set("proxy-server", proxy.URL)
    }

    return l
}
```

2. For per-request proxy, need to handle at page level via CDP:
```go
// internal/browser/proxy.go
package browser

import (
    "github.com/go-rod/rod"
    "github.com/go-rod/rod/lib/proto"
)

// ProxyConfig holds proxy settings
type ProxyConfig struct {
    URL      string
    Username string
    Password string
}

// SetPageProxy configures proxy authentication for a page
func SetPageProxy(page *rod.Page, proxy *ProxyConfig) error {
    if proxy == nil || proxy.URL == "" {
        return nil
    }

    // Enable fetch for authentication
    if proxy.Username != "" {
        go page.EachEvent(func(e *proto.FetchAuthRequired) {
            _ = proto.FetchContinueWithAuth{
                RequestID: e.RequestID,
                AuthChallengeResponse: &proto.FetchAuthChallengeResponse{
                    Response: proto.FetchAuthChallengeResponseResponseProvideCredentials,
                    Username: proxy.Username,
                    Password: proxy.Password,
                },
            }.Call(page)
        })()

        _ = proto.FetchEnable{
            HandleAuthRequests: true,
        }.Call(page)
    }

    return nil
}
```

3. Update solver to use proxy:
```go
// In Solve method
if req.Proxy != nil {
    browser.SetPageProxy(page, &browser.ProxyConfig{
        URL:      req.Proxy.URL,
        Username: req.Proxy.Username,
        Password: req.Proxy.Password,
    })
}
```

---

## 3. Cookie Injection

### Current State
- Request has `Cookies` field (type `[]any`)
- Cookies not applied before navigation

### Implementation

**File:** `internal/types/api.go`

1. Define proper cookie input type:
```go
// RequestCookie represents a cookie in the request
type RequestCookie struct {
    Name   string `json:"name"`
    Value  string `json:"value"`
    Domain string `json:"domain,omitempty"`
    Path   string `json:"path,omitempty"`
}
```

2. Update Request struct:
```go
type Request struct {
    // ... existing fields ...
    Cookies []RequestCookie `json:"cookies,omitempty"`
}
```

**File:** `internal/solver/solver.go`

3. Add cookie injection before navigation:
```go
func (s *Solver) applyCookies(page *rod.Page, cookies []types.RequestCookie, domain string) error {
    if len(cookies) == 0 {
        return nil
    }

    cdpCookies := make([]*proto.NetworkCookieParam, 0, len(cookies))
    for _, c := range cookies {
        cookieDomain := c.Domain
        if cookieDomain == "" {
            // Extract domain from URL
            cookieDomain = domain
        }

        cdpCookies = append(cdpCookies, &proto.NetworkCookieParam{
            Name:   c.Name,
            Value:  c.Value,
            Domain: cookieDomain,
            Path:   c.Path,
        })
    }

    return page.SetCookies(cdpCookies)
}
```

4. Call in Solve method before navigation:
```go
// After page creation, before Navigate
if err := s.applyCookies(page, req.Cookies, extractDomain(url)); err != nil {
    log.Warn().Err(err).Msg("Failed to set cookies")
}
```

---

## 4. Prometheus Metrics

### Current State
- Config has `PrometheusEnabled` and `PrometheusPort`
- No metrics endpoint

### Implementation

**File:** `internal/metrics/metrics.go` (new)

```go
package metrics

import (
    "net/http"
    "sync/atomic"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    RequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "flaresolverr_requests_total",
            Help: "Total number of requests processed",
        },
        []string{"command", "status"},
    )

    RequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "flaresolverr_request_duration_seconds",
            Help:    "Request duration in seconds",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"command"},
    )

    BrowserPoolSize = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "flaresolverr_browser_pool_size",
            Help: "Current browser pool size",
        },
    )

    BrowserPoolAvailable = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "flaresolverr_browser_pool_available",
            Help: "Available browsers in pool",
        },
    )

    ActiveSessions = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "flaresolverr_active_sessions",
            Help: "Number of active sessions",
        },
    )

    ChallengesSolved = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "flaresolverr_challenges_solved_total",
            Help: "Total challenges solved by type",
        },
        []string{"type"},
    )

    MemoryUsageBytes = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "flaresolverr_memory_usage_bytes",
            Help: "Current memory usage in bytes",
        },
    )
)

func init() {
    prometheus.MustRegister(
        RequestsTotal,
        RequestDuration,
        BrowserPoolSize,
        BrowserPoolAvailable,
        ActiveSessions,
        ChallengesSolved,
        MemoryUsageBytes,
    )
}

// Handler returns the Prometheus HTTP handler
func Handler() http.Handler {
    return promhttp.Handler()
}
```

**File:** `cmd/flaresolverr/main.go`

Add metrics server startup:
```go
// Start metrics server if enabled
if cfg.PrometheusEnabled {
    go func() {
        metricsAddr := fmt.Sprintf(":%d", cfg.PrometheusPort)
        metricsMux := http.NewServeMux()
        metricsMux.Handle("/metrics", metrics.Handler())

        log.Info().
            Int("port", cfg.PrometheusPort).
            Msg("Starting Prometheus metrics server")

        if err := http.ListenAndServe(metricsAddr, metricsMux); err != nil {
            log.Error().Err(err).Msg("Metrics server failed")
        }
    }()
}
```

**File:** `internal/handlers/handlers.go`

Add metrics instrumentation:
```go
import "github.com/Rorqualx/flaresolverr-go/internal/metrics"

// In ServeHTTP
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    startTime := time.Now()
    // ... handle request ...

    // Record metrics at end
    duration := time.Since(startTime).Seconds()
    metrics.RequestDuration.WithLabelValues(req.Cmd).Observe(duration)
    metrics.RequestsTotal.WithLabelValues(req.Cmd, status).Inc()
}
```

**go.mod addition:**
```
require github.com/prometheus/client_golang v1.18.0
```

---

## 5. Comprehensive Test Coverage

### Current State
- Basic tests for pool and session
- No integration tests
- No solver tests

### Implementation

**File:** `internal/solver/solver_test.go` (new)

```go
package solver

import (
    "testing"
)

func TestDetectChallenge(t *testing.T) {
    s := &Solver{}

    tests := []struct {
        name     string
        html     string
        expected ChallengeType
    }{
        {
            name:     "no challenge",
            html:     "<html><body>Normal content</body></html>",
            expected: ChallengeNone,
        },
        {
            name:     "js challenge - just a moment",
            html:     "<html><body>Just a moment... Checking your browser</body></html>",
            expected: ChallengeJavaScript,
        },
        {
            name:     "turnstile challenge",
            html:     "<html><body><div class=\"cf-turnstile\"></div></body></html>",
            expected: ChallengeTurnstile,
        },
        {
            name:     "access denied",
            html:     "<html><body>Access denied Cloudflare Ray ID: abc123</body></html>",
            expected: ChallengeAccessDenied,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := s.detectChallenge(tt.html)
            if got != tt.expected {
                t.Errorf("detectChallenge() = %v, want %v", got, tt.expected)
            }
        })
    }
}
```

**File:** `internal/handlers/handlers_test.go` (new)

```go
package handlers

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestHealthEndpoint(t *testing.T) {
    // Create mock handler (without real browser pool)
    handler := &Handler{}

    req := httptest.NewRequest("GET", "/health", nil)
    w := httptest.NewRecorder()

    handler.handleHealth(w, time.Now())

    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }

    var resp types.Response
    if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
        t.Fatalf("Failed to unmarshal response: %v", err)
    }

    if resp.Status != types.StatusOK {
        t.Errorf("Expected status ok, got %s", resp.Status)
    }
}

func TestInvalidCommand(t *testing.T) {
    handler := &Handler{}

    reqBody := types.Request{Cmd: "invalid.command"}
    body, _ := json.Marshal(reqBody)

    req := httptest.NewRequest("POST", "/v1", bytes.NewReader(body))
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    var resp types.Response
    json.Unmarshal(w.Body.Bytes(), &resp)

    if resp.Status != types.StatusError {
        t.Errorf("Expected error status for invalid command")
    }
}
```

**File:** `internal/config/config_test.go` (new)

```go
package config

import (
    "os"
    "testing"
    "time"
)

func TestLoadDefaults(t *testing.T) {
    cfg := Load()

    if cfg.Port != 8191 {
        t.Errorf("Expected default port 8191, got %d", cfg.Port)
    }

    if cfg.BrowserPoolSize != 3 {
        t.Errorf("Expected default pool size 3, got %d", cfg.BrowserPoolSize)
    }

    if !cfg.Headless {
        t.Error("Expected headless to be true by default")
    }
}

func TestLoadFromEnv(t *testing.T) {
    os.Setenv("PORT", "9999")
    os.Setenv("BROWSER_POOL_SIZE", "5")
    os.Setenv("HEADLESS", "false")
    defer func() {
        os.Unsetenv("PORT")
        os.Unsetenv("BROWSER_POOL_SIZE")
        os.Unsetenv("HEADLESS")
    }()

    cfg := Load()

    if cfg.Port != 9999 {
        t.Errorf("Expected port 9999 from env, got %d", cfg.Port)
    }

    if cfg.BrowserPoolSize != 5 {
        t.Errorf("Expected pool size 5 from env, got %d", cfg.BrowserPoolSize)
    }

    if cfg.Headless {
        t.Error("Expected headless false from env")
    }
}
```

---

## Implementation Order

1. **Cookie Injection** (30 min) - Simple, enables more test scenarios
2. **Proxy Support** (1 hr) - Important for real-world usage
3. **POST with Form Data** (1 hr) - Completes API compatibility
4. **Prometheus Metrics** (1 hr) - Production monitoring
5. **Comprehensive Tests** (2 hr) - Quality assurance

## Dependencies to Add

```go
// go.mod additions
require (
    github.com/prometheus/client_golang v1.18.0
)
```

---

## Testing the Complete Implementation

```bash
# Run all tests
go test -v ./...

# Run with race detection
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Integration test (requires Chrome)
go test -v ./internal/browser/... ./internal/solver/...

# Build and run
go build -o bin/flaresolverr ./cmd/flaresolverr
./bin/flaresolverr

# Test API
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd": "request.get", "url": "https://example.com"}'
```
