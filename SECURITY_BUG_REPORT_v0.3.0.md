# FlareSolverr v0.3.0 Security & Bug Fix Report

## Executive Summary

This release addresses **7 security vulnerabilities** (1 critical, 4 high, 2 medium) and adds **4 new features** for enhanced debugging and authentication.

---

## Security Vulnerabilities Fixed

### CRITICAL

#### 1. JavaScript Injection in Proxy Extension (CVE-like severity: 9.8)
**File:** `internal/browser/proxy_extension.go`
**Lines:** 102-159 (MV3), 256-309 (MV2)

**Vulnerability:** Proxy credentials were embedded in JavaScript using `fmt.Sprintf` without escaping. A malicious proxy URL with crafted credentials could inject arbitrary JavaScript into the browser extension.

**Attack Vector:**
```
Proxy password: "; alert('XSS'); //
```

**Fix:** Use `json.Marshal` for all credential values before embedding in JavaScript.

```go
// Before (VULNERABLE)
script := fmt.Sprintf(`username: "%s", password: "%s"`, e.username, e.password)

// After (SAFE)
usernameJSON, _ := json.Marshal(e.username)
passwordJSON, _ := json.Marshal(e.password)
script := fmt.Sprintf(`username: %s, password: %s`, usernameJSON, passwordJSON)
```

---

### HIGH

#### 2. Metrics Registration Panic
**File:** `internal/metrics/metrics.go`
**Lines:** 130-149

**Bug:** `prometheus.MustRegister()` panics if metrics are already registered. This causes crashes during tests or if the package is imported multiple times.

**Fix:** Wrap registration in `sync.Once`:
```go
var registerOnce sync.Once

func init() {
    registerOnce.Do(func() {
        prometheus.MustRegister(...)
    })
}
```

#### 3. TOCTOU Race Condition in Session Page Access
**File:** `internal/session/session.go`
**Lines:** 336-365

**Bug:** `sess.Page` was checked for nil and then used, but could become nil between check and use (Time-of-Check to Time-of-Use race).

**Fix:** Added `SafeGetPage()` method that atomically returns page reference under mutex:
```go
func (s *Session) SafeGetPage() *rod.Page {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.Page
}
```

**File:** `internal/handlers/handlers.go`
**Lines:** 469-477

Updated to use `SafeGetPage()` instead of direct access.

#### 4. Header Access Race in Timeout Middleware
**File:** `internal/middleware/timeout.go`
**Lines:** 43-51

**Bug:** `Header()` returned unprotected reference to underlying headers map, allowing concurrent access from handler and timeout goroutines.

**Fix:** Added mutex synchronization:
```go
func (tw *timeoutWriter) Header() http.Header {
    tw.mu.Lock()
    defer tw.mu.Unlock()
    return tw.ResponseWriter.Header()
}
```

#### 5. Missing Context Cancellation in Browser Pool
**File:** `internal/browser/pool.go`
**Lines:** 248-261, 506-514

**Bug:** `spawnBrowser()` didn't accept context, preventing cancellation during shutdown.

**Fix:** Added context parameter with cancellation check:
```go
func (p *Pool) spawnBrowser(ctx context.Context) (*rod.Browser, error) {
    if ctx != nil {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }
    }
    // ... spawn browser
}
```

---

### MEDIUM

#### 6. ReDoS Vulnerability in Rate Limit Detector
**File:** `internal/ratelimit/detector.go`
**Lines:** 9-11, 42-140, 145-151

**Bug:** Regex patterns using `.{0,N}` could cause catastrophic backtracking with crafted input.

**Fix:**
1. Changed patterns from `.{0,N}` to `[^<]{0,N}` (excludes HTML tags)
2. Added 100KB body size limit before regex matching:
```go
const maxBodyLenForRegex = 100 * 1024

func Detect(statusCode int, body string) Info {
    if len(body) > maxBodyLenForRegex {
        body = body[:maxBodyLenForRegex]
    }
    // ...
}
```

#### 7. Port Conflict Validation
**File:** `internal/config/config.go`
**Lines:** 221-252

**Bug:** No validation for conflicting ports between main server, Prometheus, and pprof.

**Fix:** Added port conflict detection with auto-adjustment:
```go
usedPorts := make(map[int]string)
if c.Port > 0 {
    usedPorts[c.Port] = "PORT"
}
if c.PrometheusEnabled {
    if _, exists := usedPorts[c.PrometheusPort]; exists {
        // Auto-adjust to next available port
    }
}
```

---

## Bug Fixes

### 1. Improved Stealth Error Handling
**File:** `internal/browser/stealth.go`
**Lines:** 15-50

**Bug:** Stealth script errors were silently swallowed, hiding critical issues.

**Fix:** Return errors for critical failures (SyntaxError, ReferenceError), log warnings for non-critical:
```go
if strings.Contains(errStr, "SyntaxError") {
    return fmt.Errorf("stealth script syntax error: %w", err)
}
```

### 2. Cookie Error Propagation
**File:** `internal/solver/solver.go`
**Lines:** 44, 791-802, 858-859

**Bug:** Cookie retrieval errors weren't exposed to API consumers.

**Fix:** Added `CookieError` field to Result struct and API response.

### 3. Unbounded Domain Stats Growth
**File:** `internal/stats/domain_stats.go`
**Lines:** 11-12, 31, 184-222

**Bug:** Domain statistics map could grow unboundedly, causing memory exhaustion.

**Fix:** Added LRU eviction with 10,000 domain limit:
```go
const maxDomains = 10000

func (m *Manager) getOrCreate(domain string) *DomainStats {
    if len(m.domains) >= maxDomains {
        m.evictOldestLocked()
    }
    // ...
}
```

---

## New Features

### 1. API Key Authentication
**Files:**
- `internal/config/config.go` (lines 64-66, 121-123, 254-260)
- `internal/middleware/apikey.go` (new file, 45 lines)

**Environment Variables:**
- `API_KEY_ENABLED` - Enable authentication (default: false)
- `API_KEY` - Required key (recommended: 16+ characters)

**Usage:**
```bash
curl -H "X-API-Key: your-key" http://localhost:8191/v1 ...
# or
curl "http://localhost:8191/v1?api_key=your-key" ...
```

### 2. Extended Browser State Extraction
**File:** `internal/solver/solver.go`
**Lines:** 50-53, 823-828, 864-866, 900-1043

**New extraction functions:**
- `extractLocalStorage()` - All localStorage key-value pairs
- `extractSessionStorage()` - All sessionStorage key-value pairs
- `extractResponseHeaders()` - Cloudflare metadata from page

**API Response:**
```json
{
  "solution": {
    "localStorage": {"key": "value"},
    "sessionStorage": {"key": "value"},
    "responseHeaders": {"cf-ray": "abc123"}
  }
}
```

### 3. Response Metadata Fields
**Files:**
- `internal/types/api.go` (lines 60-63, 65-67)
- `internal/handlers/handlers.go` (lines 616-618, 621-628)

**New fields:**
- `responseTruncated` - True if HTML was truncated (10MB limit)
- `cookieError` - Error message if cookies couldn't be retrieved
- `localStorage` - Browser localStorage contents
- `sessionStorage` - Browser sessionStorage contents
- `responseHeaders` - Extracted response metadata

### 4. Session Page Nil Error Type
**File:** `internal/types/errors.go`
**Line:** 21

```go
ErrSessionPageNil = errors.New("session page is nil or has been closed")
```

---

## Code Changes Summary

| File | Lines Changed | Type |
|------|---------------|------|
| `internal/browser/proxy_extension.go` | +60 | Security fix |
| `internal/metrics/metrics.go` | +8 | Bug fix |
| `internal/session/session.go` | +17 | Security fix |
| `internal/handlers/handlers.go` | +17 | Feature + fix |
| `internal/middleware/timeout.go` | +4 | Security fix |
| `internal/middleware/apikey.go` | +45 (new) | Feature |
| `internal/browser/pool.go` | +19 | Security fix |
| `internal/stats/domain_stats.go` | +33 | Bug fix |
| `internal/config/config.go` | +49 | Feature + fix |
| `internal/ratelimit/detector.go` | +20 | Security fix |
| `internal/browser/stealth.go` | +15 | Bug fix |
| `internal/solver/solver.go` | +150 | Feature |
| `internal/types/api.go` | +7 | Feature |
| `internal/types/errors.go` | +1 | Feature |
| `CHANGELOG.md` | +20 | Documentation |
| `README.md` | +35 | Documentation |

**Total: 16 files changed, ~475 lines added**

---

## Testing Verification

### Automated Tests
- All existing tests pass
- Race detector (`go test -race`) passes
- No data races detected

### Manual Testing Required
1. API key authentication flow
2. ComicVine/nowsecure localStorage extraction
3. Port conflict auto-adjustment
4. Proxy with special characters in credentials

---

## Deployment Notes

### Breaking Changes
None - all changes are backward compatible.

### New Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY_ENABLED` | `false` | Enable API key auth |
| `API_KEY` | (none) | Required API key |

### Upgrade Path
1. Stop existing container
2. Pull new image
3. Optionally configure API key
4. Start new container

---

## Contributors
- Security fixes and features implemented with Claude Opus 4.5

## Version
- **Version:** 0.3.0
- **Date:** 2025-01-17
- **Git Tag:** v0.3.0
