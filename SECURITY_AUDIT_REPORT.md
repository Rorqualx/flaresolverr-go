# Security Audit Report - FlareSolverr Go

**Date:** 2026-01-15
**Auditor:** Claude Security Analysis
**Scope:** Full codebase security review

---

## Executive Summary

This security audit identified **8 vulnerabilities** across the FlareSolverr Go codebase:
- **2 HIGH** severity issues
- **3 MEDIUM** severity issues
- **3 LOW** severity issues

The most critical findings relate to SSRF bypass techniques and credential exposure in proxy extensions.

---

## Findings

### 1. SSRF URL Validation Bypasses [HIGH]

**File:** `internal/security/url_validator.go`

**Description:** The URL validation can be bypassed using several techniques:

#### 1.1 IP Encoding Bypasses
The validator checks for literal IP strings but doesn't handle alternative IP encodings:

```go
// Current check (vulnerable)
ip := net.ParseIP(hostname)

// Bypasses not handled:
// - Decimal IP: 2130706433 (equivalent to 127.0.0.1)
// - Octal IP: 0177.0.0.1 (equivalent to 127.0.0.1)
// - Hex IP: 0x7f000001 (equivalent to 127.0.0.1)
// - Mixed encoding: 127.0.0x1
```

**Proof of Concept:**
```
http://2130706433/  → Resolves to 127.0.0.1
http://0177.0.0.1/  → Resolves to 127.0.0.1 (some parsers)
http://0x7f.0.0.1/  → Resolves to 127.0.0.1
```

#### 1.2 Incomplete Loopback Range Check
Only specific localhost strings are blocked, not the entire 127.0.0.0/8 range:

```go
// Current: Only blocks specific strings
localHostnames := []string{
    "localhost",
    "127.0.0.1",
    // Missing: 127.0.0.2-127.255.255.254
}
```

**Bypasses:**
- `http://127.0.0.2/` - Valid loopback, not blocked
- `http://127.1/` - Shortened form, resolves to 127.0.0.1
- `http://127.1.1.1/` - Alternative loopback

#### 1.3 IPv4-Mapped IPv6 Addresses
Missing check for IPv4-mapped IPv6 format:

```go
// Not blocked:
// ::ffff:127.0.0.1 → Maps to 127.0.0.1
// ::ffff:169.254.169.254 → Maps to metadata IP
```

#### 1.4 Missing Cloud Metadata IPs
Some cloud providers use different metadata IPs:

```go
// Missing from isCloudMetadataIP():
"192.0.0.192"      // Oracle Cloud Instance Metadata
"fc00:ec2::254"    // AWS IPv6 (alternate)
```

**Recommendation:**
1. Normalize all IP addresses before validation
2. Check entire 127.0.0.0/8 CIDR range
3. Add IPv4-mapped IPv6 handling
4. Add comprehensive cloud metadata IP list

---

### 2. DNS Rebinding Vulnerability [HIGH]

**Files:** `internal/security/url_validator.go`, `internal/solver/solver.go`

**Description:** Time-of-check-to-time-of-use (TOCTOU) vulnerability between URL validation and browser navigation.

**Attack Flow:**
1. Attacker controls DNS for `attacker.com`
2. First DNS query (validation) returns safe IP `1.2.3.4`
3. Validation passes
4. Attacker changes DNS to return `169.254.169.254`
5. Browser navigates and hits cloud metadata service

```go
// url_validator.go - Validation happens here
ips, err := net.LookupIP(hostname)  // Returns 1.2.3.4

// solver.go - Navigation happens later
page.Navigate(opts.URL)  // DNS may now return different IP
```

**Recommendation:**
1. Resolve DNS once and pass resolved IP to browser
2. Or use browser-level DNS resolution with blocklist
3. Or re-validate response headers/URL after navigation

---

### 3. Proxy Credential Exposure [MEDIUM]

**File:** `internal/browser/proxy_extension.go`

**Description:** Proxy credentials are written to temporary files with world-readable permissions.

```go
// Line 88 - Creates world-readable file
if err := os.WriteFile(manifestPath, data, 0644); err != nil {

// Line 135 - Credentials embedded in plain text
if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {

// Script contains:
username: "%s",
password: "%s"
```

**Impact:**
- Any local user can read proxy credentials
- Credentials may persist in temp directory on crash
- Credentials visible in process memory

**Recommendation:**
1. Use `0600` permissions for extension files
2. Securely delete extension directory on cleanup
3. Consider in-memory proxy authentication via CDP

---

### 4. JavaScript Injection in POST Form [MEDIUM]

**File:** `internal/solver/solver.go`

**Description:** User-controlled `postData` is injected into JavaScript with incomplete escaping.

```go
// buildFormFieldsJS() at line 309
func (s *Solver) buildFormFieldsJS(postData string) string {
    // Escaping performed:
    key = strings.ReplaceAll(key, "\\", "\\\\")
    key = strings.ReplaceAll(key, "'", "\\'")
    key = strings.ReplaceAll(key, "\n", "\\n")
    key = strings.ReplaceAll(key, "\r", "\\r")

    // Missing escapes for:
    // - </script> tag injection
    // - Unicode escapes (\\u0027)
    // - Backticks (template literals)
}
```

**Potential Attack:**
```
postData: "key=value</script><script>malicious()</script>"
```

**Recommendation:**
1. Use JSON encoding for values instead of string escaping
2. Or use `json.Marshal()` for proper escaping
3. Validate postData format before processing

---

### 5. Browser Sandbox Disabled [MEDIUM]

**File:** `internal/browser/pool.go`

**Description:** Chrome sandbox is disabled for container compatibility, reducing security isolation.

```go
// Line 132-134
l = l.Set("no-sandbox").
    Set("disable-setuid-sandbox").
    Set("disable-dev-shm-usage")
```

**Impact:**
- Exploits in rendered pages can escape browser process
- Required for Docker but increases attack surface

**Recommendation:**
1. Document security implications clearly
2. Only disable sandbox when running as root in containers
3. Consider using seccomp profiles for additional isolation

---

### 6. Certificate Validation Disabled [MEDIUM]

**File:** `internal/browser/pool.go`

**Description:** TLS certificate errors are ignored, enabling MITM attacks.

```go
// Line 200
browser = browser.MustIgnoreCertErrors(true)
```

**Impact:**
- Man-in-the-middle attacks possible
- Proxy interception won't be detected

**Recommendation:**
1. Make this configurable via environment variable
2. Default to `false` and only enable when using proxies
3. Log when certificate errors are ignored

---

### 7. Rate Limiting Header Spoofing [LOW]

**File:** `internal/middleware/ratelimit.go`

**Description:** Rate limiting trusts X-Forwarded-For and X-Real-IP headers without validation.

```go
// Line 130-147
func getClientIP(r *http.Request) string {
    // Trusts X-Forwarded-For header
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        // Takes first IP without validation
        return xff[:firstComma]
    }

    // Trusts X-Real-IP header
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    // ...
}
```

**Impact:**
- Attackers can bypass rate limiting by spoofing headers
- Only affects deployments not behind trusted proxy

**Recommendation:**
1. Add configuration for trusted proxy mode
2. When not behind proxy, use only RemoteAddr
3. Validate IP format from headers

---

### 8. Information Disclosure in Logs [LOW]

**Files:** Multiple

**Description:** Sensitive information may be logged:

```go
// middleware/recovery.go - Stack traces logged
log.Error().
    Str("stack", string(debug.Stack())).
    Msg("Panic recovered")

// handlers/handlers.go - URLs with potential sensitive data
log.Info().
    Str("url", req.URL).  // May contain API keys in query params
    Msg("Request received")
```

**Impact:**
- Stack traces may reveal internal structure
- URLs may contain sensitive query parameters

**Recommendation:**
1. Sanitize URLs before logging (remove query params)
2. Don't log full stack traces in production
3. Add log level configuration guidance

---

### 9. pprof Exposure Risk [LOW]

**File:** `cmd/flaresolverr/main.go`

**Description:** pprof server exposes detailed runtime information when enabled.

```go
// Line 8
import _ "net/http/pprof"

// Line 119-136 - Starts pprof server
if cfg.PProfEnabled {
    // Exposes /debug/pprof/* endpoints
}
```

**Impact:**
- Heap dumps may contain sensitive data
- Goroutine stacks reveal internal state
- CPU profiles can aid reverse engineering

**Current Mitigation:** Disabled by default (good)

**Recommendation:**
1. Add warning in logs when enabled
2. Consider requiring authentication
3. Bind to localhost only by default

---

## Security Strengths

The codebase demonstrates several security best practices:

1. **Request Body Size Limits** - 1MB limit prevents memory exhaustion
2. **Response Size Limits** - 10MB max prevents large response DoS
3. **Sync.Pool Usage** - Reduces GC pressure and memory predictability
4. **Rate Limiting** - Enabled by default with configurable limits
5. **Panic Recovery** - Prevents crashes from propagating
6. **Session Validation** - SessionID validation prevents injection
7. **Cookie Domain Sanitization** - Prevents cookie injection attacks
8. **Graceful Shutdown** - Proper resource cleanup on termination
9. **pprof Disabled by Default** - Good security default

---

## Risk Matrix

| Finding | Severity | Exploitability | Impact | CVSS Estimate |
|---------|----------|----------------|--------|---------------|
| SSRF Bypasses | HIGH | Medium | High | 7.5 |
| DNS Rebinding | HIGH | Medium | High | 7.2 |
| Proxy Credentials | MEDIUM | Low | Medium | 5.5 |
| JS Injection | MEDIUM | Low | Medium | 5.0 |
| Sandbox Disabled | MEDIUM | Low | High | 4.7 |
| Cert Validation | MEDIUM | Medium | Medium | 4.5 |
| Rate Limit Bypass | LOW | Medium | Low | 3.5 |
| Info Disclosure | LOW | Low | Low | 3.0 |
| pprof Exposure | LOW | Low | Low | 2.5 |

---

## Recommendations Summary

### Immediate (Before Production)

1. **Fix SSRF bypasses** in `url_validator.go`:
   - Normalize IP addresses before validation
   - Check entire 127.0.0.0/8 range
   - Add IPv4-mapped IPv6 handling
   - Add complete cloud metadata IP list

2. **Fix proxy credential permissions**:
   - Change file permissions to 0600
   - Ensure cleanup on crash/panic

### Short-Term

3. Implement DNS rebinding protection
4. Improve JavaScript escaping in POST form builder
5. Make certificate validation configurable
6. Add trusted proxy configuration for rate limiting

### Long-Term

7. Consider moving to browser-level proxy auth
8. Add security headers to responses
9. Implement request signing/authentication option
10. Add security logging/alerting

---

## Appendix: Test Cases for Validation

### SSRF Bypass Tests

```bash
# Decimal IP bypass
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"http://2130706433/"}'

# IPv4-mapped IPv6
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"http://[::ffff:127.0.0.1]/"}'

# Alternative loopback
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"http://127.0.0.2/"}'
```

### Rate Limit Bypass Tests

```bash
# Spoofed X-Forwarded-For
for i in {1..100}; do
  curl -H "X-Forwarded-For: fake-ip-$i" http://localhost:8191/v1
done
```

---

*This report was generated as part of a security audit. Findings should be verified and prioritized based on deployment context.*
