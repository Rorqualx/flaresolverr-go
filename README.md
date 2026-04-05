# FlareSolverr Go Edition

A high-performance Cloudflare bypass proxy server written in Go. This is a **drop-in replacement** for the original Python [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) with significant performance improvements.

## Drop-in Replacement

This project is fully API-compatible with the original FlareSolverr. You can replace your existing FlareSolverr instance without changing any client code:

- Same API endpoints (`/` and `/v1`)
- Same request/response format
- Same command names (`request.get`, `request.post`, `sessions.create`, etc.) plus new `sessions.keepalive`
- Same default port (8191)

**Just swap the Docker image or binary and you're done.**

## Features

- **Browser Pooling** - Reuses browser instances instead of spawning new ones per request (150-250MB vs 400-700MB)
- **Direct CDP Protocol** - Uses Chrome DevTools Protocol directly, bypassing Selenium overhead
- **Go Concurrency** - Native goroutines for better concurrency than Python's GIL
- **Memory Management** - Active memory monitoring with automatic browser recycling
- **Session Support** - TTL-based session management with per-request TTL override, keepalive command, and automatic cleanup
- **Cloudflare Bypass** - Solves JavaScript challenges and Turnstile CAPTCHAs
- **Anti-Fingerprinting** - 20 composable stealth patches with configurable fingerprint profiles (default, Windows, macOS, minimal)
- **Per-Session Chrome Flags** - Custom window size, language, timezone, and Chrome flags per session with dedicated browser instances
- **Human-Like Behavior** - Bezier curve mouse movements, randomized timing, and natural scroll patterns
- **Two-Phase CDP Bypass** - Bypasses Cloudflare's managed challenge loop by launching a clean Chrome without CDP for challenge resolution
- **External CAPTCHA Fallback** - Pluggable provider registry with 2Captcha, CapSolver, and anti-captcha.com for Turnstile and hCaptcha
- **hCaptcha Support** - Detects hCaptcha challenges, extracts sitekeys, and solves via external providers with token injection
- **Hot-Reload Selectors** - Update challenge selectors via file watching or remote URL without restarts
- **Adaptive Solving** - Per-domain tracking of which solving methods work best
- **Custom JS Execution** - Run arbitrary JavaScript on pages after challenge solving
- **Binary Downloads** - Download files as base64 through the browser (bypasses TLS fingerprinting)
- **Prometheus Metrics** - `/metrics` endpoint compatible with Prometheus/Grafana
- **OpenAPI Docs** - `/docs` endpoint serves the full API specification
- **CLI Dashboard** - Optional split-screen TUI showing live requests and server stats (`DASHBOARD_ENABLED=true`)
- **Multi-Architecture** - Docker images for amd64, arm64, and armv7
- **Docker Support** - Production-ready Docker image with Xvfb

## Quick Start

### Docker (Recommended)

```bash
docker run -d -p 8191:8191 --name flaresolverr rorqualx/flaresolverr-go:latest
```

### From Source

```bash
go build -o flaresolverr ./cmd/flaresolverr
./flaresolverr
```

### Check Version

```bash
./flaresolverr --version
```

## API Reference

The API accepts POST requests with JSON body at both `/` and `/v1` endpoints. All commands return the same response format.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | POST | Main API endpoint (legacy) |
| `/v1` | POST | Main API endpoint (recommended) |
| `/health` | GET | Health check with pool and domain stats |
| `/metrics` | GET | Prometheus-compatible metrics |
| `/docs` | GET | OpenAPI 3.0 specification (YAML) |

### Commands

#### `request.get` - Fetch a URL

Navigates to a URL, solves any Cloudflare challenges, and returns the page content.

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "request.get",
    "url": "https://example.com",
    "maxTimeout": 60000
  }'
```

#### `request.post` - Submit a POST request

Navigates to a URL with POST data.

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "request.post",
    "url": "https://example.com/login",
    "postData": "username=user&password=pass",
    "maxTimeout": 60000
  }'
```

#### `sessions.create` - Create a persistent session

Creates a session that persists cookies and browser state across requests.

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "sessions.create",
    "session": "my-session-id",
    "session_ttl_minutes": 60
  }'
```

The optional `session_ttl_minutes` parameter overrides the global `SESSION_TTL` for this session (1-1440 minutes). If omitted, the server default is used.

#### `sessions.list` - List active sessions

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "sessions.list"
  }'
```

#### `sessions.keepalive` - Refresh a session's TTL

Touches the session to prevent expiration. Optionally extends the TTL.

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "sessions.keepalive",
    "session": "my-session-id",
    "keepaliveTtl": 120
  }'
```

If `keepaliveTtl` is provided (in minutes), the session's TTL is updated to that value. If omitted, the session is simply touched to reset its inactivity timer.

#### `sessions.destroy` - Destroy a session

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "sessions.destroy",
    "session": "my-session-id"
  }'
```

### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cmd` | string | Yes | Command to execute |
| `url` | string | For request.* | Target URL to navigate to |
| `session` | string | No | Session ID for persistent sessions |
| `session_ttl_minutes` | int | No | Per-session TTL override in minutes (1-1440, default: server `SESSION_TTL`) |
| `maxTimeout` | int | No | Maximum timeout in milliseconds (default: 60000) |
| `cookies` | array | No | Cookies to set before navigation |
| `proxy` | object | No | Proxy configuration for this request |
| `postData` | string | For request.post | URL-encoded POST data |
| `returnOnlyCookies` | bool | No | Return only cookies, not HTML |
| `returnScreenshot` | bool | No | Return base64 PNG screenshot |
| `disableMedia` | bool | No | Block images, CSS, fonts to speed up loading |
| `waitInSeconds` | int | No | Wait N seconds before returning response |
| `contentType` | string | No | POST content type: `application/json` or `application/x-www-form-urlencoded` |
| `headers` | object | No | Custom HTTP headers (max 50) |
| `tabsTillVerify` | int | No | Tab presses for Turnstile keyboard navigation (0-50) |
| `download` | bool | No | Download URL as binary, return base64 in `response` field |
| `followRedirects` | bool | No | Follow HTTP redirects (default: true) |
| `userAgent` | string | No | Override User-Agent for this request |
| `returnRawHtml` | bool | No | Return raw HTML before JavaScript renders |
| `executeJs` | string | No | Custom JavaScript to execute after solving |
| `captchaSolver` | string | No | Per-request captcha provider: `2captcha`, `capsolver`, `anticaptcha`, or `none` |
| `captchaApiKey` | string | No | Per-request captcha API key |
| `keepaliveTtl` | int | No | New TTL in minutes for `sessions.keepalive` (0 = just touch, max 1440) |
| `cookieExtractDelay` | int | No | Seconds to wait before extracting cookies (0-30). Captures late-set JS cookies |
| `browserFlags` | object | No | Per-session Chrome flag overrides (`sessions.create` only). See below |
| `fingerprint` | object | No | Per-request browser fingerprint customization. See below |

#### Cookie Object

```json
{
  "name": "session_id",
  "value": "abc123",
  "domain": ".example.com",
  "path": "/",
  "secure": true,
  "httpOnly": true
}
```

#### Proxy Object

```json
{
  "url": "http://proxy.example.com:8080",
  "username": "user",
  "password": "pass"
}
```

Supported proxy schemes: `http`, `https`, `socks4`, `socks5`

#### Browser Flags Object

Per-session Chrome flag overrides. Sessions created with custom flags get a **dedicated browser** (not from the pool) that is closed when the session is destroyed.

```json
{
  "windowSize": "1280,720",
  "language": "fr-FR",
  "timezone": "Europe/Paris",
  "headless": true,
  "disableGpu": false,
  "extraArgs": ["--disable-extensions"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `windowSize` | string | Window dimensions as `"width,height"` (e.g. `"1280,720"`) |
| `language` | string | Accept-Language override (e.g. `"fr-FR"`, `"de-DE"`) |
| `timezone` | string | Timezone for stealth patches (e.g. `"Europe/Paris"`) |
| `headless` | bool | Override global headless setting |
| `disableGpu` | bool | Force software rendering |
| `extraArgs` | array | Additional Chrome flags (validated against security whitelist) |

**Security**: `extraArgs` are validated against an allowed whitelist. Dangerous flags like `--disable-web-security` and `--remote-debugging-port` are blocked.

**Example**: Create a French-language session with a smaller viewport:
```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "sessions.create",
    "session": "my-french-session-01",
    "browserFlags": {
      "windowSize": "1280,720",
      "language": "fr-FR",
      "timezone": "Europe/Paris"
    }
  }'
```

#### Fingerprint Object

Per-request browser fingerprint customization. Controls which stealth patches apply and what values they report.

```json
{
  "profile": "desktop-chrome-windows",
  "overrides": {
    "timezone": "Asia/Tokyo",
    "screenWidth": 1920,
    "screenHeight": 1080
  },
  "disablePatches": ["canvas", "audio"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `profile` | string | Builtin profile name (see below) |
| `overrides` | object | Override individual fingerprint dimensions |
| `disablePatches` | array | Stealth patches to skip by name |

**Builtin Profiles:**

| Profile | Description |
|---------|-------------|
| `default` | All patches enabled, standard 1920x1080, 8GB memory, 4 cores |
| `desktop-chrome-windows` | Windows UA, NVIDIA WebGL, 16GB memory, 8 cores |
| `desktop-chrome-mac` | macOS UA, Apple M1 WebGL, 2560x1440, 16GB, 10 cores |
| `minimal` | Only essential patches (webdriver, plugins, chrome-runtime) |

**Override Keys:** `timezone`, `locale`, `screenWidth`, `screenHeight`, `deviceMemory`, `hardwareConcurrency`, `webglVendor`, `webglRenderer`, `canvasNoiseSeed`

**Available Patches:** `webrtc`, `webdriver`, `plugins`, `languages`, `chrome-runtime`, `permissions`, `connection`, `hardware-concurrency`, `device-memory`, `tostring`, `webgl`, `notifications`, `canvas`, `audio`, `battery`, `speech`, `fonts`, `timezone`, `screen-position`, `device-pixel-ratio`

**Example**: Request with Windows fingerprint and Tokyo timezone:
```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "request.get",
    "url": "https://example.com",
    "maxTimeout": 60000,
    "fingerprint": {
      "profile": "desktop-chrome-windows",
      "overrides": {"timezone": "Asia/Tokyo"}
    }
  }'
```

### Response Format

```json
{
  "status": "ok",
  "message": "Challenge solved successfully",
  "startTimestamp": 1704067200000,
  "endTimestamp": 1704067205000,
  "version": "1.0.0",
  "solution": {
    "url": "https://example.com/",
    "status": 200,
    "response": "<html>...</html>",
    "cookies": [
      {
        "name": "cf_clearance",
        "value": "...",
        "domain": ".example.com",
        "path": "/",
        "expires": 1704153600,
        "httpOnly": true,
        "secure": true,
        "sameSite": "None"
      }
    ],
    "userAgent": "Mozilla/5.0...",
    "screenshot": "base64...",
    "turnstile_token": "..."
  }
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ok"` or `"error"` |
| `message` | string | Human-readable status message |
| `startTimestamp` | int | Request start time (Unix ms) |
| `endTimestamp` | int | Request end time (Unix ms) |
| `version` | string | FlareSolverr version |
| `solution` | object | Solution data (on success) |
| `sessions` | array | List of session IDs (for sessions.list) |

#### Solution Fields

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Final URL after redirects |
| `status` | int | HTTP status code |
| `response` | string | Page HTML content |
| `cookies` | array | All cookies from the page |
| `userAgent` | string | Browser user agent |
| `screenshot` | string | Base64 PNG (if requested) |
| `turnstile_token` | string | Cloudflare Turnstile token (if present) |
| `localStorage` | object | All localStorage key-value pairs (for debugging) |
| `sessionStorage` | object | All sessionStorage key-value pairs (for debugging) |
| `responseHeaders` | object | Extracted response metadata (cf-ray, etc.) |
| `responseTruncated` | bool | `true` if HTML was truncated due to 10MB size limit (optional) |
| `cookieError` | string | Error message if cookies could not be retrieved (optional) |
| `responseEncoding` | string | `"base64"` when `download=true` (optional) |
| `executeJsResult` | string | Result of `executeJs` custom JavaScript (optional) |
| `browserVersion` | string | Chrome major version for TLS profile matching (optional) |
| `rateLimited` | bool | `true` if rate limiting detected (optional) |
| `suggestedDelayMs` | int | Recommended delay before retry in ms (optional) |
| `errorCode` | string | Specific error code like `CF_1015` (optional) |
| `errorCategory` | string | Error category: `rate_limit`, `access_denied`, `captcha`, `geo_blocked` (optional) |

#### Rate Limit Detection

When the target site returns a rate limiting or access denied response, additional fields are included in the solution:

```json
{
  "solution": {
    "url": "https://example.com/",
    "status": 403,
    "response": "<html>Access denied...</html>",
    "rateLimited": true,
    "suggestedDelayMs": 5000,
    "errorCode": "ACCESS_DENIED",
    "errorCategory": "access_denied"
  }
}
```

**Supported Error Codes:**

| Code | Category | Description | Suggested Delay |
|------|----------|-------------|-----------------|
| `CF_1015` | rate_limit | Cloudflare rate limit | 60s |
| `CF_1020` | access_denied | Cloudflare suspicious request | 30s |
| `CF_1006-1008` | access_denied | Cloudflare access denied | 30s |
| `CF_1009` | geo_blocked | Cloudflare geo-restriction | N/A |
| `CF_1010` | access_denied | Browser signature rejected | 30s |
| `ACCESS_DENIED` | access_denied | Generic access denied | 5s |
| `RATE_LIMITED` | rate_limit | Generic rate limit | 10s |
| `TOO_MANY_REQUESTS` | rate_limit | Too many requests | 10s |
| `HTTP_429` | rate_limit | HTTP 429 status | 60s |
| `HTTP_503` | rate_limit | Service unavailable | 30s |
| `CAPTCHA_REQUIRED` | captcha | CAPTCHA challenge | N/A |

#### Response Headers

The following headers are included in responses for domain-level statistics:

| Header | Description |
|--------|-------------|
| `X-Domain-Suggested-Delay` | Recommended delay in ms based on domain history |
| `X-Domain-Error-Rate` | Error rate (0.0-1.0) for this domain |
| `X-Domain-Request-Count` | Total requests tracked for this domain |

## Configuration

All configuration is done via environment variables.

### Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8191` | Server port |

### Browser Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HEADLESS` | `true` | Run browser in headless mode |
| `BROWSER_PATH` | (auto) | Path to Chrome/Chromium executable |
| `BROWSER_POOL_SIZE` | `3` | Number of browser instances in pool |
| `BROWSER_POOL_TIMEOUT` | `30s` | Timeout for acquiring a browser |
| `MAX_MEMORY_MB` | `2048` | Memory limit before recycling browsers |

### Session Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_TTL` | `30m` | Session time-to-live |
| `SESSION_CLEANUP_INTERVAL` | `1m` | Cleanup interval for expired sessions |
| `MAX_SESSIONS` | `100` | Maximum concurrent sessions |

### Timeout Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_TIMEOUT` | `60s` | Default request timeout |
| `MAX_TIMEOUT` | `300s` | Maximum allowed timeout |

### Proxy Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | (none) | Default proxy URL for all requests |
| `PROXY_USERNAME` | (none) | Default proxy username |
| `PROXY_PASSWORD` | (none) | Default proxy password |

### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `RATE_LIMIT_RPM` | `60` | Requests per minute per IP |
| `TRUST_PROXY` | `false` | Trust X-Forwarded-For headers |
| `CORS_ALLOWED_ORIGINS` | (all) | Comma-separated allowed origins |
| `ALLOW_LOCAL_PROXIES` | `true` | Allow localhost/private IP proxies |
| `IGNORE_CERT_ERRORS` | `false` | Ignore TLS certificate errors |
| `API_KEY_ENABLED` | `false` | Enable API key authentication |
| `API_KEY` | (none) | Required API key (use 16+ chars) |

### API Key Authentication

When enabled, all requests (except `/health`) require authentication:

```bash
# Via header (recommended)
curl -X POST http://localhost:8191/v1 \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"cmd": "sessions.list"}'

# Via query parameter
curl -X POST "http://localhost:8191/v1?api_key=your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"cmd": "sessions.list"}'
```

**Enable in Docker:**
```yaml
environment:
  - API_KEY_ENABLED=true
  - API_KEY=your-secret-key-at-least-16-chars
```

### CAPTCHA Solver Settings

External CAPTCHA solver fallback for Turnstile and hCaptcha challenges that native solving cannot handle.

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTCHA_NATIVE_ATTEMPTS` | `3` | Native solve attempts before external fallback (1-10) |
| `CAPTCHA_FALLBACK_ENABLED` | `false` | Enable external CAPTCHA solver fallback |
| `TWOCAPTCHA_API_KEY` | (none) | 2Captcha API key |
| `CAPSOLVER_API_KEY` | (none) | CapSolver API key |
| `ANTICAPTCHA_API_KEY` | (none) | anti-captcha.com API key |
| `CAPTCHA_PRIMARY_PROVIDER` | `2captcha` | Primary provider: `2captcha`, `capsolver`, or `anticaptcha` |
| `CAPTCHA_SOLVER_TIMEOUT` | `120s` | Timeout for external solver API (30s-300s) |

**Supported CAPTCHA types:**
- **Turnstile** — Cloudflare's challenge widget (native + external solving)
- **hCaptcha** — Detected automatically, solved via external provider

**How it works:**
1. FlareSolverr attempts native Turnstile solving first (click methods, keyboard, etc.)
2. If native solving fails after `CAPTCHA_NATIVE_ATTEMPTS`, it falls back to the external solver
3. For hCaptcha, external solving is used directly (no native solving available)
4. External solver extracts the sitekey, submits to the provider, and injects the token
5. Per-request override: use `captchaSolver` and `captchaApiKey` fields in the request

**Example configuration:**
```yaml
environment:
  - CAPTCHA_FALLBACK_ENABLED=true
  - TWOCAPTCHA_API_KEY=your-2captcha-api-key
  - CAPTCHA_NATIVE_ATTEMPTS=2
```

### Selectors Settings

Hot-reload capable selectors for adapting to Cloudflare changes without restarts. Supports local files and remote URLs.

| Variable | Default | Description |
|----------|---------|-------------|
| `SELECTORS_PATH` | (none) | Path to external selectors.yaml override file |
| `SELECTORS_HOT_RELOAD` | `false` | Enable file watching for automatic reload |
| `SELECTORS_REMOTE_URL` | (none) | HTTP(S) URL to fetch selectors from |
| `SELECTORS_REMOTE_REFRESH` | `1h` | Refresh interval for remote selectors (5m-24h) |

When `SELECTORS_HOT_RELOAD` is enabled, changes to the selectors file are automatically detected and applied without restarting the service.

When `SELECTORS_REMOTE_URL` is configured, selectors are fetched periodically from the remote URL. File selectors take priority over remote selectors if both are configured.

### Logging & Monitoring

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `LOG_HTML` | `false` | Log HTML responses (verbose) |
| `LOG_FILE` | (none) | Path to log file (in addition to stdout) |
| `TZ` | (none) | Browser timezone (e.g., `America/New_York`) |
| `LANG` | (none) | Browser language (e.g., `en_GB`) |
| `TEST_URL` | `https://www.google.com` | URL to verify browser works on startup |
| `DASHBOARD_ENABLED` | `true` | TUI dashboard (auto-disables without TTY) |
| `PPROF_ENABLED` | `false` | Enable pprof profiling |
| `PPROF_PORT` | `6060` | pprof server port |
| `PPROF_BIND_ADDR` | `127.0.0.1` | pprof bind address |

### CLI Dashboard

FlareSolverr launches a split-screen terminal dashboard by default when running in an interactive terminal:

```
┌──────── Incoming Requests ────────┬──────────── Server Stats ──────────┐
│ 16:03:22 POST /v1 example.com 200 │ Server                             │
│ 16:03:21 POST /v1 site.org   200  │  Uptime: 2h 14m  Req/s: 2.1       │
│ 16:03:19 POST /v1 example.com 200 │  Total: 1,247    Goroutines: 42   │
│ 16:03:15 POST /v1 blocked.io 403  │  Memory: 312 MB                   │
│                                    │ Pool                               │
│                                    │  2/3 available                     │
│                                    │ Sessions                           │
│                                    │  4 active                          │
│                                    │ Domains (3)                        │
│                                    │  example.com  842 req  96% ok     │
│                                    │  site.org     231 req  89% ok     │
└────────────────────────────────────┴────────────────────────────────────┘
```

**Left pane:** Live request log with method, path, status code, and latency.
**Right pane:** Server stats including uptime, request rate, memory, browser pool state, active sessions, and top domains by request count.

Press `q` or `ctrl+c` to exit. Logging is suppressed while the dashboard is active.

The dashboard auto-disables when stdout is not a terminal (e.g., Docker logs, piped output). To explicitly disable it: `DASHBOARD_ENABLED=false`.

## Docker Compose Example

```yaml
version: "3.8"
services:
  flaresolverr:
    image: rorqualx/flaresolverr-go:latest
    container_name: flaresolverr
    ports:
      - "8191:8191"
    environment:
      - LOG_LEVEL=info
      - BROWSER_POOL_SIZE=3
      - MAX_TIMEOUT=300s
    restart: unless-stopped
```

## Migration from Python FlareSolverr

1. Stop your existing FlareSolverr container
2. Update your docker-compose.yml or run command to use this image
3. Start the new container
4. Your existing clients will work without any changes

**No code changes required in your applications.**

### Cookie Format Difference

There is one minor difference in cookie field naming:

| Field | Python FlareSolverr | Go Edition |
|-------|---------------------|------------|
| Expiration | `expiry` | `expires` |

Both values are Unix timestamps (seconds since epoch). If your client code explicitly checks for cookie expiration, use this pattern to handle both:

**JavaScript/TypeScript:**
```javascript
const expiry = cookie.expiry ?? cookie.expires;
```

**Python:**
```python
expiry = cookie.get('expiry') or cookie.get('expires')
```

**Go:**
```go
expiry := cookie.Expiry
if expiry == 0 {
    expiry = cookie.Expires
}
```

### Additional Cookie Fields

The Go edition includes extra fields not in Python FlareSolverr:

| Field | Type | Description |
|-------|------|-------------|
| `size` | int | Cookie size in bytes |
| `session` | bool | Whether it's a session cookie |

These are optional and can be safely ignored if not needed.

## Performance Comparison

| Metric | Python FlareSolverr | Go Edition |
|--------|---------------------|------------|
| Memory per session | 400-700 MB | 150-250 MB |
| Startup time | 5-10s | <1s |
| Request latency | Higher (Selenium) | Lower (CDP) |
| Concurrent requests | Limited (GIL) | Native goroutines |

## Health Check

```bash
curl http://localhost:8191/health
```

Returns:
```json
{
  "status": "ok",
  "message": "FlareSolverr is ready",
  "version": "1.0.0",
  "pool": {
    "size": 3,
    "available": 2,
    "acquired": 150,
    "released": 148,
    "recycled": 5,
    "errors": 2
  },
  "domainStats": {
    "example.com": {
      "requestCount": 45,
      "successCount": 42,
      "errorCount": 3,
      "rateLimitCount": 2,
      "avgLatencyMs": 2340,
      "lastRequestTime": "2025-01-15T10:35:00Z",
      "lastRateLimited": "2025-01-15T10:30:00Z",
      "suggestedDelayMs": 5000
    }
  },
  "defaults": {
    "minDelayMs": 1000,
    "maxDelayMs": 30000
  }
}
```

### Pool Statistics

| Field | Description |
|-------|-------------|
| `size` | Configured pool size (number of browser instances) |
| `available` | Browsers currently idle and ready for requests |
| `acquired` | Total browsers acquired from pool |
| `released` | Total browsers returned to pool |
| `recycled` | Browsers recycled due to memory or errors |
| `errors` | Total browser operation errors |

### Domain Statistics

When requests have been made, the health endpoint includes per-domain statistics:

| Field | Description |
|-------|-------------|
| `requestCount` | Total requests to this domain |
| `successCount` | Successful requests (2xx/3xx, no rate limiting) |
| `errorCount` | Failed requests |
| `rateLimitCount` | Requests that were rate limited |
| `avgLatencyMs` | Average response time |
| `lastRateLimited` | Timestamp of last rate limit event |
| `suggestedDelayMs` | Recommended delay between requests |

The `suggestedDelayMs` is calculated using an algorithm inspired by [Scrapy's AutoThrottle](https://docs.scrapy.org/en/latest/topics/autothrottle.html), considering latency, error rates, and recent rate limiting events.

## Performance Tuning

### Understanding Concurrency

FlareSolverr uses a browser pool to handle concurrent requests efficiently:

- **`BROWSER_POOL_SIZE`** controls how many requests can be processed simultaneously
- **`RATE_LIMIT_RPM`** controls the maximum requests per minute per IP

**Example behavior with defaults (`BROWSER_POOL_SIZE=3`, `RATE_LIMIT_RPM=60`):**

- 3 requests can be processed in parallel
- Additional requests queue until a browser becomes available
- Rate limiting kicks in at 60 requests/minute per client IP

### Tuning for Your Use Case

| Scenario | Recommended Settings |
|----------|---------------------|
| Low volume, fast response | `BROWSER_POOL_SIZE=2`, `RATE_LIMIT_RPM=30` |
| Medium volume | `BROWSER_POOL_SIZE=3`, `RATE_LIMIT_RPM=60` (defaults) |
| High volume, more memory | `BROWSER_POOL_SIZE=5`, `RATE_LIMIT_RPM=120` |
| Single client, max throughput | `BROWSER_POOL_SIZE=5`, `RATE_LIMIT_ENABLED=false` |

### Memory Considerations

Each browser instance consumes approximately:
- **100-150MB** base memory
- **+50-100MB** per active page (during request processing)

For a pool size of 3 with 5 active pages, expect **500-700MB** total memory usage.

Use `MAX_MEMORY_MB` to set a memory ceiling. When exceeded, browsers are automatically recycled.

## Troubleshooting

### Common Issues

#### "Access denied" errors
- **IP blocked**: The target site may have blocked your IP. Try using a proxy.
- **Bot detection**: Some sites have aggressive bot detection. Session reuse can help maintain cookies.
- **Rate limiting**: Reduce request frequency or use `RATE_LIMIT_RPM` to self-throttle.

#### Session requests failing
- Sessions auto-expire after `SESSION_TTL` (default: 30 minutes)
- Use `sessions.keepalive` to refresh a session's TTL without making a full request
- Use `keepaliveTtl` parameter to extend the TTL (e.g., `"keepaliveTtl": 120` for 2 hours)
- Always check if session exists with `sessions.list` before using
- Destroy and recreate sessions if they become stale

#### High memory usage
- Reduce `BROWSER_POOL_SIZE` (each browser uses 100-150MB)
- Enable `disableMedia: true` in requests to skip images/CSS
- Set `MAX_MEMORY_MB` to trigger automatic browser recycling

#### Browser pool exhaustion
- Increase `BROWSER_POOL_SIZE` for higher concurrency
- Increase `BROWSER_POOL_TIMEOUT` if requests timeout waiting for browsers
- Check `/health` endpoint to monitor pool stats

#### Container crashes
- Ensure adequate memory (minimum 512MB recommended)
- Check Docker logs for OOM kills
- Reduce `BROWSER_POOL_SIZE` if memory constrained

### Debug Mode

Enable debug logging to see detailed information:

```bash
docker run -e LOG_LEVEL=debug -p 8191:8191 rorqualx/flaresolverr-go:latest
```

### Getting Help

- [GitHub Issues](https://github.com/Rorqualx/flaresolverr-go/issues) - Bug reports and feature requests
- Check `/health` endpoint for pool statistics
- Review container logs for error messages

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## Attribution

Built with [Claude Code](https://claude.ai/code) by Anthropic

## License

MIT License - See [LICENSE](LICENSE) for details.
