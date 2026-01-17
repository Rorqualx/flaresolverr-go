# FlareSolverr Go Edition

A high-performance Cloudflare bypass proxy server written in Go. This is a **drop-in replacement** for the original Python [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) with significant performance improvements.

## Drop-in Replacement

This project is fully API-compatible with the original FlareSolverr. You can replace your existing FlareSolverr instance without changing any client code:

- Same API endpoints (`/` and `/v1`)
- Same request/response format
- Same command names (`request.get`, `request.post`, `sessions.create`, etc.)
- Same default port (8191)

**Just swap the Docker image or binary and you're done.**

## Features

- **Browser Pooling** - Reuses browser instances instead of spawning new ones per request (150-250MB vs 400-700MB)
- **Direct CDP Protocol** - Uses Chrome DevTools Protocol directly, bypassing Selenium overhead
- **Go Concurrency** - Native goroutines for better concurrency than Python's GIL
- **Memory Management** - Active memory monitoring with automatic browser recycling
- **Session Support** - TTL-based session management with automatic cleanup
- **Cloudflare Bypass** - Solves JavaScript challenges and Turnstile CAPTCHAs
- **Docker Support** - Production-ready Docker image with Xvfb

## Quick Start

### Docker (Recommended)

```bash
docker run -d -p 8191:8191 --name flaresolverr ghcr.io/rorqualx/flaresolverr-go:latest
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
| `/health` | GET | Health check endpoint |

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
    "session": "my-session-id"
  }'
```

#### `sessions.list` - List active sessions

```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "sessions.list"
  }'
```

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
| `maxTimeout` | int | No | Maximum timeout in milliseconds (default: 60000) |
| `cookies` | array | No | Cookies to set before navigation |
| `proxy` | object | No | Proxy configuration for this request |
| `postData` | string | For request.post | URL-encoded POST data |
| `returnOnlyCookies` | bool | No | Return only cookies, not HTML |
| `returnScreenshot` | bool | No | Return base64 PNG screenshot |
| `disableMedia` | bool | No | Block images, CSS, fonts to speed up loading |
| `waitInSeconds` | int | No | Wait N seconds before returning response |

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

When enabled, all requests (except `/health` and `/metrics`) require authentication:

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

### Logging & Monitoring

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `LOG_HTML` | `false` | Log HTML responses (verbose) |
| `PROMETHEUS_ENABLED` | `false` | Enable Prometheus metrics |
| `PROMETHEUS_PORT` | `8192` | Prometheus metrics port |
| `PPROF_ENABLED` | `false` | Enable pprof profiling |
| `PPROF_PORT` | `6060` | pprof server port |
| `PPROF_BIND_ADDR` | `127.0.0.1` | pprof bind address |

## Docker Compose Example

```yaml
version: "3.8"
services:
  flaresolverr:
    image: ghcr.io/rorqualx/flaresolverr-go:latest
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
