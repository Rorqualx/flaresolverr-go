# Changelog

All notable changes to FlareSolverr Go Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-02-06

### Added
- **Browser state extraction** - API response now includes `localStorage`, `sessionStorage`, and `responseHeaders` fields for debugging sites that use browser storage instead of cookies.
- **Improved Turnstile solving** - Added `.cf-turnstile` selector detection, widget click with coordinates, and tries all methods (widget, iframe, keyboard) regardless of individual success.
- **browserVersion in API response** - Exposes Chrome major version to help users select matching tls-client profiles for JA3 fingerprint compatibility.
- **Per-request proxy support** - Requests can specify a proxy that spawns a dedicated browser instance with WebRTC leak prevention flags.
- **Security hardening** - Bind to localhost by default, header validation with size limits and security-sensitive header blocking, DNS pinning to detect rebinding attacks.
- **Shadow DOM traversal** - CDP-native access to closed shadow roots for Turnstile checkbox detection in nested shadow DOM.
- **Network capture** - Thread-safe HTTP response capture with status codes and headers from main document.
- **Custom headers support** - Pass custom headers to solver (validated via security/headers.go) with `contentType` for POST requests.
- **Enhanced domain statistics** - Success/failure rate tracking, average response time, challenge type tracking per domain.
- **Comprehensive test suite** - Added proxy extension tests, probe tests covering config, errors, health, integration, sessions, solver, stealth, and Turnstile.

### Changed
- **Chrome user agent updated to v132** - Updated to match current stable version and avoid anti-bot detection.
- **Improved stealth evasion** - WebRTC blocking at JavaScript level, Chrome loadTimes() caching, updated challenge selectors for newer Cloudflare versions.
- **Improved middleware** - Better error handling, configurable CORS origins, request ID tracking, rate limit burst support, improved panic logging with stack traces.
- **Removed Prometheus metrics** - Module was unused; will reconsider in future iteration if needed.
- **Alpine upgraded to 3.21** - Provides newer Chromium (136 vs 124) for better compatibility.
- **Slice pre-allocation in stealth** - `buildBlockPatterns()` now pre-allocates slice capacity.

### Fixed
- **SwiftShader WebGL support** - Added chromium-swiftshader and Mesa packages in Docker for software WebGL rendering that was causing Cloudflare to not set cookies.
- **Cookie retrieval** - Use `Network.getAllCookies` CDP API instead of `page.Cookies()` to match Python FlareSolverr's Selenium behavior.
- **User-Agent consistency** - Use browser's actual UA and normalize format instead of hardcoding, which caused detection when versions mismatched.
- **Rate limit false positives** - CAPTCHA detection pattern now only matches actual challenges, not pages with background reCAPTCHA scripts.
- **Headless mode bug** - Explicitly disable headless when `HEADLESS=false` to properly use Xvfb virtual display.
- **Timer leak prevention** - Replaced `time.After()` with `time.NewTimer()` in solver with explicit `timer.Stop()`.
- **Variable shadowing in solver** - Renamed error variables to avoid shadowing outer `err` used by panic recovery.
- **Concurrent session manager close** - Added closing flag and reference count draining with timeout to prevent races.
- **Race conditions in timeout middleware** - Use `atomic.Bool` for timedOut flag and synchronized ResponseWriter writes.
- **Deadlocks in page event handlers** - Event handlers now cancel context instead of calling cleanup to prevent circular waits.
- **Context cleanup in browser pool** - Added `defer spawnCancel()` in `recycleBrowser()` to prevent context leaks.
- **Error handling in tests** - Added proper error checks for `json.Unmarshal` calls in handlers tests and benchmarks.
- **Golangci-lint errors** - Fixed errcheck, gocritic, and gofmt issues.

### Security
- **XSS prevention** - Version string sanitization with `html.EscapeString` and `html/template` for health page to prevent injection via malicious ldflags.
- **SSRF protection expanded** - Added cloud metadata endpoints for AWS, GCP, Azure, Alibaba, Oracle, IBM, DigitalOcean, Hetzner, Vultr, Linode, Tencent, and Kubernetes API.

### Documentation
- **Docker Hub registry** - Fixed image reference from ghcr.io to rorqualx/flaresolverr-go.
- **Development roadmap** - Added ROADMAP.md documenting planned features.

## [0.3.0] - 2025-01-17

### Added
- **Rate limit detection** - Responses now include `rateLimited`, `suggestedDelayMs`, `errorCode`, and `errorCategory` fields when target sites return rate limiting or access denied responses. Detects Cloudflare errors (1015, 1020, 1006-1010), generic rate limits, and CAPTCHAs.
- **Per-domain statistics** - Track request counts, success rates, error rates, and latency per domain. Adaptive delay calculation inspired by Scrapy's AutoThrottle algorithm.
- **Enhanced health endpoint** - `/health` now includes `domainStats` with per-domain metrics and `suggestedDelayMs` for each tracked domain.
- **Domain statistics headers** - Responses include `X-Domain-Suggested-Delay`, `X-Domain-Error-Rate`, and `X-Domain-Request-Count` headers for quick client access.
- **Cookie migration docs** - README now documents the `expires` vs `expiry` difference from Python FlareSolverr with code examples for multiple languages.
- **API key authentication** - Optional API key authentication via `API_KEY_ENABLED` and `API_KEY` environment variables. Supports `X-API-Key` header or `api_key` query parameter.
- **LRU eviction for domain stats** - Domain statistics are now limited to 10,000 entries with LRU eviction to prevent unbounded memory growth.
- **Cookie error tracking** - Result now includes `cookieError` field when cookies cannot be retrieved.
- **Extended browser state extraction** - API response now includes `localStorage`, `sessionStorage`, and `responseHeaders` fields for debugging sites that use browser storage instead of cookies for authentication state.

### Changed
- Response `solution` object now has optional rate limit fields (backward compatible - only present when rate limiting detected).

### Security
- **CRITICAL: Fixed JavaScript injection vulnerability** - Proxy credentials in browser extension now use `json.Marshal` for proper escaping, preventing XSS/injection attacks via malicious proxy credentials.
- **Fixed metrics registration panic** - Prometheus metrics now use `sync.Once` to prevent panics when metrics are already registered (e.g., during tests).
- **Fixed race condition in session page access** - Added `SafeGetPage()` method with proper mutex synchronization to prevent TOCTOU races.
- **Fixed header access race** - Timeout middleware now synchronizes header access to prevent races between handler and timeout goroutines.
- **Fixed context cancellation in browser pool** - `spawnBrowser()` now accepts context for proper cancellation during shutdown.
- **ReDoS prevention** - Rate limit detector regex patterns rewritten to use `[^<]{0,N}` instead of `.{0,N}` and body truncated to 100KB before regex matching.
- **Port conflict validation** - Configuration now validates and auto-adjusts conflicting ports for Prometheus and pprof.
- **Improved stealth error handling** - Critical stealth script errors (syntax/reference) now return errors instead of being silently swallowed.

## [0.2.3] - 2025-01-17

### Fixed
- **Session reuse stealth errors** - Fixed `TypeError: Cannot read properties of undefined (reading 'apply')` that occurred when making multiple requests with the same session. Stealth patches are now only applied to fresh pages, not reused session pages.
- **Cookie partitionKey warning** - Chrome 114+ returns `partitionKey` as a string field causing JSON unmarshal warnings. Now handled gracefully at debug log level.
- **Defensive stealth script** - Added existence checks for `.call` method in toString and WebGL patches to prevent errors in edge cases.

### Added
- **Health endpoint pool stats** - `/health` now returns detailed pool statistics including size, available, acquired, released, recycled, and errors counts.
- **Performance tuning documentation** - README now includes guidance on tuning `BROWSER_POOL_SIZE` and `RATE_LIMIT_RPM` for different use cases.

### Changed
- Stealth script failures now log at debug level instead of warn (non-blocking errors).

## [0.2.2] - 2025-01-16

### Fixed
- **WebGL spoofing** - Replaced Proxy-based WebGL spoof with simple function wrapper for better compatibility across browser contexts.

## [0.2.1] - 2025-01-16

### Fixed
- **Lint errors** - Resolved gofmt formatting and spelling issues.
- **Anti-detection improvements** - Enhanced Xvfb headed mode and WebGL fingerprint spoofing.

## [0.2.0] - 2025-01-15

### Added
- Initial Go rewrite of FlareSolverr
- Browser pooling for memory efficiency
- Direct CDP protocol (no Selenium)
- Session management with TTL
- Rate limiting per IP
- Prometheus metrics support
- SSRF protection
- Docker support with Xvfb

### Changed
- Complete rewrite from Python to Go
- Memory usage reduced from 400-700MB to 150-250MB per session
- Startup time reduced from 5-10s to <1s

---

## Migration Notes

### From Python FlareSolverr
No code changes required. This is a drop-in replacement:
1. Stop existing container
2. Replace image with `rorqualx/flaresolverr-go:latest`
3. Start new container

### Session Best Practices (v0.2.3+)
- Sessions maintain browser state across requests
- First request applies stealth patches
- Subsequent requests reuse the same browser context
- Sessions auto-expire after `SESSION_TTL` (default: 30m)
- Destroy sessions when done to free resources
