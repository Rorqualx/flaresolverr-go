# Changelog

All notable changes to FlareSolverr Go Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.4] - 2026-10-11

### Security
- **Cookies and storage leaked between callers** - Pooled browsers are reused, and nothing cleared them between requests: a cookie with an expiry set during one request was sent with the next caller's request to the same site, and every cookie in the browser (including another site's `cf_clearance`) was returned in later responses for unrelated sites. Each stateless request now runs in its own browser context (private cookies, localStorage, cache), which is disposed when the request ends. Reproduced and re-probed live.

### Changed
- **Sessions no longer take browsers from the request pool** - A session used to hold a pooled browser for its whole lifetime, so `BROWSER_POOL_SIZE` sessions blocked every other request. Sessions are now isolated browser contexts on one shared session browser, started with the first session and closed with the last. Measured on the production Chromium: about 150MB per session with a script-heavy page open, against about 300MB for a dedicated browser, and creation in about 0.2s. Sessions created with `browserFlags` still get a browser process of their own.
- **`MAX_SESSIONS` default lowered from 100 to 20** - With the pool no longer acting as an accidental cap, the default is sized to memory. A warning is logged at startup when the limit times ~150MB exceeds `MAX_MEMORY_MB`.
- **Session proxy** - A `proxy` given to `sessions.create` is now applied to the session (it was ignored unless `browserFlags` was also set), including proxy credentials. A `proxy` on a request that uses a session is still ignored, as in the original FlareSolverr, and is now logged.

### Fixed
- **Sessions with a timezone could not be destroyed** - Applying the timezone at `sessions.create` leaked a page reference, so the session looked permanently in use: `sessions.destroy` returned "in use" and, since v0.8.3, the TTL cleanup skipped it too.
- **Browser launched before validation** - `sessions.create` with `browserFlags` started Chrome before checking for a duplicate ID or a full session table.

## [0.8.3] - 2026-10-11

### Fixed
- **Browsers closed while still in use** - The 30-minute age recycle and the memory-pressure recycle closed every tracked browser, including ones serving a request or held by a session, and left the dead browser queued so its replacement was discarded. Recycling now replaces idle browsers only; a checked-out browser is flagged and replaced when it is released.
- **Double release of pooled browsers** - `sessions.create` with an existing session ID released the same browser twice, so two requests could share one browser and the first to finish closed the other's page. `Release` now ignores a browser that is not checked out, and closes (never queues) a browser the pool does not own. `Session.Create` no longer releases the browser on error: the caller keeps ownership until it succeeds.
- **Unbounded browser teardown** - `CleanupBrowser` waited indefinitely for Chrome to exit and never killed it, in places while holding the pool lock. The close request now has a deadline, a process that does not exit is killed, and no teardown runs under the lock. Failed and timed-out launches kill the process and remove its user-data dir.
- **Pool shrinking after a failed respawn** - A replacement browser that failed to launch removed its pool slot permanently. The slot is now kept and retried on each health check.
- **Session teardown races** - Concurrent `sessions.destroy` calls (or a destroy racing the TTL cleanup) could each release the session's browser. Exactly one teardown now wins. A destroy that times out because the session is busy leaves the session usable instead of stranding it, and the TTL cleanup no longer closes a session's page while a request is using it.
- **Default proxy bypass for custom-flag sessions** - `sessions.create` with `browserFlags` and no proxy launched Chrome without the configured `PROXY_URL`.
- **Unbounded health-check and release calls** - The pool's own health check and page cleanup now run under a deadline, so a frozen browser is recycled instead of blocking `Acquire` or `Release`.

## [0.8.2] - 2026-10-11

### Security
- **SSRF read via `returnRawHtml`** - The raw-HTML path returned the page body before the post-navigation URL check ran, so a public URL that redirected to an internal host could be read back. The check now runs on that path too. Reproduced and re-probed live.
- **Octal host bypass of the SSRF validator** - An all-digit host with a leading zero (`http://01200000001/`) was parsed as a decimal, public address while Chrome reads it as octal (`10.0.0.1`). Single-number hosts are now parsed with the same `0` / `0x` rules as the WHATWG URL parser, and a single trailing dot is ignored. Reproduced and re-probed live.
- **Special-purpose IP ranges** - The validator now also blocks CGNAT (`100.64.0.0/10`), benchmarking, TEST-NET, multicast, reserved, Teredo, site-local and discard ranges, and validates the IPv4 address embedded in NAT64 and 6to4 addresses.
- **Unvalidated proxy on `sessions.create`** - With `browserFlags`, the proxy URL was passed to Chrome without the proxy SSRF check that `request.get`/`request.post` apply.
- **API key authentication failed open** - `API_KEY_ENABLED=true` with an empty `API_KEY` accepted every request, because a missing header matched the empty key. All requests are now rejected in that configuration.
- **Proxy credentials sent to origin servers** - Proxy credentials were supplied to every browser auth challenge, including a target site's `401`. They are now provided only for challenges from the proxy, once per request; other challenges are cancelled.
- **9kw API key in logs** - Transport errors from the 9kw client included the request URL and its `apikey` parameter.
- **Dependencies** - `golang.org/x/net` v0.55.0 and `golang.org/x/text` v0.39.0 for GO-2026-5026 and GO-2026-5970, both reachable from URL validation.

### Changed
- **Go 1.26** - The dependency updates require Go 1.25+, and Go 1.24 is out of support. `go.mod`, CI and the Docker images now build with Go 1.26.
- **Proxy authentication retries** - A proxy that rejects its credentials now gets one attempt before the request is cancelled.

### Known limitations
- A public URL that redirects to a private host is rejected in the response, but the browser still sends the request to that host. Closing this needs per-hop interception or an egress proxy.

## [0.8.1] - 2026-08-15

### Added
- **Managed-challenge Turnstile param capture across OOPIF (#11)** - Completes the #11 work begun in v0.8.0. Cloudflare's *managed challenge* renders Turnstile from its own challenge platform into a cross-origin **out-of-process iframe** (OOPIF) nested in a closed shadow root — so `sitekey`, `action`, `cData`, and `chlPageData` exist only inside that separate CDP target and are invisible to `querySelector`, `getFrameTree`, `getTargets`, and the pierced DOM of the main target (the earlier "read the live DOM via `Runtime.evaluate`" approach is a no-op for this case). On installing the `turnstile.render` interceptor, the solver now enables CDP `Target.setAutoAttach{autoAttach, flatten, waitForDebuggerOnStart}` on the page session, listens for child-attach events on the **browser-level** event stream (go-rod's `Page.EachEvent` filters them out), injects the interceptor into each paused OOPIF child via `Page.addScriptToEvaluateOnNewDocument` at `document_start`, then resumes it with `Runtime.runIfWaitingForDebugger`. `ReadCapturedChallengeParams` / `InjectCapturedCallback` now also consult OOPIF children, so all four params are captured and the solved token is injected via the captured callback. Children are processed **synchronously and single-level** by design — a goroutine-per-child/recursive variant flooded CDP and pushed a theverge.com solve from 17s to 98s. The capture mechanism was validated end-to-end on a synthesized OOPIF (a two-origin `Document-Isolation-Policy` fixture; see `docs/INVESTIGATION-issue-11-oopif-probes.md`) and regression-validated live (nowsecure, theverge, example, filecrypt homepage — no hang, no CDP flood). **Known limitation:** even with valid params, a flagged IP/fingerprint can still withhold `cf_clearance` at submit time (the #13 wall) independent of the token — clean egress + the clearance cache remain the dominant levers there.
  - `pool.go` carries a guard: never add `site-per-process` to `--disable-features`. go-rod's default launcher disables site isolation (`--disable-features=site-per-process` + `--disable-site-isolation-trials`), which collapses cross-origin iframes in-process and silently no-ops OOPIF auto-attach; the pool overrides that default, and re-disabling it would break this feature.

### Changed
- **Health-check and stats logs demoted to DEBUG (#14)** - Routine per-interval health-check and stats-reporter lines were logged at INFO, spamming logs during normal operation. They are now DEBUG, so default (INFO) logs stay quiet unless something is actually happening. Set `LOG_LEVEL=debug` to restore the previous verbosity.

## [0.8.0] - 2026-06-19

### Fixed
- **Browser fingerprint gate-2 tells (#11/#13)** - Live probes against bot detectors (see `docs/INVESTIGATION-fingerprint-gate2.md`) found two automation tells on the primary `request.get`/POST paths, which used only `go-rod/stealth`: (1) a **macOS WebGL renderer reported on a Linux browser** (OS-layer inconsistency), and (2) **`screen` stuck at the headless 800×600 default** while the viewport was larger — a physically impossible geometry. Added `ApplyGate2Corrections` (a surgical WebGL-OS + coherent screen/window geometry override) applied on all request paths. Validated on live Chrome: WebGL now reports a Linux ANGLE renderer, geometry satisfies `inner ≤ outer ≤ avail ≤ screen`, and sannysoft still passes every check with no regression. Probes also **ruled out** TLS/JA3/HTTP2 (genuine Chrome 136) and the CDP `Runtime.enable` leak (go-rod never calls it) as tells.
- **Path traversal detection** - Replaced simple `strings.Contains("..")` checks with proper `filepath.Clean()` and `filepath.Abs()` normalization in config validation. Handles edge cases like `....//`, symlinks, and other obfuscation techniques.
- **Context cancellation leak** - Fixed non-deferred `cancel()` call in selectors manager that could leak context on early returns.
- **Context propagation in POST** - `navigatePost()` and `navigatePostJSON()` now accept explicit context parameter instead of using `page.GetContext()` for proper timeout/cancellation propagation.
- **Error wrapping** - Added `fmt.Errorf` wrapping with context to errors in solver and URL validator for better debugging and error chain support with `errors.Is()`.
- **Response body cleanup** - Added `defer resp.Body.Close()` to all integration test functions following Go best practices.

### Added
- **Sticky clean-egress proxy pool** (#11/#13, clean-egress path Layer 1) - A pool of egress proxies with a selection strategy, configured via `PROXY_LIST` (comma/newline-separated, embedded `user:pass@` supported) and `PROXY_STRATEGY` (`sticky-domain` default, `round-robin`, `per-request`). `sticky-domain` maps each registrable domain to a stable proxy so a site always exits the same IP — which is what keeps the Layer-2 cf_clearance cache valid (clearance is IP-bound). Selection runs only when no per-request `proxy` is supplied. Validated live: requests route through the selected egress and the clearance cache keys on it. Together with the clearance cache, this is the "demote-the-tier + reuse-the-clearance" path for Cloudflare managed challenges.
- **cf_clearance reuse cache** (#11/#13, clean-egress path Layer 2) - Caches a minted `cf_clearance` (plus the exact User-Agent that minted it) keyed by registrable-domain + egress identity, then injects it before navigation on subsequent requests so the normal solve clears instantly. Turns the expensive cold solve — especially the ~minutes-long two-phase CDP bypass — into a once-per-(domain,egress) cost. `cf_clearance` is IP+UA-bound, so the cache key includes the egress and the entry carries the UA; reuse only happens when both match (no cross-egress leakage). Validated live: 2nd+ requests fire the fast path and clear on the first detection attempt. Configurable via `CLEARANCE_CACHE_ENABLED` (default true) and `CLEARANCE_TTL` (default 25m).
- **9kw.eu CAPTCHA provider** (#3) - Added the 9kw.eu human-powered solver as a fourth external provider. Configure via `NINEKW_API_KEY` and select with `CAPTCHA_PRIMARY_PROVIDER=9kw` or the per-request `captchaSolver` field. 9kw solves hCaptcha (and image/reCAPTCHA-style challenges) but has **no Cloudflare Turnstile support**, so `SolveTurnstile` returns an unsupported error and the chain falls through to a Turnstile-capable provider. It does not help the Cloudflare managed-challenge path in #11/#13.
- **Per-request session TTL** - `session_ttl_minutes` field in `sessions.create` requests now overrides the global `SESSION_TTL` for individual sessions (1-1440 minutes). Sessions without a custom TTL continue using the server default.
- **CLI dashboard** - New `internal/dashboard` package provides a split-screen TUI showing live incoming requests and server stats (pool, sessions, domains, memory, request rate). Enable via `DASHBOARD_ENABLED=true`. Built with bubbletea/lipgloss.
- **Human-like behavior patterns** - New `internal/humanize` package with randomized timing, natural mouse movements using Bezier curves, and realistic scroll behavior. Makes automated actions appear more human-like to avoid detection.
- **External CAPTCHA solver fallback** - Integration with 2Captcha and CapSolver APIs for Turnstile challenges that native solving cannot handle. Configurable via `CAPTCHA_FALLBACK_ENABLED`, `TWOCAPTCHA_API_KEY`, and `CAPSOLVER_API_KEY` environment variables.
- **Hot-reload selectors** - New `internal/selectors` manager supports loading selectors from external YAML files with file watching for automatic reload. Configure via `SELECTORS_PATH` and `SELECTORS_HOT_RELOAD` environment variables.
- **Remote selector fetch** - Selectors can now be fetched from a remote HTTP(S) URL with periodic refresh for centralized management. Configure via `SELECTORS_REMOTE_URL` and `SELECTORS_REMOTE_REFRESH` environment variables.
- **Advanced anti-fingerprinting** - Extended stealth script with Battery API mock, Speech Synthesis voice list spoofing, Font enumeration limiting, and Timezone/Intl API consistency.
- **Enhanced canvas fingerprinting protection** - Canvas toBlob, getImageData, and WebGL readPixels now include session-consistent noise injection to prevent fingerprinting while maintaining visual consistency.
- **Turnstile method tracking** - Per-domain statistics track which solving methods (wait, shadow, keyboard, widget, iframe, positional) work best. The solver adapts by prioritizing historically successful methods.
- **Invisible Turnstile detection** - Solver now checks for `cf_clearance` cookie presence to detect solved invisible Turnstile challenges even when widget remains visible.
- **Randomized poll intervals** - Solver uses 0.8-1.5s random intervals instead of fixed 1s for more human-like timing patterns.

### Changed
- **Solver architecture** - New `SolverConfig` struct for full configuration injection. `StatsManager` interface enables per-domain learning.
- **Handler initialization** - `NewWithSelectors` constructor supports custom SelectorsManager injection.
- **Stealth script optimization** - Script now detects about:blank pages and skips non-essential patches (canvas, audio, WebGL) that may fail on blank pages.
- **WebGL getParameter safety** - Added function validity check before calling original getParameter to prevent "Cannot read properties of undefined" errors.

### New Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTCHA_NATIVE_ATTEMPTS` | `3` | Native solve attempts before external fallback |
| `CAPTCHA_FALLBACK_ENABLED` | `false` | Enable external CAPTCHA solver fallback |
| `TWOCAPTCHA_API_KEY` | (none) | 2Captcha API key |
| `CAPSOLVER_API_KEY` | (none) | CapSolver API key |
| `CAPTCHA_PRIMARY_PROVIDER` | `2captcha` | Primary provider: `2captcha` or `capsolver` |
| `CAPTCHA_SOLVER_TIMEOUT` | `120s` | Timeout for external solver API |
| `SELECTORS_PATH` | (none) | Path to external selectors.yaml override |
| `SELECTORS_HOT_RELOAD` | `false` | Enable file watching for selector hot-reload |
| `SELECTORS_REMOTE_URL` | (none) | HTTP(S) URL to fetch selectors from |
| `SELECTORS_REMOTE_REFRESH` | `1h` | Refresh interval for remote selectors (5m-24h) |
| `DASHBOARD_ENABLED` | `true` | TUI dashboard (auto-disables without TTY) |

### Removed
- **All Prometheus references** - Removed unused `PROMETHEUS_ENABLED` and `PROMETHEUS_PORT` environment variables from Dockerfile and docker-compose.yml. Removed `/metrics` endpoint bypass from API key middleware. Prometheus was never implemented; use the new CLI dashboard for monitoring instead.

### Documentation
- **Python strategies comparison** - Updated PYTHON_STRATEGIES.md to reflect complete implementation status for stealth (17 patches), proxy support, and new Go advantages.
- **Contributing guide** - Added new packages (humanize, captcha, selectors, stats, security) to CONTRIBUTING.md.

## [0.5.0] - 2025-02-06

### Added
- **Browser state extraction** - API response now includes `localStorage`, `sessionStorage`, and `responseHeaders` fields for debugging sites that use browser storage instead of cookies.
- **Improved Turnstile solving** - Added `.cf-turnstile` selector detection, widget click with coordinates, and tries all methods (widget, iframe, keyboard) regardless of individual success.
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
- **Removed Prometheus metrics** - Module was unused; replaced by the built-in CLI dashboard.
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

## [0.4.0] - 2025-02-06

### Added
- **browserVersion in API response** - Exposes Chrome major version to help users select matching tls-client profiles for JA3 fingerprint compatibility.
- **Per-request proxy support** - Requests can specify a proxy that spawns a dedicated browser instance with WebRTC leak prevention flags.

### Fixed
- **Docker Hub registry** - Fixed image reference from ghcr.io to rorqualx/flaresolverr-go.
- **Golangci-lint errors** - Fixed errcheck and gofmt issues.

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
