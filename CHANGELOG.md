# Changelog

All notable changes to FlareSolverr Go Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
